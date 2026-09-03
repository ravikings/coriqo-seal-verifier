"""
run_pdf_bundle: GET /api/v1/engagements/{id}/deliverable.pdf.

A sealed deliverable PDF is NOT shaped like a deliverables.zip. It carries
exactly two attachments toward this check -- manifest.json and
certificate.json -- and no separate third bundled file: manifest.json lists
a `deck_content` row, but deck_content's bytes are a JSON snapshot that
exists only inside the manifest's own recorded hash, never as its own
extractable attachment. So the chain under test here is two links, not
three: signature -> statement.bundle_binding.manifest_sha256 ->
manifest.json bytes. See sealed_deliverable.py's module-level fix and
run_pdf_bundle's own docstring.

Reuses test_bundle_verifier.py's manifest/certificate builders (format is
JSON either way -- only the container differs) rather than re-deriving
signing from scratch a second time.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_bundle_verifier as tb  # noqa: E402 — reuses _build_manifest, _signed_certificate, _serialize_manifest

pypdf = pytest.importorskip("pypdf", reason="sealed-PDF verification needs pypdf")


def _write_pdf(path: Path, attachments: dict[str, bytes]) -> None:
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    for name, data in attachments.items():
        writer.add_attachment(name, data)
    with open(path, "wb") as fh:
        writer.write(fh)


def _sealed_pdf(tmp_path: Path, *, tamper_manifest: bool = False,
                 corrupt_binding: bool = False, omit_certificate: bool = False) -> Path:
    """A minimal sealed-deliverable-shaped manifest (no zip-only `files`
    payload entries — just the deck_content + certificate.json rows the real
    module produces) plus a real signed certificate binding it."""
    manifest = {
        "document": "engagement_deliverable",
        "sealed": True,
        "engagement_id": "eng-test-1",
        "model_id": None,
        "generated_at": "2026-09-01T00:00:00Z",
        "generated_by": "test-actor",
        "files": [
            {"name": "deck_content", "status": "present",
             "sha256": hashlib.sha256(b'{"models": 27}').hexdigest(),
             "source_endpoint": "GET /api/v1/reports/engagement-deck"},
            {"name": "certificate.json", "status": "present", "sha256": None,
             "sha256_omitted_reason": "circular — see module docstring"},
        ],
        "note": "sealed",
    }
    manifest_bytes = tb._serialize_manifest(manifest)
    # NOT mutated after signing: cert["statement"] bytes are exactly what
    # _signed_certificate signed. Editing "bundle" post-hoc here would be
    # the same self-inflicted invalidation the corrupt_binding path
    # deliberately tests for as an ATTACK — don't do it by accident in a
    # fixture meant to be clean.
    cert = tb._signed_certificate(manifest_bytes, corrupt_binding=corrupt_binding)

    pdf_manifest_bytes = manifest_bytes
    if tamper_manifest:
        tampered = json.loads(manifest_bytes)
        tampered["files"][0]["sha256"] = "0" * 64
        pdf_manifest_bytes = tb._serialize_manifest(tampered)

    attachments = {"manifest.json": pdf_manifest_bytes}
    if not omit_certificate:
        attachments["certificate.json"] = json.dumps(cert, indent=2).encode("utf-8")

    p = tmp_path / "engagement_deliverable_sealed.pdf"
    _write_pdf(p, attachments)
    return p


def test_clean_sealed_pdf_verifies(tmp_path):
    p = _sealed_pdf(tmp_path)
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_OK


def test_auto_routes_a_manifest_carrying_pdf_to_the_full_check(tmp_path):
    """The routing rule itself: a positional PDF with manifest.json must not
    take the weak certificate-only path."""
    p = _sealed_pdf(tmp_path)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK


def test_tampered_deck_content_hash_fails_the_binding(tmp_path):
    """THE case this exists for: deck_content's recorded hash is rewritten
    post-signing (the classic cover-a-changed-figure move). The certificate
    was signed over the ORIGINAL manifest bytes, so this must fail at link
    2/2 even though the certificate's own signature is untouched."""
    p = _sealed_pdf(tmp_path, tamper_manifest=True)
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_TAMPER


def test_tampered_deck_content_hash_fails_through_auto_routing_too(tmp_path):
    p = _sealed_pdf(tmp_path, tamper_manifest=True)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_TAMPER


def test_corrupted_binding_fails_at_the_signature_not_the_binding_check(tmp_path):
    """An attacker without the signing key who rewrites bundle_binding
    itself (not just a files row) changes the signed statement's bytes, so
    this must fail the certificate's OWN signature check (link 1), before
    the binding comparison (link 2) is even reached."""
    p = _sealed_pdf(tmp_path, corrupt_binding=True)
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_TAMPER


def test_pdf_without_certificate_is_unsealed(tmp_path):
    p = _sealed_pdf(tmp_path, omit_certificate=True)
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_UNSEALED


def test_pdf_without_manifest_attachment_is_malformed(tmp_path):
    p = tmp_path / "no_manifest.pdf"
    cert = tb._signed_certificate(b"{}")
    _write_pdf(p, {"certificate.json": json.dumps(cert).encode()})
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_MALFORMED


def test_pdf_with_unparseable_manifest_is_malformed(tmp_path):
    p = tmp_path / "bad_manifest.pdf"
    _write_pdf(p, {"manifest.json": b"not json {{{"})
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_MALFORMED


def test_missing_bundle_binding_entirely_is_a_link2_failure(tmp_path):
    """A certificate that doesn't bind ANY manifest (e.g. a bare continuity
    certificate someone attached alongside an unrelated manifest.json) must
    not be treated as vouching for it."""
    p = tmp_path / "unbound.pdf"
    manifest_bytes = tb._serialize_manifest({"sealed": True, "files": []})
    # A certificate signed with no bundle_binding at all — reuse testdata's
    # own real certificate, which was never bound to anything.
    cert = json.loads((tb.TESTDATA / "certificate.json").read_text())
    assert "bundle_binding" not in cert["statement"]
    _write_pdf(p, {
        "manifest.json": manifest_bytes,
        "certificate.json": json.dumps(cert).encode(),
    })
    assert verify_proof.run_pdf_bundle(str(p)) == verify_proof.EXIT_TAMPER


def test_result_names_which_link_failed(tmp_path, capsys):
    p = _sealed_pdf(tmp_path, tamper_manifest=True)
    verify_proof.run_pdf_bundle(str(p))
    out = capsys.readouterr().out
    assert "manifest.json hash matches the signed binding" in out
    assert "FAIL" in out
    assert "SEALED DELIVERABLE VERIFICATION FAILED" in out


def test_clean_result_states_deck_content_is_not_separately_checkable(tmp_path, capsys):
    """The honest limitation this container has and a zip does not: no
    separate deck_content object exists to verify byte-for-byte, and the
    report must say so rather than silently omitting the caveat."""
    p = _sealed_pdf(tmp_path)
    verify_proof.run_pdf_bundle(str(p))
    out = capsys.readouterr().out
    assert "deck_content" in out
    assert "does" in out.lower() and "not" in out.lower()
