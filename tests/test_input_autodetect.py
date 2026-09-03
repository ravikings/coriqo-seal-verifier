"""
Positional INPUT auto-detection (verify_proof.py <file>, no --proof /
--certificate / --bundle needed).

Ported from the standalone examiner-facing verifier's load_bundle_input
(coriqo-seal-verifier/verify_proof.py), which extracts a certificate.json or
proof.json out of a zip/PDF and checks ONLY that object. That is the wrong
answer for a Coriqo deliverables bundle (a zip carrying manifest.json): its
certificate can verify perfectly while a payload file was tampered with and
manifest.json rewritten to match. The tests below exist to pin the routing
rule that closes that gap — a zip WITH manifest.json always gets the full
--bundle check, never the weaker extraction — and to cover the rest of
run_auto_input()'s cases (bare certificate/proof JSON, a zip without a
manifest, a PDF attachment, --proof/positional exclusivity, shape-based
proof/certificate classification).

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_bundle_verifier as tb  # noqa: E402 — reuses _sealed_bundle etc.

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"
VERIFY_PROOF_PY = Path(__file__).resolve().parent.parent / "verify_proof.py"


def _load(name):
    return json.loads((TESTDATA / name).read_text())


# --- the critical routing rule: a deliverables.zip is NEVER downgraded ----

def test_positional_deliverables_zip_gets_the_full_bundle_check(tmp_path):
    """A clean sealed deliverables.zip passes via the positional route,
    identically to --bundle."""
    p = tb._sealed_bundle(tmp_path)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK
    assert verify_proof.run_auto_input(str(p)) == verify_proof.run_bundle(str(p))


def test_positional_deliverables_zip_with_edited_payload_and_rewritten_manifest_hash_fails(tmp_path):
    """THE test this feature exists for: payload file tampered AND its
    manifest.json sha256 row rewritten to match. The weak "extract
    certificate.json and check only that" path would report this VERIFIED,
    because the certificate's own signature and linkage are untouched — only
    run_bundle's manifest-binding check (link 2/3) catches it. A positional
    zip carrying manifest.json MUST be routed to that full check, not the
    weak one."""
    p = tb._sealed_bundle(tmp_path, tamper_and_rewrite_manifest_hash=True)

    # Prove the weak path really would be fooled, so this test is pinning a
    # real gap and not a tautology: extracting just certificate.json out of
    # the same zip and checking it alone verifies clean.
    data, kind = verify_proof._load_from_zip(str(p))
    assert kind == "certificate"
    assert verify_proof.verify_certificate_dict(data) is True

    # The actual behavior under test: routed to the full three-link check,
    # which fails at link 2/3 (manifest hash no longer matches the signed
    # binding).
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_TAMPER
    assert verify_proof.run_auto_input(str(p)) == verify_proof.run_bundle(str(p))


def test_positional_deliverables_zip_with_edited_payload_only_fails(tmp_path):
    p = tb._sealed_bundle(tmp_path, tamper_payload=True)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_TAMPER


def test_positional_unsealed_deliverables_zip_reports_unsealed(tmp_path):
    entries = [("deck.html", b"<html>deck</html>")]
    manifest = tb._build_manifest(entries, sealed=False, seal_reason="No key configured.")
    manifest_bytes = tb._serialize_manifest(manifest)
    p = tmp_path / "deliverables.zip"
    tb._write_bundle(p, manifest_bytes, None, entries)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_UNSEALED


# --- weak path: zip WITHOUT manifest.json ----------------------------------

def test_positional_zip_without_manifest_takes_the_weak_path_and_says_so(tmp_path, capsys):
    """A zip that is not a deliverables bundle (no manifest.json) — just a
    certificate.json packaged up some other way. Extract-and-verify-only-
    that-object is correct here, but the report must say plainly that only
    the extracted certificate was checked, not the rest of the zip."""
    cert = _load("certificate.json")
    p = tmp_path / "cert_only.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("certificate.json", json.dumps(cert))
        zf.writestr("stowaway.txt", b"unrelated file, never checked")

    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK
    out = capsys.readouterr().out
    assert "container" in out.lower()
    assert "certificate" in out.lower()
    assert "was extracted" in out or "extracted from it" in out
    # The disclaimer must be legible about what was NOT checked.
    assert "not" in out.lower() or "nothing else" in out.lower()


def test_positional_zip_without_manifest_containing_proof_verifies(tmp_path):
    proof = _load("proof.json")
    p = tmp_path / "proof_only.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("proof.json", json.dumps(proof))
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK


def test_zip_prefers_certificate_over_proof_when_both_present(tmp_path):
    cert = _load("certificate.json")
    proof = _load("proof.json")
    p = tmp_path / "both.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("proof.json", json.dumps(proof))
        zf.writestr("certificate.json", json.dumps(cert))
    _, kind = verify_proof._load_from_zip(str(p))
    assert kind == "certificate"


def test_zip_with_neither_member_is_malformed(tmp_path):
    p = tmp_path / "empty.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", b"nothing useful here")
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_MALFORMED


def test_positional_bad_zip_is_malformed(tmp_path):
    p = tmp_path / "broken.zip"
    p.write_bytes(b"not actually a zip")
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_MALFORMED


# --- bare JSON: shape-based classification, no container disclaimer -------

def test_positional_bare_certificate_json_verifies(tmp_path):
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(_load("certificate.json")))
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK


def test_positional_bare_proof_json_verifies(tmp_path):
    p = tmp_path / "proof.json"
    p.write_text(json.dumps(_load("proof.json")))
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK


def test_positional_bare_json_has_no_container_disclaimer(tmp_path, capsys):
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(_load("certificate.json")))
    verify_proof.run_auto_input(str(p))
    out = capsys.readouterr().out
    assert "is a container" not in out


def test_positional_bare_json_classifies_certificate_by_statement_shape():
    assert verify_proof._classify_bundle_json({"statement": {}}) == "certificate"
    assert verify_proof._classify_bundle_json({"leaf_input": "ab"}) == "proof"
    assert verify_proof._classify_bundle_json({}) == "proof"


def test_positional_malformed_json_is_malformed(tmp_path):
    p = tmp_path / "certificate.json"
    p.write_text("{not valid json")
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_MALFORMED


def test_positional_nonexistent_file_is_malformed(tmp_path):
    assert verify_proof.run_auto_input(str(tmp_path / "nope.json")) == verify_proof.EXIT_MALFORMED


# --- PDF path ---------------------------------------------------------------

pypdf = pytest.importorskip("pypdf", reason="PDF auto-detect needs pypdf")


def _pdf_with_attachment(path: Path, filename: str, data: bytes) -> None:
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_attachment(filename, data)
    with open(path, "wb") as fh:
        writer.write(fh)


def test_positional_pdf_with_attached_certificate_verifies(tmp_path):
    p = tmp_path / "examiner_package.pdf"
    _pdf_with_attachment(p, "certificate.json", json.dumps(_load("certificate.json")).encode())
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK


def test_positional_pdf_takes_the_weak_path_and_says_so(tmp_path, capsys):
    p = tmp_path / "examiner_package.pdf"
    _pdf_with_attachment(p, "certificate.json", json.dumps(_load("certificate.json")).encode())
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK
    out = capsys.readouterr().out
    assert "container" in out.lower()


def test_positional_pdf_with_attached_proof_verifies(tmp_path):
    p = tmp_path / "examiner_package.pdf"
    _pdf_with_attachment(p, "proof.json", json.dumps(_load("proof.json")).encode())
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_OK


def test_positional_pdf_with_no_attachment_is_malformed(tmp_path):
    p = tmp_path / "empty.pdf"
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with open(p, "wb") as fh:
        writer.write(fh)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_MALFORMED


def test_pdf_path_raises_a_clear_importerror_when_pypdf_is_unavailable(tmp_path, monkeypatch):
    """Simulate pypdf not being installed — the ImportError must name the
    package and explain that plain --proof/--certificate/--bundle JSON
    verification does not need it."""
    p = tmp_path / "examiner_package.pdf"
    p.write_bytes(b"%PDF-1.4 fake")

    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name == "pypdf" or name.startswith("pypdf."):
            raise ImportError("No module named 'pypdf'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)
    with pytest.raises(ImportError, match="pypdf"):
        verify_proof._load_from_pdf(str(p))


def test_positional_pdf_is_skipped_cleanly_when_pypdf_is_unavailable(tmp_path, monkeypatch, capsys):
    """run_auto_input must not crash when pypdf is missing — it reports a
    clean FAIL with the same malformed-input exit code, not a traceback."""
    p = tmp_path / "examiner_package.pdf"
    _pdf_with_attachment(p, "certificate.json", json.dumps(_load("certificate.json")).encode())

    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name == "pypdf" or name.startswith("pypdf."):
            raise ImportError("No module named 'pypdf'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)
    assert verify_proof.run_auto_input(str(p)) == verify_proof.EXIT_MALFORMED
    out = capsys.readouterr().out
    assert "pypdf" in out


# --- CLI-level: mutual exclusivity, argparse wiring -------------------------

def test_positional_and_proof_flag_together_is_a_clean_argparse_error(tmp_path):
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(_load("certificate.json")))
    result = subprocess.run(
        [sys.executable, str(VERIFY_PROOF_PY), str(p), "--proof", str(TESTDATA / "proof.json")],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "not allowed" in result.stderr


def test_positional_and_certificate_flag_together_is_a_clean_argparse_error(tmp_path):
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(_load("certificate.json")))
    result = subprocess.run(
        [sys.executable, str(VERIFY_PROOF_PY), str(p),
         "--certificate", str(TESTDATA / "certificate.json")],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "not allowed" in result.stderr


def test_positional_and_bundle_flag_together_is_a_clean_argparse_error():
    result = subprocess.run(
        [sys.executable, str(VERIFY_PROOF_PY), "some.zip", "--bundle", "deliverables.zip"],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "not allowed" in result.stderr


def test_cli_positional_certificate_verifies(tmp_path):
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(_load("certificate.json")))
    result = subprocess.run(
        [sys.executable, str(VERIFY_PROOF_PY), str(p)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "CONTINUITY VERIFIED" in result.stdout


def test_cli_no_arguments_still_errors_exactly_as_before():
    result = subprocess.run(
        [sys.executable, str(VERIFY_PROOF_PY)],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "Pass exactly one of" in result.stderr
