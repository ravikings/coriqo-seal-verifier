"""
--bundle mode: GET /api/v1/engagements/{id}/deliverables.zip.

The chain under test is signature -> statement.bundle_binding.manifest_sha256
-> manifest.json bytes -> each file's recorded sha256 -> file bytes (see
api/domains/engagements/deliverables.py's module docstring and
verify_proof.py's run_bundle docstring). Every case here states what an
attacker would be doing and what must happen to them, same convention as
test_verifier.py.

Fixtures are assembled by hand from SPEC.md-shaped primitives in
tests/make_corpus.py (canonical_bytes, sign, the fixed test key) plus the
exact manifest/bundle_binding field names read from
api/domains/engagements/deliverables.py — not by importing that module,
so this is a second implementation of the bundle format, same reasoning
test_verify_sh.py gives for building its own .coriqo bundles by hand.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_corpus as mc  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"
KEY = Ed25519PrivateKey.from_private_bytes(mc.SEED)
PUBKEY_PEM = (TESTDATA / "pubkey.pem").read_text()

MANIFEST_NAME = "manifest.json"
CERTIFICATE_NAME = "certificate.json"


def _serialize_manifest(manifest: dict) -> bytes:
    """Byte-for-byte the same encoding _serialize_manifest uses in
    api/domains/engagements/deliverables.py: json.dumps(indent=2,
    sort_keys=False, default=str)."""
    return json.dumps(manifest, indent=2, sort_keys=False, default=str).encode("utf-8")


def _build_manifest(entries: list[tuple[str, bytes]], *, sealed: bool = True,
                     seal_reason: str | None = None,
                     engagement_id: str = "eng-test-1") -> dict:
    files = [
        {"name": name, "status": "present", "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in entries
    ]
    if sealed:
        files.append({
            "name": CERTIFICATE_NAME,
            "status": "present",
            "sha256": None,
            "sha256_omitted_reason": (
                "certificate.json signs this manifest, so this manifest cannot hash it "
                "without circularity."
            ),
            "source_endpoint": "derived — composed and signed at download time, never stored",
            "generator_provenance": None,
        })
    else:
        files.append({
            "name": CERTIFICATE_NAME,
            "status": "absent",
            "reason": seal_reason or "No signed certificate could be produced for this bundle.",
        })
    return {
        "bundle_note": "sealed" if sealed else "unsigned",
        "sealed": sealed,
        "seal": {
            "status": "signed" if sealed else "unsigned",
            "reason": None if sealed else (seal_reason or "No signing key available."),
            "certificate_file": CERTIFICATE_NAME if sealed else None,
            "binding_path": "statement.bundle_binding.manifest_sha256" if sealed else None,
            "verify_command": (
                "python verify_proof.py --certificate certificate.json" if sealed else None
            ),
        },
        "engagement_id": engagement_id,
        "model_id": None,
        "documents": {"total": len(entries), "bundled": len(entries), "excluded": []},
        "generated_at": "2026-09-01T00:00:00Z",
        "generated_by": "test-actor",
        "files": files,
    }


def _signed_certificate(manifest_bytes: bytes, *, engagement_id: str = "eng-test-1",
                         key: Ed25519PrivateKey = KEY, key_id: str = mc.KEY_ID,
                         corrupt_binding: bool = False) -> dict:
    """A real continuity statement (borrowed from testdata/certificate.json,
    which already verifies under _check_certificate_linkage/coverage/etc.)
    with bundle_binding added exactly as _bind_manifest does, then signed."""
    base = json.loads((TESTDATA / "certificate.json").read_text())
    statement = json.loads(json.dumps(base["statement"]))  # deep copy
    statement["bundle_binding"] = {
        "bundle": "engagement_deliverables_zip",
        "engagement_id": engagement_id,
        "manifest_filename": MANIFEST_NAME,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest_bytes": len(manifest_bytes),
        "generated_at": "2026-09-01T00:00:00Z",
        "generated_by": "test-actor",
        "_how_to_check": (
            "sha256 of the manifest.json entry in this zip, byte for byte as stored."
        ),
    }
    if corrupt_binding:
        # Model an attacker rewriting the binding itself to match a tampered
        # manifest, WITHOUT holding the signing key — i.e. edited after
        # signing. This must fail at the signature check, not the binding
        # check, because the statement bytes no longer match what was signed.
        statement["bundle_binding"]["manifest_sha256"] = "0" * 64
    return {
        "statement": statement,
        "signature_hex": mc.sign(statement, key),
        "key_id": key_id,
        "public_keys": {key_id: {"pem": PUBKEY_PEM, "revoked": False}},
    }


def _write_bundle(path: Path, manifest_bytes: bytes, cert: dict | None,
                   entries: list[tuple[str, bytes]], *,
                   extra_zip_entries: list[tuple[str, bytes]] | None = None) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(MANIFEST_NAME, manifest_bytes)
        if cert is not None:
            zf.writestr(CERTIFICATE_NAME, json.dumps(cert, indent=2).encode("utf-8"))
        for name, data in entries:
            zf.writestr(name, data)
        for name, data in (extra_zip_entries or []):
            zf.writestr(name, data)


def _sealed_bundle(tmp_path: Path, *, entries=None, tamper_payload: bool = False,
                    tamper_and_rewrite_manifest_hash: bool = False,
                    corrupt_binding: bool = False,
                    extra_zip_entries=None) -> Path:
    entries = entries or [("deck.html", b"<html>deck</html>"),
                           ("model_card.pdf", b"%PDF-1.4 fake model card")]
    manifest = _build_manifest(entries)
    original_manifest_bytes = _serialize_manifest(manifest)

    # The certificate is always signed over the ORIGINAL, honestly-generated
    # manifest bytes -- an attacker who doesn't hold the signing key cannot
    # produce a certificate that binds anything else. This is what makes
    # tamper_and_rewrite_manifest_hash below an actual attack simulation
    # rather than a second legitimate seal.
    cert = _signed_certificate(original_manifest_bytes, corrupt_binding=corrupt_binding)

    zip_entries = list(entries)
    manifest_bytes_in_zip = original_manifest_bytes
    if tamper_payload or tamper_and_rewrite_manifest_hash:
        # Attacker edits the first payload file's bytes post-hoc.
        name, _ = zip_entries[0]
        zip_entries[0] = (name, b"<html>ALTERED BY ATTACKER</html>")
        if tamper_and_rewrite_manifest_hash:
            # ...and rewrites manifest.json's row to match, hoping the
            # per-file check alone would be fooled. The attacker has no
            # signing key, so certificate.json (built above) still commits
            # to the ORIGINAL manifest bytes -- this tampered manifest.json
            # is what actually ships in the zip instead.
            manifest["files"][0]["sha256"] = hashlib.sha256(zip_entries[0][1]).hexdigest()
            manifest_bytes_in_zip = _serialize_manifest(manifest)

    p = tmp_path / "deliverables.zip"
    _write_bundle(p, manifest_bytes_in_zip, cert, zip_entries,
                  extra_zip_entries=extra_zip_entries)
    return p


# --- clean bundle -------------------------------------------------------

def test_clean_sealed_bundle_verifies(tmp_path):
    p = _sealed_bundle(tmp_path)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_OK


def test_clean_sealed_bundle_verifies_under_pinned_key(tmp_path):
    p = _sealed_bundle(tmp_path)
    assert verify_proof.run_bundle(str(p), pubkey_path=str(TESTDATA / "pubkey.pem")) == \
        verify_proof.EXIT_OK


# --- the critical attack: this is the whole point of --bundle ------------

def test_edited_payload_fails(tmp_path):
    """Attacker edits deck.html but leaves manifest.json's sha256 alone."""
    p = _sealed_bundle(tmp_path, tamper_payload=True)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_TAMPER


def test_edited_payload_with_rewritten_manifest_hash_still_fails(tmp_path):
    """CRITICAL: attacker edits deck.html AND rewrites its sha256 row in
    manifest.json to match the new bytes. The per-file hash check alone
    would now pass -- but manifest.json's own bytes changed, so its sha256
    no longer matches statement.bundle_binding.manifest_sha256, which is
    INSIDE the signed statement. This is the attack --bundle mode exists to
    catch; a verifier that only compared file hashes to the (attacker-
    controlled) manifest would miss it entirely."""
    p = _sealed_bundle(tmp_path, tamper_and_rewrite_manifest_hash=True)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_TAMPER


def test_edited_bundle_binding_fails_at_the_signature(tmp_path):
    """Attacker edits statement.bundle_binding directly (no signing key).
    Must fail at the certificate signature check, not the binding-hash
    check -- the statement bytes no longer match what was signed at all."""
    p = _sealed_bundle(tmp_path, corrupt_binding=True)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_TAMPER


# --- unsealed bundle -------------------------------------------------------

def test_unsealed_bundle_reports_its_reason_with_its_own_exit_code(tmp_path):
    entries = [("deck.html", b"<html>deck</html>")]
    manifest = _build_manifest(entries, sealed=False,
                                seal_reason="No signing key configured on this server.")
    manifest_bytes = _serialize_manifest(manifest)
    p = tmp_path / "deliverables.zip"
    _write_bundle(p, manifest_bytes, None, entries)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_UNSEALED


# --- malformed input ---------------------------------------------------

def test_missing_manifest_is_malformed(tmp_path):
    p = tmp_path / "deliverables.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("deck.html", b"<html>deck</html>")
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_MALFORMED


def test_missing_certificate_when_manifest_claims_sealed_is_treated_as_unsealed(tmp_path):
    """manifest says sealed=True but certificate.json is absent from the
    zip: report via the unsealed path (there's nothing to verify a
    signature against), not a crash."""
    entries = [("deck.html", b"<html>deck</html>")]
    manifest = _build_manifest(entries, sealed=True)
    manifest_bytes = _serialize_manifest(manifest)
    p = tmp_path / "deliverables.zip"
    _write_bundle(p, manifest_bytes, None, entries)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_UNSEALED


def test_not_a_zip_is_malformed(tmp_path):
    p = tmp_path / "deliverables.zip"
    p.write_bytes(b"not actually a zip file")
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_MALFORMED


def test_nonexistent_bundle_is_malformed(tmp_path):
    assert verify_proof.run_bundle(str(tmp_path / "nope.zip")) == verify_proof.EXIT_MALFORMED


# --- per-file checks -----------------------------------------------------

def test_present_row_with_no_matching_zip_entry_fails(tmp_path):
    entries = [("deck.html", b"<html>deck</html>")]
    manifest = _build_manifest(entries)
    # Claim a second file is present that was never written to the zip.
    manifest["files"].insert(1, {
        "name": "model_card.pdf", "status": "present",
        "sha256": hashlib.sha256(b"whatever").hexdigest(),
    })
    manifest_bytes = _serialize_manifest(manifest)
    cert = _signed_certificate(manifest_bytes)
    p = tmp_path / "deliverables.zip"
    _write_bundle(p, manifest_bytes, cert, entries)  # model_card.pdf never written
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_TAMPER


def test_null_sha256_certificate_row_is_skipped_not_failed(tmp_path):
    """certificate.json's own manifest row carries sha256: null by design
    (see sha256_omitted_reason) -- a clean bundle must not fail on it."""
    p = _sealed_bundle(tmp_path)
    manifest = json.loads(zipfile.ZipFile(p).read(MANIFEST_NAME))
    cert_row = next(r for r in manifest["files"] if r["name"] == CERTIFICATE_NAME)
    assert cert_row["sha256"] is None
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_OK


def test_unlisted_zip_entry_is_a_warning_not_a_failure(tmp_path, capsys):
    """A zip entry not named in manifest.json's files is printed as a
    warning but does not fail verification: the certificate's signature
    covers manifest.json's bytes, and the manifest never claimed anything
    about an entry it does not mention."""
    p = _sealed_bundle(tmp_path, extra_zip_entries=[("stowaway.txt", b"not in manifest")])
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_OK
    out = capsys.readouterr().out
    assert "stowaway.txt" in out
    assert "WARN" in out


# --- absent-status rows are not checked against zip bytes -----------------

def test_absent_status_row_is_not_hash_checked(tmp_path):
    entries = [("deck.html", b"<html>deck</html>")]
    manifest = _build_manifest(entries)
    manifest["files"].insert(1, {
        "name": "restricted_doc.pdf", "status": "absent",
        "reason": "classification restricted",
    })
    manifest_bytes = _serialize_manifest(manifest)
    cert = _signed_certificate(manifest_bytes)
    p = tmp_path / "deliverables.zip"
    _write_bundle(p, manifest_bytes, cert, entries)
    assert verify_proof.run_bundle(str(p)) == verify_proof.EXIT_OK
