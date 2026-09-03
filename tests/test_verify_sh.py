"""
verify.sh — the zero-flag wrapper an examiner actually runs.

test_verifier.py covers verify_proof.py's checks. Nothing covered the wrapper
that invokes it, which is the only part of the bundle a bank examiner types.
Every case here builds a real .coriqo-shaped bundle on disk and EXECUTES
verify.sh against it, asserting the exit code and the line the reader is
supposed to act on.

The bundle is assembled from SPEC.md primitives via tests/make_corpus.py's
helpers — the second implementation, not Coriqo's source — for the same
reason the corpus is: a wrapper that only ever passes against bytes Coriqo
produced has not been shown to check anything.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_corpus  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
VERIFY_SH = REPO / "verify.sh"
VERIFY_PROOF = REPO / "verify_proof.py"

TREE_VERSION = 2  # the construction .coriqo containers seal under

# Three evidence files, deliberately odd: an odd level is where the RFC 6962
# construction promotes a lone node instead of duplicating it, so a wrapper
# tested only on a power-of-two bundle is untested on the shape half of all
# real bundles have.
EVIDENCE = {
    "evidence/custody.json": b'{\n  "stage": "institutional"\n}\n',
    "evidence/model_inventory.json": b'{\n  "models": []\n}\n',
    "evidence/scope.json": b'{\n  "from": null,\n  "to": null\n}\n',
}


def _build_bundle(root: Path, *, sealed: bool = True,
                  unavailable_reason: str | None = None,
                  vendored_verifier: bool = True) -> Path:
    """
    Write a .coriqo container to `root`, byte-shaped like the one
    api/domains/reports/coriqo_container.py packs: same proof bundle fields,
    same manifest keys, same paths.
    """
    key = Ed25519PrivateKey.from_private_bytes(make_corpus.SEED)
    root.mkdir(parents=True, exist_ok=True)
    (root / "evidence").mkdir(exist_ok=True)
    (root / "proofs" / "evidence").mkdir(parents=True, exist_ok=True)

    names = sorted(EVIDENCE)
    for name in names:
        (root / name).write_bytes(EVIDENCE[name])

    # The leaf is the evidence file's sha256 digest bytes; leaf_input is that
    # digest in hex.
    leaf_hex = [hashlib.sha256(EVIDENCE[n]).hexdigest() for n in names]
    leaves = [bytes.fromhex(h) for h in leaf_hex]
    merkle_root = make_corpus.merkle_root(leaves, TREE_VERSION)

    sth_body = {
        "container_id": "coriqo-container-test",
        "subject": "coriqo_examiner_bundle",
        "issued_at": "2026-09-02T00:00:00+00:00",
        "tree_version": TREE_VERSION,
        "tree_size": len(leaves),
        "merkle_root": merkle_root,
        "key_id": make_corpus.KEY_ID,
    }
    signature_hex = make_corpus.sign(sth_body, key)
    pub_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    if sealed:
        (root / "proofs" / "pubkey.pem").write_text(pub_pem)
        (root / "proofs" / "root_signature.sig").write_text(signature_hex + "\n")
        for i, name in enumerate(names):
            proof = {
                "checkpoint_id": sth_body["container_id"],
                "event_id": name,
                "issued_at": sth_body["issued_at"],
                "subject": sth_body["subject"],
                "leaf_index": i,
                "tree_size": len(leaves),
                "leaf_input": leaf_hex[i],
                "proof_path": make_corpus.inclusion_proof(i, leaves, TREE_VERSION),
                "merkle_root": merkle_root,
                "sth_body": sth_body,
                "checkpoint_signature": signature_hex,
                "key_id": make_corpus.KEY_ID,
                "public_key_pem": pub_pem,
            }
            (root / "proofs" / "evidence" / f"{Path(name).stem}.proof.json").write_text(
                json.dumps(proof, indent=2, sort_keys=True)
            )

    (root / "manifest.json").write_text(json.dumps({
        "container_format": "coriqo/1",
        "container_id": sth_body["container_id"],
        "sealed": sealed,
        "unavailable_reason": unavailable_reason,
        "evidence": [
            {"name": n, "sha256": leaf_hex[i], "bytes": len(EVIDENCE[n])}
            for i, n in enumerate(names)
        ],
    }, indent=2, sort_keys=True))

    dest = (root / "seal-verifier" / "verify_proof.py") if vendored_verifier \
        else (root / "verify_proof.py")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(VERIFY_PROOF.read_bytes())

    sh = root / "verify.sh"
    sh.write_bytes(VERIFY_SH.read_bytes())
    sh.chmod(0o755)
    return root


def _run(root: Path):
    """Execute the bundle's own verify.sh the way an examiner would."""
    return subprocess.run([str(root / "verify.sh")], cwd=root,
                          capture_output=True, text=True)


@pytest.fixture()
def sealed_bundle(tmp_path):
    return _build_bundle(tmp_path / "model-risk-package-v1.coriqo")


# --- the script itself -------------------------------------------------------

def test_verify_sh_is_a_committed_executable_script():
    """
    The container copies this file in with mode 0755 and the tarball is the
    only thing an examiner gets. A wrapper that lost its shebang or its
    executable bit in the repo would ship exactly that way.
    """
    assert VERIFY_SH.is_file()
    assert VERIFY_SH.read_bytes().startswith(b"#!/usr/bin/env bash\n")
    assert os.stat(VERIFY_SH).st_mode & stat.S_IXUSR


def test_verify_sh_parses_as_bash():
    assert subprocess.run(["bash", "-n", str(VERIFY_SH)]).returncode == 0


# --- a sealed bundle ---------------------------------------------------------

def test_clean_sealed_bundle_verifies_with_no_flags(sealed_bundle):
    """The whole point: `./verify.sh`, nothing else typed, exit 0."""
    p = _run(sealed_bundle)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "every evidence file verified against the sealed Merkle root" in p.stdout
    # Every proof was actually visited, not just the first.
    for name in EVIDENCE:
        assert f"{Path(name).stem}.proof.json" in p.stdout


def test_one_flipped_byte_in_one_evidence_file_fails(sealed_bundle):
    """The sha256 pre-check must name the file, not emit a generic verdict."""
    target = sealed_bundle / "evidence" / "custody.json"
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 0xFF
    target.write_bytes(bytes(data))

    p = _run(sealed_bundle)
    assert p.returncode == 1
    assert "evidence/custody.json has changed since sealing" in p.stderr
    assert "one or more evidence files FAILED verification" in p.stderr


def test_a_tampered_proof_path_fails_even_though_the_evidence_is_intact(sealed_bundle):
    """
    Leave every evidence file untouched and rewrite the tree instead. The
    sha256 pre-check passes, so this can only be caught by verify_proof.py —
    which is the wrapper's actual job: it has to notice the exit code.
    """
    pf = sealed_bundle / "proofs" / "evidence" / "custody.proof.json"
    proof = json.loads(pf.read_text())
    proof["proof_path"] = list(reversed(proof["proof_path"]))
    pf.write_text(json.dumps(proof, indent=2, sort_keys=True))

    p = _run(sealed_bundle)
    assert p.returncode == 1
    assert "PROOF INVALID" in p.stdout
    assert "one or more evidence files FAILED verification" in p.stderr


def test_a_missing_evidence_file_warns_but_still_checks_the_seal(sealed_bundle):
    """
    A file dropped from the bundle is not a forged seal — the leaf it was
    sealed under still verifies. Recorded because the distinction is
    deliberate: it warns, it does not fail.
    """
    (sealed_bundle / "evidence" / "scope.json").unlink()
    p = _run(sealed_bundle)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "evidence/scope.json is missing from this bundle" in p.stderr


def test_a_sealed_manifest_with_no_proofs_refuses_rather_than_passing(sealed_bundle):
    """
    An empty loop must never fall through to "everything verified". A bundle
    claiming a seal it carries no proofs for is a broken bundle, exit 2.
    """
    for f in (sealed_bundle / "proofs" / "evidence").glob("*.proof.json"):
        f.unlink()
    p = _run(sealed_bundle)
    assert p.returncode == 2
    assert "nothing to verify" in p.stderr
    assert "verified against the sealed Merkle root" not in p.stdout


def test_a_missing_vendored_verifier_says_so_instead_of_a_traceback(sealed_bundle):
    (sealed_bundle / "seal-verifier" / "verify_proof.py").unlink()
    p = _run(sealed_bundle)
    assert p.returncode == 2
    assert "verify_proof.py is missing" in p.stderr


def test_verifier_beside_the_script_is_found_when_seal_verifier_is_absent(tmp_path):
    """The standalone-checkout layout: verify_proof.py next to verify.sh."""
    root = _build_bundle(tmp_path / "flat.coriqo", vendored_verifier=False)
    p = _run(root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "every evidence file verified against the sealed Merkle root" in p.stdout


# --- an unsealed draft -------------------------------------------------------

def test_unsealed_draft_refuses_and_repeats_the_reason(tmp_path):
    """
    One script, both bundles: the draft branch is chosen from manifest.json at
    run time, so a copy of verify.sh cannot claim a seal the bundle in front
    of it does not have.
    """
    root = _build_bundle(
        tmp_path / "draft.coriqo", sealed=False,
        unavailable_reason="Sandbox tenants cannot seal evidence.",
    )
    p = _run(root)
    assert p.returncode == 1
    assert "unsealed draft" in p.stderr.lower()
    assert "Sandbox tenants cannot seal evidence." in p.stderr
    assert "nothing under proofs/ to verify" in p.stderr


def test_unsealed_draft_with_no_recorded_reason_still_refuses(tmp_path):
    root = _build_bundle(tmp_path / "draft2.coriqo", sealed=False)
    p = _run(root)
    assert p.returncode == 1
    assert "No reason was recorded in manifest.json." in p.stderr


def test_a_draft_that_smuggles_in_proofs_is_still_refused(tmp_path):
    """
    manifest.json's flag decides, not the presence of files: a bundle can be
    given proofs/ contents by anyone, and treating those as evidence of a
    seal would let a draft be dressed up as sealed.
    """
    root = _build_bundle(tmp_path / "liar.coriqo", sealed=True)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["sealed"] = False
    manifest["unavailable_reason"] = "Signing failed on this server."
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    p = _run(root)
    assert p.returncode == 1
    assert "unsealed draft" in p.stderr.lower()


# --- a bundle that is not a bundle -------------------------------------------

def test_a_missing_manifest_is_an_error_not_a_verdict(sealed_bundle):
    (sealed_bundle / "manifest.json").unlink()
    p = _run(sealed_bundle)
    assert p.returncode == 2
    assert "manifest.json is missing" in p.stderr
