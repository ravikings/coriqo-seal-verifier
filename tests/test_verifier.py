"""
The corpus tests. Every case states what an attacker would be doing and what
must happen to them.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"


def _load(name):
    return json.loads((TESTDATA / name).read_text())


def _run_proof(bundle, tmp_path, pubkey=None):
    p = tmp_path / "proof.json"
    p.write_text(json.dumps(bundle))
    return verify_proof.run(str(p), pubkey)


def _run_cert(bundle, tmp_path, pubkey=None):
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(bundle))
    return verify_proof.run_certificate(str(p), pubkey)


# --- the corpus verifies clean ----------------------------------------------

def test_good_proof_verifies(tmp_path):
    assert _run_proof(_load("proof.json"), tmp_path) is True


def test_good_certificate_verifies(tmp_path):
    assert _run_cert(_load("certificate.json"), tmp_path) is True


def test_good_proof_verifies_under_the_pinned_key(tmp_path):
    """The published key must be the one the bundle was actually signed with."""
    assert _run_proof(_load("proof.json"), tmp_path,
                      pubkey=str(TESTDATA / "pubkey.pem")) is True


# --- mutation 1: flip a byte in the leaf -------------------------------------

def test_flipped_leaf_byte_fails(tmp_path):
    """Claim a different event was sealed. The root stops reproducing."""
    b = _load("proof.json")
    leaf = bytearray(bytes.fromhex(b["leaf_input"]))
    leaf[0] ^= 0x01
    b["leaf_input"] = leaf.hex()
    assert _run_proof(b, tmp_path) is False


# --- mutation 2: reorder the proof path --------------------------------------

def test_reordered_proof_path_fails(tmp_path):
    """Sibling order is load-bearing: it encodes the path through the tree."""
    b = _load("proof.json")
    assert len(b["proof_path"]) >= 2, "corpus needs a multi-level tree to test this"
    b["proof_path"] = list(reversed(b["proof_path"]))
    assert _run_proof(b, tmp_path) is False


# --- mutation 3: swap a key_id -----------------------------------------------

def test_unknown_key_id_fails(tmp_path):
    """Point a checkpoint at a key the bundle does not carry."""
    b = _load("certificate.json")
    b["statement"]["checkpoints"][1]["key_id"] = "some-other-key"
    assert _run_cert(b, tmp_path) is False


def test_revoked_key_fails_even_though_the_signature_is_valid(tmp_path):
    """Revocation is not advisory. A mathematically valid signature under a
    revoked key must still fail, or revocation means nothing."""
    b = _load("certificate.json")
    for entry in b["public_keys"].values():
        entry["revoked"] = True
    assert _run_cert(b, tmp_path) is False


# --- mutation 4: drop a checkpoint from the range ----------------------------

def test_dropping_a_checkpoint_fails(tmp_path):
    """Remove the opening seal to hide what the period started from."""
    b = _load("certificate.json")
    b["statement"]["checkpoints"] = b["statement"]["checkpoints"][1:]
    assert _run_cert(b, tmp_path) is False


def test_empty_linkage_with_two_checkpoints_fails(tmp_path):
    """The vacuous forgery: claim continuity, ship no links to prove it."""
    b = _load("certificate.json")
    b["statement"]["linkage"] = []
    assert _run_cert(b, tmp_path) is False


# --- mutation 5: backdate an issued_at ---------------------------------------

def test_backdated_issued_at_fails(tmp_path):
    """Move a seal earlier in time. It sits inside the signed body."""
    b = _load("proof.json")
    b["sth_body"]["issued_at"] = "2020-01-01T00:00:00Z"
    assert _run_proof(b, tmp_path) is False


def test_altered_coverage_count_fails(tmp_path):
    """Overstate how much governance happened."""
    b = _load("certificate.json")
    b["statement"]["coverage"]["obligations_closing"]["approved"] = 99
    assert _run_cert(b, tmp_path) is False


def test_linkage_restatement_is_not_trusted(tmp_path):
    """A linkage entry restates values from the signed bodies. If a forger
    edits the restatement to match a forged proof, the mismatch against the
    signed body must be what fails -- not the restatement agreeing with itself."""
    b = _load("certificate.json")
    b["statement"]["linkage"][0]["sealed_head"] = "ab" * 32
    assert _run_cert(b, tmp_path) is False


# --- mutation 6: re-sign the whole thing with your own key -------------------

def _resign_with_attacker_key(cert):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    attacker = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pem = attacker.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    b = copy.deepcopy(cert)
    st = b["statement"]
    # The lie being told: 99 approvals instead of 1. A forger who only edits
    # the coverage block is caught by the cross-check against the signed
    # bodies, so a coherent forgery has to move the continuity block inside
    # the checkpoint too -- which it can, because it re-signs everything.
    st["checkpoints"][-1]["sth_body"]["continuity"]["obligations"]["approved"] = 99
    st["coverage"]["obligations_closing"]["approved"] = 99
    st["coverage"]["obligations_in_period"]["approved"] = 99
    for cp in st["checkpoints"]:
        cp["signature_hex"] = attacker.sign(
            verify_proof._canonical_bytes(cp["sth_body"])).hex()
    b["signature_hex"] = attacker.sign(verify_proof._canonical_bytes(st)).hex()
    b["public_keys"] = {b["key_id"]: {"pem": pem, "revoked": False}}
    return b


def test_self_signed_forgery_passes_unpinned(tmp_path):
    """DOCUMENTED LIMIT, not a defect. A bundle carrying its own key proves it
    is internally consistent -- nothing more. Anyone can sign a fabrication
    with a key they generated. This test exists so the limit is asserted rather
    than assumed, and so it fails loudly if the verifier's behaviour changes."""
    b = _resign_with_attacker_key(_load("certificate.json"))
    assert _run_cert(b, tmp_path) is True


def test_self_signed_forgery_fails_when_the_key_is_pinned(tmp_path):
    """...and this is the check that closes it. Pinning the published key is
    what turns 'internally consistent' into 'issued by Coriqo'."""
    b = _resign_with_attacker_key(_load("certificate.json"))
    assert _run_cert(b, tmp_path, pubkey=str(TESTDATA / "pubkey.pem")) is False


def test_wrong_pinned_key_fails_a_genuine_bundle(tmp_path):
    """The other direction: a real bundle must not verify under someone
    else's key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pem_path = tmp_path / "other.pem"
    pem_path.write_text(other.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
    assert _run_cert(_load("certificate.json"), tmp_path, pubkey=str(pem_path)) is False


# --- the corpus is reproducible ---------------------------------------------

def test_corpus_regenerates_byte_for_byte(tmp_path, monkeypatch):
    """make_corpus.py is a second implementation written from SPEC.md. If it
    drifts from the committed corpus, either the spec or the generator is
    wrong -- and a format nobody can regenerate is not a specification."""
    import subprocess
    before = {n: (TESTDATA / n).read_bytes()
              for n in ("proof.json", "proof_v2.json", "certificate.json",
                        "pubkey.pem", "events.json")}
    subprocess.run([sys.executable, str(Path(__file__).parent / "make_corpus.py")],
                   check=True, capture_output=True)
    after = {n: (TESTDATA / n).read_bytes() for n in before}
    assert before == after


# --- tree_size must be load-bearing ------------------------------------------

def test_truncated_proof_path_fails(tmp_path):
    """A short path cannot be waved through just because tree_size is only
    bounds-checked."""
    b = _load("proof.json")
    b["proof_path"] = b["proof_path"][:-1]
    assert _run_proof(b, tmp_path) is False


def test_proof_path_must_match_the_declared_tree_size(tmp_path):
    """Coriqo's tree duplicates the last node on odd levels, so an n-leaf tree
    and an (n+1)-leaf tree ending in a repeated leaf share a root (SPEC.md
    §5.3). The declared size is therefore checked against the path depth
    rather than trusted."""
    b = _load("proof.json")
    b["tree_size"] = b["tree_size"] + 8
    assert _run_proof(b, tmp_path) is False


# --- the unsigned-restatement forgery ----------------------------------------

def _substituted_tree_proof(good):
    """Keep the genuine sth_body and its genuine signature. Swap in a Merkle
    root, path and leaf for a tree the attacker built, containing an event
    that was never sealed."""
    import hashlib
    fake = hashlib.sha256(b"model approved by nobody").hexdigest()
    lh = lambda d: hashlib.sha256(b"\x00" + d).digest()
    nh = lambda l, r: hashlib.sha256(b"\x01" + l + r).digest()
    leaf = bytes.fromhex(fake)
    b = copy.deepcopy(good)
    b["leaf_input"] = fake
    b["leaf_index"] = 0
    b["tree_size"] = 2
    b["proof_path"] = [lh(leaf).hex()]
    b["merkle_root"] = nh(lh(leaf), lh(leaf)).hex()
    return b


def test_substituted_merkle_root_fails(tmp_path):
    """Regression for the forgery found while writing SPEC.md §7.3.

    Every field above the signature is an unsigned restatement. A forger who
    keeps a real signed checkpoint body and its real signature, but supplies
    the root and path of their own tree, was able to have an event that was
    never sealed reported as 'cryptographically proven to be part of' a
    genuine checkpoint. Both original checks passed: the Merkle walk against
    the attacker's own root, and the Ed25519 signature over the untouched
    body. The bundle is now bound to the signed body instead."""
    b = _substituted_tree_proof(_load("proof.json"))
    assert _run_proof(b, tmp_path) is False


def test_proof_is_bound_to_the_signed_tree_size(tmp_path):
    """The same substitution through tree_size alone."""
    b = _load("proof.json")
    b["tree_size"] = b["sth_body"]["tree_size"] + 1
    assert _run_proof(b, tmp_path) is False


def test_proof_missing_sth_body_fields_fails(tmp_path):
    """A bundle whose signed body carries no root cannot anchor anything."""
    b = _load("proof.json")
    del b["sth_body"]["merkle_root"]
    assert _run_proof(b, tmp_path) is False


# --- tree_version 2: the RFC 6962 construction -------------------------------
#
# The v1 bundle above and the v2 bundle here are the same chain sealed two ways.
# Both must verify: v1 checkpoints were signed against the duplicating tree and
# do not stop being valid because a newer construction exists.

def test_good_v2_proof_verifies(tmp_path):
    assert _run_proof(_load("proof_v2.json"), tmp_path) is True


def test_v2_proof_is_shorter_than_v1s_fixed_depth_would_allow(tmp_path):
    """
    The regression guard for the rule change.

    This bundle proves the last leaf of a 5-leaf tree. Its RFC 6962 audit path
    is one hash long; v1's rule (§5.3.1) demands exactly bit_length(4) = 3. If
    someone reapplies the fixed-depth check to v2, this honest bundle starts
    failing -- and so does most of production.
    """
    b = _load("proof_v2.json")
    assert b["sth_body"]["tree_version"] == 2
    assert len(b["proof_path"]) == 1
    assert (b["tree_size"] - 1).bit_length() == 3
    assert _run_proof(b, tmp_path) is True


def test_v2_truncated_and_overlong_paths_still_fail(tmp_path):
    """
    Size is still pinned -- by the RFC 6962 walk itself (sn must land on 0)
    rather than by a separate depth rule.
    """
    b = _load("proof_v2.json")
    short = copy.deepcopy(b)
    short["proof_path"] = []
    assert _run_proof(short, tmp_path) is False

    long = copy.deepcopy(b)
    long["proof_path"] = b["proof_path"] + [b["proof_path"][0]]
    assert _run_proof(long, tmp_path) is False


def test_v2_bundle_does_not_verify_as_v1(tmp_path):
    """
    Strip tree_version from the signed body and the bundle must fail, not fall
    back to a construction that happens to be more permissive. (Removing the
    key also breaks the signature, which is the point: the version is signed.)
    """
    b = copy.deepcopy(_load("proof_v2.json"))
    del b["sth_body"]["tree_version"]
    assert _run_proof(b, tmp_path) is False


def test_unsigned_tree_version_cannot_steer_verification(tmp_path):
    """
    A top-level tree_version is not read. If it were, an attacker could pick
    whichever construction their hand-built path satisfies -- the same class of
    defect as an unsigned merkle_root.
    """
    b = copy.deepcopy(_load("proof.json"))       # a genuine v1 bundle
    b["tree_version"] = 2                        # unsigned, and a lie
    assert _run_proof(b, tmp_path) is True       # ignored; still verifies as v1

    b2 = copy.deepcopy(_load("proof_v2.json"))   # a genuine v2 bundle
    b2["tree_version"] = 1                       # unsigned, and a lie
    assert _run_proof(b2, tmp_path) is True      # ignored; still verifies as v2


def test_unknown_signed_tree_version_fails(tmp_path):
    """A verifier must refuse a construction it does not implement, not guess."""
    b = copy.deepcopy(_load("proof_v2.json"))
    b["sth_body"]["tree_version"] = 99
    assert _run_proof(b, tmp_path) is False


# --- --keyring: pinning more than one key_id at once -------------------------
#
# Ahead of per-tenant signing keys. Today every real chain has one key_id and
# --pubkey covers it; these cases exercise the multi-key path before any real
# deployment needs it.

def test_keyring_directory_pins_a_certificate(tmp_path):
    ok = verify_proof.run_certificate(
        str(TESTDATA / "certificate.json"), keyring_path=str(TESTDATA / "keyring"))
    assert ok is True


def test_keyring_json_manifest_pins_a_certificate(tmp_path):
    ok = verify_proof.run_certificate(
        str(TESTDATA / "certificate.json"), keyring_path=str(TESTDATA / "keyring.json"))
    assert ok is True


def test_keyring_directory_pins_a_proof(tmp_path):
    ok = verify_proof.run(
        str(TESTDATA / "proof.json"), None, keyring_path=str(TESTDATA / "keyring"))
    assert ok is True


def test_keyring_missing_named_key_falls_back_to_pubkey(tmp_path):
    """--keyring not naming a key_id is not fatal on its own: --pubkey (or the
    bundle's own embedded key) still applies for that key_id."""
    kr_dir = tmp_path / "kr"
    kr_dir.mkdir()
    (kr_dir / "some-other-key.pem").write_text((TESTDATA / "pubkey.pem").read_text())
    ok = verify_proof.run(
        str(TESTDATA / "proof.json"), str(TESTDATA / "pubkey.pem"), keyring_path=str(kr_dir))
    assert ok is True


def test_keyring_miss_with_no_pubkey_refuses_to_fall_back_to_embedded_key_on_a_proof(tmp_path):
    """SECURITY REGRESSION (code review finding 1).

    The attack: run --proof forged.json --keyring trusted_keys/ (no --pubkey),
    intending to trust ONLY the keyring. The bundle's key_id is not in that
    keyring. Before the fix, run() fell back to proof.get('public_key_pem')
    -- the public key embedded in the bundle itself -- and verified the
    bundle's signature against its own self-supplied key. Any attacker who
    can generate an Ed25519 keypair, embed the public half as
    'public_key_pem', and sign with the private half produces a proof.json
    that reports VERIFIED under that fail-open logic, regardless of whether
    trusted_keys/ ever named their key_id.

    proof.json's own embedded key_id/public_key_pem/signature already play
    the part of that self-supplied forgery here: they are all bundle-
    internal and mutually consistent, exactly like an attacker-crafted
    bundle would be. Pointing --keyring at a directory that does not name
    this key_id, with no --pubkey, must now refuse and FAIL rather than
    silently trusting the bundle's own key.
    """
    bundle = _load("proof.json")
    assert bundle["key_id"] not in {"key-b"}, "fixture assumption changed"

    kr_dir = tmp_path / "kr"
    kr_dir.mkdir()
    # A keyring that does not name this bundle's key_id (test-key-2026) --
    # only an unrelated key_id is pinned.
    (kr_dir / "key-b.pem").write_text((TESTDATA / "keyring" / "key-b.pem").read_text())

    ok = verify_proof.run(str(TESTDATA / "proof.json"), None, keyring_path=str(kr_dir))
    assert ok is False, (
        "SECURITY HOLE: a proof bundle whose key_id is absent from --keyring, "
        "with no --pubkey given, verified against its own embedded key instead "
        "of failing closed"
    )


def test_keyring_miss_with_no_pubkey_refuses_on_certificate_too(tmp_path):
    """Same attack shape as above, but against run_certificate() -- confirms
    the two verification modes now fail closed identically (finding 4:
    run() reusing _resolve_bundle_key rather than duplicating the logic)."""
    kr_dir = tmp_path / "kr"
    kr_dir.mkdir()
    (kr_dir / "key-b.pem").write_text((TESTDATA / "keyring" / "key-b.pem").read_text())

    ok = verify_proof.run_certificate(
        str(TESTDATA / "certificate.json"), keyring_path=str(kr_dir))
    assert ok is False


def test_unpinned_proof_still_verifies_against_its_embedded_key(tmp_path):
    """Positive-path counterpart to the regression above: with NEITHER
    --keyring NOR --pubkey supplied at all, the legitimate unpinned-
    verification mode (trust the bundle's own embedded key) must keep
    working -- closing the pinned-fallback hole must not also break the
    no-pinning-requested case."""
    ok = verify_proof.run(str(TESTDATA / "proof.json"), None, keyring_path=None)
    assert ok is True


def test_keyring_missing_key_fails_a_multi_key_certificate(tmp_path):
    """A --keyring that names one of two key_ids used in the certificate, and
    supplies no --pubkey fallback, cannot pin the other -- and refusing to
    fall back to the bundle's own embedded key is the point of pinning."""
    kr_dir = tmp_path / "kr"
    kr_dir.mkdir()
    (kr_dir / "test-key-2026.pem").write_text((TESTDATA / "pubkey.pem").read_text())
    ok = verify_proof.run_certificate(
        str(TESTDATA / "certificate_key_rotation.json"), keyring_path=str(kr_dir))
    assert ok is False


def test_keyring_directory_with_no_pem_files_errors_cleanly(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError):
        verify_proof._load_keyring(str(empty))


def test_keyring_path_that_does_not_exist_errors_cleanly(tmp_path):
    with pytest.raises(ValueError):
        verify_proof._load_keyring(str(tmp_path / "nope"))


# --- key succession -----------------------------------------------------
#
# A chain signed by one key_id throughout never reaches this checker. What
# does: a custody transfer, where the outgoing key signs a record naming the
# incoming key. The cases below are the four shapes that record can take —
# genuine, missing, naming the wrong pair, and signed by the wrong party.

def test_single_key_certificate_needs_no_succession_record(tmp_path):
    """The corpus baseline: one key_id throughout, nothing to check."""
    assert _run_cert(_load("certificate.json"), tmp_path) is True


def test_key_rotation_with_succession_record_verifies(tmp_path):
    assert _run_cert(_load("certificate_key_rotation.json"), tmp_path) is True


def test_succession_record_signed_by_the_incoming_key_is_rejected(tmp_path):
    """The forgery this check exists for. The holder of the incoming key
    appends itself to somebody else's sealed history and signs the handoff
    itself — every other check in the bundle passes."""
    assert _run_cert(_load("certificate_key_rotation_forged_succession.json"),
                     tmp_path) is False


def test_succession_record_with_no_signature_is_rejected(tmp_path):
    """A record naming the right pair is a claim, not an authorisation."""
    b = _load("certificate_key_rotation.json")
    del b["statement"]["succession"][0]["signature_hex"]
    assert _run_cert(b, tmp_path) is False


def test_tampering_with_a_signed_succession_field_is_caught(tmp_path):
    """Every field of the record except signature_hex is covered by the
    signature — backdating the handoff invalidates it."""
    b = _load("certificate_key_rotation.json")
    b["statement"]["succession"][0]["effective_at"] = "2020-01-01T00:00:00Z"
    assert _run_cert(b, tmp_path) is False


def test_succession_record_without_its_type_field_is_rejected(tmp_path):
    """Domain separation: an outgoing-key signature over some other structure
    carrying these field names must not be replayable as a handoff."""
    b = _load("certificate_key_rotation.json")
    del b["statement"]["succession"][0]["type"]
    assert _run_cert(b, tmp_path) is False


def test_succession_verifies_against_the_pinned_outgoing_key(tmp_path):
    """Pinning applies to the handoff too, not only to checkpoints."""
    assert verify_proof.run_certificate(
        str(TESTDATA / "certificate_key_rotation.json"),
        keyring_path=str(TESTDATA / "keyring.json")) is True


def test_key_rotation_without_succession_record_fails(tmp_path):
    assert _run_cert(_load("certificate_key_rotation_no_succession.json"), tmp_path) is False


def test_succession_record_naming_the_wrong_keys_does_not_cover_the_change(tmp_path):
    """A succession record must name the EXACT key_id pair that changed, not
    merely exist somewhere in the list."""
    b = _load("certificate_key_rotation.json")
    b["statement"]["succession"] = [
        {"outgoing_key_id": "unrelated-key", "incoming_key_id": "also-unrelated"}
    ]
    assert _run_cert(b, tmp_path) is False


def test_succession_present_but_empty_still_fails_a_rotated_certificate(tmp_path):
    b = _load("certificate_key_rotation.json")
    b["statement"]["succession"] = []
    assert _run_cert(b, tmp_path) is False


def test_backdated_certificate_fails_timestamp_monotonicity(tmp_path):
    """Timestamp backdating is caught by the timestamp monotonicity check.
    When a checkpoint claims an earlier timestamp than a preceding checkpoint,
    the verification must fail."""
    b = _load("certificate_backdated.json")
    assert _run_cert(b, tmp_path) is False


def test_partial_coverage_certificate_reports_coverage_percentage(tmp_path):
    """A certificate with partial obligation coverage should verify (all
    cryptographic checks pass) but report the coverage percentage. The
    certificate_partial_coverage fixture has 1 out of 3 obligations covered."""
    assert _run_cert(_load("certificate_partial_coverage.json"), tmp_path) is True


def test_timestamp_consistency_check_fails_when_signed_body_has_no_issued_at():
    """Regression: a signed body with a missing/empty issued_at must FAIL
    the timestamp-consistency check, not silently PASS. Before this fix, the
    check only fired when sth_ts was truthy, so a proof bundle whose signed
    body lacks issued_at reported PASS even when its (unsigned, freely
    rewritable) top-level issued_at disagreed with it."""
    name, passed, detail = verify_proof._check_timestamp_consistency(
        proof={"issued_at": "2026-01-01T00:00:00Z"},
        sth={},  # signed body carries no issued_at at all
    )
    assert name == "Timestamp consistency"
    assert passed is False
    assert "missing issued_at" in detail


def test_timestamp_consistency_check_fails_on_genuine_mismatch():
    _name, passed, detail = verify_proof._check_timestamp_consistency(
        proof={"issued_at": "2026-01-02T00:00:00Z"},
        sth={"issued_at": "2026-01-01T00:00:00Z"},
    )
    assert passed is False
    assert "does not match" in detail


def test_timestamp_consistency_check_passes_when_matching():
    _name, passed, _detail = verify_proof._check_timestamp_consistency(
        proof={"issued_at": "2026-01-01T00:00:00Z"},
        sth={"issued_at": "2026-01-01T00:00:00Z"},
    )
    assert passed is True


def test_certificate_monotonicity_fails_when_a_checkpoint_is_missing_issued_at():
    """Regression: the certificate-path monotonicity check must not skip the
    ordering comparison just because one side is missing issued_at — that
    was the exact loophole a forger could use to omit a timestamp and defeat
    backdating detection entirely, mirroring the single-proof bug this WP
    was built to fix in the first place."""
    cert = {
        "statement": {
            "checkpoints": [
                {"checkpoint_id": "cp-1", "sth_body": {"issued_at": "2026-01-03T00:00:00Z"}},
                {"checkpoint_id": "cp-2", "sth_body": {}},  # missing issued_at
                {"checkpoint_id": "cp-3", "sth_body": {"issued_at": "2026-01-01T00:00:00Z"}},
            ]
        }
    }
    results = []
    verify_proof._check_certificate_timestamp_monotonicity(cert, results)
    assert len(results) == 1
    name, passed, detail = results[0]
    assert name == "Timestamp monotonicity"
    assert passed is False
    assert "missing issued_at" in detail


def test_certificate_monotonicity_passes_with_all_timestamps_present_and_ordered():
    cert = {
        "statement": {
            "checkpoints": [
                {"checkpoint_id": "cp-1", "sth_body": {"issued_at": "2026-01-01T00:00:00Z"}},
                {"checkpoint_id": "cp-2", "sth_body": {"issued_at": "2026-01-02T00:00:00Z"}},
            ]
        }
    }
    results = []
    verify_proof._check_certificate_timestamp_monotonicity(cert, results)
    assert results[0][1] is True


def test_compliance_coverage_detail_handles_non_numeric_obligation_value():
    """Regression: bundle JSON is attacker-controlled. A non-numeric but
    truthy obligation value must not crash the verifier with a TypeError —
    it must simply not count as covered."""
    detail, percentage = verify_proof._compliance_coverage_detail(
        {"a": "pending", "b": 1, "c": 0}, empty_note="none",
    )
    assert percentage == 33  # only "b" counts as covered
    assert "1/3" in detail or "b=1" in detail


def test_good_proof_bundle_has_consistent_timestamps():
    """End-to-end sanity check that the real corpus proof, which is signed
    and has a matching top-level/signed-body issued_at, still reports the
    timestamp check as passing after the fix (no regression on the happy
    path)."""
    bundle = _load("proof.json")
    sth = bundle.get("sth_body") or {}
    _name, passed, _detail = verify_proof._check_timestamp_consistency(bundle, sth)
    assert passed is True


def test_key_rotation_corpus_regenerates_byte_for_byte(tmp_path):
    """Same guarantee as test_corpus_regenerates_byte_for_byte, extended to
    the succession fixtures added alongside --keyring support."""
    import subprocess
    names = ("certificate_key_rotation.json",
              "certificate_key_rotation_no_succession.json",
              "certificate_backdated.json",
              "certificate_partial_coverage.json",
              "certificate_key_rotation_forged_succession.json",
              "keyring.json")
    before = {n: (TESTDATA / n).read_bytes() for n in names}
    before_keyring_dir = {p.name: p.read_bytes() for p in (TESTDATA / "keyring").glob("*.pem")}
    subprocess.run([sys.executable, str(Path(__file__).parent / "make_corpus.py")],
                   check=True, capture_output=True)
    after = {n: (TESTDATA / n).read_bytes() for n in names}
    after_keyring_dir = {p.name: p.read_bytes() for p in (TESTDATA / "keyring").glob("*.pem")}
    assert before == after
    assert before_keyring_dir == after_keyring_dir


# --- witness cosignatures (SPEC.md §9.4) -------------------------------------
#
# Four states, and the corpus must be able to tell a verifier apart on every
# one of them. The pinned-and-invalid case is the WP-2b shape: a signature
# that does not check out must FAIL, not degrade to "unverified".

WITNESS_KEYRING = str(TESTDATA / "witness_keyring")
WITNESS_SELF = "witness-demo-bank-self"
WITNESS_INDEPENDENT = "witness-lindqvist-audit"


def _run_cosigned(bundle, tmp_path, witness_keyring=None, independent=None,
                  pubkey=None):
    p = tmp_path / "proof.json"
    p.write_text(json.dumps(bundle))
    return verify_proof.run(str(p), pubkey, None, witness_keyring, None, independent)


def test_cosigned_bundle_carries_the_same_signed_body_as_the_uncosigned_one():
    """Additivity, as a fixture rather than a promise: attaching cosignatures
    must not move one byte of what any signature covers."""
    plain, cosigned = _load("proof.json"), _load("proof_cosigned.json")
    assert cosigned["sth_body"] == plain["sth_body"]
    assert cosigned["checkpoint_signature"] == plain["checkpoint_signature"]
    assert set(cosigned) - set(plain) == {"cosignatures"}


def test_cosigned_bundle_verifies_and_reports_unverified_when_nothing_is_pinned(
        tmp_path, capsys):
    """State (d). The cosignature is real, but nobody supplied a key for it,
    so it is UNVERIFIED — never verified, and never reported as absent."""
    assert _run_cosigned(_load("proof_cosigned.json"), tmp_path) is True
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert "NO COSIGNATURE" not in out
    assert "SELF-WITNESSED" not in out


def test_no_cosignature_is_its_own_state(tmp_path, capsys):
    """State (a). A bundle nobody cosigned says so."""
    assert _run_proof(_load("proof.json"), tmp_path) is True
    out = capsys.readouterr().out
    assert "NO COSIGNATURE" in out
    assert "UNVERIFIED" not in out


def test_pinned_cosignature_reports_self_witnessed(tmp_path, capsys):
    """State (b). Pinned and valid, with no operator claim of independence."""
    assert _run_cosigned(_load("proof_cosigned.json"), tmp_path,
                         witness_keyring=WITNESS_KEYRING) is True
    out = capsys.readouterr().out
    assert "SELF-WITNESSED" in out
    assert "INDEPENDENTLY WITNESSED" not in out


def test_independent_witnessing_requires_the_operator_to_say_so(tmp_path, capsys):
    """State (c). The bundle labels the second witness `independent`; that
    alone must not buy the upgrade, and --independent-witness must."""
    b = _load("proof_cosigned.json")
    assert b["cosignatures"][1]["witness_relationship"] == "independent"

    assert _run_cosigned(b, tmp_path, witness_keyring=WITNESS_KEYRING) is True
    assert "INDEPENDENTLY WITNESSED" not in capsys.readouterr().out

    assert _run_cosigned(b, tmp_path, witness_keyring=WITNESS_KEYRING,
                         independent=[WITNESS_INDEPENDENT]) is True
    assert "INDEPENDENTLY WITNESSED" in capsys.readouterr().out


def test_a_witness_the_bundle_calls_the_tenant_cannot_be_promoted(tmp_path, capsys):
    """The label can only ever downgrade. Declaring a witness independent
    when the bundle itself says it is the organisation leaves the verdict at
    self-witnessed, and says why."""
    assert _run_cosigned(_load("proof_cosigned.json"), tmp_path,
                         witness_keyring=WITNESS_KEYRING,
                         independent=[WITNESS_SELF]) is True
    out = capsys.readouterr().out
    assert "SELF-WITNESSED" in out
    assert "you declared this witness independent" in out


def test_tampered_cosignature_fails_under_a_pinned_witness_key(tmp_path, capsys):
    """
    The WP-2b regression in its cosignature form. One flipped byte, a pinned
    witness key, and the run must FAIL.
    """
    assert _run_cosigned(_load("proof_cosign_tampered.json"), tmp_path,
                         witness_keyring=WITNESS_KEYRING) is False
    out = capsys.readouterr().out
    assert "COSIGNATURE INVALID" in out
    assert "VERIFICATION FAILED" in out


def test_tampered_cosignature_is_never_reported_as_witnessed_when_unpinned(
        tmp_path, capsys):
    """Without a pinned key the forgery cannot be detected — so it must land
    in UNVERIFIED, not in either witnessed state."""
    assert _run_cosigned(_load("proof_cosign_tampered.json"), tmp_path) is True
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert "SELF-WITNESSED" not in out
    assert "INDEPENDENTLY WITNESSED" not in out


def test_a_witness_key_that_is_not_pinned_never_falls_back_to_the_bundle(
        tmp_path, capsys):
    """
    Only ONE of the two witness keys is pinned. The other must stay
    UNVERIFIED rather than borrowing the pinned key or the bundle's signing
    key — the fail-open shape --keyring already refuses for signing keys.
    """
    ring = tmp_path / "one_witness"
    ring.mkdir()
    (ring / f"{WITNESS_SELF}.pem").write_text(
        (TESTDATA / "witness_keyring" / f"{WITNESS_SELF}.pem").read_text())
    assert _run_cosigned(_load("proof_cosigned.json"), tmp_path,
                         witness_keyring=str(ring)) is True
    out = capsys.readouterr().out
    assert "[unpinned]" in out
    assert WITNESS_INDEPENDENT in out


def test_revoked_witness_key_downgrades_without_breaking_the_proof(tmp_path, capsys):
    """
    A revoked witness key carries no claim, but revoking one must not
    retroactively break bundles issued while it was live. Unlike rule 9.2.1
    for SIGNING keys, this downgrades rather than fails.
    """
    b = _load("proof_cosigned.json")
    for entry in b["cosignatures"]:
        entry["revoked"] = True
    assert _run_cosigned(b, tmp_path, witness_keyring=WITNESS_KEYRING) is True
    out = capsys.readouterr().out
    assert "revoked" in out
    assert "UNVERIFIED" in out
    assert "SELF-WITNESSED" not in out


def test_absent_revoked_flag_is_not_read_as_proof_of_liveness(tmp_path, capsys):
    """The flag can only downgrade. Its absence says nothing, and must not
    be reported as though the registry had confirmed the key is live."""
    b = _load("proof_cosigned.json")
    for entry in b["cosignatures"]:
        entry.pop("revoked")
    assert _run_cosigned(b, tmp_path, witness_keyring=WITNESS_KEYRING) is True
    out = capsys.readouterr().out
    assert "SELF-WITNESSED" in out
    assert "not revoked" not in out


def test_malformed_cosignatures_field_fails_rather_than_being_skipped(tmp_path):
    """A field of an unexpected shape is refused. Guessing at the shape is
    how an attacker gets a field ignored."""
    b = _load("proof_cosigned.json")
    b["cosignatures"] = {"nope": True}
    assert _run_cosigned(b, tmp_path, witness_keyring=WITNESS_KEYRING) is False

    b2 = _load("proof_cosigned.json")
    b2["cosignatures"] = ["not an object"]
    assert _run_cosigned(b2, tmp_path, witness_keyring=WITNESS_KEYRING) is False


def test_a_cosignature_over_different_bytes_fails(tmp_path):
    """
    The cosignature must cover the SAME sth_body the checkpoint signature
    covers. A signature over a neighbouring checkpoint's body — a real
    confusion a producer could ship — must not pass.
    """
    b = _load("proof_cosigned.json")
    other = _load("certificate.json")["statement"]["checkpoints"][0]["sth_body"]
    assert other != b["sth_body"]
    b["sth_body"] = other      # the checkpoint signature will fail too, but
    assert _run_cosigned(b, tmp_path,                # so must the cosignature
                         witness_keyring=WITNESS_KEYRING) is False


def test_certificate_reports_witness_state_per_checkpoint(tmp_path, capsys):
    """
    A range where one seal is cosigned and another is not is a different
    record from one where both are. The certificate report must not roll them
    into a single verdict.
    """
    cert = _load("certificate_cosigned.json")
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(cert))
    assert verify_proof.run_certificate(str(p), None, None, WITNESS_KEYRING) is True
    out = capsys.readouterr().out
    assert "checkpoint cp-2026-q1" in out
    assert "checkpoint cp-2026-q2" in out
    assert "NO COSIGNATURE" in out          # cp1
    assert "SELF-WITNESSED" in out          # cp2
    assert "search.sigstore.dev" in out     # the anchor, informational


def test_certificate_cosignature_metadata_is_outside_the_signed_statement():
    """`statement` is what the certificate signature covers. Cosignature and
    anchor metadata living inside it would change canonical_bytes and break
    every certificate already issued."""
    plain, cosigned = _load("certificate.json"), _load("certificate_cosigned.json")
    assert cosigned["statement"] == plain["statement"]
    assert cosigned["signature_hex"] == plain["signature_hex"]
    assert "cosignatures" not in cosigned["statement"]
    assert "anchors" not in cosigned["statement"]


def test_certificate_tampered_cosignature_fails(tmp_path):
    cert = _load("certificate_cosigned.json")
    entry = cert["cosignatures"]["cp-2026-q2"][0]
    sig = bytearray(bytes.fromhex(entry["signature_hex"]))
    sig[0] ^= 0x01
    entry["signature_hex"] = sig.hex()
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(cert))
    assert verify_proof.run_certificate(str(p), None, None, WITNESS_KEYRING) is False


def test_witness_keyring_path_that_does_not_exist_errors_cleanly(tmp_path):
    """A witness keyring the operator cannot trust the shape of is worse than
    none, so it fails rather than silently pinning nothing."""
    assert _run_cosigned(_load("proof_cosigned.json"), tmp_path,
                         witness_keyring=str(tmp_path / "nope")) is False


def test_cosign_corpus_regenerates_byte_for_byte():
    """Same guarantee as the other corpus files, extended to the cosignature
    fixtures — and it is what proves the generator, written from SPEC.md,
    still agrees with §9.4."""
    import subprocess
    names = ("proof_cosigned.json", "proof_cosign_tampered.json",
             "certificate_cosigned.json")
    before = {n: (TESTDATA / n).read_bytes() for n in names}
    before_keys = {p.name: p.read_bytes()
                   for p in (TESTDATA / "witness_keyring").glob("*.pem")}
    subprocess.run([sys.executable, str(Path(__file__).parent / "make_corpus.py")],
                   check=True, capture_output=True)
    assert {n: (TESTDATA / n).read_bytes() for n in names} == before
    assert {p.name: p.read_bytes()
            for p in (TESTDATA / "witness_keyring").glob("*.pem")} == before_keys


def test_bare_witness_pubkey_covers_every_witness_and_fails_on_a_second_one(tmp_path):
    """
    A bare --witness-pubkey asserts that EVERY cosignature verifies under one
    key, the same assertion a bare --pubkey makes for signing keys. The corpus
    bundle carries two witnesses, so it fails — recorded here because it is
    behaviour to know about, not a defect: --witness-keyring is the flag for
    more than one witness.
    """
    p = tmp_path / "proof.json"
    p.write_text(json.dumps(_load("proof_cosigned.json")))
    one_key = str(TESTDATA / "witness_keyring" / f"{WITNESS_SELF}.pem")
    assert verify_proof.run(str(p), None, None, None, one_key) is False

    # ...and naming the keys instead is what a two-witness bundle needs.
    assert verify_proof.run(str(p), None, None, WITNESS_KEYRING) is True


def test_cosignature_with_an_unusable_witness_key_id_fails(tmp_path):
    """
    A cosignature nobody can name is a cosignature nobody can pin a key for,
    so it is refused rather than silently skipped. The dict case is here
    because an unhashable id would otherwise raise out of the set lookup and
    turn a malformed bundle into a traceback instead of a verdict.
    """
    for bad_id in (None, "", 7, {"nested": "id"}, ["list"]):
        b = _load("proof_cosigned.json")
        b["cosignatures"] = [dict(b["cosignatures"][0], witness_key_id=bad_id)]
        assert _run_cosigned(b, tmp_path, witness_keyring=WITNESS_KEYRING) is False, bad_id
        assert _run_cosigned(b, tmp_path) is False, bad_id


def test_an_empty_witness_keyring_pins_nothing_and_says_so(tmp_path, capsys):
    """An empty JSON manifest supplied nothing. The report must not claim the
    cosignatures were checked against keys the operator provided."""
    manifest = tmp_path / "empty.json"
    manifest.write_text("{}")
    assert _run_cosigned(_load("proof_cosigned.json"), tmp_path,
                         witness_keyring=str(manifest)) is True
    out = capsys.readouterr().out
    assert "No witness keys were pinned" in out
    assert "UNVERIFIED" in out
