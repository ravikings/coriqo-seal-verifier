#!/usr/bin/env python3
"""
Regenerate the test corpus in ../testdata.

Deliberately written against SPEC.md rather than against Coriqo's source: it
imports nothing from Coriqo and re-implements the hashing, canonicalisation
and bundle assembly from the written specification. That makes it a second
implementation, so a disagreement between this script and verify_proof.py is
evidence the spec is wrong or incomplete -- which is the whole point of
publishing a format rather than a script.

The signing key is derived from a fixed seed, so the corpus is byte-for-byte
reproducible. It is a test key with no relationship to any Coriqo signing key.

    python tests/make_corpus.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"

# Fixed seed: this corpus must be reproducible. Test key only.
SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
KEY_ID = "test-key-2026"
GENESIS = "0" * 64

# Witness keys (SPEC.md §9.4). Fixed seeds, test keys, no relationship to any
# real witness. Two of them because self-witnessing and third-party witnessing
# are different claims and a corpus carrying only one cannot show a verifier
# keeping them apart.
WITNESS_SELF_SEED = bytes([0x11]) * 32
WITNESS_SELF_KEY_ID = "witness-demo-bank-self"
WITNESS_INDEPENDENT_SEED = bytes([0x22]) * 32
WITNESS_INDEPENDENT_KEY_ID = "witness-lindqvist-audit"

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


# --- SPEC.md §3: canonicalisation -------------------------------------------

def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- SPEC.md §4: the event chain --------------------------------------------

def event_hash(ev: dict) -> str:
    """Hash over every field except event_hash itself (SPEC.md §4.2)."""
    return sha256_hex(canonical_bytes({k: v for k, v in ev.items() if k != "event_hash"}))


def build_chain(raw: list[dict]) -> list[dict]:
    chain: list[dict] = []
    prev = GENESIS
    for seq, item in enumerate(raw):
        ev = {**item, "seq": seq, "prev_hash": prev}
        ev["event_hash"] = event_hash(ev)
        chain.append(ev)
        prev = ev["event_hash"]
    return chain


# --- SPEC.md §5: the Merkle tree --------------------------------------------
#
# Two constructions, selected by tree_version in the SIGNED body (absent = 1):
#   1 -- odd levels pair the last node with itself. Frozen; not RFC 6962's tree.
#   2 -- RFC 6962 §2.1: odd levels promote the lone node unchanged.
# The corpus carries a bundle of each, because a verifier that only ever meets
# one of them is untested on the other -- and every checkpoint sealed before
# tree_version 2 is still out there.

def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def build_levels(leaves: list[bytes], tree_version: int) -> list[list[bytes]]:
    if not leaves:
        return [[hashlib.sha256(b"").digest()]]
    current = [leaf_hash(d) for d in leaves]
    levels = [current]
    while len(current) > 1:
        if tree_version == 2:
            nxt = [node_hash(current[i], current[i + 1])
                   for i in range(0, len(current) - 1, 2)]
            if len(current) % 2:
                nxt.append(current[-1])          # promoted, not duplicated
        else:
            nxt = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                nxt.append(node_hash(left, right))
        current = nxt
        levels.append(current)
    return levels


def merkle_root(leaves: list[bytes], tree_version: int) -> str:
    return build_levels(leaves, tree_version)[-1][0].hex()


def inclusion_proof(index: int, leaves: list[bytes], tree_version: int) -> list[str]:
    levels = build_levels(leaves, tree_version)
    proof, idx = [], index
    for level in levels[:-1]:
        if tree_version == 2:
            # A lone last node on an odd level has no sibling, so it
            # contributes nothing -- which is why a v2 path length depends on
            # the leaf index and not only on the tree size.
            if not (idx == len(level) - 1 and len(level) % 2 == 1):
                proof.append(level[idx ^ 1].hex())
        else:
            if idx % 2 == 0:
                sib = idx + 1 if idx + 1 < len(level) else idx
            else:
                sib = idx - 1
            proof.append(level[sib].hex())
        idx //= 2
    return proof


# --- Checkpoints ------------------------------------------------------------

def sign(body: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(canonical_bytes(body)).hex()


def make_checkpoint(cp_id, chain, issued_at, key, continuity, tree_version=1):
    """A signed tree head over the first `len(chain)` events (SPEC.md §6)."""
    leaves = [bytes.fromhex(e["event_hash"]) for e in chain]
    # Field set and order-independence per SPEC.md §6. Note there is no
    # checkpoint_id in the signed body -- see SPEC.md §7.3 for what that means.
    body = {
        "subject": "Demo Bank — model governance chain",
        "issued_at": issued_at,
        "length": len(chain),
        "head_hash": chain[-1]["event_hash"] if chain else GENESIS,
        "merkle_root": merkle_root(leaves, tree_version),
        "tree_size": len(leaves),
        "key_id": KEY_ID,
        "continuity": continuity,
    }
    # Additive, exactly like ordering_version: emitted only from 2, so a v1
    # body reproduces the bytes it was signed over (SPEC.md §12).
    if tree_version >= 2:
        body["tree_version"] = tree_version
    return {
        "checkpoint_id": cp_id,
        "sth_body": body,
        "signature_hex": sign(body, key),
        "key_id": KEY_ID,
    }


def main() -> None:
    TESTDATA.mkdir(exist_ok=True)
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    pub_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    (TESTDATA / "pubkey.pem").write_text(pub_pem)

    chain = build_chain([
        {"timestamp": "2026-01-08T09:15:00Z", "actor": "j.okafor", "action": "register",
         "model_name": "retail-pd-scorecard", "model_version": "2.1",
         "payload": {"risk_tier": "high"}},
        {"timestamp": "2026-01-22T14:02:00Z", "actor": "j.okafor", "action": "submit",
         "model_name": "retail-pd-scorecard", "model_version": "2.1",
         "payload": {"documents": 4}},
        {"timestamp": "2026-02-11T11:40:00Z", "actor": "a.lindqvist", "action": "review",
         "model_name": "retail-pd-scorecard", "model_version": "2.1",
         "payload": {"finding_count": 2, "decision": "conditions"}},
        {"timestamp": "2026-03-03T16:20:00Z", "actor": "m.chen", "action": "approve",
         "model_name": "retail-pd-scorecard", "model_version": "2.1",
         "payload": {"conditions_cleared": True}},
        {"timestamp": "2026-05-19T10:05:00Z", "actor": "a.lindqvist", "action": "review",
         "model_name": "fraud-triage-agent", "model_version": "1.0",
         "payload": {"finding_count": 0, "decision": "pass"}},
    ])
    (TESTDATA / "events.json").write_text(json.dumps(chain, indent=2) + "\n")

    open_c = {"obligations": {"approved": 0, "reviewed": 0, "challenged": 0},
              "coverage_gaps": []}
    # A real 77-day quiet period between the approve and the next review. It is
    # in the corpus on purpose: a gap that the record shows is the normal case,
    # and a verifier that only ever sees gapless input is undertested.
    close_c = {"obligations": {"approved": 1, "reviewed": 2, "challenged": 0},
               "coverage_gaps": [{"from": "2026-03-03T16:20:00Z",
                                  "to": "2026-05-19T10:05:00Z", "days": 77,
                                  "classification": "normal_cadence",
                                  "reason": "no model events fell due in this window"}]}

    cp1 = make_checkpoint("cp-2026-q1", chain[:4], "2026-03-31T00:00:00Z", key, open_c)
    cp2 = make_checkpoint("cp-2026-q2", chain, "2026-06-30T00:00:00Z", key, close_c)

    # --- proof.json: event 2 (the review) is in checkpoint cp-2026-q2 --------
    leaves = [bytes.fromhex(e["event_hash"]) for e in chain]
    idx = 2
    proof = {
        "checkpoint_id": cp2["checkpoint_id"],
        "event_id": f"seq-{idx}",
        "issued_at": cp2["sth_body"]["issued_at"],
        "subject": cp2["sth_body"]["subject"],
        "leaf_index": idx,
        "tree_size": len(leaves),
        "leaf_input": chain[idx]["event_hash"],
        "proof_path": inclusion_proof(idx, leaves, 1),
        "merkle_root": cp2["sth_body"]["merkle_root"],
        "sth_body": cp2["sth_body"],
        "checkpoint_signature": cp2["signature_hex"],
        "key_id": KEY_ID,
        "public_key_pem": pub_pem,
        "anchor": {"status": "not anchored"},
    }
    (TESTDATA / "proof.json").write_text(json.dumps(proof, indent=2) + "\n")

    # --- certificate.json: cp1 → cp2 linkage --------------------------------
    # The link proves cp1's sealed head is a leaf of cp2's tree (SPEC.md §7.2).
    sealed_head = cp1["sth_body"]["head_hash"]
    link_idx = cp1["sth_body"]["length"] - 1
    statement = {
        "certificate_version": "1.0",
        "subject": cp2["sth_body"]["subject"],
        "period": {"from": cp1["sth_body"]["issued_at"], "to": cp2["sth_body"]["issued_at"]},
        "checkpoint_count": 2,
        "checkpoints": [cp1, cp2],
        "linkage": [{
            "from_checkpoint_id": cp1["checkpoint_id"],
            "to_checkpoint_id": cp2["checkpoint_id"],
            "sealed_head": sealed_head,
            "merkle_root": cp2["sth_body"]["merkle_root"],
            "tree_size": cp2["sth_body"]["tree_size"],
            "leaf_index": link_idx,
            "proof_path": inclusion_proof(link_idx, leaves, 1),
            "provable": True,
        }],
        "linkage_status": "proven",
        "linkage_unbroken": True,
        "links_proven": 1,
        "coverage": {
            "sealed_event_count": cp2["sth_body"]["length"],
            "events_added_in_period": cp2["sth_body"]["length"] - cp1["sth_body"]["length"],
            "obligations_in_period": {
                k: close_c["obligations"][k] - open_c["obligations"][k]
                for k in close_c["obligations"]
            },
            "obligations_closing": dict(close_c["obligations"]),
        },
        "coverage_gaps": close_c["coverage_gaps"],
        "gap_summary": {"total": 1, "normal_cadence": 1, "exceeds_policy": 0},
        "claim": ("Governance was continuous from 2026-03-31 to 2026-06-30 across "
                  "2 sealed checkpoints, with 1 quiet period at normal cadence."),
    }
    cert = {
        "statement": statement,
        "signature_hex": sign(statement, key),
        "key_id": KEY_ID,
        "public_keys": {KEY_ID: {"pem": pub_pem, "revoked": False}},
    }
    (TESTDATA / "certificate.json").write_text(json.dumps(cert, indent=2) + "\n")

    # --- proof_v2.json: the LAST event, sealed under the RFC 6962 tree ------
    # Two deliberate choices:
    #
    #   * 5 leaves, not 4 or 8. The constructions produce identical roots at
    #     every power of two, so a corpus built at those sizes would prove
    #     nothing about either.
    #   * the last leaf, index 4. Its v2 audit path is ONE hash long, where a
    #     5-leaf v1 tree always needs three. So this bundle fails outright
    #     under v1's fixed-depth rule (§5.3.1) -- which is exactly why that
    #     rule is scoped to v1, and what a verifier that wrongly applies it to
    #     v2 will do to honest records.
    cp2_v2 = make_checkpoint("cp-2026-q2-v2", chain, "2026-06-30T00:00:00Z",
                             key, close_c, tree_version=2)
    idx_v2 = len(chain) - 1
    proof_v2 = {
        "checkpoint_id": cp2_v2["checkpoint_id"],
        "event_id": f"seq-{idx_v2}",
        "issued_at": cp2_v2["sth_body"]["issued_at"],
        "subject": cp2_v2["sth_body"]["subject"],
        "leaf_index": idx_v2,
        "tree_size": len(leaves),
        "leaf_input": chain[idx_v2]["event_hash"],
        "proof_path": inclusion_proof(idx_v2, leaves, 2),
        "merkle_root": cp2_v2["sth_body"]["merkle_root"],
        "sth_body": cp2_v2["sth_body"],
        "checkpoint_signature": cp2_v2["signature_hex"],
        "key_id": KEY_ID,
        "public_key_pem": pub_pem,
        "anchor": {"status": "not anchored"},
    }
    (TESTDATA / "proof_v2.json").write_text(json.dumps(proof_v2, indent=2) + "\n")

    assert cp2_v2["sth_body"]["merkle_root"] != cp2["sth_body"]["merkle_root"], (
        "the two constructions produced the same root -- the corpus is not "
        "exercising the difference"
    )
    assert len(proof_v2["proof_path"]) != (len(leaves) - 1).bit_length(), (
        "the v2 bundle's path happens to match v1's fixed depth -- pick a leaf "
        "index where it does not, or the corpus does not test the rule change"
    )

    # --- proof_cosigned.json / proof_cosign_tampered.json -------------------
    # Witness cosignatures over the EXACT bytes cp2's own signature covers
    # (SPEC.md §9.4). Built from proof.json rather than as a separate bundle,
    # so the two files differ in nothing but the cosignatures field -- which
    # is the additivity claim, stated as a fixture: proof.json and
    # proof_cosigned.json carry the same sth_body, byte for byte, and the same
    # checkpoint_signature.
    witness_self = Ed25519PrivateKey.from_private_bytes(WITNESS_SELF_SEED)
    witness_independent = Ed25519PrivateKey.from_private_bytes(WITNESS_INDEPENDENT_SEED)
    witness_self_pem = witness_self.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    witness_independent_pem = witness_independent.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    sth_bytes = canonical_bytes(cp2["sth_body"])
    self_sig = witness_self.sign(sth_bytes).hex()
    independent_sig = witness_independent.sign(sth_bytes).hex()

    # Note what is NOT in these entries: the witness public key. A verifier
    # must pin witness keys out of band, so shipping the key inside the
    # bundle would only invite a reimplementation to verify a cosignature
    # against a key supplied by the party being witnessed.
    cosigned = dict(proof)
    cosigned["cosignatures"] = [
        {
            "witness_key_id": WITNESS_SELF_KEY_ID,
            "witness_label": "Demo Bank (itself)",
            "signature_hex": self_sig,
            "signed_at": "2026-06-30T09:00:00Z",
            "witness_relationship": "self",
            "revoked": False,
        },
        {
            "witness_key_id": WITNESS_INDEPENDENT_KEY_ID,
            "witness_label": "Lindqvist & Co",
            "signature_hex": independent_sig,
            "signed_at": "2026-07-01T11:30:00Z",
            "witness_relationship": "independent",
            "revoked": False,
        },
    ]
    (TESTDATA / "proof_cosigned.json").write_text(json.dumps(cosigned, indent=2) + "\n")
    assert canonical_bytes(cosigned["sth_body"]) == sth_bytes, (
        "attaching cosignatures moved the signed body -- the whole feature is "
        "additive or it is a break"
    )

    # One byte flipped in the self-witness signature. Must FAIL under a pinned
    # witness key, and must NOT quietly become 'unverified' -- the WP-2b
    # fail-open precedent is exactly this shape.
    tampered_sig = bytearray(bytes.fromhex(self_sig))
    tampered_sig[0] ^= 0x01
    cosign_tampered = json.loads(json.dumps(cosigned))
    cosign_tampered["cosignatures"][0]["signature_hex"] = tampered_sig.hex()
    (TESTDATA / "proof_cosign_tampered.json").write_text(
        json.dumps(cosign_tampered, indent=2) + "\n")

    # --- certificate_cosigned.json ------------------------------------------
    # The same metadata on a certificate: keyed by checkpoint_id and OUTSIDE
    # `statement`, because `statement` is what the certificate's signature
    # covers. cp1 is deliberately left uncosigned so the corpus shows a range
    # where the state differs per checkpoint.
    cp1_bytes = canonical_bytes(cp1["sth_body"])
    cert_cosigned = json.loads(json.dumps(cert))
    cert_cosigned["cosignatures"] = {
        cp2["checkpoint_id"]: cosigned["cosignatures"],
    }
    cert_cosigned["anchors"] = {
        cp2["checkpoint_id"]: {
            "status": "anchored",
            "rekor_uuid": "24296fb24b8ad77a" + "0" * 48,
            "rekor_log_index": 123456,
            "anchored_at": "2026-06-30T00:05:00Z",
        },
    }
    assert canonical_bytes(cert_cosigned["statement"]) == canonical_bytes(statement), (
        "cosignature/anchor metadata leaked into the signed statement"
    )
    assert cp1_bytes == canonical_bytes(cert_cosigned["statement"]["checkpoints"][0]["sth_body"])
    (TESTDATA / "certificate_cosigned.json").write_text(
        json.dumps(cert_cosigned, indent=2) + "\n")

    # --- witness_keyring/: pinned witness keys, the operator's copy ----------
    witness_dir = TESTDATA / "witness_keyring"
    witness_dir.mkdir(exist_ok=True)
    (witness_dir / f"{WITNESS_SELF_KEY_ID}.pem").write_text(witness_self_pem)
    (witness_dir / f"{WITNESS_INDEPENDENT_KEY_ID}.pem").write_text(witness_independent_pem)

    # --- keyring/: a directory keyring, plus a JSON-manifest keyring --------
    # Ahead of per-tenant signing keys, so --keyring has fixtures to exercise
    # before any real deployment needs more than one key_id. `key-b` here is
    # never used to sign anything in this corpus -- its purpose is to be a
    # SECOND named key a --keyring can carry, not the one this bundle needs.
    key_b = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    key_b_pem = key_b.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    keyring_dir = TESTDATA / "keyring"
    keyring_dir.mkdir(exist_ok=True)
    (keyring_dir / f"{KEY_ID}.pem").write_text(pub_pem)
    (keyring_dir / "key-b.pem").write_text(key_b_pem)
    (TESTDATA / "keyring.json").write_text(
        json.dumps({KEY_ID: pub_pem, "key-b": key_b_pem}, indent=2) + "\n"
    )

    # --- certificate_key_rotation.json: a genuine mid-range key change,
    # with a succession record naming it -------------------------------------
    # Reuses the SAME chain/checkpoints as certificate.json; only the second
    # checkpoint is re-signed under key_b to model "the tenant's key changed
    # between these two seals", which is what a real custody transfer
    # produces. The succession record is built here from SPEC.md §9.3's field
    # list and signed by the OUTGOING key -- deliberately re-implemented from
    # the written spec rather than imported from Coriqo, so a disagreement
    # with verify_proof.py is evidence the spec is wrong or incomplete.
    # The body the outgoing key signs (SPEC.md §9.3). `prior_event_hash` pins
    # the handoff to one point in the chain -- the head cp1 sealed, i.e. the
    # last state the outgoing key attested to before giving the chain up.
    succession_body = {
        "type": "key.succession",
        "tenant_schema": "demo_bank",
        "outgoing_key_id": KEY_ID,
        "incoming_key_id": "key-b",
        "effective_at": "2026-06-15T00:00:00Z",
        "prior_event_hash": cp1["sth_body"]["head_hash"],
        "reason": "custody_transfer",
    }

    cp2_rotated = make_checkpoint("cp-2026-q2-rotated", chain, "2026-06-30T00:00:00Z",
                                  key_b, close_c)
    cp2_rotated["key_id"] = "key-b"
    cp2_rotated["sth_body"]["key_id"] = "key-b"
    # Re-sign under key_b now that key_id is part of the signed body.
    cp2_rotated["signature_hex"] = sign(cp2_rotated["sth_body"], key_b)

    rotated_statement = {
        "certificate_version": "1.0",
        "subject": cp2_rotated["sth_body"]["subject"],
        "period": {"from": cp1["sth_body"]["issued_at"],
                   "to": cp2_rotated["sth_body"]["issued_at"]},
        "checkpoint_count": 2,
        "checkpoints": [cp1, cp2_rotated],
        "linkage": [{
            "from_checkpoint_id": cp1["checkpoint_id"],
            "to_checkpoint_id": cp2_rotated["checkpoint_id"],
            "sealed_head": sealed_head,
            "merkle_root": cp2_rotated["sth_body"]["merkle_root"],
            "tree_size": cp2_rotated["sth_body"]["tree_size"],
            "leaf_index": link_idx,
            "proof_path": inclusion_proof(link_idx, leaves, 1),
            "provable": True,
        }],
        "linkage_status": "proven",
        "linkage_unbroken": True,
        "links_proven": 1,
        "coverage": {
            "sealed_event_count": cp2_rotated["sth_body"]["length"],
            "events_added_in_period": (cp2_rotated["sth_body"]["length"]
                                       - cp1["sth_body"]["length"]),
            "obligations_in_period": {
                k: close_c["obligations"][k] - open_c["obligations"][k]
                for k in close_c["obligations"]
            },
            "obligations_closing": dict(close_c["obligations"]),
        },
        "coverage_gaps": close_c["coverage_gaps"],
        "gap_summary": {"total": 1, "normal_cadence": 1, "exceeds_policy": 0},
        "claim": ("Governance was continuous from 2026-03-31 to 2026-06-30 across "
                  "2 sealed checkpoints under a rotated signing key, with 1 quiet "
                  "period at normal cadence."),
        # SPEC.md §9.3: the signed body, plus the detached signature the
        # OUTGOING key made over it. `key` here is KEY_ID's private key --
        # signing this with key_b (the incoming key) would be the forgery the
        # forged fixture below models.
        "succession": [{**succession_body, "signature_hex": sign(succession_body, key)}],
    }
    rotated_cert = {
        "statement": rotated_statement,
        "signature_hex": sign(rotated_statement, key),
        "key_id": KEY_ID,
        "public_keys": {
            KEY_ID: {"pem": pub_pem, "revoked": False},
            "key-b": {"pem": key_b_pem, "revoked": False},
        },
    }
    (TESTDATA / "certificate_key_rotation.json").write_text(
        json.dumps(rotated_cert, indent=2) + "\n"
    )

    # --- certificate_key_rotation_no_succession.json: same key change, the
    # succession record stripped out -- must fail -----------------------------
    no_succession_statement = dict(rotated_statement)
    del no_succession_statement["succession"]
    no_succession_cert = {
        "statement": no_succession_statement,
        "signature_hex": sign(no_succession_statement, key),
        "key_id": KEY_ID,
        "public_keys": dict(rotated_cert["public_keys"]),
    }
    (TESTDATA / "certificate_key_rotation_no_succession.json").write_text(
        json.dumps(no_succession_cert, indent=2) + "\n"
    )

    # --- certificate_backdated.json: second checkpoint has an earlier timestamp
    # This tests the timestamp monotonicity check ---------------------------------
    cp1_backdated = dict(cp1)
    cp1_backdated["sth_body"] = cp1["sth_body"].copy()
    cp2_backdated = dict(cp2)
    cp2_backdated["sth_body"] = cp2["sth_body"].copy()
    # Backdate the second checkpoint to before the first
    cp2_backdated["sth_body"]["issued_at"] = "2026-03-15T00:00:00Z"
    # Re-sign the modified sth_body under the same key
    cp2_backdated["signature_hex"] = sign(cp2_backdated["sth_body"], key)

    backdated_statement = {
        "certificate_version": "1.0",
        "subject": cp2_backdated["sth_body"]["subject"],
        "period": {"from": cp1_backdated["sth_body"]["issued_at"],
                   "to": cp2_backdated["sth_body"]["issued_at"]},
        "checkpoint_count": 2,
        "checkpoints": [cp1_backdated, cp2_backdated],
        "linkage": [{
            "from_checkpoint_id": cp1_backdated["checkpoint_id"],
            "to_checkpoint_id": cp2_backdated["checkpoint_id"],
            "sealed_head": sealed_head,
            "merkle_root": cp2_backdated["sth_body"]["merkle_root"],
            "tree_size": cp2_backdated["sth_body"]["tree_size"],
            "leaf_index": link_idx,
            "proof_path": inclusion_proof(link_idx, leaves, 1),
            "provable": True,
        }],
        "linkage_status": "proven",
        "linkage_unbroken": True,
        "links_proven": 1,
        "coverage": {
            "sealed_event_count": cp2_backdated["sth_body"]["length"],
            "events_added_in_period": (cp2_backdated["sth_body"]["length"]
                                       - cp1_backdated["sth_body"]["length"]),
            "obligations_in_period": {
                k: close_c["obligations"][k] - open_c["obligations"][k]
                for k in close_c["obligations"]
            },
            "obligations_closing": dict(close_c["obligations"]),
        },
        "coverage_gaps": close_c["coverage_gaps"],
        "gap_summary": {"total": 1, "normal_cadence": 1, "exceeds_policy": 0},
        "claim": ("Governance chain with backdated second checkpoint "
                  "(test fixture for timestamp monotonicity check)."),
    }
    backdated_cert = {
        "statement": backdated_statement,
        "signature_hex": sign(backdated_statement, key),
        "key_id": KEY_ID,
        "public_keys": {KEY_ID: {"pem": pub_pem, "revoked": False}},
    }
    (TESTDATA / "certificate_backdated.json").write_text(
        json.dumps(backdated_cert, indent=2) + "\n"
    )

    # --- certificate_partial_coverage.json: second checkpoint with partial
    # obligation coverage (some obligations have zero values) --------------------
    cp1_partial = dict(cp1)
    cp1_partial["sth_body"] = cp1["sth_body"].copy()
    cp2_partial = dict(cp2)
    cp2_partial["sth_body"] = cp2["sth_body"].copy()
    # Modify obligations to have some zeros (partial coverage)
    cp2_partial["sth_body"]["continuity"] = {
        "obligations": {"approved": 1, "reviewed": 0, "challenged": 0},
        "coverage_gaps": close_c["coverage_gaps"],
    }
    # Re-sign the modified sth_body
    cp2_partial["signature_hex"] = sign(cp2_partial["sth_body"], key)

    partial_statement = {
        "certificate_version": "1.0",
        "subject": cp2_partial["sth_body"]["subject"],
        "period": {"from": cp1_partial["sth_body"]["issued_at"],
                   "to": cp2_partial["sth_body"]["issued_at"]},
        "checkpoint_count": 2,
        "checkpoints": [cp1_partial, cp2_partial],
        "linkage": [{
            "from_checkpoint_id": cp1_partial["checkpoint_id"],
            "to_checkpoint_id": cp2_partial["checkpoint_id"],
            "sealed_head": sealed_head,
            "merkle_root": cp2_partial["sth_body"]["merkle_root"],
            "tree_size": cp2_partial["sth_body"]["tree_size"],
            "leaf_index": link_idx,
            "proof_path": inclusion_proof(link_idx, leaves, 1),
            "provable": True,
        }],
        "linkage_status": "proven",
        "linkage_unbroken": True,
        "links_proven": 1,
        "coverage": {
            "sealed_event_count": cp2_partial["sth_body"]["length"],
            "events_added_in_period": (cp2_partial["sth_body"]["length"]
                                       - cp1_partial["sth_body"]["length"]),
            "obligations_in_period": {
                "approved": 1,
                "reviewed": 0,
                "challenged": 0,
            },
            "obligations_closing": {"approved": 1, "reviewed": 0, "challenged": 0},
        },
        "coverage_gaps": close_c["coverage_gaps"],
        "gap_summary": {"total": 1, "normal_cadence": 1, "exceeds_policy": 0},
        "claim": ("Governance chain with partial obligation coverage "
                  "(test fixture for compliance coverage percentage check)."),
    }
    partial_cert = {
        "statement": partial_statement,
        "signature_hex": sign(partial_statement, key),
        "key_id": KEY_ID,
        "public_keys": {KEY_ID: {"pem": pub_pem, "revoked": False}},
    }
    (TESTDATA / "certificate_partial_coverage.json").write_text(
        json.dumps(partial_cert, indent=2) + "\n"
    )

    # --- certificate_key_rotation_forged_succession.json: the attack -------
    # Everything here is genuine EXCEPT the handoff. The holder of key_b took
    # the outgoing party's real, key-A-signed checkpoint, appended their own
    # key_b-signed checkpoint, and asserted the A -> B succession themselves:
    # the record names the exact right pair and is signed -- by key_b, the
    # key it hands the chain TO, which is the one key that must not be able
    # to authorise it. Every other check in the bundle passes. Only the
    # succession signature check catches this, which is why it exists.
    forged_statement = dict(rotated_statement)
    forged_statement["succession"] = [
        {**succession_body, "signature_hex": sign(succession_body, key_b)}
    ]
    forged_cert = {
        "statement": forged_statement,
        # Signed under key_b as well: post-transfer, the incoming holder is
        # the one issuing certificates, so this is not a mismatch a reader
        # could spot by eye.
        "signature_hex": sign(forged_statement, key_b),
        "key_id": "key-b",
        "public_keys": dict(rotated_cert["public_keys"]),
    }
    (TESTDATA / "certificate_key_rotation_forged_succession.json").write_text(
        json.dumps(forged_cert, indent=2) + "\n"
    )

    for name in ("pubkey.pem", "events.json", "proof.json", "proof_v2.json",
                 "certificate.json", "certificate_key_rotation.json",
                 "certificate_key_rotation_no_succession.json",
                 "certificate_backdated.json", "certificate_partial_coverage.json",
                 "certificate_key_rotation_forged_succession.json",
                 "proof_cosigned.json", "proof_cosign_tampered.json",
                 "certificate_cosigned.json", "witness_keyring/",
                 "keyring.json", "keyring/"):
        print(f"wrote testdata/{name}")


if __name__ == "__main__":
    main()
