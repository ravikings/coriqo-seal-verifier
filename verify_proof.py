#!/usr/bin/env python3
"""
Coriqo V1.5 — Offline Attestation Verifier

Verifies Coriqo attestations using only mathematics. No network connection,
no Coriqo account, no Coriqo software, no trust in Coriqo as an institution.

Four modes:

  --proof        an inclusion proof — "was this governance event sealed?"
  --certificate  a Governance Continuity Certificate — "did governance ever
                 stop?" Proves unbroken linkage from checkpoint N to M,
                 reports the obligations covered, and renders every quiet
                 period with its recorded reason. Elapsed time on a
                 hash-linked chain cannot be faked, so this claim cannot be
                 issued retroactively.
  --bundle       a deliverables.zip from GET /api/v1/engagements/{id}/
                 deliverables.zip — a consultant-to-client handover bundle
                 whose manifest.json lists every file's sha256 and, when
                 sealed, is itself bound inside a signed certificate.json.
                 Checks the certificate the same way --certificate does,
                 then walks signature -> manifest hash -> each file's hash,
                 so tampering with a bundled file AND rewriting its sha256
                 in manifest.json still fails: the manifest's own bytes no
                 longer match what the certificate signed.
  INPUT          a single positional file, in place of any of the above
                 flags — this tool auto-detects what it is:
                   *.zip carrying manifest.json — a deliverables bundle;
                     routed to the SAME full check as --bundle. A zip's
                     certificate.json can verify perfectly while its payload
                     files were tampered with and its manifest rewritten to
                     match, so this case is never downgraded to the weaker
                     form below.
                   *.zip without manifest.json, or *.pdf — a certificate.json
                     or proof.json is extracted (from the zip's entries, or a
                     PDF attachment — the latter needs `pypdf`) and verified
                     on its own. The report states plainly that only the
                     extracted object was checked, not the rest of the file.
                   bare JSON — read directly; proof vs. certificate is told
                     apart by shape (a certificate has a top-level
                     "statement" object).
                 Mutually exclusive with --proof/--certificate/--bundle.

Usage
-----
    python tools/verify_proof.py --proof proof.json --pubkey pubkey.pem
    python tools/verify_proof.py --certificate certificate.json
    python tools/verify_proof.py --certificate certificate.json --keyring keys/
    python tools/verify_proof.py --certificate certificate.json --keyring keys.json
    python tools/verify_proof.py --proof proof.json --pubkey pubkey.pem \
        --witness-keyring witness_keys/ --independent-witness audit-firm-2026
    python tools/verify_proof.py --bundle deliverables.zip
    python tools/verify_proof.py --bundle deliverables.zip --pubkey pubkey.pem
    python tools/verify_proof.py deliverables.zip
    python tools/verify_proof.py certificate.json
    python tools/verify_proof.py "engagement package.pdf"

Where:
    proof.json   — the proof bundle downloaded from
                   GET /api/v1/checkpoints/{checkpoint_id}/proof/{event_id}
    pubkey.pem   — the Coriqo Ed25519 public key (published separately,
                   obtainable from GET /api/v1/checkpoints/public-key)
    certificate.json — the bundle from GET /api/v1/checkpoints/certificate.
                   Self-contained: it carries the public key for every
                   key_id it references, so no --pubkey is needed.
    --keyring    — pin MULTIPLE keys at once, one per key_id, instead of the
                   single unnamed key --pubkey pins. Every real chain today is
                   signed by exactly one key_id (coriqo-v1), so --pubkey covers
                   it; --keyring exists ahead of per-tenant signing keys and
                   key rotation, where a certificate can legitimately span more
                   than one key_id. Accepts either:
                     * a directory of "<key_id>.pem" files, one per key, or
                     * a single JSON file mapping key_id -> PEM text.
                   Entries from --keyring and --pubkey are merged; --pubkey's
                   key is used for any key_id --keyring does not name.
    --witness-keyring / --witness-pubkey
                   — the same pinning mechanism, applied to WITNESS keys
                   instead of signing keys. A witness cosignature is checked
                   ONLY against a key you supplied here. There is no fallback
                   to a key carried in the bundle, and this tool never fetches
                   a witness key from Coriqo — a cosignature checked against a
                   key Coriqo handed you at verify time witnesses nothing.
    --independent-witness KEY_ID
                   — repeatable. You assert that this witness key belongs to a
                   third party independent of the organisation whose chain
                   this is. Without it a verified cosignature is reported as
                   SELF-WITNESSED, never as independent: the bundle's own
                   label for a witness is unsigned data, and unsigned data is
                   not enough to upgrade the claim.

Exit codes
----------
--proof and --certificate:
    0  — PASS: all checks passed
    1  — FAIL: one or more checks failed

--bundle and INPUT (a wider table — a script checking $? can tell these apart
without parsing stdout; 1 keeps the same meaning it has in the other two
modes). INPUT uses this table even when it lands on the weaker
extract-and-verify path (a zip without manifest.json, a PDF, or bare JSON),
so exit-code handling never has to change depending on which mode found it:
    0  — PASS: for a deliverables bundle (--bundle, or INPUT routed there),
         the certificate verifies, it binds THIS manifest.json, and every
         present file matches its manifest sha256. For the weaker path, the
         extracted certificate/proof verified — see stdout for the scope
         disclaimer stating what was and was not checked.
    1  — TAMPER: a deliverables bundle's certificate signature/linkage
         failed, OR its manifest hash / a file hash did not match what was
         signed; or, on the weaker path, the extracted certificate/proof
         failed its own checks.
    2  — UNSEALED: a deliverables bundle carries no certificate.json —
         nothing to cryptographically verify (not a tamper finding; see
         manifest.json's own seal.status/seal.reason, printed by this tool)
    3  — MALFORMED: the input would not open or parse as the shape this tool
         expects for its mode — a zip that would not open, a missing/invalid
         manifest.json or certificate.json, JSON that will not parse, a PDF
         with no certificate/proof attachment, or a PDF input when `pypdf`
         is not installed

What is verified
----------------
    1. Merkle inclusion proof:
       leaf_hash = SHA-256(0x00 || bytes.fromhex(leaf_input))
       Walk proof_path under the construction the SIGNED body declares in
       tree_version (absent means 1):
         1 — sibling side by leaf_index parity, path length fixed by tree_size
         2 — RFC 6962 §2.1.1, which pins tree_size inside the walk itself
       Final hash must equal bytes.fromhex(merkle_root)

    2. Ed25519 checkpoint signature:
       The signature in checkpoint_signature must be valid over
       canonical_bytes(sth_body) using the provided public key.
       canonical_bytes = UTF-8 JSON with sorted keys, no extra whitespace.

Both checks are pure cryptography — they prove:
    "The governance event was part of a set of events that Coriqo attested
     to at the time the checkpoint was signed. Neither the event nor the
     set can have been altered after signing."

Key succession (certificate mode only)
------------------------------------------------------------
A certificate's checkpoints can change key_id partway through — a custody
transfer hands signing authority for one chain from one key to another. The
handoff is itself a signed statement: the OUTGOING key signs a record naming
the INCOMING key, so only the party that held the old key can nominate the
new one.

    * No key_id change across the certified range: nothing to check, and the
      report says so plainly.
    * A key_id change WITH a `statement.succession` record that names that
      exact outgoing/incoming key_id pair AND carries a valid Ed25519
      signature under the outgoing key: accepted — see SPEC.md §9.3.
    * A key_id change whose record is missing, names a different pair, or
      carries an absent/invalid signature: FAILS. An unexplained mid-range
      key change is treated as a broken continuity claim, not a benign
      detail, because a verifier that lets it pass silently could be shown a
      certificate stitched together from two unrelated signing keys — or one
      where a party holding only the NEW key appended itself to somebody
      else's sealed history — and call it one continuous chain.

Witness cosignatures (SPEC.md §9.4)
-----------------------------------
A checkpoint may carry cosignatures: independent Ed25519 signatures over the
exact bytes Coriqo's own signature covers. They answer a question the
checkpoint signature cannot — "could Coriqo have authored this history by
itself?" — because Coriqo does not hold the witness's private key.

Four states, reported separately and never collapsed into each other:

    (a) no cosignature in this bundle
    (b) SELF-WITNESSED — a cosignature verifies under a witness key YOU
        pinned, and you have not declared that witness independent
    (c) INDEPENDENTLY WITNESSED — as (b), and you passed
        --independent-witness for that key_id
    (d) UNVERIFIED — a cosignature is present but no key for it was pinned,
        or the bundle reports the witness key as revoked. Reported as
        UNVERIFIED: never as verified, and never as absent.

A cosignature that IS pinned and does not verify is a hard failure.

Two deliberate refusals, both of which make this tool less convenient:

    * The bundle carries no witness public key, and this tool would not use
      one if it did. Pinning is the entire mechanism. A witness key obtained
      from the party being witnessed is not a witness key.
    * "Independent" is never inferred from the bundle. The bundle's
      `witness_relationship` label is unsigned metadata produced by Coriqo;
      honouring it would let the party under scrutiny promote its own
      cosignature to an external audit. The label is shown, and it can only
      ever DOWNGRADE — a witness the bundle itself calls the tenant stays
      self-witnessed even if you declared it independent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Exit codes. `--proof` and `--certificate` keep the original 0/1 contract
# (see the module docstring's "Exit codes" section) — this file has shipped
# that contract to examiners already, and neither mode has a third outcome
# to report. `--bundle` has three distinct failure shapes an examiner needs
# to tell apart at a glance (a script checking $? gets this for free without
# parsing stdout), so it uses the wider table below. 1 keeps the same
# meaning it already has in the other two modes — a cryptographic/integrity
# failure — so a caller that just checks "exit code 0" never has to learn
# bundle mode exists.
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_TAMPER = 1        # signature invalid, or a hash link in the chain broke
EXIT_UNSEALED = 2       # no certificate.json — nothing to cryptographically verify
EXIT_MALFORMED = 3      # bundle/manifest/certificate isn't the shape this tool expects


# ---------------------------------------------------------------------------
# RFC 6962 Merkle primitives (copy of attestation/merkle.py — self-contained
# so examiners don't need to install the Coriqo package)
# ---------------------------------------------------------------------------

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


SUPPORTED_TREE_VERSIONS = (1, 2)


def _verify_inclusion_v1(
    leaf_input_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_path_hex: list[str],
    expected_root_hex: str,
) -> bool:
    """
    Version-1 tree: odd levels pair the last node with itself (SPEC.md §5.2).

    Frozen. Every checkpoint sealed before tree_version 2 was signed against
    this shape and must keep verifying against it.
    """
    # The proof path must be exactly as deep as the declared tree. Without
    # this, tree_size is decorative: the walk below only compares a computed
    # root, so a path of any length that happens to reproduce the signed root
    # would pass while claiming a tree of a different size. The v1 tree
    # duplicates the last node on odd levels, which means a tree of n leaves
    # and one of n+1 leaves whose last leaf repeats share a root -- so the
    # declared size has to be checked, not assumed.
    #
    # This rule applies to v1 ONLY. Under RFC 6962 the path length varies by
    # index, so applying it to a v2 proof rejects honest records.
    expected_depth = 0 if tree_size == 1 else (tree_size - 1).bit_length()
    if len(proof_path_hex) != expected_depth:
        print(f"  [ERROR] proof_path has {len(proof_path_hex)} sibling(s); a v1 tree of "
              f"{tree_size} leaves requires exactly {expected_depth}")
        return False

    computed = _leaf_hash(bytes.fromhex(leaf_input_hex))
    idx = leaf_index

    for sibling_hex in proof_path_hex:
        sibling = bytes.fromhex(sibling_hex)
        if idx % 2 == 0:
            computed = _node_hash(computed, sibling)
        else:
            computed = _node_hash(sibling, computed)
        idx //= 2

    return computed == bytes.fromhex(expected_root_hex)


def _verify_inclusion_v2(
    leaf_input_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_path_hex: list[str],
    expected_root_hex: str,
) -> bool:
    """
    Version-2 tree: RFC 6962 §2.1.1 inclusion-proof verification.

    tree_size is threaded through the walk (fn/sn) instead of being checked
    separately. sn must reach exactly 0 as the path is consumed: a path that is
    too short leaves sn != 0, and one that is too long trips sn == 0 mid-walk.
    So the declared size is verified by the algorithm itself, and no separate
    proof-depth rule is needed here -- nor would a fixed-depth rule be correct,
    because RFC 6962 audit-path length depends on the leaf's index as well as
    the tree size (a 5,161-leaf tree has valid lengths 4, 7, 8, 12 and 13).
    """
    fn = leaf_index
    sn = tree_size - 1
    r = _leaf_hash(bytes.fromhex(leaf_input_hex))

    for sibling_hex in proof_path_hex:
        if sn == 0:
            print(f"  [ERROR] proof_path is longer than a tree of {tree_size} "
                  f"leaves can produce")
            return False
        sibling = bytes.fromhex(sibling_hex)
        if (fn & 1) or fn == sn:
            r = _node_hash(sibling, r)
            if not (fn & 1):
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, sibling)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        print(f"  [ERROR] proof_path is shorter than a tree of {tree_size} "
              f"leaves requires")
        return False
    return r == bytes.fromhex(expected_root_hex)


def verify_inclusion(
    leaf_input_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_path_hex: list[str],
    expected_root_hex: str,
    tree_version: int = 1,
) -> bool:
    """
    Verify a Merkle inclusion proof under the declared tree construction.

    leaf_input_hex    — the event_hash hex (the raw bytes hashed into the leaf)
    leaf_index        — position of this leaf in the tree
    tree_size         — total number of leaves
    proof_path_hex    — ordered list of sibling hashes (hex), leaf → root
    expected_root_hex — the Merkle root hex from the checkpoint
    tree_version      — 1 = duplicate-last-node, 2 = RFC 6962 (SPEC.md §5.2).
                        The caller MUST source this from the SIGNED body; a
                        tree_version taken from an unsigned field would let a
                        forger pick whichever construction their hand-built
                        path satisfies.
    """
    if tree_size == 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False
    if tree_version not in SUPPORTED_TREE_VERSIONS:
        print(f"  [ERROR] unknown tree_version {tree_version!r}; this verifier "
              f"implements {SUPPORTED_TREE_VERSIONS}")
        return False

    if tree_version == 2:
        return _verify_inclusion_v2(
            leaf_input_hex, leaf_index, tree_size, proof_path_hex, expected_root_hex)
    return _verify_inclusion_v1(
        leaf_input_hex, leaf_index, tree_size, proof_path_hex, expected_root_hex)


# ---------------------------------------------------------------------------
# Ed25519 signature verification (requires cryptography package)
# ---------------------------------------------------------------------------

def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_signature(
    sth_body: dict,
    signature_hex: str,
    public_key_pem: str,
) -> bool:
    """
    Verify that signature_hex is a valid Ed25519 signature over
    canonical_bytes(sth_body) using the given PEM public key.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature

        pub = load_pem_public_key(public_key_pem.encode())
        sig = bytes.fromhex(signature_hex)
        msg = _canonical_bytes(sth_body)
        pub.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        print(f"  [ERROR] Signature check failed with exception: {exc}")
        return False


# ---------------------------------------------------------------------------
# Public transparency-log anchor (Sigstore Rekor)
# ---------------------------------------------------------------------------

def _print_rekor_anchor(proof: dict) -> None:
    """
    Surface the checkpoint's Sigstore Rekor anchor, if present in the bundle.

    The anchor is INFORMATIONAL — it never affects PASS/FAIL above (those are
    pure offline cryptography). It tells the examiner where the signed tree
    head was published on Rekor, a public append-only transparency log that
    Coriqo does not control, so the checkpoint's existence can be confirmed
    independently of Coriqo. The online lookup is optional and offline-
    tolerant: if Rekor cannot be reached, manual instructions are printed
    instead of failing.
    """
    anchor = proof.get("anchor")
    print("-" * 60)
    print("Public transparency-log anchor (Sigstore Rekor)")
    print("-" * 60)
    if not anchor or not anchor.get("rekor_uuid"):
        status = (anchor or {}).get("status", "not anchored")
        print(f"  No Rekor anchor in this bundle (status: {status}).")
        print("  The offline cryptographic checks above stand on their own;")
        print("  anchoring additionally witnesses the checkpoint on a public")
        print("  log outside Coriqo's control.")
        print()
        return

    uuid = anchor["rekor_uuid"]
    rekor_url = (anchor.get("rekor_url") or "https://rekor.sigstore.dev").rstrip("/")
    print(f"  Anchor status : {anchor.get('status')}")
    print(f"  Rekor UUID    : {uuid}")
    if anchor.get("rekor_log_index") is not None:
        print(f"  Log index     : {anchor['rekor_log_index']}")
    if anchor.get("anchored_at"):
        print(f"  Anchored at   : {anchor['anchored_at']}")
    print(f"  Browse        : https://search.sigstore.dev/?uuid={uuid}")
    print()

    # Optional online confirmation — best-effort, never fails the run.
    entry_url = f"{rekor_url}/api/v1/log/entries/{uuid}"
    fetched = False
    try:
        import urllib.request
        with urllib.request.urlopen(entry_url, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        entry = data.get(uuid, {})
        print("  [INFO] Rekor entry fetched — the checkpoint IS in the public log.")
        if entry.get("logIndex") is not None:
            print(f"         logIndex={entry['logIndex']} integratedTime={entry.get('integratedTime')}")
        fetched = True
    except Exception as exc:
        print(f"  [INFO] Could not reach Rekor ({type(exc).__name__}) — verify manually:")

    if not fetched:
        print()
        print("  Manual verification (any machine with internet access):")
        print(f"    1. Open https://search.sigstore.dev/?uuid={uuid}")
        print(f"       or: curl {entry_url}")
        print("    2. The entry is a hashedrekord whose artifact SHA-256 equals")
        print("       sha256(canonical_bytes(sth_body)) from this proof bundle,")
        print("       and whose signature/public key match checkpoint_signature")
        print("       and public_key_pem here.")
        print("    3. Rekor is append-only and operated by Sigstore, not Coriqo —")
        print("       a matching entry proves the checkpoint existed no later")
        print("       than its integratedTime and was not rewritten since.")
    print()


# ---------------------------------------------------------------------------
# Keyring loading — pin more than one key_id at once (--keyring)
#
# Every checkpoint sealed by Coriqo today carries key_id "coriqo-v1"; --pubkey
# alone is enough to pin it. This exists ahead of per-tenant signing keys,
# where a single certificate can legitimately reference more than one key_id
# and a single unnamed PEM has nothing to disambiguate against.
# ---------------------------------------------------------------------------

def _load_keyring(path: str, flag: str = "--keyring") -> dict[str, str]:
    """
    Load a keyring from either:
      * a directory containing "<key_id>.pem" files (one key per file, the
        filename stem is the key_id), or
      * a single JSON file mapping key_id -> PEM text.

    Raises ValueError with a message meant to be shown to the user, not a
    traceback, on anything malformed — a keyring the examiner cannot trust
    the shape of is worse than no keyring at all.
    """
    p = Path(path)
    if not p.exists():
        raise ValueError(f"{flag} path does not exist: {path}")

    if p.is_dir():
        keyring: dict[str, str] = {}
        pem_files = sorted(p.glob("*.pem"))
        if not pem_files:
            raise ValueError(f"{flag} directory {path} contains no *.pem files")
        for pem_file in pem_files:
            keyring[pem_file.stem] = pem_file.read_text()
        return keyring

    try:
        data = json.loads(p.read_text())
    except Exception as exc:
        raise ValueError(f"{flag} file {path} is not a directory and not valid JSON: {exc}")
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ValueError(
            f"{flag} file {path} must be a JSON object mapping key_id -> PEM text"
        )
    return data


def _merge_pinned(pubkey_path: str | None, keyring_path: str | None,
                  pubkey_flag: str = "--pubkey",
                  keyring_flag: str = "--keyring") -> dict[str, str] | None:
    """
    Build the `pinned` dict both run() and run_certificate() key their
    signature checks against: {key_id: pem}, with the special key `None`
    meaning "pin every key_id to this one PEM" (what a bare --pubkey means
    when no --keyring narrows it to specific key_ids).

    Returns None when neither flag was passed — "no pinning, trust the
    bundle's own embedded keys" — which is a materially different, weaker
    trust posture and must stay distinguishable from an empty keyring.
    """
    if pubkey_path is None and keyring_path is None:
        return None
    pinned: dict[str, str] = {}
    if keyring_path is not None:
        pinned.update(_load_keyring(keyring_path, keyring_flag))
    if pubkey_path is not None:
        try:
            pem = Path(pubkey_path).read_text()
        except Exception as exc:
            raise ValueError(f"Cannot read {pubkey_flag} file {pubkey_path}: {exc}")
        # A bare --pubkey with no --keyring pins everything (today's single-key
        # world: key_id lookup falls back to the sole unnamed entry). Combined
        # with --keyring it fills in whichever key_id --keyring did not name,
        # rather than clobbering the keyring's own entries.
        if keyring_path is None:
            pinned[None] = pem
        else:
            pinned.setdefault(None, pem)
    return pinned


# ---------------------------------------------------------------------------
# Witness cosignatures (SPEC.md §9.4)
#
# A cosignature is an Ed25519 signature by a party OTHER than the signer, over
# byte-for-byte the same canonical_bytes(sth_body) the checkpoint signature
# covers. It is the only signature in a bundle that Coriqo could not have
# produced, which is exactly why every rule below is about refusing to let the
# bundle influence how it is judged:
#
#   * the witness public key comes from the operator, never from the bundle
#     and never from Coriqo at verify time (day_one_trust_spec.md I-1: the
#     record must be checkable with Coriqo uncooperative);
#   * "independent" comes from the operator, never from the bundle
#     (I-3: a self-witnessed chain must never present as externally
#     witnessed — it answers "can Coriqo forge my history", not "is Coriqo
#     independently audited");
#   * a cosignature that cannot be checked is reported as UNVERIFIED, which
#     is neither "verified" nor "absent".
#
# The WP-2b precedent is the reason the pinned-and-invalid case is a hard
# failure rather than a warning: an unpinned fallback in --proof mode let a
# self-signed forgery report VERIFIED. There is no fallback here at all.
# ---------------------------------------------------------------------------

COSIGN_NONE = "none"
COSIGN_SELF = "self"
COSIGN_INDEPENDENT = "independent"
COSIGN_UNVERIFIED = "unverified"
COSIGN_INVALID = "invalid"

_COSIGN_HEADLINE = {
    COSIGN_NONE: "NO COSIGNATURE — this checkpoint carries only Coriqo's own signature",
    COSIGN_SELF: "SELF-WITNESSED — cosigned under a witness key you pinned",
    COSIGN_INDEPENDENT: "INDEPENDENTLY WITNESSED — cosigned by a third party you named",
    COSIGN_UNVERIFIED: "UNVERIFIED — a cosignature is present but you pinned no key for it",
    COSIGN_INVALID: "COSIGNATURE INVALID — a pinned witness key does not verify it",
}


def _resolve_witness_key(pinned: dict | None, witness_key_id) -> str | None:
    """
    The pinned PEM for a witness key_id, or None.

    Deliberately has no bundle-fallback branch. `_resolve_bundle_key` has one
    because a proof bundle legitimately carries the SIGNER's key and an
    unpinned run against it is a documented, weaker mode (SPEC.md §9.1). A
    witness key has no such mode: a witness key handed to you by the party
    being witnessed proves nothing, so "not pinned" can only mean "cannot be
    checked".
    """
    if pinned is None or witness_key_id is None:
        return None
    # A bare --witness-pubkey (the unnamed entry) covers every witness_key_id
    # --witness-keyring did not name, exactly as a bare --pubkey does for
    # signing keys. Read it as the assertion it is: "EVERY cosignature in this
    # bundle must verify under this key." On a bundle carrying a second
    # witness you did not expect, that assertion is false and the run fails --
    # which is the intended outcome, not a bug. Name the keys with
    # --witness-keyring when more than one witness is in play.
    return pinned.get(witness_key_id) or pinned.get(None)


def _evaluate_cosignatures(
    sth_body: dict,
    entries,
    pinned: dict | None,
    independent_ids: set,
) -> tuple[str, list[dict], list[str], list[str]]:
    """
    Judge every cosignature attached to one checkpoint.

    Returns (state, rows, failures, notes):
      state    — one of COSIGN_*, the headline for this checkpoint
      rows     — one dict per cosignature, for the printed report
      failures — non-empty means FAIL the run
      notes    — operator-facing warnings that are not failures
    """
    rows: list[dict] = []
    failures: list[str] = []
    notes: list[str] = []

    if entries is None or entries == []:
        return COSIGN_NONE, rows, failures, notes
    if not isinstance(entries, list):
        failures.append(
            "the bundle's `cosignatures` field is present but is not a list; "
            "refusing to guess at its shape")
        return COSIGN_INVALID, rows, failures, notes

    saw_invalid = False
    saw_self = False
    saw_independent = False

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"cosignature {i} is not an object")
            saw_invalid = True
            continue

        witness_key_id = entry.get("witness_key_id")
        if not isinstance(witness_key_id, str) or not witness_key_id:
            # Refused rather than tolerated. Beyond the shape argument, an
            # unhashable value here (a dict, a list) would raise out of the
            # set/dict lookups below and turn a malformed bundle into a
            # traceback instead of a verdict.
            failures.append(
                f"cosignature {i} has no usable witness_key_id "
                f"({witness_key_id!r}); a cosignature nobody can name is a "
                "cosignature nobody can pin a key for")
            saw_invalid = True
            continue
        claimed = entry.get("witness_relationship")
        declared_independent = witness_key_id in independent_ids
        row = {
            "witness_key_id": witness_key_id,
            "label": entry.get("witness_label") or "",
            "signed_at": entry.get("signed_at"),
            "claimed": claimed,
            "declared_independent": declared_independent,
        }

        # A witness key the bundle itself reports as revoked cannot carry a
        # claim. Unlike SPEC.md rule 9.2.1 this does NOT fail the run: a
        # cosignature is additive, so revoking a witness must not retroactively
        # break every proof bundle ever issued under it. It is downgraded to
        # UNVERIFIED instead, which is the honest reading — the claim is gone,
        # the checkpoint is untouched. Note the asymmetry that makes this safe:
        # `revoked: true` is a downgrade and is honoured; the ABSENCE of the
        # flag is never read as proof that a key is live.
        if entry.get("revoked") is True:
            row["status"] = "revoked"
            row["detail"] = ("the bundle reports this witness key as revoked — the "
                             "cosignature does not count")
            rows.append(row)
            continue

        pem = _resolve_witness_key(pinned, witness_key_id)
        if not pem:
            row["status"] = "unpinned"
            row["detail"] = (
                "no public key for this witness was supplied via --witness-keyring / "
                "--witness-pubkey, so this cosignature CANNOT be checked")
            rows.append(row)
            continue

        # Same message the checkpoint signature covers, by construction.
        if not verify_signature(sth_body, entry.get("signature_hex") or "", pem):
            row["status"] = "invalid"
            row["detail"] = "COSIGNATURE INVALID under the witness key you pinned"
            rows.append(row)
            saw_invalid = True
            failures.append(
                f"witness {witness_key_id!r}: cosignature does not verify under the "
                "pinned witness key. Either the cosignature was altered, or the key "
                "you pinned is not this witness's — with more than one witness, name "
                "each key with --witness-keyring rather than covering them all with "
                "a bare --witness-pubkey")
            continue

        row["status"] = "verified"
        if claimed == "self":
            row["independence"] = COSIGN_SELF
            saw_self = True
            if declared_independent:
                notes.append(
                    f"witness {witness_key_id!r}: you declared this witness independent, "
                    "but the bundle labels it as the organisation itself. Reported as "
                    "SELF-WITNESSED — the weaker of the two claims. Find out which is "
                    "true before relying on either.")
            row["detail"] = "valid, and the bundle labels this witness the organisation itself"
        elif declared_independent:
            row["independence"] = COSIGN_INDEPENDENT
            saw_independent = True
            row["detail"] = ("valid under a key you pinned and declared independent of "
                             "the organisation")
        else:
            row["independence"] = COSIGN_SELF
            saw_self = True
            row["detail"] = (
                "valid, but independence is NOT established — pass "
                f"--independent-witness {witness_key_id} only if you know this key "
                "belongs to a third party")
        rows.append(row)

    if saw_invalid:
        state = COSIGN_INVALID
    elif saw_independent:
        state = COSIGN_INDEPENDENT
    elif saw_self:
        state = COSIGN_SELF
    else:
        state = COSIGN_UNVERIFIED
    return state, rows, failures, notes


def _print_cosign_section(blocks: list[tuple[str, str, list[dict], list[str]]],
                          pinned: dict | None) -> None:
    """
    Render the witness state for each checkpoint. `blocks` is
    (label, state, rows, notes) per checkpoint — a proof bundle passes one.

    Printed for every run, including the no-cosignature case: "nobody has
    cosigned this" is a real answer to a real question and must not be
    silence, the same way the anchor section prints when there is no anchor.
    """
    print("-" * 60)
    print("Witness cosignatures")
    print("-" * 60)
    for label, state, rows, notes in blocks:
        if label:
            print(f"  {label}")
        print(f"  {_COSIGN_HEADLINE[state]}")
        # The headline names the STRONGEST state established on this
        # checkpoint. With more than one witness that is a summary, so the
        # tally follows it -- otherwise a bundle with one independent witness
        # and three unpinnable ones would read as if all four were checked.
        if len(rows) > 1:
            tally: dict[str, int] = {}
            for row in rows:
                tally[row.get("status")] = tally.get(row.get("status"), 0) + 1
            print(f"  {len(rows)} cosignature(s): "
                  + ", ".join(f"{n} {k}" for k, n in sorted(tally.items())))
        for row in rows:
            wid = row.get("witness_key_id")
            name = f" ({row['label']})" if row.get("label") else ""
            print(f"    · {wid}{name}  [{row.get('status')}]")
            print(f"      {row.get('detail')}")
            print(f"      bundle label: witness_relationship={row.get('claimed')!r} "
                  f"(unsigned; never used to upgrade this verdict)"
                  + ("  signed_at=" + str(row["signed_at"]) if row.get("signed_at") else ""))
        for note in notes:
            print(f"    NOTE: {note}")
        print()
    if all(state == COSIGN_NONE for _label, state, _rows, _notes in blocks):
        # Nothing was cosigned, so nothing here is pending. Saying more --
        # least of all the word "unverified" -- would describe a control that
        # is not in play as one that failed.
        print("  Nothing to check. A cosignature is a second signature over the")
        print("  same bytes, made by someone who is not Coriqo; none was offered.")
        print()
        return
    if not pinned:
        # `not pinned` rather than `pinned is None`: an empty keyring (an
        # empty JSON manifest) pinned nothing, and telling the operator their
        # keys were used would be false.
        print("  No witness keys were pinned (--witness-keyring / --witness-pubkey).")
        print("  Any cosignature above is therefore UNVERIFIED. Get the witness's")
        print("  public key from the witness, not from Coriqo, and re-run.")
    else:
        print("  Cosignatures were checked ONLY against the witness keys you supplied.")
        print("  This tool never fetches a witness key from Coriqo at verify time.")
    print("  A cosignature says the witness saw these exact bytes. It does not")
    print("  make the checkpoint more or less valid — that rests on the checks")
    print("  below — and self-witnessing is not third-party audit.")
    print()


def _witness_pinning(witness_pubkey_path: str | None,
                     witness_keyring_path: str | None) -> tuple[dict | None, str | None]:
    """(pinned, error). A malformed witness keyring is an error, not an empty set."""
    if not (witness_pubkey_path or witness_keyring_path):
        return None, None
    try:
        return _merge_pinned(witness_pubkey_path, witness_keyring_path,
                             pubkey_flag="--witness-pubkey",
                             keyring_flag="--witness-keyring"), None
    except ValueError as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------

def _compliance_coverage_detail(obligations: dict, *, empty_note: str) -> tuple[str, int]:
    """
    Shared by the single-proof and certificate compliance-coverage checks so
    the two paths can't silently diverge in how they report the same
    covered/total/percentage arithmetic. Returns (detail_message, percentage).
    """
    if not obligations:
        return (empty_note, 0)
    # Bundle JSON is attacker-controlled — an obligation value that isn't a
    # real number (a string, a bool, a dict) must count as not-covered, not
    # raise. `isinstance(v, (int, float))` before comparing avoids a
    # TypeError from `v > 0` on a non-numeric truthy value.
    covered = sum(
        1 for v in obligations.values()
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0
    )
    total = len(obligations)
    percentage = (covered * 100) // total if total > 0 else 0
    detail = (
        f"{covered}/{total} obligation types covered ({percentage}%): "
        f"{', '.join(f'{k}={v}' for k, v in sorted(obligations.items()))}"
    )
    return (detail, percentage)


def _check_timestamp_consistency(proof: dict, sth: dict) -> tuple[str, bool, str]:
    """
    Verify that the proof bundle's top-level (unsigned) issued_at agrees with
    the signed body's issued_at. A missing sth_ts is itself a failure, not a
    free pass — an unsigned/absent timestamp on the signed body means there
    is nothing to authenticate the proof bundle's own issued_at claim
    against, and the top-level field can be freely rewritten post-signing
    without invalidating the Ed25519 signature.
    """
    proof_ts = proof.get("issued_at")
    sth_ts = sth.get("issued_at")
    if not sth_ts:
        return (
            "Timestamp consistency",
            False,
            "signed checkpoint body is missing issued_at — cannot verify "
            "timestamp consistency",
        )
    if proof_ts != sth_ts:
        return (
            "Timestamp consistency",
            False,
            f"proof bundle timestamp {proof_ts!r} does not match signed body "
            f"{sth_ts!r}",
        )
    return (
        "Timestamp consistency",
        True,
        f"checkpoint timestamp {sth_ts!r} is consistent with proof bundle",
    )


def run(proof_path: str | None, pubkey_path: str | None, keyring_path: str | None = None,
        witness_keyring_path: str | None = None,
        witness_pubkey_path: str | None = None,
        independent_witnesses: list[str] | None = None,
        proof_data: dict | None = None) -> bool:
    """
    Load the proof bundle and public key, run all checks, print report.
    Returns True if all checks pass.

    witness_* pin the keys any COSIGNATURE in the bundle is checked against.
    They are a separate pinned set from pubkey_path/keyring_path on purpose:
    a witness key and a signing key answer different questions, and merging
    them would let a signing key Coriqo published stand in for a witness key
    it must not hold. See _evaluate_cosignatures.

    keyring_path, if given, is looked up by the proof's own key_id (see
    _load_keyring). It takes precedence over pubkey_path for that key_id;
    pubkey_path stays the escape hatch for the common single-key case and
    is used when the keyring does not name the proof's key_id.

    proof_data, when given, is used instead of reading/parsing proof_path —
    the caller (the positional-INPUT auto-detection path) has already
    resolved it out of a zip, PDF, or bare JSON file.
    """
    if proof_data is not None:
        proof = proof_data
    else:
        try:
            proof = json.loads(Path(proof_path).read_text())
        except Exception as exc:
            print(f"FAIL: Cannot load proof file: {exc}")
            return False

    print("=" * 60)
    print("Coriqo Merkle Inclusion Proof Verifier")
    print("=" * 60)
    print(f"  Checkpoint ID : {proof.get('checkpoint_id')}")
    print(f"  Event ID      : {proof.get('event_id')}")
    print(f"  Issued at     : {proof.get('issued_at')}")
    print(f"  Subject       : {proof.get('subject')}")
    print(f"  Leaf index    : {proof.get('leaf_index')} of {proof.get('tree_size')} events")
    print()

    results: list[tuple[str, bool, str]] = []

    # ── Check 0: the proof must describe the checkpoint it is signed under ──
    # The signature covers sth_body and nothing else. Every top-level field
    # here is an unsigned restatement, so the Merkle check below must be
    # anchored to the signed body rather than to the bundle's own headline
    # values. Without this, a forger keeps a genuine sth_body and its genuine
    # signature, swaps in a merkle_root and proof_path for a tree they built
    # themselves, and both remaining checks pass while the bundle claims an
    # event was sealed that never was.
    sth = proof.get("sth_body") or {}
    binding = []
    for field in ("merkle_root", "tree_size"):
        top, signed = proof.get(field), sth.get(field)
        if signed is None:
            binding.append(f"sth_body is missing {field}")
        elif top != signed:
            binding.append(
                f"{field} in the bundle ({top!r}) disagrees with the signed "
                f"checkpoint body ({signed!r})")
    results.append((
        "proof fields match the signed checkpoint body",
        not binding,
        "; ".join(binding) if binding
        else "merkle_root and tree_size are the values the signature covers",
    ))

    # ── Check 1: Merkle inclusion proof ─────────────────────────────────
    # Root and size come from the SIGNED body when it carries them, so the
    # check below is against what Coriqo attested, not what the file asserts.
    # tree_version comes from the SIGNED body and nowhere else. Absent means 1
    # (every checkpoint sealed before the RFC 6962 construction). Reading it
    # from the bundle's top level would reintroduce exactly the defect Check 0
    # closes: an unsigned field steering how the signed root is interpreted.
    merkle_ok = not binding and verify_inclusion(
        leaf_input_hex=proof["leaf_input"],
        leaf_index=proof["leaf_index"],
        tree_size=sth.get("tree_size", proof["tree_size"]),
        proof_path_hex=proof["proof_path"],
        expected_root_hex=sth.get("merkle_root", proof["merkle_root"]),
        tree_version=sth.get("tree_version", 1),
    )
    results.append((
        "Merkle inclusion proof",
        merkle_ok,
        "event_hash is proven to be in the Merkle tree" if merkle_ok
        else "PROOF INVALID — event may not be in this checkpoint",
    ))

    # ── Check 2: Ed25519 STH signature ──────────────────────────────────
    # Key resolution goes through the exact same pinned-set logic
    # run_certificate() uses (_merge_pinned / _resolve_bundle_key), so both
    # verification modes fail closed identically: if --keyring and/or
    # --pubkey were supplied and neither names this bundle's key_id, refuse
    # to fall back to the key embedded in the bundle rather than silently
    # trusting a self-supplied key. With no pinning requested at all (no
    # --keyring, no --pubkey), the bundle's own embedded key is used — the
    # legitimate unpinned-verification mode. See _resolve_bundle_key's
    # docstring for the reasoning.
    key_id = proof.get("key_id")
    pin_error = None
    pinned = None
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
        except ValueError as exc:
            pin_error = str(exc)

    if pin_error is not None:
        results.append(("Ed25519 checkpoint signature", False, pin_error))
    else:
        # _resolve_bundle_key expects a {"public_keys": {key_id: {...}}}
        # shape (the certificate bundle's own layout); a proof bundle
        # carries a single embedded key at the top level instead, so it is
        # wrapped here to reuse the exact same resolution/refusal logic
        # rather than re-implementing it.
        fake_bundle = {
            "public_keys": {key_id: {"pem": proof.get("public_key_pem") or "", "revoked": False}}
        }
        pub_pem, _revoked, key_detail = _resolve_bundle_key(fake_bundle, key_id, pinned)

        if not pub_pem:
            results.append((
                "Ed25519 checkpoint signature",
                False,
                key_detail or "No public key available — provide --pubkey/--keyring or "
                "ensure the proof bundle contains public_key_pem",
            ))
        else:
            sig_ok = verify_signature(
                sth_body=proof["sth_body"],
                signature_hex=proof["checkpoint_signature"],
                public_key_pem=pub_pem,
            )
            results.append((
                "Ed25519 checkpoint signature",
                sig_ok,
                f"STH signed by {proof.get('key_id')} — signature valid" if sig_ok
                else "SIGNATURE INVALID — checkpoint may have been tampered with",
            ))

    # ── Check 3: Timestamp backdating ───────────────────────────────────
    results.append(_check_timestamp_consistency(proof, sth))

    # ── Check 4: Compliance coverage ────────────────────────────────────
    # Calculate coverage percentage based on obligations in the checkpoint.
    # For a single proof, we report the obligations from the signed body.
    continuity = sth.get("continuity") or {}
    obligations = continuity.get("obligations") or {}
    coverage_detail, _percentage = _compliance_coverage_detail(
        obligations, empty_note="no obligations recorded in checkpoint",
    )
    results.append((
        "Compliance coverage percentage",
        True,  # Report coverage percentage; it's informational, not a pass/fail
        coverage_detail,
    ))
    # ── Check 5: witness cosignatures ───────────────────────────────────
    # Additive: a checkpoint with no cosignature is complete and this check
    # contributes nothing. A cosignature that IS present and IS pinned must
    # verify, or the run fails.
    witness_pinned, witness_pin_error = _witness_pinning(
        witness_pubkey_path, witness_keyring_path)
    independent_ids = set(independent_witnesses or ())
    if witness_pin_error is not None:
        cosign_state, cosign_rows, cosign_notes = COSIGN_UNVERIFIED, [], []
        results.append(("witness cosignatures", False, witness_pin_error))
    else:
        cosign_state, cosign_rows, cosign_failures, cosign_notes = _evaluate_cosignatures(
            sth, proof.get("cosignatures"), witness_pinned, independent_ids)
        if cosign_state != COSIGN_NONE:
            results.append((
                "witness cosignatures",
                not cosign_failures,
                "; ".join(cosign_failures) if cosign_failures
                else _COSIGN_HEADLINE[cosign_state],
            ))

    # ── Print results ─────────────────────────────────────────────────────
    all_pass = all(r[1] for r in results)
    _print_rekor_anchor(proof)
    _print_cosign_section([("", cosign_state, cosign_rows, cosign_notes)], witness_pinned)
    for name, passed, detail in results:
        tag = "PASS" if passed else "FAIL"
        print(f"  [{tag}] {name}")
        print(f"         {detail}")
        print()

    print("=" * 60)
    if all_pass:
        print("RESULT: VERIFIED ✓")
        print()
        print("  The governance event is cryptographically proven to be part of")
        print(f"  checkpoint {proof.get('checkpoint_id')} issued at {proof.get('issued_at')}.")
        print("  This proof was verified without contacting Coriqo's servers.")
        # The banner is about the checkpoint. Say what the witness state is
        # too, so "VERIFIED" is never read as "independently witnessed".
        print(f"  Witness state: {_COSIGN_HEADLINE[cosign_state]}")
    else:
        print("RESULT: VERIFICATION FAILED ✗")
        print()
        print("  One or more checks failed. The event may not be part of this")
        print("  checkpoint, or the checkpoint may have been tampered with.")
    print("=" * 60)

    return all_pass


# ---------------------------------------------------------------------------
# Governance Continuity Certificate verifier
# (verifiable_governance_strategy.md §2)
#
# An inclusion proof answers "was this event sealed?". A certificate answers
# "did governance ever stop?" — which is the claim a competitor cannot issue
# retroactively, because elapsed time on a hash-linked chain cannot be faked.
#
# Everything below is pure offline mathematics over the bundle's own bytes:
# no network, no Coriqo import, no keyring directory. The public key for
# every key_id referenced is carried inside the bundle, each flagged with its
# revocation state.
# ---------------------------------------------------------------------------

def _pem_fingerprint(pem: str) -> str:
    """SHA-256 over the PEM's base64 body — stable, and comparable by eye."""
    try:
        body = "".join(
            line.strip() for line in pem.splitlines() if not line.startswith("-----")
        )
        import base64
        return hashlib.sha256(base64.b64decode(body)).hexdigest()
    except Exception:
        return "unavailable"


def _print_key_trust(cert: dict, pinned: dict | None) -> None:
    """
    Show exactly which key each signature was checked against.

    The bundle carries its own public keys so it verifies with no network.
    That is what makes offline verification possible — but it also means the
    bundle alone proves internal consistency, not authorship: anyone can sign
    a fabricated statement with their own key and ship the matching PEM. The
    fingerprints below are what an examiner compares against Coriqo's
    published keyring (GET /api/v1/checkpoints/public-keys) to close that
    gap, or they can pin the key directly with --pubkey.
    """
    print("-" * 60)
    print("Signing keys used for verification")
    print("-" * 60)
    keys = cert.get("public_keys") or {}
    if not keys:
        print("  None in bundle — every signature check below will fail.")
        print()
        return
    any_pinned = False
    for key_id, entry in sorted(keys.items()):
        embedded_pem = (entry or {}).get("pem") or ""
        flag = " [REVOKED]" if (entry or {}).get("revoked") else ""
        # Report what _resolve_bundle_key actually did for THIS key_id, not
        # a single blanket flag for the whole report -- a key_id a partial
        # --keyring doesn't name is not pinned, even when other keys are.
        is_pinned = pinned is not None and (key_id in pinned or None in pinned)
        if is_pinned:
            any_pinned = True
            source = "pinned via --keyring" if key_id in pinned else "pinned via --pubkey"
            # Fingerprint the PEM that was actually used to verify (the
            # pinned one), not the bundle's own embedded copy -- otherwise
            # the fingerprint an examiner compares against Coriqo's
            # published keyring isn't the key that did the verifying.
            fingerprint_pem = pinned.get(key_id) or pinned.get(None) or embedded_pem
        else:
            source = "from bundle (unpinned)"
            fingerprint_pem = embedded_pem
        print(f"  {key_id}{flag}  ({source})")
        print(f"    sha256: {_pem_fingerprint(fingerprint_pem)}")
    print()
    if any_pinned:
        print("  Keys marked \"pinned\" above were checked against the PEM you supplied")
        print("  via --keyring/--pubkey, so a self-signed forgery under those key_ids")
        print("  cannot pass. Any key marked \"from bundle\" was NOT pinned and was")
        print("  checked only against its own embedded copy -- compare its fingerprint")
        print("  against the published keyring separately.")
    else:
        print("  NOTE: keys came from the bundle itself. The checks below prove the")
        print("  certificate is internally consistent and unaltered. To also prove it")
        print("  was issued by Coriqo, compare the fingerprint(s) above against the")
        print("  published keyring, or re-run with --pubkey <key.pem> to pin it.")
    print()


def _resolve_bundle_key(cert: dict, key_id: str, pinned: dict | None = None) -> tuple[str | None, bool, str]:
    """
    Resolve the public key for key_id.

    With --pubkey the supplied PEM(s) win outright: a bundle that names a key
    the examiner did not supply cannot be verified, which is what turns
    "internally consistent" into "issued by the holder of this key".
    """
    if pinned is not None:
        # Revocation still applies when a key is pinned. The bundle's revoked
        # flag is a claim by the issuer that this key must not be trusted;
        # supplying the PEM yourself says "this is the right key", not "ignore
        # the revocation". Dropping it here would make --pubkey a way to
        # silently launder a revoked attestation (key_management.md rule 4).
        bundle_revoked = bool(
            ((cert.get("public_keys") or {}).get(key_id) or {}).get("revoked")
        )
        if key_id in pinned:
            return pinned[key_id], bundle_revoked, "pinned"
        # An unnamed PEM (bare --pubkey, no --keyring naming this key_id)
        # pins any signature not covered by a named --keyring entry.
        if None in pinned:
            return pinned[None], bundle_revoked, "pinned"
        return None, False, (
            f"key_id '{key_id}' was not supplied via --keyring/--pubkey; refusing to "
            "fall back to the key embedded in the bundle"
        )
    entry = (cert.get("public_keys") or {}).get(key_id) or {}
    if not entry:
        return None, False, f"no public key in the bundle for key_id '{key_id}'"
    return entry.get("pem"), bool(entry.get("revoked")), entry.get("detail") or ""


def _check_certificate_signatures(cert: dict, results: list, pinned: dict | None = None) -> None:
    """The certificate's own signature, then every checkpoint under its OWN key_id."""
    statement = cert.get("statement") or {}

    def _one(body, sig_hex, key_id, label):
        pem, revoked, detail = _resolve_bundle_key(cert, key_id, pinned)
        if pem is None and detail:
            return False, detail
        if revoked:
            # Rule 4 of docs/notes/key_management.md: revocation is explicit
            # and LOUD. A revoked key may still verify mathematically; that is
            # precisely why it must fail here rather than pass quietly.
            return False, (
                f"KEY REVOKED — '{key_id}' has been revoked. {label} must NOT be "
                "trusted even though its signature may be mathematically valid."
            )
        if not pem:
            return False, f"no public key in the bundle for key_id '{key_id}'"
        if verify_signature(body, sig_hex, pem):
            return True, f"{label} signed by {key_id} — signature valid"
        return False, f"{label} SIGNATURE INVALID under {key_id}"

    results.append(("certificate signature",) + _one(
        statement, cert.get("signature_hex", ""), cert.get("key_id", ""), "certificate"))

    failures = []
    checkpoints = statement.get("checkpoints") or []
    for cp in checkpoints:
        ok, detail = _one(cp.get("sth_body") or {}, cp.get("signature_hex", ""),
                          cp.get("key_id", ""), f"checkpoint {cp.get('checkpoint_id')}")
        if not ok:
            failures.append(detail)
    results.append((
        "checkpoint signatures (each under its recorded key_id)",
        not failures,
        "; ".join(failures) if failures else f"all {len(checkpoints)} checkpoint signatures valid",
    ))


def _check_certificate_linkage(cert: dict, results: list) -> None:
    """
    Unbroken linkage: each checkpoint's sealed head must be a leaf of the
    NEXT checkpoint's Merkle tree, proven against that checkpoint's signed
    root. This is what turns "governance never stopped" into a proof.

    Every value used here comes from the checkpoints' `sth_body` — the bytes
    their signatures actually cover — never from the linkage entry's own
    restatement of them. A linkage entry is unsigned convenience data; a
    proof verified against it would only show the entry is self-consistent,
    which a forger can arrange trivially.

    Completeness is enforced as well: N checkpoints must produce exactly N-1
    links joining consecutive pairs. Otherwise a bundle claiming ten
    checkpoints could ship an empty linkage list and pass vacuously.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    links = statement.get("linkage") or []
    failures = []

    expected = max(0, len(cps) - 1)
    if len(links) != expected:
        failures.append(
            f"expected {expected} link(s) for {len(cps)} checkpoint(s), found {len(links)}")
        links = []

    # The status is inside the signed body, so an issuer cannot relabel a
    # certificate after the fact -- but it must still agree with the evidence
    # actually shipped. A single checkpoint has no consecutive pair and
    # therefore proves nothing about continuity; a bundle claiming `proven`
    # with no links would be asserting exactly the vacuous truth this check
    # exists to catch.
    status = statement.get("linkage_status")
    if status == "proven" and expected == 0:
        failures.append(
            "statement claims linkage 'proven' but a single checkpoint has no "
            "consecutive pair to link")
    if status == "not_applicable" and expected > 0:
        failures.append(
            f"statement claims linkage 'not_applicable' but {len(cps)} checkpoints "
            f"were supplied, which must be linked")
    claimed_proven = statement.get("links_proven")
    if isinstance(claimed_proven, int) and claimed_proven > expected:
        failures.append(
            f"statement claims {claimed_proven} proven link(s) but only {expected} "
            f"are possible for {len(cps)} checkpoint(s)")

    for i, link in enumerate(links):
        earlier, later = cps[i], cps[i + 1]
        label = f"{link.get('from_checkpoint_id')} → {link.get('to_checkpoint_id')}"

        if (link.get("from_checkpoint_id") != earlier.get("checkpoint_id")
                or link.get("to_checkpoint_id") != later.get("checkpoint_id")):
            failures.append(f"link {i} does not join consecutive checkpoints {label}")
            continue

        earlier_body = earlier.get("sth_body") or {}
        later_body = later.get("sth_body") or {}
        sealed_head = earlier_body.get("head_hash")
        earlier_len = earlier_body.get("length")
        root = later_body.get("merkle_root")
        tree_size = later_body.get("tree_size")
        # A link proves the earlier head is a leaf of the LATER tree, so the
        # later checkpoint's construction is the one that applies. Signed body
        # only, and absent means 1.
        later_tree_version = later_body.get("tree_version", 1)

        if link.get("sealed_head") != sealed_head:
            failures.append(f"{label}: sealed_head disagrees with the signed checkpoint body")
            continue
        if link.get("merkle_root") != root or link.get("tree_size") != tree_size:
            failures.append(f"{label}: merkle_root/tree_size disagree with the signed body")
            continue
        if not isinstance(earlier_len, int) or not isinstance(tree_size, int):
            failures.append(f"{label}: signed body is missing length/tree_size")
            continue
        if earlier_len > tree_size:
            failures.append(f"{label}: chain shrank between seals ({earlier_len} → {tree_size})")
            continue
        if earlier_len == 0:
            continue  # empty chain at the earlier seal — nothing to prove
        if later_tree_version not in SUPPORTED_TREE_VERSIONS:
            failures.append(
                f"{label}: signed body declares unknown tree_version "
                f"{later_tree_version!r}")
            continue

        leaf_index = earlier_len - 1
        if link.get("leaf_index") != leaf_index:
            failures.append(f"{label}: leaf_index does not match the signed length")
            continue
        if not link.get("provable"):
            failures.append(f"{label}: {link.get('detail') or 'link not provable'}")
            continue
        if not root or not sealed_head:
            failures.append(f"{label}: signed body is missing merkle_root/head_hash")
            continue

        try:
            ok = verify_inclusion(
                sealed_head, leaf_index, tree_size,
                link.get("proof_path") or [], root,
                tree_version=later_tree_version,
            )
        except ValueError:
            failures.append(f"{label}: malformed hex in the linkage proof")
            continue
        if not ok:
            failures.append(f"{label}: inclusion proof does not reproduce the sealed root")

    if not statement.get("linkage_unbroken", False):
        for problem in statement.get("linkage_problems") or []:
            failures.append(problem)
        if not failures:
            failures.append("certificate does not claim unbroken linkage")

    results.append((
        "chain linkage across the range",
        not failures,
        "; ".join(failures) if failures
        else (f"{len(links)} consecutive checkpoint link(s) proven against the signed "
              "roots — governance was continuous across the certified range"),
    ))


def _check_certificate_coverage(cert: dict, results: list) -> None:
    """
    Recompute every coverage and gap claim from the SIGNED checkpoint bodies.

    The certificate is generated by Coriqo, so its claims are only worth what
    the seals behind them support. This check re-derives them independently;
    if the issuer ever claimed coverage the signatures do not back, it fails.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    coverage = statement.get("coverage") or {}
    problems = []

    if not cps:
        results.append(("coverage matches the sealed events", False, "no checkpoints in the bundle"))
        return

    first_body = cps[0].get("sth_body") or {}
    last_body = cps[-1].get("sth_body") or {}

    if coverage.get("sealed_event_count") != last_body.get("length"):
        problems.append("sealed_event_count does not match the closing checkpoint's signed length")
    expected_added = (last_body.get("length") or 0) - (first_body.get("length") or 0)
    if coverage.get("events_added_in_period") != expected_added:
        problems.append(
            f"events_added_in_period claims {coverage.get('events_added_in_period')}, "
            f"signed lengths give {expected_added}")

    opening = ((first_body.get("continuity") or {}).get("obligations")) or {}
    closing = ((last_body.get("continuity") or {}).get("obligations")) or {}
    for key, claimed in (coverage.get("obligations_in_period") or {}).items():
        o, c = opening.get(key), closing.get(key)
        expected = (c - o) if isinstance(o, int) and isinstance(c, int) else None
        if claimed != expected:
            problems.append(f"obligation '{key}' claims {claimed}, signed bodies give {expected}")

    # The cumulative counts are what a single-checkpoint chain actually
    # displays, so they must be attested too — not merely echoed.
    for key, claimed in (coverage.get("obligations_closing") or {}).items():
        if claimed != closing.get(key):
            problems.append(
                f"cumulative obligation '{key}' claims {claimed}, "
                f"the closing signed body gives {closing.get(key)}")

    # Reported gaps must be a subset of what the closing checkpoint sealed.
    # A certificate may narrow gaps to its window; it may never invent one,
    # and it may never quietly drop one that the seal recorded.
    sealed_gaps = ((last_body.get("continuity") or {}).get("coverage_gaps")) or []
    sealed_keys = {(g.get("from"), g.get("to")) for g in sealed_gaps}
    for gap in statement.get("coverage_gaps") or []:
        if (gap.get("from"), gap.get("to")) not in sealed_keys:
            problems.append(
                f"reported gap {gap.get('from')} → {gap.get('to')} is not in the signed record")

    results.append((
        "coverage matches the sealed events",
        not problems,
        "; ".join(problems) if problems
        else "every coverage and gap claim is backed by a signed checkpoint body",
    ))


# ---------------------------------------------------------------------------
# Key succession (SPEC.md §9.3)
#
# A certificate's checkpoints may span more than one key_id, because signing
# authority for a chain can be handed over — a custody transfer moves an
# engagement from the validator that produced it to the bank that owns it.
#
# The handoff is a signed statement, not a label. `statement.succession` is a
# list of records; each is the canonical body the OUTGOING key signed, plus
# the detached `signature_hex` over it. Verifying it needs nothing beyond
# this bundle: the outgoing key's PEM is already carried in `public_keys` (or
# pinned via --pubkey/--keyring), and the body is canonicalised exactly the
# way every other signature in this format is (§3).
#
# The signed body is the record with `signature_hex` removed — every other
# field it carries is covered. That is deliberate: it means a forger cannot
# staple an unsigned field (an approver name, an earlier date) onto a
# genuine record, and it means a field added to the record in a future
# version is signed automatically rather than silently unchecked.
#
# What this closes: before signature verification, a party holding only the
# INCOMING key could take somebody else's genuine, outgoing-key-signed
# checkpoints, append their own checkpoints under their own key, assert a
# `{outgoing, incoming}` pair, and the whole thing verified. Nothing in the
# bundle required the outgoing party's consent to the handoff. Now it does.
# ---------------------------------------------------------------------------

# Domain separation: the body a key succession signs declares what it is.
# Requiring it stops a signature made by the outgoing key over some *other*
# structure that happens to carry these two field names from being replayed
# here as a handoff the outgoing party never authorised.
SUCCESSION_BODY_TYPE = "key.succession"


def _succession_signed_body(record: dict) -> dict:
    """The bytes the outgoing key signed: the record minus its own signature."""
    return {k: v for k, v in record.items() if k != "signature_hex"}


def _check_certificate_succession(cert: dict, results: list, pinned: dict | None = None) -> None:
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    if len(cps) < 2:
        return  # nothing to transition between

    key_ids = [cp.get("key_id") for cp in cps]
    transitions = [
        (i, key_ids[i], key_ids[i + 1])
        for i in range(len(key_ids) - 1)
        if key_ids[i] != key_ids[i + 1]
    ]
    if not transitions:
        results.append((
            "key succession",
            True,
            f"single signing key ({key_ids[0]!r}) throughout — no succession record needed",
        ))
        return

    succession = statement.get("succession")
    records = [r for r in (succession if isinstance(succession, list) else [])
               if isinstance(r, dict)]
    problems = []
    for i, outgoing, incoming in transitions:
        label = (f"{cps[i].get('checkpoint_id')} ({outgoing!r}) → "
                 f"{cps[i + 1].get('checkpoint_id')} ({incoming!r})")
        # A record only explains THIS change if it names this exact pair:
        # `outgoing_key_id` must be the key that signed the checkpoint
        # before the change, `incoming_key_id` the key that signed the one
        # after. A record naming some other pair explains some other
        # handoff, and leaves this one unexplained.
        candidates = [
            r for r in records
            if r.get("outgoing_key_id") == outgoing and r.get("incoming_key_id") == incoming
        ]
        if not candidates:
            problems.append(
                f"{label}: signing key changed with no matching record in "
                "statement.succession — an unexplained key change is not a "
                "provable continuity claim"
            )
            continue

        # Verify under the OUTGOING key. Resolution goes through the same
        # path every other signature in this bundle uses, so --pubkey /
        # --keyring pinning applies here too: a bundle that ships its own
        # "outgoing" key is no more trusted for the handoff than it is for a
        # checkpoint. Revocation is not re-checked here — the outgoing key is
        # by construction a checkpoint's key_id in this range, so
        # _check_certificate_signatures has already failed the certificate
        # loudly if it is revoked.
        pem, _revoked, detail = _resolve_bundle_key(cert, outgoing, pinned)
        if not pem:
            problems.append(f"{label}: {detail or f'no public key available for {outgoing!r}'}")
            continue

        reasons = []
        for r in candidates:
            body = _succession_signed_body(r)
            if body.get("type") != SUCCESSION_BODY_TYPE:
                reasons.append(
                    f"record does not declare type={SUCCESSION_BODY_TYPE!r} — "
                    "an unlabelled body is not a key-succession statement"
                )
                continue
            sig = r.get("signature_hex")
            if not isinstance(sig, str) or not sig:
                reasons.append("record carries no signature_hex")
                continue
            if verify_signature(body, sig, pem):
                break
            reasons.append(f"record's signature does not verify under {outgoing!r}")
        else:
            problems.append(
                f"{label}: {'; '.join(reasons)}. Only the holder of the outgoing "
                "key can hand its chain to a successor, so a record it did not "
                "sign does not authorise this key change."
            )

    if problems:
        results.append(("key succession", False, "; ".join(problems)))
    else:
        results.append((
            "key succession",
            True,
            f"{len(transitions)} key change(s), each authorised by a succession "
            "record naming that exact outgoing/incoming key_id pair and signed "
            "under the outgoing key (see SPEC.md §9.3 for what a succession "
            "record does and does not prove)",
        ))


def _check_certificate_timestamp_monotonicity(cert: dict, results: list) -> None:
    """
    Verify that checkpoint timestamps are non-decreasing in the chain.

    Checkpoints should be ordered chronologically. A record claiming an
    earlier timestamp than a preceding record in the hash chain indicates
    backdating and should be flagged as a failure.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []

    if len(cps) < 2:
        results.append((
            "Timestamp monotonicity",
            True,
            "single checkpoint — no timestamp ordering to verify",
        ))
        return

    problems = []
    for i in range(1, len(cps)):
        prev_body = cps[i - 1].get("sth_body") or {}
        curr_body = cps[i].get("sth_body") or {}
        prev_ts = prev_body.get("issued_at")
        curr_ts = curr_body.get("issued_at")

        # A missing issued_at on either side is itself a failure, not a free
        # pass — omitting the timestamp on one checkpoint must not let a
        # forger defeat this check the same way a missing sth_ts would have
        # defeated the single-proof _check_timestamp_consistency.
        if not prev_ts or not curr_ts:
            problems.append(
                f"checkpoint {cps[i].get('checkpoint_id')!r} or "
                f"{cps[i-1].get('checkpoint_id')!r} is missing issued_at — "
                f"cannot verify ordering between them"
            )
        elif prev_ts > curr_ts:
            problems.append(
                f"checkpoint {cps[i].get('checkpoint_id')} ({curr_ts!r}) "
                f"backdated relative to {cps[i-1].get('checkpoint_id')} ({prev_ts!r})"
            )

    results.append((
        "Timestamp monotonicity",
        not problems,
        "; ".join(problems) if problems
        else f"{len(cps)} checkpoint timestamps are in non-decreasing order",
    ))


def _check_certificate_compliance_coverage(cert: dict, results: list) -> None:
    """
    Calculate and report compliance coverage percentage based on obligations.

    Counts the number of obligation types with non-zero values in the final
    checkpoint's continuity block and reports coverage as a percentage of
    all tracked obligation types.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []

    if not cps:
        results.append((
            "Compliance coverage percentage",
            True,
            "no checkpoints — coverage cannot be computed",
        ))
        return

    # Use the closing checkpoint's obligations
    last_body = cps[-1].get("sth_body") or {}
    continuity = last_body.get("continuity") or {}
    obligations = continuity.get("obligations") or {}

    coverage_detail, _percentage = _compliance_coverage_detail(
        obligations, empty_note="no obligations recorded in closing checkpoint",
    )

    results.append((
        "Compliance coverage percentage",
        True,  # Report coverage percentage; it's informational, not a pass/fail
        coverage_detail,
    ))


def _check_certificate_cosignatures(
    cert: dict, results: list, pinned: dict | None, independent_ids: set,
) -> list[tuple[str, str, list[dict], list[str]]]:
    """
    Witness state for EVERY checkpoint in the certified range, kept per
    checkpoint rather than rolled up.

    A range where the first two seals are cosigned and the rest are not is a
    materially different record from one where all of them are, and a single
    aggregated verdict would hide exactly that. day_one_trust_spec.md I-3
    ("a pending control renders as pending") is a per-checkpoint rule.

    `cert["cosignatures"]` is UNSIGNED metadata keyed by checkpoint_id — the
    same trust class as the top-level restatements §7.3 warns about — which
    is why nothing here is taken from it except the raw signature bytes and
    the witness key_id, both of which are then checked against a key the
    operator supplied.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    by_checkpoint = cert.get("cosignatures")
    if by_checkpoint is not None and not isinstance(by_checkpoint, dict):
        results.append((
            "witness cosignatures",
            False,
            "the bundle's `cosignatures` field is present but is not an object "
            "keyed by checkpoint_id; refusing to guess at its shape",
        ))
        return []

    blocks = []
    failures = []
    states = []
    for cp in cps:
        cp_id = cp.get("checkpoint_id")
        entries = (by_checkpoint or {}).get(cp_id)
        state, rows, cp_failures, notes = _evaluate_cosignatures(
            cp.get("sth_body") or {}, entries, pinned, independent_ids)
        blocks.append((f"checkpoint {cp_id}", state, rows, notes))
        states.append(state)
        failures.extend(f"{cp_id}: {f}" for f in cp_failures)

    if all(s == COSIGN_NONE for s in states):
        return blocks  # nothing cosigned anywhere; no assertion to make
    results.append((
        "witness cosignatures (each checkpoint under its own witness keys)",
        not failures,
        "; ".join(failures) if failures
        else "; ".join(f"{cp.get('checkpoint_id')}: {_COSIGN_HEADLINE[s]}"
                       for cp, s in zip(cps, states)),
    ))
    return blocks


def _print_certificate_anchors(cert: dict) -> None:
    """
    Rekor references for the certified checkpoints. Informational, exactly as
    for a proof bundle (SPEC.md §10): the anchor never moves PASS/FAIL, and a
    verifier that failed because Rekor was unreachable would have made offline
    verification conditional on being online.
    """
    anchors = cert.get("anchors")
    if not isinstance(anchors, dict) or not anchors:
        return
    print("-" * 60)
    print("Public transparency-log anchors (Sigstore Rekor)")
    print("-" * 60)
    for cp in (cert.get("statement") or {}).get("checkpoints") or []:
        cp_id = cp.get("checkpoint_id")
        anchor = anchors.get(cp_id) or {}
        uuid = anchor.get("rekor_uuid")
        status = anchor.get("status") or "not anchored"
        if not uuid:
            print(f"  {cp_id}: not anchored (status: {status})")
            continue
        print(f"  {cp_id}: {status} — https://search.sigstore.dev/?uuid={uuid}")
        if anchor.get("rekor_log_index") is not None:
            print(f"      log index {anchor['rekor_log_index']}  "
                  f"anchored at {anchor.get('anchored_at')}")
    print()
    print("  Informational only — no check above depends on reaching Rekor.")
    print()


def _print_continuity_summary(cert: dict) -> None:
    """
    The human readout. Gaps are shown even when everything passes — silence in
    the chain is meant to be visible and sold, not fought
    (verifiable_governance_strategy.md §7). A quiet fortnight on a small model
    book is ordinary operation, and is labelled as such rather than as a fault.
    """
    statement = cert.get("statement") or {}
    period = statement.get("period") or {}
    coverage = statement.get("coverage") or {}
    summary = statement.get("gap_summary") or {}

    print("-" * 60)
    print("Governance continuity")
    print("-" * 60)
    print(f"  Subject:            {statement.get('subject')}")
    print(f"  Period:             {period.get('from')} → {period.get('to')}")
    print(f"  Checkpoints:        {statement.get('checkpoint_count')}")
    print(f"  Events sealed:      {coverage.get('sealed_event_count')} "
          f"({coverage.get('events_added_in_period')} added in period)")

    obligations = coverage.get("obligations_in_period") or {}
    if obligations:
        rendered = ", ".join(
            f"{k}={v}" for k, v in sorted(obligations.items()) if v is not None
        )
        print(f"  Obligations:        {rendered or 'none recorded in period'}")

    print()
    print(f"  Quiet periods:      {summary.get('total', 0)} "
          f"({summary.get('normal_cadence', 0)} normal cadence, "
          f"{summary.get('exceeds_policy', 0)} beyond policy)")
    for gap in statement.get("coverage_gaps") or []:
        label = "normal cadence" if gap.get("classification") == "normal_cadence" else "BEYOND POLICY"
        reason = gap.get("reason") or "no reason recorded"
        still_open = " (still open)" if gap.get("open_ended") else ""
        print(f"    · {gap.get('days')} days, {gap.get('from')} → {gap.get('to')}{still_open}")
        print(f"      {label} — {reason}")
    if not (statement.get("coverage_gaps") or []):
        print("    · none — no quiet period reached the reporting threshold")

    # Prefer the reasoned list; fall back to the id-only field for certificates
    # issued before it existed. Reporting every exclusion as "no Merkle root"
    # would be wrong for the non-reproducible ones and would read to an examiner
    # as a different, milder problem than the one actually present.
    # Withheld checkpoints are pulled out of this list and reported on their
    # own below. Naming one here as well would describe it twice, and the
    # milder description — "excluded from linkage proofs" — would be the one an
    # examiner read first.
    detailed = [item for item in (statement.get("excluded_checkpoints") or [])
                if not (isinstance(item, dict)
                        and item.get("reason") == REASON_SIGNATURE_NOT_VERIFIABLE)]
    excluded = statement.get("excluded_v1_checkpoints") or []
    if detailed:
        print()
        print(f"  NOTE: {len(detailed)} checkpoint(s) in this range are excluded from")
        print("        linkage proofs:")
        for item in detailed:
            print(f"    · {item.get('checkpoint_id')} ({item.get('issued_at')})")
            print(f"      {item.get('detail') or item.get('reason')}")
    elif excluded:
        print()
        print(f"  NOTE: {len(excluded)} V1 checkpoint(s) in this range carry no Merkle root")
        print("        and are excluded from linkage proofs. Re-issue to upgrade them.")
    print()


# ---------------------------------------------------------------------------
# Checkpoints withheld from the certified range (SPEC.md §8.4)
#
# `excluded_checkpoints` has carried only mild reasons until now. A pre-Merkle
# checkpoint has no root to link against; a non-reproducible one cannot be
# re-derived. Neither says the record is wrong.
#
# `signature_not_verifiable` says exactly that. It means the issuer found a
# checkpoint whose signature does not check out, could not repair it —
# checkpoints are append-only — and dropped it from the certified set under a
# named declaration. Reporting that in the same NOTE, in the same voice, as
# "this one predates Merkle roots" would hand an examiner the milder of two
# very different facts.
#
# Two rules follow, and they pull against each other on purpose:
#
#   * the declaration is reproduced in full, because the reader's real
#     question is what is missing from this range and on whose word;
#   * none of it is verified, and the output says so in those words. The
#     checks below ran over the checkpoints the certificate carries. A
#     withheld checkpoint is not here to check. Collapsing the two is how a
#     removal starts to read as a repair.
#
# One thing here IS checked, because its failure mode is real rather than
# hypothetical: a certificate that lists a checkpoint as withheld while still
# counting it among the certified set has removed it on paper only, and a
# declaration with no declarant is an unattributable deletion wearing the word
# "quarantine". Both are properties of the bundle, so both are decidable
# offline. Whether the removal was warranted is not, and is not claimed.
# ---------------------------------------------------------------------------

REASON_SIGNATURE_NOT_VERIFIABLE = "signature_not_verifiable"

_QUARANTINE_FIELDS = (
    ("declared_by", "Declared by"),
    ("declared_at", "Declared at"),
    ("operator_reason", "Stated reason"),
    ("verification_failure", "Failure recorded"),
)


def _withheld_checkpoints(statement: dict) -> list[dict]:
    """Exclusions dropped from the certified set because their signature fails."""
    return [item for item in (statement.get("excluded_checkpoints") or [])
            if isinstance(item, dict)
            and item.get("reason") == REASON_SIGNATURE_NOT_VERIFIABLE]


def _print_withheld_checkpoints(cert: dict) -> None:
    """The loud half of the disclosure: what was removed, and who removed it."""
    statement = cert.get("statement") or {}
    withheld = _withheld_checkpoints(statement)
    if not withheld:
        return
    certified = {cp.get("checkpoint_id")
                 for cp in (statement.get("checkpoints") or []) if isinstance(cp, dict)}

    print("=" * 60)
    print(f"WITHHELD FROM THE CERTIFIED RANGE — {len(withheld)} checkpoint(s)")
    print("=" * 60)
    print()
    print("  These checkpoints fall inside the period above but were taken out of")
    print("  the certified set: the issuer declares that their signatures do not")
    print("  verify. This verifier checked none of them. What follows is the")
    print("  issuer's own declaration, reproduced so you can see what was removed")
    print("  and on whose authority.")
    print()
    for item in withheld:
        cp_id = item.get("checkpoint_id") or "(no checkpoint_id recorded)"
        print(f"  · {cp_id}  (sealed {item.get('issued_at') or 'date not recorded'})")
        if item.get("detail"):
            print(f"      {item['detail']}")
        quarantine = item.get("quarantine")
        if isinstance(quarantine, dict) and quarantine:
            for key, label in _QUARANTINE_FIELDS:
                print(f"      {label + ':':<18}{quarantine.get(key) or 'not recorded'}")
        else:
            print("      No quarantine record — this removal names nobody.")
        if item.get("checkpoint_id") in certified:
            print("      Still counted among the certified checkpoints as well, which")
            print("      the check below fails on.")
        print()
    print("  A PASS below covers the checkpoints this certificate carries. It says")
    print("  nothing about the ones listed here, and it is not agreement that they")
    print("  were rightly removed. To judge that, compare this list against your own")
    print("  record of what should have been sealed in the period.")
    print()


def _check_certificate_withheld(cert: dict, results: list) -> None:
    """
    Coherence of the withholding, and nothing beyond it.

    Adds no result at all when nothing is withheld, so a certificate without
    quarantines reads exactly as it did before.
    """
    statement = cert.get("statement") or {}
    withheld = _withheld_checkpoints(statement)
    if not withheld:
        return
    certified = {cp.get("checkpoint_id")
                 for cp in (statement.get("checkpoints") or []) if isinstance(cp, dict)}

    problems = []
    for item in withheld:
        cp_id = item.get("checkpoint_id")
        label = cp_id or "(no checkpoint_id)"
        if not cp_id:
            problems.append("an exclusion names no checkpoint_id")
        elif cp_id in certified:
            problems.append(f"{label}: declared withheld but still counted among the "
                            "certified checkpoints")
        quarantine = item.get("quarantine")
        if not isinstance(quarantine, dict) or not quarantine:
            problems.append(f"{label}: declared unverifiable with no quarantine record, "
                            "so the removal names nobody")
            continue
        missing = [key for key, _ in _QUARANTINE_FIELDS if not quarantine.get(key)]
        if missing:
            problems.append(f"{label}: quarantine record is missing {', '.join(missing)}")

    results.append((
        "withheld checkpoints (attributable, and actually out of the certified set)",
        not problems,
        "; ".join(problems) if problems else
        f"{len(withheld)} checkpoint(s) withheld as unverifiable; each names a declarant, "
        "and none of them is counted among the checkpoints checked here. That is the "
        "shape of the declaration, not its truth — whether the removal was warranted is "
        "the issuer's claim, and an offline verifier cannot settle it.",
    ))


def run_certificate(cert_path: str, pubkey_path: str | None = None,
                     keyring_path: str | None = None,
                     witness_keyring_path: str | None = None,
                     witness_pubkey_path: str | None = None,
                     independent_witnesses: list[str] | None = None) -> bool:
    """Verify a Governance Continuity Certificate bundle offline.

    Thin wrapper around `verify_certificate_dict` that loads the certificate
    from a file path. `--bundle` mode (see `run_bundle`) reads a certificate
    out of a zip entry instead of a standalone file, so the actual checking
    logic lives in `verify_certificate_dict` and both callers share it —
    there is exactly one implementation of "is this certificate's signature
    and linkage valid", not two that could drift apart.
    """
    try:
        cert = json.loads(Path(cert_path).read_text())
    except Exception as exc:
        print(f"FAIL: Cannot load certificate file: {exc}")
        return False

    return verify_certificate_dict(cert, pubkey_path, keyring_path,
                                    witness_keyring_path, witness_pubkey_path,
                                    independent_witnesses)


def verify_certificate_dict(cert: dict, pubkey_path: str | None = None,
                             keyring_path: str | None = None,
                             witness_keyring_path: str | None = None,
                             witness_pubkey_path: str | None = None,
                             independent_witnesses: list[str] | None = None) -> bool:
    """Same checks as `run_certificate`, but on an already-loaded dict."""
    pinned = None
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
        except ValueError as exc:
            print(f"FAIL: {exc}")
            return False

    statement = cert.get("statement")
    if not isinstance(statement, dict):
        print("FAIL: Not a certificate bundle — no 'statement' object. "
              "For an inclusion proof use --proof instead.")
        return False

    print("=" * 60)
    print("Coriqo — Governance Continuity Certificate Verification")
    print("=" * 60)
    print()

    witness_pinned, witness_pin_error = _witness_pinning(
        witness_pubkey_path, witness_keyring_path)
    if witness_pin_error is not None:
        print(f"FAIL: {witness_pin_error}")
        return False

    _print_continuity_summary(cert)
    _print_withheld_checkpoints(cert)
    _print_certificate_anchors(cert)
    _print_key_trust(cert, pinned)

    results: list[tuple[str, bool, str]] = []
    _check_certificate_signatures(cert, results, pinned)
    _check_certificate_linkage(cert, results)
    _check_certificate_coverage(cert, results)
    _check_certificate_succession(cert, results, pinned)
    _check_certificate_timestamp_monotonicity(cert, results)
    _check_certificate_compliance_coverage(cert, results)
    _check_certificate_withheld(cert, results)
    cosign_blocks = _check_certificate_cosignatures(
        cert, results, witness_pinned, set(independent_witnesses or ()))
    if cosign_blocks:
        _print_cosign_section(cosign_blocks, witness_pinned)

    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    all_pass = all(r[1] for r in results)
    withheld = _withheld_checkpoints(statement)
    print("=" * 60)
    if all_pass:
        # Decision: a withholding narrows the verdict's scope. It does not
        # weaken the verdict, and it does not get to be silent.
        #
        # Two easier answers were both wrong. Failing a certificate because it
        # excludes something would punish the issuer for disclosing — naming an
        # unverifiable checkpoint is the honest move, and a verifier that turns
        # disclosure into a FAIL teaches issuers to say nothing instead.
        # Printing the same unqualified "CONTINUITY VERIFIED" as a certificate
        # with nothing withheld is worse: readers take the last line as the
        # answer, and that line would be answering a narrower question than the
        # one they asked.
        #
        # So the verdict stays PASS — the mathematics over the checkpoints that
        # ARE here is sound, and a proof over a smaller set is still a proof —
        # and the headline states its scope. Someone who reads nothing but the
        # last line still learns that checkpoints were removed, and how many.
        if withheld:
            print("RESULT: CONTINUITY VERIFIED OVER A REDUCED RANGE ✓")
            print()
            print(f"  {len(withheld)} checkpoint(s) in this period were withheld as "
                  "unverifiable and")
            print("  are not covered by this result. Each one, and the declaration behind")
            print("  it, is listed under WITHHELD FROM THE CERTIFIED RANGE above.")
        else:
            print("RESULT: CONTINUITY VERIFIED ✓")
        print()
        # A malformed bundle can omit `claim` even though every cryptographic
        # check passed. Printing a bare "None" under a PASS banner reads as a
        # verifier fault rather than a missing field, so say which it is.
        claim = statement.get("claim")
        print(f"  {claim}" if claim else
              "  (the certificate carries no claim text; the checks above still hold)")
        print()
        print("  Verified with mathematics alone — no network access, no Coriqo")
        print("  software, and no trust in Coriqo as an institution.")
    else:
        print("RESULT: CONTINUITY VERIFICATION FAILED ✗")
        print()
        print("  Do not rely on this certificate. One or more checks failed above;")
        print("  a revoked signing key or a broken link between checkpoints means")
        print("  the continuity claim is not supported by the sealed record.")
    print("=" * 60)

    return all_pass


# ---------------------------------------------------------------------------
# --bundle mode: GET /api/v1/engagements/{id}/deliverables.zip
#
# manifest.json (first zip entry) carries a sha256 for every bundled file.
# On its own that proves nothing — anyone who edits a file can edit its
# sha256 in the same manifest. certificate.json (second entry, when the
# bundle is sealed) is a Governance Continuity Certificate whose signed
# `statement.bundle_binding.manifest_sha256` is the hash of manifest.json's
# OWN bytes. The chain this function walks is:
#
#     signature -> statement.bundle_binding.manifest_sha256
#               -> manifest.json bytes -> each file's recorded sha256 -> file bytes
#
# Editing a bundled file breaks its manifest sha256 (link 4). Editing the
# manifest to cover that up changes manifest.json's bytes, which breaks the
# signed manifest_sha256 (link 2). Editing the binding to cover THAT up
# breaks the Ed25519 signature (link 1). None of the three is repairable
# without the signing key — that is the whole point of binding the manifest
# hash inside the signed statement instead of leaving it beside it.
# ---------------------------------------------------------------------------

MANIFEST_ENTRY = "manifest.json"
CERTIFICATE_ENTRY = "certificate.json"


def _check_manifest_binding(cert: dict, manifest_bytes: bytes) -> list[tuple[str, bool, str]]:
    """The link-2 check shared by every container format that binds a
    manifest into a certificate's signed statement: is `manifest_bytes`
    genuinely the thing `statement.bundle_binding.manifest_sha256` commits
    to? Pure — no I/O — so `run_bundle` (zip) and `run_pdf_bundle` (PDF) both
    call this on whatever manifest bytes they extracted, rather than each
    reimplementing the same three sub-checks and risking them drifting apart.
    """
    statement = cert.get("statement") if isinstance(cert.get("statement"), dict) else {}
    binding = statement.get("bundle_binding")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    results: list[tuple[str, bool, str]] = []

    if not isinstance(binding, dict):
        results.append((
            "certificate binds a manifest",
            False,
            "statement.bundle_binding is missing. This certificate does not seal a "
            "manifest at all (or the binding was stripped after signing) — its "
            "signature was never checked against this manifest.",
        ))
        return results

    bound_hash = binding.get("manifest_sha256")
    if bound_hash == manifest_hash:
        results.append((
            f"{MANIFEST_ENTRY} hash matches the signed binding",
            True,
            f"sha256({MANIFEST_ENTRY}) = {manifest_hash}, equals "
            "statement.bundle_binding.manifest_sha256.",
        ))
    else:
        results.append((
            f"{MANIFEST_ENTRY} hash matches the signed binding",
            False,
            f"sha256({MANIFEST_ENTRY}) = {manifest_hash} but "
            f"statement.bundle_binding.manifest_sha256 = {bound_hash!r}. "
            f"{MANIFEST_ENTRY} was changed after the certificate signed it — the "
            "signature no longer commits to this manifest, whatever its 'files' "
            "hashes say.",
        ))

    exp_name = binding.get("manifest_filename")
    results.append((
        "bundle_binding.manifest_filename matches the entry hashed",
        exp_name == MANIFEST_ENTRY,
        (f"binding names {exp_name!r}, matching {MANIFEST_ENTRY!r}."
         if exp_name == MANIFEST_ENTRY else
         f"statement.bundle_binding.manifest_filename = {exp_name!r}, but the entry "
         f"actually hashed was {MANIFEST_ENTRY!r}."),
    ))

    exp_len = binding.get("manifest_bytes")
    results.append((
        "bundle_binding.manifest_bytes matches the entry length",
        exp_len == len(manifest_bytes),
        (f"{MANIFEST_ENTRY} is {len(manifest_bytes)} bytes, matching the binding."
         if exp_len == len(manifest_bytes) else
         f"{MANIFEST_ENTRY} is {len(manifest_bytes)} bytes but "
         f"statement.bundle_binding.manifest_bytes = {exp_len!r}."),
    ))
    return results


def run_bundle(bundle_path: str, pubkey_path: str | None = None,
                keyring_path: str | None = None,
                witness_keyring_path: str | None = None,
                witness_pubkey_path: str | None = None,
                independent_witnesses: list[str] | None = None) -> int:
    """Verify a deliverables.zip bundle offline. Returns an exit code — see
    the module docstring's "Exit codes" section (EXIT_OK / EXIT_TAMPER /
    EXIT_UNSEALED / EXIT_MALFORMED).

    Never executes anything read from the bundle. manifest.json carries a
    human-readable `seal.verify_command` / `_how_to_check` string for
    examiners without this tool — those are DATA describing what a human
    could type, not instructions this function runs.
    """
    print("=" * 60)
    print("Coriqo — Deliverables Bundle Verification")
    print("=" * 60)
    print()

    try:
        zf = zipfile.ZipFile(bundle_path)
    except (FileNotFoundError, zipfile.BadZipFile, OSError, PermissionError) as exc:
        print(f"FAIL: Cannot open bundle: {exc}")
        return EXIT_MALFORMED

    with zf:
        names = zf.namelist()

        if MANIFEST_ENTRY not in names:
            print(f"FAIL: {MANIFEST_ENTRY} is missing from this bundle — a deliverables "
                  "bundle without a manifest cannot be verified at all.")
            return EXIT_MALFORMED

        manifest_bytes = zf.read(MANIFEST_ENTRY)
        try:
            manifest = json.loads(manifest_bytes)
        except Exception as exc:
            print(f"FAIL: {MANIFEST_ENTRY} is not valid JSON: {exc}")
            return EXIT_MALFORMED

        if not isinstance(manifest, dict):
            print(f"FAIL: {MANIFEST_ENTRY} does not decode to a JSON object.")
            return EXIT_MALFORMED

        seal = manifest.get("seal") if isinstance(manifest.get("seal"), dict) else {}

        if CERTIFICATE_ENTRY not in names:
            # An unsealed bundle is not a tamper failure — it was never
            # signed, so there is nothing here to cryptographically verify.
            # Report exactly what the manifest itself says happened.
            status = seal.get("status", "unknown")
            reason = seal.get("reason") or manifest.get("bundle_note") or (
                "manifest.json does not explain why this bundle is unsealed.")
            print("  [INFO] seal.status")
            print(f"         {status!r}")
            print()
            print(f"UNSEALED: this bundle carries no {CERTIFICATE_ENTRY} — {reason}")
            print()
            print("This is not proof of tampering. It means this bundle was never signed,")
            print("so this tool has nothing to check a signature against. Ask for a sealed")
            print("bundle if you need a verifiable one.")
            print("=" * 60)
            return EXIT_UNSEALED

        cert_bytes = zf.read(CERTIFICATE_ENTRY)
        try:
            cert = json.loads(cert_bytes)
        except Exception as exc:
            print(f"FAIL: {CERTIFICATE_ENTRY} is not valid JSON: {exc}")
            return EXIT_MALFORMED

        entry_names = set(names)

    print(f"manifest.json seal.status : {seal.get('status', 'unknown')!r}")
    print()
    print("-- link 1/3: certificate signature and checkpoint linkage " + "-" * 12)
    print()

    cert_ok = verify_certificate_dict(cert, pubkey_path, keyring_path,
                                       witness_keyring_path, witness_pubkey_path,
                                       independent_witnesses)
    if not cert_ok:
        print()
        print("=" * 60)
        print("RESULT: BUNDLE VERIFICATION FAILED ✗")
        print()
        print("  The certificate's own signature or checkpoint linkage did not verify")
        print("  (see the checks above). This is a problem with the certificate itself —")
        print(f"  it was never checked whether it actually binds this {MANIFEST_ENTRY}, or")
        print("  whether the bundled files match it, because a certificate that fails on")
        print("  its own terms cannot vouch for anything sealed under it.")
        print("=" * 60)
        return EXIT_TAMPER

    print()
    print("-- link 2/3: manifest bound to the signed certificate " + "-" * 12)
    print()

    results = _check_manifest_binding(cert, manifest_bytes)

    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    binding_ok = all(r[1] for r in results)

    print("-- link 3/3: every bundled file matches its manifest hash " + "-" * 8)
    print()

    file_results: list[tuple[str, bool, str]] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        file_results.append((
            "manifest.files is present and usable",
            False,
            f"{MANIFEST_ENTRY}['files'] is missing or not a list — nothing to check "
            "bundled files against.",
        ))
    else:
        named: set[str] = set()
        with zipfile.ZipFile(bundle_path) as zf2:
            for row in files:
                if not isinstance(row, dict):
                    continue
                name = row.get("name")
                if not isinstance(name, str):
                    continue
                named.add(name)
                status = row.get("status")
                sha = row.get("sha256")
                if sha is None:
                    # A manifest cannot hash the certificate that signs it —
                    # e.g. certificate.json's own row (see
                    # sha256_omitted_reason). Nothing to compare; skip, don't fail.
                    continue
                if status == "absent":
                    continue
                if name not in entry_names:
                    file_results.append((
                        f"present in the zip: {name}",
                        False,
                        f"manifest lists {name!r} as status={status!r} with a recorded "
                        "sha256, but no such entry exists in this zip.",
                    ))
                    continue
                actual = hashlib.sha256(zf2.read(name)).hexdigest()
                if actual == sha:
                    file_results.append((
                        f"sha256 matches: {name}",
                        True,
                        f"sha256 = {actual}, matches manifest.json.",
                    ))
                else:
                    file_results.append((
                        f"sha256 matches: {name}",
                        False,
                        f"sha256(zip entry) = {actual} but manifest.json records {sha!r} "
                        f"for {name!r}. This file was altered after the manifest was "
                        "written and signed — rewriting the manifest's own sha256 row to "
                        "match does not help, because the manifest's bytes are themselves "
                        "bound to the certificate's signature (link 2/3 above).",
                    ))

        extra = sorted(entry_names - named - {MANIFEST_ENTRY})
        if extra:
            print("  [WARN] zip entries not listed in manifest.json's files:")
            for name in extra:
                print(f"         {name}")
            print("         Not scored as a failure: the certificate's signature commits")
            print("         to manifest.json's bytes, and the manifest never claimed")
            print("         anything about these entries one way or the other — but an")
            print("         examiner should know they are here and unaccounted for.")
            print()

    for name, passed, detail in file_results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    files_ok = all(r[1] for r in file_results)
    all_pass = binding_ok and files_ok

    print("=" * 60)
    if all_pass:
        print("RESULT: BUNDLE VERIFIED ✓")
        print()
        print(f"  The certificate's signature covers statement.bundle_binding, which")
        print(f"  matches sha256({MANIFEST_ENTRY}) for the {MANIFEST_ENTRY} actually in this")
        print("  zip, and every present file in that manifest matches its recorded")
        print("  sha256. Signature -> manifest -> files, unbroken.")
    else:
        print("RESULT: BUNDLE VERIFICATION FAILED ✗")
        print()
        print("  Do not rely on this bundle. One or more links in the chain below the")
        print("  certificate's own signature failed — see the checks above for which")
        print("  file or field broke it.")
    print("=" * 60)

    return EXIT_OK if all_pass else EXIT_TAMPER


# ---------------------------------------------------------------------------
# Positional INPUT auto-detection (zip / PDF / bare JSON)
#
# Ported from the standalone examiner-facing verifier
# (coriqo-seal-verifier/verify_proof.py's load_bundle_input), which lets an
# examiner pass one file and skip choosing --proof/--certificate/--bundle by
# hand. That copy's extraction pulls certificate.json or proof.json out of a
# zip or PDF and checks ONLY that object — which is exactly wrong for a
# Coriqo deliverables bundle (a zip with manifest.json), because this file's
# --bundle mode exists precisely to catch a payload file tampered with AND
# its manifest.json sha256 row rewritten to match: the extracted-certificate
# check alone would report that bundle VERIFIED.
#
# So routing here adds one rule the standalone copy does not have: a zip
# carrying manifest.json is a deliverables bundle and goes to run_bundle()
# for the full signature -> manifest -> file check, same as --bundle. Only a
# zip WITHOUT manifest.json, a PDF, or bare JSON takes the weaker
# extract-and-verify-only-that-object path — and that path always says so.
# ---------------------------------------------------------------------------

_BUNDLE_MEMBER_NAMES = ("certificate.json", "proof.json")


def _classify_bundle_json(data: dict) -> str:
    """A certificate carries a top-level "statement" object; a proof does not."""
    return "certificate" if isinstance(data, dict) and isinstance(data.get("statement"), dict) else "proof"


def _extract_bundle_member(names_and_readers, source_label: str) -> tuple[dict, str]:
    """
    Shared by the zip and PDF extraction paths: given (name, read_bytes)
    pairs, pick certificate.json over proof.json when a container carries
    both, parse it, and classify it.
    """
    found = {}
    for name, read in names_and_readers:
        base = name.rsplit("/", 1)[-1]
        if base in _BUNDLE_MEMBER_NAMES and base not in found:
            found[base] = read
    for base in _BUNDLE_MEMBER_NAMES:  # certificate.json takes priority
        if base in found:
            data = json.loads(found[base]())
            return data, _classify_bundle_json(data)
    raise ValueError(
        f"no certificate.json or proof.json found inside {source_label}")


def _zip_has_manifest(zip_path: str) -> bool:
    """True when PATH is a Coriqo deliverables bundle — i.e. it carries
    manifest.json — rather than a plain certificate/proof container."""
    with zipfile.ZipFile(zip_path) as zf:
        return MANIFEST_ENTRY in zf.namelist()


def _load_from_zip(zip_path: str) -> tuple[dict, str]:
    with zipfile.ZipFile(zip_path) as zf:
        return _extract_bundle_member(
            ((info.filename, (lambda i=info: zf.read(i))) for info in zf.infolist()
             if not info.is_dir()),
            zip_path,
        )


def _pdf_attachments(pdf_path: str) -> dict[str, bytes]:
    """{attachment_name: bytes} for every attachment a PDF carries, last
    revision of each name winning (matches pypdf's own "most recent" pick
    used elsewhere in this file). Raises ImportError with the same message
    `_load_from_pdf` uses when pypdf is absent."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ImportError(
            "Reading attachments out of a PDF requires the 'pypdf' package "
            "(pip install pypdf). Plain --proof/--certificate/--bundle JSON "
            "verification does not need it."
        ) from exc
    reader = PdfReader(pdf_path)
    out: dict[str, bytes] = {}
    for name in reader.attachments:
        blobs = list(reader.attachments[name])
        if blobs:
            out[name] = blobs[-1]
    return out


def run_pdf_bundle(pdf_path: str, pubkey_path: str | None = None,
                    keyring_path: str | None = None,
                    witness_keyring_path: str | None = None,
                    witness_pubkey_path: str | None = None,
                    independent_witnesses: list[str] | None = None) -> int:
    """Verify a sealed engagement-deliverable PDF offline — the PDF analogue
    of `run_bundle`, for the container `sealed_deliverable.py` produces.

    Structurally NOT the same shape as a deliverables.zip. A PDF only ever
    carries two attachments toward this check — manifest.json and
    certificate.json — never a third bundled file: `manifest["files"]` also
    lists a `deck_content` row, but deck_content's bytes are a JSON snapshot
    that exists only inside the manifest's own hash, not as a separate
    extractable object in this container. So this function checks exactly
    two links — certificate signature/linkage, then manifest bound to the
    signed certificate — and says so, rather than padding the report with a
    fabricated third link or silently failing a row this container was never
    going to attach.

    Never executes anything read from the PDF; same non-negotiable as
    `run_bundle`.
    """
    print("=" * 60)
    print("Coriqo — Sealed Deliverable (PDF) Verification")
    print("=" * 60)
    print()

    try:
        attachments = _pdf_attachments(pdf_path)
    except ImportError as exc:
        print(f"FAIL: {exc}")
        return EXIT_MALFORMED
    except Exception as exc:
        print(f"FAIL: Cannot open PDF: {exc}")
        return EXIT_MALFORMED

    if MANIFEST_ENTRY not in attachments:
        print(f"FAIL: {MANIFEST_ENTRY} is missing from this PDF's attachments — a "
              "sealed deliverable without a manifest cannot be verified at all.")
        return EXIT_MALFORMED

    manifest_bytes = attachments[MANIFEST_ENTRY]
    try:
        manifest = json.loads(manifest_bytes)
    except Exception as exc:
        print(f"FAIL: {MANIFEST_ENTRY} is not valid JSON: {exc}")
        return EXIT_MALFORMED
    if not isinstance(manifest, dict):
        print(f"FAIL: {MANIFEST_ENTRY} does not decode to a JSON object.")
        return EXIT_MALFORMED

    seal = manifest.get("seal") if isinstance(manifest.get("seal"), dict) else {}

    if CERTIFICATE_ENTRY not in attachments:
        status = seal.get("status", "unknown")
        reason = seal.get("reason") or manifest.get("note") or (
            "manifest.json does not explain why this document is unsealed.")
        print("  [INFO] seal.status" if status != "unknown" else "  [INFO] sealed")
        print(f"         {status!r}" if status != "unknown" else f"         {manifest.get('sealed')!r}")
        print()
        print(f"UNSEALED: this PDF carries no {CERTIFICATE_ENTRY} — {reason}")
        print()
        print("This is not proof of tampering. It means this document was never")
        print("signed, so this tool has nothing to check a signature against.")
        print("=" * 60)
        return EXIT_UNSEALED

    cert_bytes = attachments[CERTIFICATE_ENTRY]
    try:
        cert = json.loads(cert_bytes)
    except Exception as exc:
        print(f"FAIL: {CERTIFICATE_ENTRY} is not valid JSON: {exc}")
        return EXIT_MALFORMED

    print(f"manifest.json sealed : {manifest.get('sealed')!r}")
    print()
    print("-- link 1/2: certificate signature and checkpoint linkage " + "-" * 12)
    print()

    cert_ok = verify_certificate_dict(cert, pubkey_path, keyring_path,
                                       witness_keyring_path, witness_pubkey_path,
                                       independent_witnesses)
    if not cert_ok:
        print()
        print("=" * 60)
        print("RESULT: SEALED DELIVERABLE VERIFICATION FAILED ✗")
        print()
        print("  The certificate's own signature or checkpoint linkage did not verify")
        print("  (see the checks above). This is a problem with the certificate itself —")
        print(f"  it was never checked whether it actually binds this {MANIFEST_ENTRY},")
        print("  because a certificate that fails on its own terms cannot vouch for")
        print("  anything sealed under it.")
        print("=" * 60)
        return EXIT_TAMPER

    print()
    print("-- link 2/2: manifest bound to the signed certificate " + "-" * 12)
    print()

    results = _check_manifest_binding(cert, manifest_bytes)
    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    binding_ok = all(r[1] for r in results)

    print("  [INFO] deck_content")
    print(f"         manifest.json records a sha256 for deck_content (the page's rendered")
    print("         figures), but this container attaches no separate deck_content object")
    print("         to check it against — only manifest.json and certificate.json are")
    print("         attached. This check proves manifest.json (and therefore its copy of")
    print("         deck_content's hash) is genuinely what the certificate sealed. It does")
    print("         NOT independently re-derive the figures from source and compare — that")
    print("         would require trusting a live call back to Coriqo, which this offline")
    print("         tool deliberately does not do.")
    print()

    print("=" * 60)
    if binding_ok:
        print("RESULT: SEALED DELIVERABLE VERIFIED ✓")
        print()
        print("  The certificate's signature covers statement.bundle_binding, which")
        print(f"  matches sha256({MANIFEST_ENTRY}) for the {MANIFEST_ENTRY} actually")
        print("  attached to this PDF. Signature -> manifest, unbroken.")
    else:
        print("RESULT: SEALED DELIVERABLE VERIFICATION FAILED ✗")
        print()
        print("  Do not rely on this document. The manifest binding failed — see the")
        print("  checks above for which field broke it.")
    print("=" * 60)

    return EXIT_OK if binding_ok else EXIT_TAMPER


def _load_from_pdf(pdf_path: str) -> tuple[dict, str]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ImportError(
            "Reading a certificate/proof out of a PDF requires the 'pypdf' "
            "package (pip install pypdf). Plain --proof/--certificate/--bundle "
            "JSON verification does not need it."
        ) from exc

    reader = PdfReader(pdf_path)
    pairs = []
    for name in reader.attachments:
        blobs = list(reader.attachments[name])
        if blobs:
            pairs.append((name, (lambda b=blobs[-1]: b)))
    return _extract_bundle_member(pairs, pdf_path)


def _run_extracted(data: dict, kind: str, source: str,
                    pubkey_path: str | None, keyring_path: str | None,
                    witness_keyring_path: str | None, witness_pubkey_path: str | None,
                    independent_witnesses: list[str] | None,
                    *, container: bool) -> int:
    """
    Run the weaker "one attestation object was found, verify only it" path
    shared by (zip without manifest.json), PDF, and bare-JSON input.

    When `container` is true, prints an explicit scope disclaimer first —
    what was checked (the extracted certificate/proof) and what was NOT
    (anything else the container held) — so this is never mistaken for a
    whole-bundle verification.
    """
    if container:
        print("=" * 60)
        print(f"NOTE: {source} is a container. A {kind} was extracted from it and")
        print(f"is verified BELOW on its own — nothing else {source} may contain was")
        print("checked: no manifest, no other bundled files, nothing beyond this")
        print(f"{kind} object. A Coriqo deliverables bundle (a zip carrying")
        print("manifest.json) gets the full signature -> manifest -> file check")
        print("automatically; this is not one of those.")
        print("=" * 60)
        print()

    if kind == "certificate":
        ok = verify_certificate_dict(data, pubkey_path, keyring_path,
                                      witness_keyring_path, witness_pubkey_path,
                                      independent_witnesses)
    else:
        ok = run(None, pubkey_path, keyring_path,
                 witness_keyring_path, witness_pubkey_path,
                 independent_witnesses, proof_data=data)
    return EXIT_OK if ok else EXIT_TAMPER


def run_auto_input(path: str, pubkey_path: str | None = None,
                    keyring_path: str | None = None,
                    witness_keyring_path: str | None = None,
                    witness_pubkey_path: str | None = None,
                    independent_witnesses: list[str] | None = None) -> int:
    """
    Auto-detect a positional INPUT's kind and verify it. Returns an exit code
    from the module's "Exit codes" table (the wide table also used by
    --bundle, since a positional zip can be routed there).

    Routing:
      *.zip WITH a manifest.json entry — a Coriqo deliverables bundle.
        Routed to run_bundle() for the full signature -> manifest -> file
        check, identical to --bundle. Not optional: a zip's certificate.json
        can verify perfectly while its payload files (and the manifest
        describing them) were tampered with, and only run_bundle's
        manifest/file linkage catches that.
      *.pdf WITH a manifest.json attachment — a Coriqo sealed deliverable.
        Routed to run_pdf_bundle() for the two checks this container
        structurally supports: certificate signature/linkage, then manifest
        binding. (Not three: unlike a zip, a PDF attaches no separate
        deck_content object for a manifest row to be checked against — see
        run_pdf_bundle's own docstring for why.)
      *.zip WITHOUT manifest.json, or *.pdf without one — a container that
        is not a Coriqo bundle at all. certificate.json or proof.json is
        pulled out and checked on its own; the report says explicitly that
        only the extracted object was checked.
      anything else (bare JSON) — read directly; certificate vs. proof is
        told apart by shape (a certificate has a top-level "statement").
    """
    suffix = Path(path).suffix.lower()

    if suffix == ".zip":
        try:
            is_bundle = _zip_has_manifest(path)
        except (FileNotFoundError, zipfile.BadZipFile, OSError, PermissionError) as exc:
            print(f"FAIL: Cannot open {path}: {exc}")
            return EXIT_MALFORMED
        if is_bundle:
            print(f"[INFO] {path} carries {MANIFEST_ENTRY} — this is a Coriqo")
            print("       deliverables bundle. Verifying it in full (same checks as")
            print("       --bundle): certificate signature/linkage, then manifest")
            print("       binding, then every file's hash.")
            print()
            return run_bundle(path, pubkey_path, keyring_path,
                               witness_keyring_path, witness_pubkey_path,
                               independent_witnesses)
        try:
            data, kind = _load_from_zip(path)
        except (zipfile.BadZipFile, ValueError, json.JSONDecodeError, OSError) as exc:
            print(f"FAIL: Cannot read a certificate/proof out of {path}: {exc}")
            return EXIT_MALFORMED
        return _run_extracted(data, kind, path, pubkey_path, keyring_path,
                               witness_keyring_path, witness_pubkey_path,
                               independent_witnesses, container=True)

    if suffix == ".pdf":
        try:
            is_sealed_deliverable = MANIFEST_ENTRY in _pdf_attachments(path)
        except ImportError as exc:
            print(f"FAIL: {exc}")
            return EXIT_MALFORMED
        except Exception as exc:
            print(f"FAIL: Cannot open {path}: {exc}")
            return EXIT_MALFORMED
        if is_sealed_deliverable:
            print(f"[INFO] {path} carries {MANIFEST_ENTRY} — this is a Coriqo sealed")
            print("       deliverable PDF. Verifying it in full: certificate")
            print("       signature/linkage, then manifest binding.")
            print()
            return run_pdf_bundle(path, pubkey_path, keyring_path,
                                   witness_keyring_path, witness_pubkey_path,
                                   independent_witnesses)
        try:
            data, kind = _load_from_pdf(path)
        except ImportError as exc:
            print(f"FAIL: {exc}")
            return EXIT_MALFORMED
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            print(f"FAIL: Cannot read a certificate/proof out of {path}: {exc}")
            return EXIT_MALFORMED
        return _run_extracted(data, kind, path, pubkey_path, keyring_path,
                               witness_keyring_path, witness_pubkey_path,
                               independent_witnesses, container=True)

    # Bare JSON — not a container, so no scope disclaimer is needed: there is
    # nothing else in the file that this tool declined to check.
    try:
        data = json.loads(Path(path).read_text())
    except Exception as exc:
        print(f"FAIL: Cannot load {path}: {exc}")
        return EXIT_MALFORMED
    if not isinstance(data, dict):
        print(f"FAIL: {path} does not decode to a JSON object.")
        return EXIT_MALFORMED
    kind = _classify_bundle_json(data)
    return _run_extracted(data, kind, path, pubkey_path, keyring_path,
                           witness_keyring_path, witness_pubkey_path,
                           independent_witnesses, container=False)


def main():
    parser = argparse.ArgumentParser(
        description="Verify a Coriqo attestation offline (inclusion proof or continuity certificate).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "input", nargs="?", default=None, metavar="INPUT",
        help=("A single file to auto-detect and verify, in place of "
              "--proof/--certificate/--bundle: a .zip (routed to the full "
              "--bundle check when it carries manifest.json, otherwise a "
              "certificate/proof is extracted and verified on its own), a "
              ".pdf (certificate/proof read out of a PDF attachment; "
              "requires the 'pypdf' package), or a bare certificate.json / "
              "proof.json (told apart by shape). Mutually exclusive with "
              "--proof/--certificate/--bundle."),
    )
    mode.add_argument(
        "--proof", required=False, default=None,
        help="Path to the proof bundle JSON file from GET /api/v1/checkpoints/{id}/proof/{event_id}",
    )
    mode.add_argument(
        "--certificate", required=False, default=None,
        help="Path to a Governance Continuity Certificate from GET /api/v1/checkpoints/certificate",
    )
    mode.add_argument(
        "--bundle", required=False, default=None,
        help=("Path to a deliverables.zip from GET /api/v1/engagements/{id}/"
              "deliverables.zip. Checks, in order: the certificate.json entry's "
              "own signature and checkpoint linkage (same checks as --certificate); "
              "that sha256(manifest.json) matches the certificate's signed "
              "statement.bundle_binding.manifest_sha256; and that every file "
              "manifest.json marks present matches the sha256 of that zip entry's "
              "actual bytes. Exit code distinguishes tamper (1) from an unsealed "
              "bundle (2) from a malformed one (3) — see 'Exit codes' above."),
    )
    parser.add_argument(
        "--pubkey", required=False, default=None,
        help=("Path to the Coriqo Ed25519 public key PEM. Optional but recommended: "
              "without it, keys are read from the bundle, which proves the bundle is "
              "internally consistent but not who issued it. With it, signatures are "
              "pinned to the key you supply."),
    )
    parser.add_argument(
        "--keyring", required=False, default=None,
        help=("Pin MULTIPLE keys at once, one per key_id: a directory of "
              "'<key_id>.pem' files, or a single JSON file mapping key_id -> "
              "PEM text. Ahead of per-tenant signing keys / key rotation, "
              "where a certificate can span more than one key_id and a bare "
              "--pubkey has nothing to disambiguate against. Merges with "
              "--pubkey, which covers any key_id --keyring does not name."),
    )
    parser.add_argument(
        "--witness-keyring", required=False, default=None,
        help=("Pin WITNESS public keys — same two forms as --keyring, a "
              "directory of '<witness_key_id>.pem' files or a JSON file "
              "mapping witness_key_id -> PEM text. A cosignature is checked "
              "ONLY against a key pinned here; there is no fallback to the "
              "bundle and no key is ever fetched from Coriqo. Get these keys "
              "from the witnesses themselves."),
    )
    parser.add_argument(
        "--witness-pubkey", required=False, default=None,
        help=("A single witness public key PEM, covering any witness_key_id "
              "--witness-keyring does not name. The common case: your own "
              "organisation is the only witness on its own chain. It asserts "
              "that EVERY otherwise-unnamed cosignature verifies under this "
              "key, so a bundle carrying a second witness fails — use "
              "--witness-keyring when more than one witness is in play."),
    )
    parser.add_argument(
        "--independent-witness", action="append", default=None,
        metavar="WITNESS_KEY_ID",
        help=("Repeatable. Assert that this witness key belongs to a third "
              "party independent of the organisation whose chain this is. "
              "Without it, a verified cosignature reports as SELF-WITNESSED: "
              "the bundle's own label is unsigned and can only downgrade."),
    )
    args = parser.parse_args()

    modes = (bool(args.input), bool(args.proof), bool(args.certificate), bool(args.bundle))
    if sum(modes) != 1:
        parser.error("Pass exactly one of INPUT, --proof, --certificate, or --bundle.")

    if args.input:
        sys.exit(run_auto_input(args.input, args.pubkey, args.keyring,
                                 args.witness_keyring, args.witness_pubkey,
                                 args.independent_witness))

    if args.bundle:
        sys.exit(run_bundle(args.bundle, args.pubkey, args.keyring,
                             args.witness_keyring, args.witness_pubkey,
                             args.independent_witness))

    ok = (run_certificate(args.certificate, args.pubkey, args.keyring,
                          args.witness_keyring, args.witness_pubkey,
                          args.independent_witness) if args.certificate
          else run(args.proof, args.pubkey, args.keyring,
                   args.witness_keyring, args.witness_pubkey,
                   args.independent_witness))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
