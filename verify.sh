#!/usr/bin/env bash
# Coriqo .coriqo container — offline verifier wrapper.
#
# Copied verbatim into every .coriqo container as ./verify.sh by
# api/domains/reports/coriqo_container.py. Edit it here, not inside a built
# container: a container's copy is a build artifact and regenerating the
# container overwrites it.
#
# Verifies every evidence file's Merkle inclusion proof and Ed25519
# checkpoint signature via the vendored seal-verifier/verify_proof.py.
# Zero flags, zero network, no Coriqo account or software required beyond
# python3 and the `cryptography` package (pip install cryptography).
#
# Sealed and unsealed-draft containers are handled by this one script, which
# reads manifest.json's "sealed" flag at run time. That matters because a
# script copied out of a container has to keep telling the truth about
# whatever bundle it is pointed at — a build-time-selected variant would
# claim whatever was true of the container it happened to be generated for.
#
# Before shelling out, each evidence file's sha256 is recomputed and compared
# against the leaf_input its own proof file recorded. This is redundant with
# what the Merkle check would catch anyway (a modified evidence file no
# longer hashes to the leaf that was sealed, so the inclusion proof fails to
# reproduce merkle_root either way) but gives a much clearer message than a
# generic "PROOF INVALID" when the simple case — one byte changed in one
# file — is what actually happened.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$DIR/manifest.json"
PUBKEY="$DIR/proofs/pubkey.pem"
# Inside a container the verifier is vendored under seal-verifier/. A bundle
# that instead carries verify_proof.py beside this script (the layout of the
# standalone github.com/ravikings/coriqo-seal-verifier checkout) also works.
VERIFIER="$DIR/seal-verifier/verify_proof.py"
if [ ! -f "$VERIFIER" ]; then
  VERIFIER="$DIR/verify_proof.py"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to run the verifier and was not found on PATH." >&2
  exit 2
fi

if [ ! -f "$MANIFEST" ]; then
  echo "manifest.json is missing from this bundle, so there is no way to tell" >&2
  echo "what it claims to be. Run this script from inside an unpacked .coriqo" >&2
  echo "container." >&2
  exit 2
fi

# "sealed" plus, when it is false, the reason recorded alongside it. Tab
# separated so a reason containing spaces survives intact.
manifest_line="$(python3 - "$MANIFEST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
reason = d.get("unavailable_reason") or "No reason was recorded in manifest.json."
print("%s\t%s" % ("true" if d.get("sealed") else "false", reason.replace("\t", " ")))
PY
)"
sealed="${manifest_line%%$'\t'*}"
reason="${manifest_line#*$'\t'}"

if [ "$sealed" != "true" ]; then
  echo "This bundle is an unsealed draft. See manifest.json for the reason." >&2
  echo "  Reason: $reason" >&2
  echo "There is nothing under proofs/ to verify." >&2
  exit 1
fi

if [ ! -f "$VERIFIER" ]; then
  echo "The vendored verifier seal-verifier/verify_proof.py is missing from this" >&2
  echo "bundle, so the seal cannot be checked here. Get a fresh container, or run" >&2
  echo "verify_proof.py from github.com/ravikings/coriqo-seal-verifier against the" >&2
  echo "files under proofs/evidence/." >&2
  exit 2
fi

if ! python3 -c "import cryptography" >/dev/null 2>&1; then
  echo "The 'cryptography' package is required (pip install cryptography)." >&2
  exit 2
fi

shopt -s nullglob
proofs=("$DIR"/proofs/evidence/*.proof.json)
if [ ${#proofs[@]} -eq 0 ]; then
  echo "No proof files found under proofs/evidence/ — nothing to verify." >&2
  exit 2
fi

fail=0
for proof in "${proofs[@]}"; do
  name="$(basename "$proof")"
  echo "== $name =============================================="

  read -r evidence_rel leaf_input < <(python3 - "$proof" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d["event_id"], d["leaf_input"])
PY
)
  evidence_path="$DIR/$evidence_rel"
  if [ -f "$evidence_path" ]; then
    actual="$(python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$evidence_path")"
    if [ "$actual" != "$leaf_input" ]; then
      echo "  [FAIL] $evidence_rel has changed since sealing: sha256 does not match the sealed leaf hash" >&2
      fail=1
      echo
      continue
    fi
  else
    echo "  [WARN] $evidence_rel is missing from this bundle" >&2
  fi

  if ! python3 "$VERIFIER" --proof "$proof" --pubkey "$PUBKEY"; then
    fail=1
  fi
  echo
done

if [ "$fail" -ne 0 ]; then
  echo "RESULT: one or more evidence files FAILED verification." >&2
  exit 1
fi
echo "RESULT: every evidence file verified against the sealed Merkle root."
exit 0
