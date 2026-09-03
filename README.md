# Coriqo seal verifier

Check a Coriqo attestation yourself, offline.

Coriqo seals governance records — a model registered, reviewed, approved,
retired — into a hash-linked chain and signs periodic checkpoints over it. This
repository is the verifier for those seals, plus the written format they use.

It runs on your machine. No network, no Coriqo account, no Coriqo software, and
no trust in Coriqo as an institution.

```bash
pip install cryptography

python verify_proof.py --proof proof.json --pubkey pubkey.pem
python verify_proof.py --certificate certificate.json

# Multiple signing keys in one bundle (ahead of per-tenant signing keys —
# every certificate today uses one key_id, so --pubkey alone covers it):
python verify_proof.py --certificate certificate.json --keyring keys/          # dir of <key_id>.pem
python verify_proof.py --certificate certificate.json --keyring keyring.json   # {key_id: pem} manifest

# Witness cosignatures (§9.4). A cosignature is checked only against a key you
# supply — never one from the bundle, and never one fetched from Coriqo:
python verify_proof.py --proof proof.json --pubkey pubkey.pem \
    --witness-keyring witness_keys/

# ...and it reports as SELF-WITNESSED until you say whose key it is:
python verify_proof.py --proof proof.json --pubkey pubkey.pem \
    --witness-keyring witness_keys/ --independent-witness audit-firm-2026

# A deliverables.zip: certificate signature/linkage, then that the manifest's
# own bytes are what the signature commits to, then every file's sha256:
python verify_proof.py --bundle deliverables.zip

# Or skip the flag entirely — point it at one file and let it figure out
# what that file is:
python verify_proof.py deliverables.zip          # a bundle, a bare cert/proof, or a PDF
python verify_proof.py certificate.json
python verify_proof.py "engagement package.pdf"
```

Exit code 0 means every check passed; 1 means at least one failed and the output
says which. `--bundle` (and a positional `.zip` routed there — see below) uses a
wider table that also distinguishes an unsealed bundle (2) from a malformed one
(3); the module docstring in `verify_proof.py` has the full table.

### The positional form

`verify_proof.py FILE` (with no `--proof`/`--certificate`/`--bundle`) auto-detects
what `FILE` is instead of making you choose the flag by hand:

* **a `.zip` carrying `manifest.json`** — a Coriqo deliverables bundle. Routed to
  the exact same check as `--bundle`: certificate signature and linkage, then the
  manifest's bytes against the signed binding, then every file's hash. This is
  not optional — a bundle's `certificate.json` can verify perfectly on its own
  while a payload file was edited and `manifest.json`'s row for it rewritten to
  match, and only the manifest-binding check catches that. A `.zip` with a
  manifest is never handed the weaker check below.
* **a `.pdf` carrying `manifest.json`** — a sealed Coriqo engagement deliverable
  (`engagement_deliverable_sealed.pdf`). Routed to the two checks this container
  structurally supports: certificate signature and linkage, then the manifest's
  bytes against the signed binding. Not three links like a zip — a sealed PDF
  attaches only `manifest.json` and `certificate.json`, never a separate
  `deck_content` object for a manifest row to be checked against — the report
  says so plainly rather than padding in a fabricated third link. A PDF with a
  manifest is never handed the weaker check below. Needs `pip install pypdf`.
* **a `.zip` without `manifest.json`, or a `.pdf` without one** — not a Coriqo
  bundle at all, just a container carrying a `certificate.json` or `proof.json`
  (the PDF case reads it out of an attachment, and needs `pip install pypdf`).
  That single object is extracted and checked on its own, and the report says
  so in as many words: what was checked (the extracted certificate/proof) and
  what was not (anything else the file holds).
* **anything else** — read as bare JSON; a certificate is told apart from a
  proof by shape (a certificate has a top-level `"statement"` object).

`FILE` and `--proof`/`--certificate`/`--bundle` are mutually exclusive —
combining them is an argparse error, not undefined behaviour.

## What's here

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The format. Byte layouts, hashing, canonicalisation, and every rule a verifier has to enforce. |
| `verify_proof.py` | Reference implementation. Standard library plus `cryptography`. |
| `verify.sh` | The zero-flag wrapper shipped inside every `.coriqo` container: it walks `proofs/evidence/*.proof.json`, re-hashes each evidence file, and runs `verify_proof.py` over each proof. It reads `manifest.json`'s `sealed` flag itself, so it refuses to claim success on an unsealed draft. Run it from an unpacked container, not from this checkout. |
| `testdata/` | Conformance corpus: bundles that must verify, one per tree construction, plus a `--keyring` directory/JSON manifest, three key-rotation bundles (§9.3): one carrying a valid succession record, one carrying none, and one whose record was signed by the incoming key instead of the outgoing one, and a cosigned pair (§9.4, provisional): one with two genuine witness cosignatures, one with a byte flipped in a signature. Entirely synthetic — invented bank, invented people, signing keys generated from published seeds. No real governance record, and no key of ours, is in here. |
| `tests/` | The corpus generator, and the cases that must fail. |

`SPEC.md` is the deliverable that matters. A verifier published without its
format is a second copy of the original's bugs — only an implementation built
from a written specification can disagree with the original, and disagreement is
what makes either one checkable. Write one in Rust or Go and tell us if it
disagrees.

## Two tree constructions

Checkpoints carry a `tree_version` inside the signed body. Version 2 is
RFC 6962's Merkle Tree Hash, so a version-2 proof can be checked with standard
Certificate Transparency tooling and not only with this script. Version 1 is an
earlier construction that duplicated the last node on odd levels; it is not
RFC 6962's tree, and `SPEC.md` §5.3 says exactly what that costs and what
contains it.

Version-1 checkpoints were signed against version-1 trees and stay valid — a
root is a commitment to a tree of a specific shape, so it cannot be recomputed
under a different one. A verifier needs both, and this one implements both.

## What a passing check proves

That the bytes in front of you were covered by a signature when the checkpoint
was signed, and that nothing has changed since. Elapsed time on a hash-linked
chain cannot be faked, so a continuity claim across a range of seals cannot be
issued after the fact.

**It does not prove the record is true.** An organisation that lies to Coriqo
gets a tamper-evident record of a lie. The seal proves the record has not
changed since it was made, not that it was accurate when made.

**Pin the key.** A bundle carries its own public key, which is what lets it
verify with no network — and it means the bundle alone proves internal
consistency, not authorship. Anyone can sign a fabrication with a key they
generated and ship the matching PEM. Pass `--pubkey` with the key from
`GET /api/v1/checkpoints/public-keys`, or compare the fingerprint the verifier
prints against the published one. Without that step you have checked the bundle
against itself. `SPEC.md` §9 covers this properly.

**Self-witnessing is not third-party audit.** A cosignature by the
organisation itself proves Coriqo cannot author that organisation's history
unnoticed, because Coriqo does not hold the witness key. It says nothing about
whether anyone outside the organisation has looked. This verifier keeps the
two apart and will not call a cosignature independent on the bundle's say-so —
you name the witness with `--independent-witness`, because you are the one who
knows where the key came from. §9.4.

## Running the tests

```bash
pip install cryptography pytest
python -m pytest tests/ -q
python tests/make_corpus.py     # regenerates testdata/ byte-for-byte
```

`make_corpus.py` is written from `SPEC.md` and imports nothing from Coriqo, so
it is a second implementation of the format. If it and `verify_proof.py`
disagree, the specification is wrong.

## Found something

`bounty@coriqo.io`.

Worth reporting: a verifier that passes input it should reject, a rule in
`SPEC.md` that does not match what the code does, and any ambiguity that led you
to build something incompatible. Writing this specification turned up two real
problems in the verifier, both now fixed and both recorded in `SPEC.md` (§5.3,
§7.3) rather than quietly patched.

## Licence

Apache-2.0. The verifier is deliberately more permissively licensed than Coriqo
itself, because a verifier you cannot embed is a verifier you cannot use.
