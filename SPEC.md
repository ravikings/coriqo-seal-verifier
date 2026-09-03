# Coriqo Attestation Format — specification v1.0

This document defines the byte formats and verification rules for Coriqo
attestations, so that a verifier can be written from this text alone, in any
language, with no reference to Coriqo's source.

That is the point of publishing it. A verifier without a written format is a
second copy of the original's bugs; only an independent implementation built
from a specification can disagree with the original, and disagreement is the
only thing that makes either one checkable.

`verify_proof.py` in this repository is the reference implementation. Where
this document and that script disagree, **this document is wrong** and should
be corrected — the script is what customers and examiners already run against
sealed records, and its behaviour is fixed by artifacts already issued.

Conformance corpus: `testdata/`. See §11.

---

## 1. What an attestation proves, and what it does not

Coriqo records governance actions — a model registered, submitted, reviewed,
approved, retired — as events in a hash-linked chain, and periodically seals
the chain by signing a **checkpoint** over a Merkle tree of the event hashes.

Two artifacts are derived from those seals:

| Artifact | Question it answers |
|---|---|
| **Inclusion proof** | Was this specific event sealed into this checkpoint? |
| **Continuity certificate** | Did governance run without interruption across a range of checkpoints? |

**What verification proves.** That the bytes in front of you were covered by an
Ed25519 signature at the time the checkpoint was signed, and that nothing has
been altered since. Elapsed time on a hash-linked chain cannot be faked, so a
continuity claim over a range of seals cannot be issued retroactively.

**What verification does not prove.** That the sealed events describe reality.
An organisation that lies to Coriqo gets a tamper-evident record of a lie. The
seal proves the record has not changed since it was made; it says nothing about
whether the record was true when made. Any material that claims otherwise is
overclaiming.

**The trust boundary is §9.** Read it before relying on a verdict. A bundle
carrying its own public key proves internal consistency and nothing about
authorship.

---

## 2. Notation

- `SHA256(x)` — SHA-256 over the byte string `x`, 32 bytes.
- `hex(x)` — lowercase hexadecimal, no prefix, no separators.
- `||` — byte concatenation.
- All hash values in JSON are `hex()` of the raw digest: 64 lowercase hex
  characters, matching `^[0-9a-f]{64}$`.
- All timestamps are ISO 8601 in UTC with a `Z` suffix, e.g.
  `2026-06-30T00:00:00Z`. Timestamps inside signed bodies are compared as
  opaque strings, never parsed, so a verifier must not normalise them.
- "MUST" and "MUST NOT" mark rules a conforming verifier is required to
  enforce. A verifier that skips a MUST will accept forgeries.

---

## 3. Canonicalisation

Every signature and every hash in this format is computed over the canonical
serialisation of a JSON object:

```
canonical_bytes(obj) = UTF-8 encoding of
    JSON.stringify(obj) with:
      - object keys sorted lexicographically by code point, at every depth
      - no whitespace between tokens (separators are "," and ":")
      - non-ASCII characters emitted literally, not \u-escaped
```

The Python reference is:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

**This definition is frozen.** Once a record is sealed, changing how these
bytes are produced invalidates every historical hash and signature. Treat any
change as a format-breaking version bump.

Two consequences that trip up reimplementations:

1. **`ensure_ascii=False` matters.** A non-ASCII character in an actor name or
   a note is serialised as its literal UTF-8 bytes, not as `\uXXXX`. A verifier
   that escapes will compute different bytes and report a false FAIL. Most
   languages' default JSON encoders do not escape; Python's does.
2. **Number formatting must round-trip.** All numeric fields in this format are
   integers. A verifier that reserialises them as floats (`5` → `5.0`) will
   compute different bytes. Parse into a representation that preserves integer
   form.

A verifier that recomputes a signature over a re-serialised object MUST
reproduce these bytes exactly. The safest implementation strategy is to
canonicalise from the parsed object, not to reuse the original file's bytes —
whitespace in the transmitted file is not significant and must not be relied on.

---

## 4. The event chain

### 4.1 Event fields

Each governance event commits to these fields, and only these:

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | Position in the chain, 0-based, contiguous |
| `timestamp` | string | ISO 8601 UTC |
| `actor` | string | User or service account identifier |
| `action` | string | `register`, `submit`, `review`, `approve`, `retire`, … |
| `model_name` | string | Subject model |
| `model_version` | string | Subject model version |
| `payload` | object | Action-specific detail |
| `prev_hash` | string | `event_hash` of event `seq - 1` |

### 4.2 Event hash

```
event_hash = hex(SHA256(canonical_bytes({
    seq, timestamp, actor, action, model_name, model_version, payload, prev_hash
})))
```

`event_hash` is **not** part of the hashed object — a field cannot commit to its
own value. A verifier recomputing an event hash MUST remove `event_hash` from
the object before canonicalising, and MUST NOT add or remove any other field.

### 4.3 Chain linkage

`prev_hash` of event 0 is the genesis value, 64 zero characters:

```
0000000000000000000000000000000000000000000000000000000000000000
```

For every subsequent event, `prev_hash` equals the previous event's
`event_hash`. Altering any event changes its hash and breaks every link after
it, which is what makes the chain tamper-evident without any key at all.

### 4.4 Chain head

The **head hash** is the `event_hash` of the highest-`seq` event, or the genesis
value for an empty chain. This is the single value a checkpoint seals.

---

## 5. The Merkle tree

### 5.1 Leaf and node hashing

```
leaf_hash(data) = SHA256(0x00 || data)
node_hash(l, r) = SHA256(0x01 || l || r)
```

The leaf input `data` is the **raw 32 bytes** of an event's `event_hash` —
`bytes.fromhex(event_hash)`, not its 64-character hex text. Hashing the hex
string instead is the single most common reimplementation error.

The `0x00` / `0x01` domain-separation prefixes are taken from RFC 6962 §2.1.
They ensure a leaf hash can never equal an internal node hash, which closes the
second-preimage attack on naive Merkle trees.

### 5.2 Tree construction

Leaves are the event hashes in the order defined by §5.5. **Two constructions
exist**, selected by `sth_body.tree_version`. The field is absent on every
checkpoint sealed before the second construction was introduced, and **absent
means 1**. Both use the leaf/node hashing of §5.1 unchanged; only the shape
differs. An empty tree has the root `SHA256("")` in both.

A verifier MUST implement both. Version-1 checkpoints were signed against the
version-1 shape and do not stop being valid because a newer one exists.

#### 5.2.1 `tree_version` 1 — duplicate the last node

Each level is formed by pairing adjacent nodes left to right. **When a level
has an odd number of nodes, the last node is paired with itself.** Repeat until
one node remains: that is the Merkle root.

```
level[0]   = [leaf_hash(e) for e in event_hashes]
level[k+1] = [node_hash(level[k][2i], level[k][2i+1 if it exists else 2i])
              for i in 0 .. ceil(len(level[k])/2) - 1]
root       = the single node in the final level
```

This shape has a known ambiguity — see §5.3.

#### 5.2.2 `tree_version` 2 — RFC 6962 Merkle Tree Hash

RFC 6962 §2.1's MTH, which splits at the largest power of two below `n` rather
than duplicating:

```
MTH({})   = SHA256("")
MTH({d0}) = leaf_hash(d0)
MTH(D[n]) = node_hash(MTH(D[0:k]), MTH(D[k:n]))    for n > 1
            where k is the largest power of two strictly less than n
```

Equivalently, and more convenient to implement without recursion: build level
by level as in 5.2.1, but when a level has an odd number of nodes, **promote
the last node unchanged** to the next level instead of pairing it with itself.
The two formulations produce identical trees for every `n`.

This construction is injective over leaf lists: distinct leaf lists give
distinct roots. That is the property §5.3 says version 1 lacks.

**The two shapes agree exactly when `n` is a power of two** (and for `n` of 0
or 1). Test vectors built at 2, 4, or 8 leaves therefore pass under both and
distinguish nothing. Use a leaf count that is not a power of two.

### 5.3 Why `tree_version` 1 is ambiguous, and what a verifier owes it

Version 1 uses RFC 6962's leaf and node hashing with a **different tree shape**
(§5.2.1). That shape has a known ambiguity — the same one behind Bitcoin's
CVE-2012-2459. Distinct leaf lists can produce an identical root:

```
leaves [a, b, c]     root e9636069c740c9ff51625b01a0b040396d265a9b920cc6febdfa5ecc9f58ecce
leaves [a, b, c, c]  root e9636069c740c9ff51625b01a0b040396d265a9b920cc6febdfa5ecc9f58ecce
```

A version-1 root is therefore **not** a unique commitment to its leaf set. Any
consumer that treats such a root alone as the identity of an event set —
comparing roots across systems, deduplicating by root, or co-signing a bare
root — loses that guarantee.

What contains it: `tree_size` and `length` are inside the **signed** checkpoint
body (§6), so an issuer cannot present an n-leaf tree as an (n+1)-leaf tree
without breaking the signature. The collisions only occur across different
sizes, so exploiting the ambiguity requires the signing key, at which point it
is not the weakest available attack.

Version 2 (§5.2.2) removes the ambiguity rather than containing it. Version-1
checkpoints cannot be migrated: a root is a signed commitment to a tree of a
specific shape, and recomputing it under version 2 gives a different root. They
remain valid, and remain fully reproducible under version 1.

**Rule 5.3.1 (MUST, `tree_version` 1 only).** Because a version-1 root does not
pin the leaf count, a verifier MUST check the declared size against the proof
depth:

```
expected_depth = 0 if tree_size == 1 else bit_length(tree_size - 1)
len(proof_path) MUST equal expected_depth
```

Without this check `tree_size` is decorative for version 1: the walk only
compares a computed root, so a path of any length reproducing that root would
pass while declaring a tree of a different size.

**Rule 5.3.2 (MUST NOT).** Do **not** apply Rule 5.3.1 to `tree_version` 2.
Under RFC 6962 the audit-path length depends on the leaf's index as well as the
tree size — a 5,161-leaf tree has valid path lengths of 4, 7, 8, 12 and 13 — so
a fixed-depth check rejects honest proofs. Version 2 needs no such rule: the
verification walk of §7.2.2 pins `tree_size` itself.

**Rule 5.3.3 (MUST).** Take `tree_version` from `sth_body` and nowhere else. A
`tree_version` read from an unsigned part of a bundle would let a forger select
whichever construction their hand-built path satisfies — the same class of
defect as an unsigned `merkle_root` (§7.3).

### 5.5 Leaf ordering

A checkpoint's scope is either an entire chain or a single model version, named
by `sth_body.subject` (`version:<id>` scopes to one version). Within that scope,
from `ordering_version` 2, leaves are the `event_hash` values of the scoped
events with `ordinal <= ordinal_watermark`, ordered by `ordinal`.

`ordinal` is assigned when an event is appended and never changes. That makes
the order **total** (it is unique) and **append-only** (a new event always sorts
after every event already sealed), which are the two properties the tree
depends on. `ordinal_watermark` is inside the signed body, so a checkpoint pins
its own leaf set: "every event with ordinal ≤ W" is exact and reproducible
forever.

`ordinal` is deliberately **not** part of `event_hash` (§4.2). It describes
where an event sits, not what it says.

#### The v1 ordering, and why it was replaced

Checkpoints with `ordering_version` 1 — or with neither field, which means the
same thing — were ordered by `(created_at, seq)`. That key failed both
properties:

- **Not total.** `created_at` is transaction time, so events written together
  share it, and `seq` is per-version rather than global. Events from different
  versions in one transaction tied on both columns, and ties have no defined
  order. On a live tenant: 5,161 events, 4,825 distinct order keys, 279 tied
  groups. Two equally legal orderings of the same unmodified events gave
  different roots.
- **Not append-only.** `created_at` is a business timestamp that can precede
  insertion, so a backdated write landed *mid-stream*. On the same tenant, two
  checkpoints' sealed heads had drifted 759 and 359 positions after later
  writes were dated before them.

The consequence ran in the dangerous direction. This never let anyone forge a
seal; it let an **honest** record fail verification — a recomputed root that
disagrees, inclusion proofs pointing at shifted leaves, continuity linkage that
cannot be proven. A verifier reporting FAIL on an unaltered record is the worst
output this format can produce, because FAIL is supposed to mean something.

For a `ordering_version` 1 checkpoint the sealed permutation was never recorded
and cannot be recovered. Such checkpoints keep a valid signature — what is gone
is the ability to rebuild the tree it covers. Coriqo marks them
`reproducible: false` and excludes them from continuity linkage with a stated
reason, rather than reporting them as breaks. A verifier reading one should say
the same: the signature is sound, the tree is not rebuildable.

### 5.4 Inclusion proof path

For the leaf at `leaf_index`, the proof path is the sequence of sibling hashes
from the leaf level upward, excluding the root. Walk up the levels of the tree
built per §5.2, halving the index at each step.

**`tree_version` 1.** At each level the sibling of an even index `i` is `i + 1`
(or `i` itself if `i + 1` is past the end — the duplicated case); the sibling of
an odd index is `i - 1`. Every leaf's path is the same length.

**`tree_version` 2.** At each level, a node that is the last of an odd-length
level was promoted and has **no sibling** there, so it contributes nothing to
the path; otherwise the sibling is `i XOR 1`. Path length therefore depends on
the leaf index as well as the tree size. Equivalently, RFC 6962 §2.1.1:

```
PATH(0, {d0}) = {}
PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])        if m < k
              = PATH(m - k, D[k:n]) : MTH(D[0:k])     if m >= k
```

A single-leaf tree has an empty proof path in both: the leaf is the root.

---

## 6. Checkpoints

A checkpoint is an Ed25519 signature over a **signed tree head** (`sth_body`).

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `subject` | string | always | What the chain covers |
| `issued_at` | string | always | ISO 8601 UTC, when the seal was made |
| `length` | integer | always | Number of events in the chain at seal time |
| `head_hash` | string | always | Chain head hash (§4.4) at seal time |
| `merkle_root` | string | always (v1.5) | Root of the tree over those events |
| `tree_size` | integer | always (v1.5) | Number of leaves; equals `length` |
| `key_id` | string | always | Which signing key was used |
| `ordering_version` | integer | from v2 | Leaf-ordering rule; absent means 1 (§5.5) |
| `ordinal_watermark` | integer | from v2 | Highest `ordinal` this seal covers |
| `tree_version` | integer | from v2 | Tree construction; absent means 1 (§5.2) |
| `continuity` | object | when present | Attested obligation counts and coverage gaps (§8.3) |
| `cohort_rollup` | object | when present | Attested cohort oversight rollup |

`continuity` and `cohort_rollup` are included **only when non-null**, so
checkpoints sealed before those fields existed keep verifying against the exact
bytes they were signed over. A verifier MUST NOT insert them as empty defaults.

**There is no `checkpoint_id` in the signed body.** A seal is identified within
its signature by `subject` and `issued_at`. See §7.3.

```
signature = Ed25519_sign(signing_key, canonical_bytes(sth_body))
```

Every field a certificate later relies on lives **inside** `sth_body`. This is
deliberate: unsigned restatements elsewhere in a bundle are convenience data and
MUST NOT be trusted (§8.2).

---

## 7. Inclusion proof bundle

### 7.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `checkpoint_id` | string | Which seal this proves membership in |
| `event_id` | string | Identifier of the event being proven |
| `issued_at` | string | Echo of the checkpoint's issue time (display only) |
| `subject` | string | Echo of the checkpoint's subject (display only) |
| `leaf_index` | integer | Position of the event's leaf, 0-based |
| `tree_size` | integer | Number of leaves in the tree |
| `leaf_input` | string | The event's `event_hash`, hex |
| `proof_path` | array of string | Sibling hashes, hex, leaf → root |
| `merkle_root` | string | Root the path must reproduce |
| `sth_body` | object | The signed checkpoint body (§6) |
| `checkpoint_signature` | string | Ed25519 signature over `canonical_bytes(sth_body)`, hex |
| `key_id` | string | Which signing key was used |
| `public_key_pem` | string | PEM public key (see §9 before trusting it) |
| `anchor` | object | Optional Rekor anchor (§10), informational only |
| `cosignatures` | array of object | Witness cosignatures over this checkpoint (§9.4). Unsigned; may be empty |
| `_verify_with`, `_how_it_works` | string | Human instructions. Display only; a verifier MUST ignore them. |

### 7.2 Verification

A conforming verifier MUST perform both checks and MUST fail if either fails.

**Check 1 — Merkle inclusion.** Common preconditions, then one of two walks
selected by `sth_body.tree_version` (absent means 1; rule 5.3.3):

```
if tree_size == 0                      -> FAIL
if leaf_index < 0 or >= tree_size      -> FAIL
if tree_version not in {1, 2}          -> FAIL          (do not guess)
```

#### 7.2.1 `tree_version` 1

```
if len(proof_path) != expected_depth   -> FAIL          (rule 5.3.1)

computed = leaf_hash(bytes.fromhex(leaf_input))
idx = leaf_index
for sibling in proof_path:
    computed = node_hash(computed, sibling) if idx is even
               else node_hash(sibling, computed)
    idx = idx // 2

computed MUST equal bytes.fromhex(merkle_root)
```

#### 7.2.2 `tree_version` 2 — RFC 6962 §2.1.1

No proof-depth precondition (rule 5.3.2). `tree_size` is threaded through the
walk instead: `sn` must reach exactly 0 as the path is consumed, so a path that
is too short leaves `sn != 0` and one that is too long trips `sn == 0` mid-walk.

```
fn = leaf_index
sn = tree_size - 1
r  = leaf_hash(bytes.fromhex(leaf_input))

for sibling in proof_path:
    if sn == 0                        -> FAIL     (path longer than the tree)
    if (fn is odd) or (fn == sn):
        r = node_hash(sibling, r)
        if fn is even:
            while fn != 0 and fn is even:
                fn = fn >> 1
                sn = sn >> 1
    else:
        r = node_hash(r, sibling)
    fn = fn >> 1
    sn = sn >> 1

sn MUST equal 0, and r MUST equal bytes.fromhex(merkle_root)
```

**Check 2 — Ed25519 checkpoint signature.**

```
Ed25519_verify(public_key, bytes.fromhex(checkpoint_signature),
               canonical_bytes(sth_body))  MUST succeed
```

### 7.3 Binding the bundle to the signature

**Everything above `sth_body` in the bundle is unsigned.** `merkle_root`,
`tree_size`, `leaf_index`, `checkpoint_id`, `issued_at` and `subject` at the top
level are restatements for display; the Ed25519 signature covers `sth_body` and
nothing else.

**Rule 7.3.1 (MUST).** Before the inclusion check, `merkle_root` and `tree_size`
at the top level MUST equal `sth_body.merkle_root` and `sth_body.tree_size`, and
the inclusion check MUST use the values from `sth_body`.

**Rule 7.3.2 (MUST).** `tree_version` is not restated at the top level, and a
verifier MUST ignore it if some producer adds it there. It is read from
`sth_body` alone (rule 5.3.3). A `tree_version` an attacker can set is a
`tree_version` they will set.

Skipping this is a complete break of the proof bundle, not a nicety. A forger
keeps a genuine `sth_body` and its genuine, untouched signature, and supplies the
root, path and leaf of a tree they built themselves. The Merkle walk succeeds
against the attacker's own root; the signature verifies over the real body; the
verifier reports that an event which was never sealed is "cryptographically
proven to be part of" a real checkpoint.

This was found while writing this specification, against the reference
implementation, and fixed. It is recorded here because the class of mistake —
verifying a proof against a value the proof itself supplies — is easy to repeat
in a reimplementation, and because a format specification that hides its own
history is not worth reading. The regression test is
`tests/test_verifier.py::test_substituted_merkle_root_fails`.

**Residual limitation (v1, not fixed).** `checkpoint_id` is absent from
`sth_body`, so the identifier a bundle displays is not covered by any signature:
a genuine proof can be relabelled with a different `checkpoint_id` and still
verify. What is signed is `subject` and `issued_at`, which is what actually
identifies the seal. Fixing this means adding a field to the signed body, which
changes the canonical bytes and so applies only to newly issued checkpoints
(§12). A verifier displaying `checkpoint_id` SHOULD show `sth_body.issued_at`
and `sth_body.subject` alongside it, and treat those as the authoritative
identity.

---

## 8. Continuity certificate

Answers "did governance ever stop?" over a range of checkpoints. Self-contained:
it carries the public key for every `key_id` it references, so it verifies with
no network access.

### 8.1 Structure

```
{
  "statement":  { ... the signed claim ... },
  "signature_hex": "...",          Ed25519 over canonical_bytes(statement)
  "key_id": "...",
  "public_keys": { "<key_id>": { "pem": "...", "revoked": false } },
  "cosignatures": { "<checkpoint_id>": [ ... §9.4 ... ] },   unsigned
  "anchors":      { "<checkpoint_id>": { ... §10 ... } }     unsigned
}
```

Those four are the only top-level keys. Everything else, including
`certificate_version`, sits **inside** `statement` so that the signature
covers it.

`statement` contains:

| Field | Meaning |
|---|---|
| `certificate_version` | Format version, e.g. `"1.0"` |
| `issued_at` | When the certificate was composed, ISO 8601 UTC |
| `subject`, `period`, `claim` | Human-readable scope and claim text |
| `checkpoint_window` | The checkpoint range the statement covers |
| `checkpoint_count` | Number of checkpoints in the range |
| `checkpoints` | Ordered array of `{checkpoint_id, sth_body, signature_hex, key_id}` |
| `linkage` | Array of links joining consecutive checkpoints (§8.2) |
| `linkage_status` | `proven`, `not_applicable`, … |
| `linkage_unbroken` | Boolean claim |
| `links_proven` | Integer claim |
| `coverage` | Obligation and event counts (§8.3) |
| `coverage_gaps` | Quiet periods with recorded reasons |
| `gap_summary` | Counts by classification |
| `linkage_problems` | Why linkage is not established, when it is not |
| `excluded_v1_checkpoints` | Pre-Merkle checkpoints in range, excluded from linkage |
| `excluded_checkpoints` | Reasoned exclusions, including withholdings (§8.4) |

### 8.2 Linkage

For each consecutive pair, the earlier checkpoint's sealed head must be proven
to be a leaf of the later checkpoint's tree. That is what makes "governance
never stopped" a proof: the later seal demonstrably contains the earlier one's
final state, so the chain did not restart, fork, or lose history between seals.

A link carries `from_checkpoint_id`, `to_checkpoint_id`, `sealed_head`,
`merkle_root`, `tree_size`, `leaf_index`, `proof_path`, `provable`.

**Rule 8.2.1 (MUST).** Every value used in the inclusion check MUST be taken
from the checkpoints' `sth_body` — never from the link's own restatement of it.
A link is unsigned convenience data; a proof verified against its own
restatement shows only that the link is self-consistent, which a forger arranges
trivially. The link's copies MUST be compared against the signed bodies and any
disagreement MUST fail.

**Rule 8.2.2 (MUST).** `len(linkage)` MUST equal `len(checkpoints) - 1`.
Otherwise a certificate claiming ten checkpoints can ship an empty linkage array
and pass vacuously. Related: `linkage_status == "proven"` with fewer than two
checkpoints MUST fail, and `links_proven` greater than `len(checkpoints) - 1`
MUST fail.

**Rule 8.2.3 (MUST).** The link's `leaf_index` MUST equal
`earlier.sth_body.length - 1`, and `earlier.length` MUST NOT exceed
`later.tree_size` — a chain that shrank between seals is a broken chain, not a
continuous one.

### 8.3 Coverage

The certificate reports obligation counts and quiet periods. These are claims
made by the issuer, so a verifier MUST re-derive them from the signed bodies
rather than accept them:

- `coverage.sealed_event_count` MUST equal the closing checkpoint's signed `length`.
- `coverage.events_added_in_period` MUST equal closing `length` − opening `length`.
- Each `coverage.obligations_in_period[k]` MUST equal
  `closing.continuity.obligations[k] − opening.continuity.obligations[k]`.
- Each `coverage.obligations_closing[k]` MUST equal `closing.continuity.obligations[k]`.
- Every reported gap MUST appear in the closing checkpoint's signed
  `continuity.coverage_gaps`. A certificate may narrow gaps to its window; it
  MUST NOT invent one, and MUST NOT drop one the seal recorded.

Gaps are a normal feature of a real record. A quiet fortnight on a small model
book is ordinary operation and is classified `normal_cadence`, not a fault. A
verifier MUST display gaps even when every check passes.

### 8.4 Withheld checkpoints

`excluded_checkpoints` lists checkpoints inside the period that the certificate
does not certify, each with a `reason`. Entries look like:

```
{
  "checkpoint_id": "...",
  "issued_at": "...",
  "reason": "v1_no_merkle_root" | "not_reproducible" | "signature_not_verifiable",
  "detail": "one sentence for a human",
  "quarantine": {          only for signature_not_verifiable
    "declared_by": "...", "declared_at": "...",
    "operator_reason": "...", "verification_failure": "..."
  }
}
```

The first two reasons describe a checkpoint that cannot be linked or
re-derived. `signature_not_verifiable` describes one whose signature does not
check out at all: the issuer could not repair it, because checkpoints are
append-only, and removed it from the certified set under an attributable
declaration.

**Rule 8.4.1 (MUST).** A verifier MUST report `signature_not_verifiable`
entries separately from the other reasons, with the full `quarantine` record,
and MUST NOT present any part of that record as something it verified. The
withheld checkpoint is not in the bundle to check.

**Rule 8.4.2 (MUST).** A `signature_not_verifiable` entry MUST NOT name a
`checkpoint_id` that also appears in `statement.checkpoints`, and its
`quarantine` object MUST carry all four fields. A checkpoint withheld on paper
while still counted, or withheld by nobody, MUST fail.

**Rule 8.4.3 (MUST).** The verdict MUST still rest on the checkpoints the
certificate carries — a withholding neither fails the certificate nor is
excused by it — and a passing verdict MUST state that its range was reduced,
with the count. A proof over a narrower set is still a proof, but a reader must
not be able to mistake it for one over the whole period.

---

## 9. Keys, revocation, and the trust boundary

### 9.1 The boundary

A bundle carries its own public keys, which is what makes offline verification
possible. It is also the limit of what the bundle can prove on its own:

> **A self-contained bundle proves internal consistency, not authorship.**
> Anyone can sign a fabricated statement with a key they generated and ship the
> matching PEM. Every cryptographic check will pass.

Two ways to close it, and a verifier MUST make clear which one is in force:

1. **Pin the key.** Supply the public key out of band (`--pubkey`). Signatures
   must then verify under the supplied key, so a self-signed forgery fails.
2. **Compare fingerprints.** Print `hex(SHA256(base64-decoded PEM body))` for
   every key used and compare it against Coriqo's published keyring
   (`GET /api/v1/checkpoints/public-keys`).

A verifier that reports PASS without stating which keys were used, and where
they came from, is giving a misleading verdict. The reference implementation
prints the fingerprints and an explicit note whenever keys came from the bundle.

`testdata/` contains the assertion of this limit as an executable test
(`test_self_signed_forgery_passes_unpinned`) so that it stays a documented
property rather than an assumption.

### 9.2 Revocation

A key entry may carry `"revoked": true`. A signature under a revoked key is
often still mathematically valid — which is exactly why:

**Rule 9.2.1 (MUST).** A signature under a revoked key MUST fail verification,
loudly, even when the signature is valid.

**Rule 9.2.2 (MUST).** Pinning a key MUST NOT clear a revocation. Supplying a
PEM says "this is the right key", not "ignore the revocation". Dropping the flag
when a key is pinned would make key pinning a way to launder a revoked
attestation.

### 9.3 Multiple keys, and key succession

A certificate's checkpoints can span more than one `key_id`. Two things produce
that: per-tenant signing keys with rotation, and a **custody transfer** — an
engagement moving from the validator that produced it to the bank that owns it,
where signing authority for the chain moves with it.

**Keyring pinning.** `--keyring` names one PEM per `key_id` — a directory of
`<key_id>.pem` files, or a JSON file mapping `key_id` to PEM text — instead of
the single unnamed PEM `--pubkey` supplies. The two combine: a named
`--keyring` entry wins for that `key_id`; `--pubkey` covers any `key_id`
`--keyring` does not name. A `key_id` covered by neither is refused, per §9.1
rule 1 — the whole point of pinning is that an unlisted key does not fall back
to trusting the bundle's own copy of itself.

**Key succession.** A certificate `statement` MAY carry a `succession` array. A
certificate whose checkpoints share one `key_id` throughout needs no
`succession` entry at all, and a verifier has nothing to check.

Each entry is the canonical body the **outgoing** key signed, plus the detached
signature over it:

| Field | Meaning |
|---|---|
| `type` | Always `"key.succession"`. Domain separation — see Rule 9.3.3. |
| `tenant_schema` | The tenant whose chain is being handed over. |
| `outgoing_key_id` | The key giving the chain up; the key that signs this record. |
| `incoming_key_id` | The key receiving it. |
| `effective_at` | ISO-8601 UTC instant the handoff takes effect. |
| `prior_event_hash` | The chain head immediately before the succession event. |
| `reason` | Free text, e.g. `"custody_transfer"`. |
| `signature_hex` | Ed25519 over `canonical_bytes(record without signature_hex)`, made by `outgoing_key_id`. |

**Rule 9.3.1 (MUST).** A change of `key_id` between two consecutive checkpoints
in a certified range, with no `succession` entry naming that exact
`outgoing_key_id` → `incoming_key_id` pair, MUST fail verification. An
unexplained key change is not evidence the chain kept its own author — it is
exactly what a bundle stitched together from two unrelated signing keys would
also look like. `outgoing_key_id` MUST equal the `key_id` of the checkpoint
*before* the change and `incoming_key_id` the `key_id` of the one *after*: a
record naming some other pair explains some other handoff, and leaves this one
unexplained.

**Rule 9.3.2 (MUST).** The matching entry's `signature_hex` MUST verify as an
Ed25519 signature by `outgoing_key_id` over `canonical_bytes(entry)` with
`signature_hex` removed, resolving that key exactly as §9.1/§9.2 resolve any
other key (pinned PEM wins; an unpinned run falls back to the bundle's
`public_keys`). An absent or invalid signature MUST fail the certificate.

Without this rule the handoff is a claim by whoever assembled the bundle. A
party holding only the **incoming** key can take the outgoing party's genuine
signed checkpoints — a certificate is handed to examiners, so they are not
secret — append their own checkpoints under their own key, and assert the pair
themselves. Every other check in this specification passes on such a bundle:
the old checkpoints really were signed by the old key, the new ones really were
signed by the new key, and the Merkle links between them can be constructed by
the forger, since they control the later tree. The outgoing key's signature over
the record is the only thing that distinguishes a handoff from a hijacking.

The enclosing certificate signature (§8) does **not** supply this. After a
transfer the incoming holder is the party issuing certificates, so the
statement, `succession` array included, is signed by the incoming key by
design.

**Rule 9.3.3 (MUST).** The entry MUST carry `type` equal to `"key.succession"`,
inside the signed body. Without it, a signature the outgoing key made over some
*other* structure that happens to carry `outgoing_key_id` and `incoming_key_id`
fields could be replayed here as a handoff that party never authorised.

**Rule 9.3.4 (MUST NOT).** A verifier MUST NOT reconstruct the signed body from
a fixed field list. Take the entry as-is and remove only `signature_hex`. Every
other field is then covered by the signature, so an unsigned field cannot be
stapled onto a genuine record, and a field added in a later version is verified
rather than silently ignored.

**What this checker does not do**, deliberately, and what a reader must not
infer from a passing `key succession` line:

* It does **not** check `prior_event_hash` against anything. That leaves one
  real gap. The value is signed, so it cannot be altered, but nothing ties it
  to the checkpoints in the bundle, which makes a genuine record
  **replayable**: one real A → B handoff lets B present *any* chain A ever
  signed as a chain A gave them, by splicing B-signed checkpoints onto A's
  genuine ones and attaching the real record. Binding the two is not possible
  with what a certificate carries today. `prior_event_hash` is the chain head
  the succession event was appended after, while the last outgoing-key
  checkpoint seals a head that already includes that event, and any number of
  ordinary events can sit between the two — so requiring the two values to
  match rejects honest transfers. Closing this needs the certificate to carry
  the succession event's own position in the chain, which is a format change,
  not a verifier change.
* It does **not** check `effective_at` against the surrounding checkpoints'
  `issued_at`. A record signed today can name any effective date; the signature
  proves the outgoing key asserted it, not that it was true.
* It does **not** check who authorised the transfer on either side. There is no
  approver identity in the record, so a compromised outgoing key produces a
  succession that verifies. Key compromise is handled by revocation (§9.2), not
  here.
* It does **not** check that the incoming key was live, or that the outgoing
  key was not already revoked at `effective_at` — only the current revocation
  flags, via the checkpoint signature checks those keys also appear in.

What a passing check does prove, and no more: the party that held the outgoing
key signed a statement naming this successor. Which chain that statement was
meant for is not established here — see the `prior_event_hash` point above.

### 9.4 Witness cosignatures (PROVISIONAL)

A checkpoint may be cosigned. A **witness** — the organisation itself, an
audit firm, a bankers' league — generates its own Ed25519 keypair and hands
over only the public half, then signs **byte-for-byte the same
`canonical_bytes(sth_body)`** the checkpoint signature covers:

```
cosignature = Ed25519_sign(witness_private_key, canonical_bytes(sth_body))
```

It answers a question the checkpoint signature cannot. Coriqo signs on the
organisation's behalf and can reach that private key at sign time; it cannot
reach a witness's. So a cosignature is the one signature in a bundle Coriqo
could not have produced alone.

**This is additive and lives outside every signed body.** A cosignature is a
signature *over* `sth_body`, so cosignature metadata inside `sth_body` would
be circular as well as breaking. On a proof bundle it is the top-level
`cosignatures` array; on a certificate it is a top-level `cosignatures`
object keyed by `checkpoint_id`, a sibling of `statement` and never a member
of it. Both are unsigned, the same trust class as the restatements §7.3
warns about.

| Field | Type | Meaning |
|---|---|---|
| `witness_key_id` | string | The witness's public handle. This is the name a pinned PEM is filed under |
| `witness_label` | string \| null | Display name. Display only |
| `signature_hex` | string | Ed25519 over `canonical_bytes(sth_body)`, hex |
| `signed_at` | string \| null | ISO 8601 UTC. Display only; not covered by anything |
| `witness_relationship` | string | `self` \| `independent` \| `unknown`. A **claim**, see 9.4.2 |
| `revoked` | boolean | The issuer's claim that this witness key is no longer live |

**No witness public key appears in the bundle, by design.** §9.1 explains why
a bundle that carries its own key proves internal consistency and not
authorship. For a *witness* key there is no weaker-but-useful mode at all: a
witness key handed to you by the party being witnessed witnesses nothing. So
the key never travels with the bundle, and the reference implementation would
not use it if it did.

#### Rule 9.4.1 (MUST) — pin, or report UNVERIFIED

A cosignature MUST be verified only against a public key supplied out of band
by the verifier's operator (`--witness-keyring` / `--witness-pubkey`, the same
two forms `--keyring` / `--pubkey` take for signing keys). A verifier MUST NOT
fall back to any key in the bundle, and MUST NOT fetch a witness key from
Coriqo at verify time — a cosignature checked against a key the witnessed
party supplied at verify time is not evidence.

A cosignature with no pinned key is **UNVERIFIED**. Never "verified", and —
the failure that matters — never rendered as though no cosignature existed.

#### Rule 9.4.2 (MUST) — independence is never inferred from the bundle

`witness_relationship` is unsigned metadata produced by the party under
scrutiny. A verifier MUST NOT report a cosignature as independently witnessed
on the strength of that field alone; the operator must name the witness
(`--independent-witness <witness_key_id>`).

The label may only ever **downgrade**. A witness the bundle itself calls
`self` stays self-witnessed even when the operator declares it independent —
the disagreement is reported, and the weaker of the two claims stands.

Self-witnessing is a real and useful control: it means Coriqo cannot author
the organisation's history unnoticed. It is not third-party audit, and a
verifier that renders one as the other has answered the wrong question.

#### The four states

A verifier MUST distinguish, per checkpoint, and MUST NOT collapse any pair:

| State | When | Verdict effect |
|---|---|---|
| **no cosignature** | `cosignatures` absent or empty | none |
| **self-witnessed** | verifies under a pinned key; operator did not declare it independent | none |
| **independently witnessed** | verifies under a pinned key the operator declared independent | none |
| **UNVERIFIED** | present, but no key pinned for it, or `revoked: true` | none |

A cosignature that IS pinned and does NOT verify is a **hard failure**
(rule 9.4.3).

#### Rule 9.4.3 (MUST) — fail closed on a cosignature that does not verify

If a witness key is pinned for a cosignature and the signature does not
verify under it, the verifier MUST fail, loudly. It MUST NOT downgrade to
UNVERIFIED, and MUST NOT keep a PASS verdict on the rest of the bundle.

A `cosignatures` field of an unexpected shape MUST also fail rather than be
skipped. A field an attacker can get ignored is a field an attacker will
malform.

#### Rule 9.4.4 (MUST NOT) — a cosignature never rescues a checkpoint

The PASS/FAIL verdict on inclusion and on the checkpoint signature is
unchanged by any cosignature. Cosignatures are additive: a checkpoint is
complete and verifiable on Coriqo's own signature the moment it is issued.

#### Revocation, and why it differs from 9.2.1

`revoked: true` downgrades a cosignature to UNVERIFIED. It does **not** fail
the run, which is the opposite of rule 9.2.1 for signing keys. A signing key
is what the artifact rests on, so a revoked one poisons it; a cosignature is
additive, so failing the run would let revoking a witness retroactively break
every proof bundle issued while that witness was live. The claim goes away;
the checkpoint does not.

The asymmetry that keeps this safe: `revoked: true` is a downgrade and is
honoured. The **absence** of the flag is never read as evidence that a key is
live.

#### Why PROVISIONAL

Marked **PROVISIONAL** for the same reason §9.3 is: the shape of the record
that establishes a witness's independence does not exist yet. Today
independence is asserted by the operator on the command line, which is
honest — the operator is the one who knows where they got the key — but it is
not attestable, and two operators can reach different verdicts on the same
bundle. When a registry of witnesses with verifiable, signed provenance
lands, this section and the reference implementation should be tightened to
check it. Until then, "the operator pinned this key and vouched for it" is
the full extent of the independence claim, and the report says so.

---

## 10. Public transparency-log anchor

A bundle may carry an `anchor` object recording publication of the signed tree
head to Sigstore Rekor, a public append-only log Coriqo does not operate.

| Field | Meaning |
|---|---|
| `status` | Anchor state |
| `rekor_uuid` | Entry UUID |
| `rekor_log_index` | Log index |
| `rekor_url` | Log base URL, default `https://rekor.sigstore.dev` |
| `anchored_at` | ISO 8601 UTC |

**The anchor is informational and MUST NOT affect the PASS/FAIL verdict.** The
offline checks stand alone; anchoring adds an independent witness that the
checkpoint existed no later than the log's `integratedTime`. A verifier that
fails because Rekor was unreachable has made offline verification conditional on
being online, which defeats the purpose.

To confirm an anchor manually: the Rekor entry is a `hashedrekord` whose
artifact SHA-256 equals `SHA256(canonical_bytes(sth_body))`, with a signature
and public key matching the bundle's.

---

## 11. Conformance

`testdata/` is the conformance corpus, regenerated by `tests/make_corpus.py`:

| File | Contents |
|---|---|
| `events.json` | A five-event chain, including a real 77-day quiet period |
| `proof.json` | Inclusion proof for event 2 under `tree_version` 1, MUST verify |
| `proof_v2.json` | Inclusion proof for event 4 under `tree_version` 2, MUST verify |
| `certificate.json` | Two-checkpoint continuity certificate, MUST verify |
| `pubkey.pem` | The corpus signing key — a test key, fixed seed, no relation to any Coriqo key |
| `proof_cosigned.json` | `proof.json` plus two genuine cosignatures (§9.4), one labelled `self`, one `independent`. Same `sth_body` and same `checkpoint_signature`, byte for byte |
| `proof_cosign_tampered.json` | The same bundle with one byte flipped in the self-witness signature. MUST fail under a pinned witness key |
| `certificate_cosigned.json` | `certificate.json` plus per-checkpoint `cosignatures` and `anchors`, outside `statement`. `cp-2026-q1` is deliberately left uncosigned |
| `witness_keyring/` | The two witness public keys, the operator's copy — test keys, fixed seeds |

The chain is five events on purpose. Five is not a power of two, so the two tree
constructions genuinely differ over it; at 2, 4 or 8 leaves they produce the
same root and the corpus would distinguish nothing (§5.2.2).

`proof_v2.json` proves the **last** leaf, whose RFC 6962 audit path is a single
hash where a five-leaf version-1 tree always needs three. It therefore fails
outright under Rule 5.3.1 — which is the point: an implementation that applies
that rule to version 2 will reject this bundle, and will reject honest proofs in
production for the same reason.

`make_corpus.py` is written against this document rather than against Coriqo's
source, and imports nothing from Coriqo. It is a second implementation on
purpose: if it and `verify_proof.py` disagree, this specification is wrong or
incomplete, and `tests/test_verifier.py::test_corpus_regenerates_byte_for_byte`
is what catches that.

`proof_cosigned.json` and `proof.json` differ in exactly one top-level field.
That is the point: attaching a cosignature must not move one byte of what any
signature covers, so the two files carry the same `sth_body` and the same
`checkpoint_signature`, and the corpus asserts it
(`test_cosigned_bundle_carries_the_same_signed_body_as_the_uncosigned_one`).
`certificate_cosigned.json` makes the same claim for `statement`.

A conforming implementation MUST verify the clean corpus bundles, and MUST
reject every mutation in `tests/test_verifier.py` — currently forty-odd cases
covering leaf tampering, path reordering and truncation, key substitution,
revocation, checkpoint removal, vacuous linkage, backdating, coverage
overstatement, substituted Merkle roots, unknown and unsigned `tree_version`,
version-2 paths that are too short or too long, and the §9.4 cases: a
tampered cosignature under a pinned witness key, a cosignature whose key was
never pinned, a bundle asserting independence the operator did not, an
operator asserting independence the bundle contradicts, a revoked witness
key, and a malformed `cosignatures` field.

---

## 12. Stability

Frozen for the lifetime of v1 — changing any of these breaks artifacts already
issued:

- `canonical_bytes` (§3)
- The event hash field set and construction (§4.2)
- `0x00` / `0x01` prefixes (§5.1), and each tree construction once issued
  against — version 1 and version 2 are both permanent (§5.2)
- Ed25519 over `canonical_bytes(sth_body)` (§6)

Additive changes are permitted: new optional fields may appear in bundles, and a
verifier MUST ignore fields it does not recognise rather than fail. Note that
adding a field to a **signed** object changes its canonical bytes, so new fields
inside `sth_body` or `statement` only appear in newly issued artifacts.

Known issue carried by v1, recorded here rather than silently dropped: the
unsigned `checkpoint_id` on proof bundles (§7.3). It is contained by fields that
*are* signed.

`cosignatures` and `anchors` are additive under this rule and add nothing to
any signed object: they are metadata about already-signed artifacts, and a
verifier written before they existed keeps verifying bundles that carry them.
The reverse is not true and is not meant to be — such a verifier reports "no
cosignature" for a cosigned chain, which is why rule 9.4.1 spells out that
UNVERIFIED and absent are different answers.

Two others have been fixed, and both are kept in this document rather than
deleted, because a verifier will still meet artifacts issued under them:

- **Leaf ordering** (§5.5), fixed from `ordering_version` 2. Checkpoints sealed
  under version 1 cannot be repaired retroactively and are marked
  non-reproducible.
- **The duplicating tree** (§5.3), fixed from `tree_version` 2, which uses
  RFC 6962's construction. Version-1 checkpoints are *not* marked
  non-reproducible: they reproduce exactly, under the construction they were
  sealed with. They simply cannot be recomputed as version 2, and are not.

---

## 13. Reporting a problem

A defect in this specification, or in `verify_proof.py`, is worth telling us
about: `bounty@coriqo.io`.

That includes a verifier that reports PASS on input it should reject, a rule
here that does not match what the reference implementation does, and any
ambiguity that led you to build something incompatible. A specification nobody
can implement from is not a specification.
