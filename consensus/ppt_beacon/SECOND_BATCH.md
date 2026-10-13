# PPTB: AWSS, local-share extraction, OEC and full batch audit

The live PPT path is now:

1. Share f/g and commit canonical recipient messages; reliably deliver public
   roots and h. Ready comes only from a happy holder. The AWSS preparation
   certificate is independent of this recipient having its private message.
2. ACS fixes a sorted dealer set D. Only selected AWSS instances activate
   missing-message retrieval and verifiable complaint/report/assist recovery.
3. Each recipient multiplies its LOCAL f-shares, ordered by D, by the same
   super-invertible matrix. For m=|D| there are m-f output polynomials per coin,
   of degree at most f. Broadcast these output shares once, without inventing
   original-dealer Merkle paths for transformed values.
4. Polynomial OEC recovers each output polynomial online. Emit its constant
   coefficient in canonical (coin, sub-output) order. Recover/open the entire
   batch even after first-match leader selection succeeds.
5. Only after the entire local batch has opened, multicast original f-shares,
   masks, nonce shares, actual instance key shares and original key/cipher
   dispersal rows needed to rebuild every committed message.
6. Rebuild all selected dealers' original polynomials, all sharing points, share
   trees, canonical plaintexts, encrypted messages and RS fragment/meta trees.
   Compare complete rebuilt roots with those delivered by public RBC.
7. A complete transferable reconstruction certificate can prove dealer error.
   Invalid provider proofs never establish dealer guilt. Preserve this round's
   already-decided set; apply proven exclusions to subsequent ACS rounds.

Former dealer-secret-first recovery and point-proof-only audit remain labelled
legacy comparison helpers. The PPT dispatcher rejects their reconstruction/audit
wire messages. BEA/HashRand keeps its implementation, wire discriminants,
configuration and benchmark defaults.

## Arithmetic and OEC

### R=1 main-batch degree test

The live GF2 path now samples B small-field f polynomials and ONE independent
large-field g polynomial. After committing every recipient's f/g/nonce data,
it derives one domain-separated challenge coefficient theta_l per input and
broadcasts a single h = g + sum_l theta_l*f_l (minus equals plus in GF2).
Recipients authenticate all original points, enforce base/extension membership
and the exact f+1 coefficient bound, then verify the complete batch identity.
A proper subset of main inputs cannot pass as a complete batch. Complaint
recovery rechecks the same identity at the recovering recipient's point.

Challenge inputs bind the round, dealer, field widths, B, n, f, the complete
root vector and coefficient position. This retains a commitment-hash challenge
approach, adapted to a coefficient vector. It is not a full implementation or
adaptive/QROM proof of JoC section 7, and it does not change ACS coin bootstrap.
R remains exactly 1; field widths and target128 configuration gates are unchanged.

The main private payload encodes only one 32-byte mask share. Internal state
expands it into a repeated per-coin view for existing bookkeeping; that view is
not the encrypted transport encoding. Audit decodes/re-evaluates the shared mask
once and rebuilds the identical compact plaintext, ciphertext and Merkle roots.
Existing per-coin nonce shares, share roots and Merkle proofs are retained.

The 12 sealed reserve coins KEEP independent masks and individual h responses,
in their independently keyed SecMsg instance. Main audit must not reveal a mask
relation involving a sealed reserve. Public h layout in GF2 is therefore
[main_h, reserve_h_0, ..., reserve_h_11], not one h over all B+12 inputs.
Prime-field comparisons retain per-coin h/masks; they have no extension-field
soundness claim. The PPT-only PublicBundle version is now 2; all PPT nodes must
update together. Shared BEA/HashRand messages and implementation are unchanged.

At n=16, f=5, B=1000, raw public h coefficients fall from 194304 bytes to
2496 bytes per dealer (including the 12 reserves). Main private mask values
fall from 32000 bytes to 32 bytes per recipient. These are payload counts,
not measured network traffic or throughput; RBC/SecMsg, proofs, metadata,
complaints, ACS and audit costs remain. Retained per-coin proofs prevent this
change alone from establishing a strict O(n) total amortized communication bound.

The matrix uses sorted dealer IDs+1 as input points and the next m-f distinct
points as output points. All recipients use identical input order/dimensions.
GF2 matrices and output reconstruction use GF(2^w_p); large-field mask evaluation
uses small-field multiplication where possible. Prime-field arithmetic remains
a legacy comparison, not a true extension-field construction.

For degree d=f and at most f faulty providers, OEC accepts only when at least
d+f+1=2f+1 DISTINCT points match a degree-at-most-d candidate. At least d+1 matching
points are honest, establishing uniqueness when honest providers hold the same
polynomial. With e received errors, d+f+1+e arrivals suffice; the worst case is
all n=3f+1 arrivals. For n=4 and n=16 the confirmation thresholds are 3 and 11;
the error budgets remain 1 and 5.

The normal path interpolates with a cached inverse Vandermonde matrix, then
checks every received point and the support threshold. A previously confirmed
point set is an interpolation hint for the next coordinate, always followed by
a fresh support check. Berlekamp-Welch locates errors when the fast path fails.
Exact division, degree, field membership and support are checked after decoding.
Duplicate/equivocating provider slots cannot add votes. Missing points, decode
failure or worker failure leave the coordinate pending. Transformed shares have
no f+1-only fallback.

Beacon polynomial OEC is distinct from SecMsg's byte-oriented Reed-Solomon
erasure coding. The latter reconstructs ORIGINAL committed bytes from proved
fragments and re-encodes the codeword before accepting its root.

## Audit objects and sealed reserves

SecMsg has independent beacon and PR10 coin-reserve instances, each with its own
key/cipher root pair bound into public RBC. Keys use the independent 521-bit
Mersenne prime 2^521-1. Publishing a beacon key never decrypts a reserve ciphertext.
Reserve coin generation, commitment-root theta, genesis coin and out-of-window
fallback retain their PR10 algorithms.

Each dispersal row contains the provider's shard of every recipient message and
both Merkle proof levels. Successful distribution implies at least f+1 honest
row holders. After batch opening these rows recover exact original key/cipher
vectors even if a Byzantine recipient withholds its key/plaintext. Bad row proofs
are rejected as provider evidence. Valid fragments that fail ORIGINAL codeword
rebuilding prove a bad dealer; missing fragments merely cause waiting.

For every beacon coin, audit OEC recovers f, nonce and (in the prime comparison)
large-field f, then re-evaluates all n points. GF2 audit recovers the ONE main
g polynomial once; the prime comparison retains per-coin g. Rebuild each share tree, generate
its original point paths, serialize the original bincode recipient layout,
encrypt with the reconstructed actual key share and apply the original RS
encoding/tree shape. Rebuild the key polynomial, canonical key encoding and both
key/cipher meta-roots. A plaintext tree cannot stand in for a ciphertext commitment.
Commitment nonces are never encryption keys; audit never reveals pairwise secrets.

PPTB trees use a domain-separated SHA-256 node rule consistently for sharing,
key/cipher dispersal, forwarding and audit. The legacy shared AES compression
had different single-tree/batch semantics and failed to retain encrypted blocks
in its single-tree path. PPTB no longer uses it; BEA hashing/verification stays
unchanged. The existing 32-byte digest width is retained; this is not a complete
concrete quantum-security proof.

Lite retains its actual-private-channel/algebra comparison role. Its audit
authenticates original points before OEC and rebuilds the FULL polynomial/tree;
it has no invented SecMsg key/cipher commitment. Transferable missing-share
complaints require SecMsg, so target128 rejects Lite. Defaults are not switched.

## Consistent exclusion and lifetime

Round r+1 sharing may overlap round r reconstruction. Its ACS waits for the full
round-r audit. The exact root-bound reconstruction rules give every honest node
the same valid/fault verdict for each selected dealer, so subsequent ACS uses
the same accumulated exclusions. Early ACS messages are buffered and replayed.
Fault certificates relay original evidence without modifying a decided set.

Keep original materials until batch output AND full audit complete. Selected
share-serving evidence waits for ALL share ACKs; audit rows wait for all audit
ACKs. Reserve serving waits for the next ACS to finish and all reserve ACKs.
An n-f quorum or timeout could omit a delayed honest party. A Byzantine can
withhold an ACK and retain historical caches; bounded certified checkpoints or
reconfiguration remain an unresolved lifetime requirement.

## Configuration and security boundary

Initial deployments: n=4,f=1 and n=16,f=5; total adaptive corruption at most f;
128-bit post-quantum computational-security target. The 2^-40 statistical budget
is a separate event-specific calculation, not a consequence of hash size.

PPT-only flags preserve explicit comparison defaults:

- `--ppt-channel benchmark`: plaintext TCP+HMAC, without confidentiality.
- `--ppt-channel private`: AES-256/HMAC with existing provisioned 32-byte pairwise
  secrets and fresh per-packet nonce/domain separation.
- `--ppt-channel external-private`: operator asserts an actual private,
  authenticated underlying channel.
- `--ppt-security benchmark`: algebra/performance comparison parameters.
- `--ppt-security target128`: requires SecMsg, a private channel, a true GF2
  extension and w_q>128+n. This checks parameters, not the protocol proof.

Example per PPT node: `--transport secmsg --field 'GF2(64,256)'
--ppt-channel private --ppt-security target128`. Use matching configuration on
all PPT nodes. The benchmark script does not implicitly add these flags.

Fresh theta timing/source, first pi_Beacon and the complete ACS common-coin
bootstrap/unbounded supply remain deferred. Public PR10 genesis and deterministic
fallback cannot justify unpredictable-common-coin or full asynchronous termination
claims. Field-size/channel/OEC/audit checks do not resolve these source/proof gaps.
Security is not established by renaming functions or running a benchmark.

## Verification

Compile the complete workspace using `cargo build --release` on Linux with Rust
1.65 through the PR11 workflow. The assistant runs no tests or benchmarks.
A successful build establishes compilation only; beacon agreement, throughput
and Byzantine/adaptive termination require separate evidence.
