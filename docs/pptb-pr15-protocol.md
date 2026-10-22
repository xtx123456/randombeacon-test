# PPTB: complaint-scoped recovery, Compact Broadcast and BatchRec

This change is stacked on PR14. All nodes in one deployment must use the new
binary: public bundles are version 5, and old full-payload RBC, transformed-share
and all-dealer audit wire slots are decoded but not used by the live protocol.
R remains 1. The existing fields, extraction matrix, reserve-coin construction,
output ordering and application mapping are retained.

## Execution paths

Normal execution is sharing/verification, ACS selection, share-level extraction,
then two-layer batched public reconstruction. It sends no audit rows and never
waits for a previous batch's audit before starting ACS. A batch's chosen dealer
set is immutable once the ABA decisions are fixed.

After ACS selects an instance, a recipient lacking its share requests its own
authenticated key/cipher fragments. If the reconstructed committed message is
provably invalid, it broadcasts a complaint. Report propagation carries the
original, publicly checkable complaint; valid assists let unhappy recipients
recover from f+1 authenticated Happy messages. Missing data, worker errors and
an unsuccessful OEC attempt are not dealer-fault evidence.

An assist-send latch is consumed only after its proof is available. Later
transport deliveries and recovered shares re-drive the relevant state machines.
The recovery chain is independent of audit completion and batch opening.

## Progress argument and problem A

Assume authenticated reliable private links, at most f total corruptions,
sound normal share verification, and the completeness of the sharing transport.
A public AVSS completion certificate implies f+1 honest Happy holders. Once a
valid complaint is available, these holders can supply f+1 valid assists to each
unhappy honest recipient. All honest recipients can then reconstruct consistent
shares. Thus public reconstruction can eventually receive n-f correct provider
points; Byzantine senders are not needed to complete it.

This is an availability invariant, not a conclusion inferred from a timeout.
OEC failure requests diagnosis of locally missing selected shares and leaves the
coordinate pending for later points. Even with all dealers honest, f Byzantine
reconstruction providers can submit bad points while honest points are delayed.
OEC=None therefore neither identifies a faulty dealer nor authorizes disclosure.
There is no unproved timeout/quorum abandonment protocol in this change.

## Local exclusions and problem B

Verified complaints update a local selection preference. An unfed ABA instance
for a proven corrupt dealer receives input 0, including when its proposal has
not been delivered. Non-excluded instances receive input 1 after proposal
delivery and local AVSS completion; the existing n-f-decided-1 force-zero rule
remains. Inputs are never rewritten.

Evidence arrival can differ between honest nodes. RBC, ABA and selected-instance
recovery still process messages regardless of that local preference. The ACS
output remains exactly the common set of ABA decisions 1, with no local
post-filtering. If a locally excluded instance is nevertheless chosen, it is
still recovered. After evidence has reached all honest parties, newly started
instances can unanimously input 0. There is no fixed exclusion-round bound from
the first observation of a fault.

No audit evidence is added to ACS proposals. Transferable compact witnesses,
evidence availability and an agreed activation frontier are separate extensions;
they are not prerequisites for removing the unconditional audit barrier.

## Compact Broadcast

The live driver in `coded_broadcast.rs` uses the existing JoC Section 3.2.2
state machine for both public AVSS bundles and ACS proposals. A proposer sends
each recipient its own encoded fragment and Merkle proof; recipients echo their
authenticated fragments, and the Bracha thresholds decide a root.

Before delivery, a receiver decodes, canonically re-encodes, rebuilds the Merkle
tree, and compares its root with the decided root (JoC Fig. 5). Inclusion proofs
alone do not establish that a dealer committed to a valid codeword. Invalid
committed encodings terminate with the protocol's bottom outcome instead of
being delivered as arbitrary bytes. Invalid ACS proposals receive local input 0.

The state enforces instance-specific fragment bounds, sender/index binding,
proof shape and at most one counted root per authenticated echo/vote sender.
Honest ECHOs are sent to every node on reliable links; there is no broadcast
request that makes n holders each return the entire payload. Communication is
O(n|M| + lambda n^2 log n), including all honest fragment transmissions.

## Dealer-scoped audit and disclosure boundary

The audit key is (round, dealer), not just round. A valid complaint is required
locally before a node requests, serves or audits bulk disclosure material. Only
the accused dealer's original MAIN key/cipher rows are exchanged. Main and
reserve transports are separately instantiated in dealer generation, and the
audit checks that main roots do not alias either reserve root. No reserve
state or other dealer's payload is included. Alias cases remain recoverable
through the complaint/assist path; they do not authorize a broader disclosure.

For a valid dealer-fault complaint, the adversary already controls that dealer;
its contribution is not the source of the beacon's honest entropy. The existing
assist protocol already exposes enough authenticated messages to interpolate
its shares. Disclosing only that dealer's independent main instance can therefore
run before the overall batch opens, without exposing honest dealers' or future
reserve-coin material. This is why the new audit does not require LocalBatchOpened.

Audit requests themselves carry no disclosure authority. Small per-peer request
records may be retained across message reordering, while unsolicited bulk rows
are discarded until a local complaint is verified. A provider serves its row at
most once per requester, and only after both original rows are available and
verified. New row versions re-drive pending audits. Invalid provider material is
not attributed to the dealer. Audit completion is never required for output,
selected-share recovery, or subsequent ACS.

This is full verification of the accused dealer's batch, not a full audit of
all selected dealers. For q accused dealers the relevant work scales with q;
q=Theta(n) does not improve the worst-case order merely by narrowing the scope.

## Two-layer batched public reconstruction

Let k=f+1. After applying the unchanged extraction matrix, divide the local
output shares into k-element blocks, with deterministic zero padding of the
final block. For a block of k shared output values, each party evaluates its
coefficient vector at n public points and privately sends value j to owner j.
Owner j uses degree-f OEC to recover the correct encoded value at that point.
This is the first layer.

Each honest owner broadcasts only its confirmed encoded values. Every node
applies degree-(k-1) OEC across owner indices to recover the k coefficients.
This second layer does not run another RBC: n-f honest owners send the same
correct value to every recipient, while at most f owners can equivocate.

Parameters explicitly enforce the error budget n-k >= 2f. At n=3f+1 and k=f+1,
this is equality: the code tolerates exactly f arbitrary errors. Distinct field
points, canonical elements, sender-bound evaluation positions, stage separation,
block ranges, and a fixed-length reconstruction-context digest are checked.
OEC never assumes that the first 2f+1 arrivals are all correct. The digest binds
round, selected dealer set, dimensions and the actual extraction field.

Messages batch block values per recipient; they do not repeat an n-element
dealer list in each point message. Each honest sender contributes at most one
point per block and phase. Both layers together send O(lambda n^2) bits per
Theta(n)-output block, giving O(lambda n) amortized per output.

A fast node must finish all its OWN first-layer recovery and second-layer
broadcast duties before releasing output work. Otherwise Byzantine owners
could help only the fast node decode, then withhold from slow nodes after the
fast node stopped supplying its missing owner values. Worker callbacks retain
version checks, and new arrivals re-drive undecoded blocks.

## Lifecycle and cost accounting

Output work is released independently of audit completion. Selected transport
rows and public commitments remain available for slow recipients and delayed
valid complaints. Derived caches can be released after the relevant duties are
finished. Without an additional retirement/availability mechanism, this does
not claim a fixed bound on retained serving history under adversarial scheduling
or ACK withholding.

Let B be the code's `batch_size`, m the number of selected dealers, and
N=B(m-f) the number of output field elements, where m=Theta(n).

* One dealer's normal sharing: O(lambda B n + lambda n^2 log n).
* n dealer sharing instances: O(lambda B n^2 + lambda n^3 log n).
* Two-layer public reconstruction of N outputs: O(lambda n N + lambda n^2).
* Sharing plus reconstruction per output:
  O(lambda n + lambda n^3 log n / N), equivalently
  O(lambda n + lambda n^2 log n / B) in the code's batch-size notation.

These are data-path bounds. ACS/ABA control traffic, coin generation and its
number of rounds, complaint/report/assist traffic, and audits are accounted for
separately. Field arithmetic is still present; this change does not establish a
hash-only total computation bound or a complete adaptive/post-quantum security
proof. In particular, unchanged genesis/finite-reserve coin behavior is not a
newly proved asynchronous termination guarantee.

Validation follows the requested scope: Rust 1.65 on Ubuntu 22.04,
`cargo build --release --locked`. No tests or benchmarks are added or run.
