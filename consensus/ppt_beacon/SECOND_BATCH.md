# PPTB second batch: sharing transport, reliable delivery and selected recovery

This branch is based on PR10. It does not change BEA/HashRand, shared Merkle
verification, existing CoinMsg variant numbers, or benchmark defaults. The only
shared wire addition is an appended PPTBExtension variant; BEA ignores it.

The initial target deployments are n=4,f=1 and n=16,f=5, with total adaptive
corruption bounded by f and a 128-bit post-quantum computational-security target.
This is a design target, not a completed adaptive-security proof. PR10's theta,
genesis coin and reserve-window fallback are deliberately retained. Share-level
matrix extraction, beacon OEC and full commitment-rebuilding audits belong to
later changes. A 2^-40 statistical failure budget is separate from computational
security and must be derived for each event; it is not supplied by a hash size.

## Channel configuration

PPT-only flags (unchanged defaults are explicit comparison settings):

- `--ppt-channel benchmark`: existing plaintext TCP+HMAC, no confidentiality.
- `--ppt-channel private`: encrypted, authenticated packets using existing
  provisioned 32-byte pairwise secrets. AES-256 encrypts with a fresh per-packet
  key derived by domain-separated HMAC from a 32-byte random nonce, source,
  destination and round. The existing HMAC verifies the encrypted envelope
  before decryption. No threshold setup, public-key encryption or new dependency.
- `--ppt-channel external-private`: the operator explicitly asserts an actual
  private authenticated underlying channel. Plain TCP and a trusted-looking LAN
  do not by themselves satisfy this assumption.
- `--ppt-security benchmark`: permits algebra/performance comparison profiles.
- `--ppt-security target128`: requires a private channel, SecMsg and a true GF2
  extension with w_q > 128+n. It validates configuration, not the deferred
  randomness or the complete protocol proof.

For the intended sizes, `--transport secmsg --field 'GF2(64,256)'
--ppt-channel private --ppt-security target128` meets the configured field and
channel checks. Apply these flags to every PPT node, not to the BEA command.
The current benchmark script defaults are not silently changed.

SecMsg's transport-key Shamir field is independent of the beacon fields: use the
521-bit Mersenne prime 2^521-1, avoiding a low-entropy transport key. Beacon share,
degree-test and extraction arithmetic keep the selected small/large GF2 profile.
SecMsg still needs private channels for its key fragments. Key/cipher evidence
and canonical encoding remain available through recovery and batch audit.
Per-instance SecMsg keys may later be disclosed by audit; long-term pairwise
channel secrets must never be disclosed as audit data.

## Public delivery

The public sharing transcript (all per-coin commitments and h coefficients) is
delivered by its own scoped Bracha RBC. Cache/apply it only after a matching
READY quorum. Public-transcript and ACS-proposal instances have distinct wire
scopes, and include the round and proposer. Both support hash-checked retrieval
from honest holders after f+1 READY votes, including a recipient that received
a conflicting first SEND. Early requests are remembered until content arrives.
Payload responses do not create votes or bypass delivery thresholds. Existing
sender/root/index Merkle checks are preserved. Recovery caches needed by slow
recipients are not expired using a timeout or a local completion assumption.

## AWSS preparation and selected recovery

The normal share-generation/degree-check path is retained. Only happy holders
send AVSSReady. With n=3f+1, n-f matching Ready votes imply at least f+1 honest
happy holders. AVSSComplete is a one-sided-vote relay: send after n-f Ready or
f+1 Complete; public preparation finishes after n-f Complete. This public state
no longer requires the local recipient to have private materials. Public RBC
must have delivered before the preparation certificate is applied.

SecMsg's public bundle binds both key/cipher meta-roots, in addition to the
original share commitments and h. Reordered key/cipher messages wait for this
bundle. Delivery/forwarding verifies recipient and fragment indices, Merkle
depth/positions and the agreed root, then reconstructs/re-encodes the ORIGINAL
RS codeword. A valid proof of a malformed original codeword is kept as bottom
evidence. Bad relay proofs do not establish dealer guilt.

After ACS, only selected instances can activate recovery. A missing-data request
causes providers to replay fragments for the REQUESTER's key/ciphertext, privately
to that requester. It never asks providers to reveal their own share plaintext.
An unhappy recipient forwards its committed message (or bottom evidence) as a
complaint. Before accepting it, receivers verify both committed channels and run
the existing share/degree check at the complaint's original recipient index.
Only a verified unhappy message triggers assists from happy holders. Relays
include the original complaint as a report, so assist/report message reordering
does not lose the evidence. This follows the complaint/assist mechanism in
Shoup-Smart, Journal of Cryptology 2024, Section 5.1, adapted to PPTB's post-ACS
selection: https://doi.org/10.1007/s00145-024-09505-6.

With f+1 validated happy assists, interpolate the local recipient's f/g shares
using a single coefficient vector per provider set, check them against h, and
keep their original certificates. GF2 coefficients remain in the small field;
large mask shares use mul_small. These derived local shares have no original
Merkle paths. Until the subsequent matrix/OEC change, PR10 reconstruction imports
only the certified original points at their original provider indices.

Lite is retained as a private-channel performance comparison. It lacks the
transferable key/cipher evidence needed by this SecMsg complaint implementation,
so target128 rejects Lite. No default transport is switched. The later complete
audit/OEC changes are still needed for the final PPTB path, particularly the
bad-case audit of recovered local shares. This PR does not claim all second-batch
requirements or Byzantine/adaptive end-to-end termination are already proved.

Selected serving evidence is released only after local batch audit and ACKs from
ALL participants. n-f ACKs could omit an honest delayed recipient. A Byzantine
can withhold its ACK and keep historical transport evidence in memory; safe
bounded garbage collection/reconfiguration is a separate unresolved requirement.
No network delay bound or timeout is introduced to hide that limitation.

## Validation status

At the user's request, no build, tests or benchmarks are run by the assistant.
Source/diff inspection does not establish compilation or runtime correctness.
