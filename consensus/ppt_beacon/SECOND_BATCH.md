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

## Validation

At the user's request, no build, tests or benchmarks are run by the assistant.
Source/diff inspection does not establish compilation or runtime correctness.
