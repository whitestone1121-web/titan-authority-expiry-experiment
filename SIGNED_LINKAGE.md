# Signed grant → approval → effect linkage

All signed envelopes are `{payload, signature}`. Ed25519 signs UTF-8 JSON with sorted keys, compact separators, ASCII escaping and non-finite numbers prohibited. This is the declared Python canonicalization, not RFC 8785. Public keys are base64 raw 32-byte Ed25519 keys; signatures are base64 64-byte signatures. SHA-256 identifiers use `sha256:` plus lowercase hex. The signed context pins role public-key fingerprints, case, declared case inventory, batch ID/label, root-scenario identifier and source/freeze claims.

| Signed unit | Role | Fields that bind the chain |
| --- | --- | --- |
| `experimental.native_approval.v1` | native authorizer (`approval`) | Full grant including expiry and native MAC tag; grant digest; decision ID; operation ID; parameters/input fingerprint; `native_permitted`; reason codes; actual observed durable consumption row and first-consumption timestamp; context and context digest |
| Gateway permit | `gateway` | Nested signed approval, its digest, parameters/input fingerprint, context digest, monotonic permit interval |
| Destination receipt | `destination` | Approval digest, permit digest, operation ID, exact parameters/fingerprint, acceptance sequence/version and observed acceptance monotonic timestamp |
| `titan.forge.effect_entry.v1` journal chain | `journal` | Full grant digest as authority reference; exact effect-input commitment; operation ID; signed context digest in request ID; case-root and source identity; sequence/previous hash; phase and response digest |
| Exact destination observation | `observer` | Context digest and original signed destination rows; conflicting or historical evidence remains distinguishable |
| `experimental.final_inventory.v1` | separate `operator` attestor | Whole public-record digest, complete approval/permit/acceptance/observation digests and counts, journal phases/count/terminal head, timeline digest and finality |

The checker requires the permitted approval's full grant digest and input fingerprint to match the journal's grant/effect unit. Each destination receipt must reference a verified permit and native approval in the sealed inventory. Receipt, operation and acceptance-sequence duplicates are rejected. Missing approval evidence is a hard failure, not a relabelable evidence gap. A denied replay may legitimately retain the previously consumed SQL row; that is not another permitted approval or effect.

Timing verdicts use the **signed** `first_consumption_at` and full-grant `expires_at`. The native expiry comparison is `first_consumption_at > expires_at` (equality is permitted). Late native consumption decisions are reported separately from late-consumption effects. No unsigned event, old adjudication label or expected total controls that comparison. Other security properties must not be inferred from the narrower `SIGNED_APPROVAL_WITHIN_GRANT_WINDOW` label.

`first_consumption_at` is the timestamp recorded in the real native SQLite row, read by the authorizer after the actual native decision; it is not independently timed physical COMMIT. The destination's monotonic timestamp is also an observed sample, not proof of physical COMMIT. The signed operator inventory authenticates the archived local timeline but does not turn it into independent clock evidence.

In the new baseline case 15, the signed grant expiry is 1791866524.9479723 and the signed first consumption is 1791866525.1554255: about 207.45 ms later. The approval digest is `sha256:a27d8cf2a1c611abbb5a0efdb2ae1d05250c1999001f5fedd108cd9e23584675`; the corresponding signed permit and destination receipt reference that approval. See `before/15-native_expiry_between_verify_and_consume.json` for every original signed unit and public key. The repaired case has a signed denied decision and no effect.

The grant's native MAC is not publicly recomputable. Public approval verification authenticates the authorizer's binding and observed decision under its pinned Ed25519 key. The bundled issuer public key is not a substitute for releasing a MAC verification key or an independent authority-service attestation.
