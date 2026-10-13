# Independent verification scope

A separate Codex review agent, which did not author the producer or final checker, copied only the 52 public records, manifest and two verification utilities into its own clean directory. It ran the system Python 3.12 interpreter with `-I -B` and real cryptography against the exact manifest SHA-256 `4167c98c403e728deb97258e583832780f5b51f6cb7ff0207768ef9bd94eb630`.

The actual checker verified all 52 records; the shipped negative utility rejected all 16 mutations. Recomputed totals match `recomputed-results.json`: one signed late consumption/effect before, zero after, and one deliberately unqualified legacy effect per batch. The baseline's signed native row is 207.453251 ms after its signed grant expiry; the repaired case has a signed expired-grant denial, no consumption row and no effect.

Source preflight and finite semantic controls were reviewed separately, including duplicate receipt rejection, whole-case omission rejection from signed case inventory, mandatory approval/permit linkage and the file-copy traversal guard. Initial failed development candidates were preserved internally; this report describes only the identified final utilities and fresh captures.

This is independent agent review within the same engineering session, not certification by an unrelated organization, independent physical-clock witness or external signing-key custodian. An outside reviewer can repeat the public verifier and tamper controls without Titan source or secrets. Archive checksum verification and release approval are separate from this content review.
