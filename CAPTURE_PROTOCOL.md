# Fresh bounded capture protocol

This is a new v0.2.0 capture, not a relabeling or re-signing of v0.1.0. The new private harness adds a separate native-authorizer process which signs actual native decisions/SQL first-consumption observations, and a separate operator-attestor process that reads durable inventories before signing the final public record. The controller keeps only the issuer signing role. Signing roles remain under the same host UID; no stronger credential-isolation claim is made.

The same new harness bytes were run serially against the baseline native implementation and the committed expiry repair. The declared 26 case names are in the manifest and are cryptographically bound inside every signed case context. The test target is a synthetic local account mutation through experimental Unix-socket adapters; no production customer, payment, external publication, trading or model-training effect occurs.

Baseline capture source commit: `bfd42682133deff00d40c8c08c11dcbff6454b8e` (parent original experiment `e9395dd3a3329ff79037acfd40bd86cebd5e18fd`).

Repaired capture source commit: `de78a882232053c013f0479246707b51339bc895` (parent actual repair `e2229db68837f9ca2fa58b0336ed63283a3a1a17`).

Same harness SHA-256: `1a82b24cab8268b95f90e611aa2bfebbb9cda222654f8481c846ce8441ec701a`.

Baseline freeze digest: `sha256:d8138f0e1f7db491c63fb9317a2b8ff0468bb3d890714ad979be6ec99aa131fe`.

Repaired freeze digest: `sha256:83326817c029565500da597d72073d4bb5f970468146351e3df504b763785029`.

The six declared native dependency hashes and full source/tree claims are in `capture-provenance.json`. The five non-ledger files match between the two frozen captures; the ledger differs by the qualified expiry repair. This is not a claim that every file in the two entire repository trees is identical.

Each batch completed once (26 cases, exit zero), in 24.59 seconds baseline and 25.49 seconds repaired. Both committed source identities and clean working-tree state were unchanged afterward. No setup failures occurred in these two batches. Earlier v0.1 captures, failed development controls and review findings are retained internally; v0.1.0 remains available unchanged at its original release. The checker repairs were independently reviewed and tested before these batches; the public archive is reviewed separately after capture.

These scenarios and root identifiers are experimental fixtures, not authentic customer lineage or training examples. Missing production authority, operational isolation, authentic data and benchmark qualification remain separate training blockers.
