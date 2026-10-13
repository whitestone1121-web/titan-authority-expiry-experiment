# Titan authority experiment — public evidence verification candidate

This source-free export lets a reviewer verify archived Ed25519 evidence and independently recalculate the supplied 26-case before/after results. It contains no Titan implementation, experiment executable, private key, database, model, or private repository history. Full implementation reproduction is unavailable under the current source-release restriction.

## Run offline

Requires Python 3.12 and cryptography 41.0.7 (actual clean verification provider will be recorded in independent-review.json). Dependency installation may require network access; verification itself requires none. The supplied verifier is inspectable utility code, not Titan source. Do not use Python -O.

```sh
python3 -I verify_public_evidence.py --root . --manifest-sha256 0e1c927eb7214e36fe9b6883a5ca64a1044e5febb7c07e27f58dfc54eeb8c201
```

Obtain that manifest digest and the final package digest through an authenticated operator channel independent of this download. The manifest pins every case file and every role public key. It is not an operator-signed release manifest. A replacement bundle with a replacement digest does not authenticate itself. No publisher private key is created by the collector or verifier.

## Results and identities

The same frozen 26-case experiment file was used for both archived batches. Its SHA256 is d3cb41f23befb95067edabc9e4e9090fa7002bc048a73c55bee20f8ebdae4ec1; local control commit e9395dd3a3329ff79037acfd40bd86cebd5e18fd. Baseline implementation commit87c1f9f0bdfac988650c543eb05b360535928884/native ledger9fcf4df9c3e39fd76924ff32cfbca781335612c7b1f834af25ef454622e5d439. The repaired trial tested an UNCOMMITTED snapshot with ledger96af66cf9710ba6947469a04981850c8080421316ab00c66e1b1a44daf2f411f; repair full/source qualification remains pending. Subsequent formatting and integration are not retroactively called this trial's tested commit.

| Recomputed metric | Before | After |
|---|---:|---:|
| Destination acceptances | 15 | 14 |
| Unauthorized expired effects | 1 | 0 |
| Unqualified legacy acceptance | 1 | 1 |
| Duplicate / false completion / unsafe recovery | 0 / 0 / 0 | 0 / 0 / 0 |
| UNKNOWN | 13 | 14 |
| Valid normal effects | 1 | 1 |

A control that detects the vulnerability is a successful reproduction of a defect, not a safe implementation verdict. The repair bounds first nonce consumption after waiting for the SQLite write lock. It does not promise an absolute physical COMMIT, dispatch, or remote transport deadline. Real wall clocks and a held SQLite writer synchronized the expiry interleaving; no production clock or TTL was changed. The earlier120-second Alpaca fixture issue and Claude#3482 chat-entry grants are different mechanisms.

## What signatures mean

Payloads use Ed25519 over UTF-8 Python sorted JSON with separators(',',':'), ensure_ascii=True and allow_nan=False. Signatures and raw32-byte public keys use base64. This is the actual experiment serialization, not RFC8785. The manifest gives SHA256 fingerprints of the raw public keys, separately for issuer, gateway, destination, observer and journal. Keys were freshly generated per case by one experiment operator; role names and many signatures do not establish independent witnesses.

The original83 checks for the repaired run are14destination receipts+27observer envelopes+42journal records. The verifier additionally checks gateway permits and repeated nested destination receipts, so its reported verification-attempt count differs. See signature-counts.json. Issuer public keys are published, but capability grants use HMAC and cannot be independently authenticated with these public keys; no HMAC secret is released.

## Evidence boundaries and limitations

Destination receipts, observer snapshots, gateway permits and journal chains can be cryptographically checked. Local event timestamps, exported consumed-nonce rows, expected inputs, source identities and worker text are UNSIGNED. Recalculated authority/expiry counters therefore remain conditional on those supplied local inputs; hashes authenticate their archive integrity relative to the externally obtained manifest pin, not their truth. This verifier does not turn unsigned evidence into an operational authority attestation.

The attacked worker ran in bubblewrap user/PID/network namespaces with closed inherited descriptors, read-only Python/library/source mounts and two local Unix API sockets. It received no authority/observer private-key configuration. Trusted roles were separate processes with role-specific key files and dumpability disabled, but all shared host UID1000. The test is a Byzantine worker protocol test, not proof against a fully compromised host. The canonical observer trust registry rejected the same-UID policy. Role separation, key custody and host clocks are not independently attested by this public package.

The destination was a dummy-account local API, message drops simulated partitions, and transport/observer adapters were experimental. Actual ToolHub execution, real GitHub delivery, real customer acceptance and payments were not exercised. Signed source fields still refer to the tested precommit snapshot and are not silently rewritten. A wrong-operation historical receipt is validly signed but rejected semantically. Conflict and entered-but-unresolved operations retain UNKNOWN, with no blind redispatch. One intentionally unsafe default-off legacy configuration remains an unqualified acceptance; it is not hidden.

The package verifies completeness only within its52declared case files and their supplied signed records. It cannot prove absence of unobserved effects, omitted events inside a fabricated source archive, or independently verify implementation bytes not released. No certification, production readiness, training eligibility, or universal security claim is made. Qualified training examples0; weights loaded0; optimizer steps0.

## Publication

Prepared candidate only. Proposed public repository: whitestone1121-web/titan-authority-expiry-experiment. Publication authorization and operator authentication of the release digest are pending. Do not publish Titan source or private history. Existing public repositories signalbrain and receipt-gate-demo were inspected as alternatives; no repository was modified.

Verifier negative controls: `make verify-negative-controls` executes the supplied portable driver, copying only the52casefiles, manifest and verifier into a temporary directory. It never modifies the evidence source.
