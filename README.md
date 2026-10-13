# Titan authority-expiry experiment — fresh signed approval evidence v0.2.0

This source-free package contains a **new, separately captured** 26-case baseline and 26-case repaired comparison. It closes the v0.1.0 timing-authentication gap by signing the actual native approval decision, full grant and observed durable first-consumption row **before the permit/effect**, then linking that approval to the signed destination receipt and journal. The v0.1.0 release is unchanged; its records were not retrospectively signed.

Fresh offline verification computes one expired-consumption effect before the repair and zero after. The deliberately unsafe legacy configuration remains unqualified and produces one effect in each batch. These are bounded experimental results, not production qualification or training data.

## Verify

Python 3.12 and `cryptography==41.0.7` were used for the actual clean verification. Install that dependency in an environment you control. No Titan code, credentials, network access, GPU or model weights are needed by either command.

```sh
python3 -I -B verify_signed_approval_evidence.py . --manifest-sha256 4167c98c403e728deb97258e583832780f5b51f6cb7ff0207768ef9bd94eb630
python3 -I -B negative_signed_approval_controls.py . --manifest-sha256 4167c98c403e728deb97258e583832780f5b51f6cb7ff0207768ef9bd94eb630 --verifier-sha256 69da325ed240dc2812440030e0dc4488b8309acf326ab5d421d6a3771a9f8506
```

Or run `make verify-archive` and `make verify-negative-controls`. Results are calculated from authenticated records, with no assertions requiring expected headline totals. The declared **case inventory** is signed inside every context; it is a completeness requirement, not a hardcoded success/violation count. All 16 public tamper controls were executed successfully, including edits with recomputed outer hashes, timing relabeling and whole-case omission.

Authenticate the release/archive and manifest hash through a separately trusted channel before trusting these bundled public keys or executing these utilities. A replacement archive containing new attacker-controlled keys and a new trust pin is a different trust root.

## Evidence and limits

- [Signed linkage specification](SIGNED_LINKAGE.md): exact signatures and hash links from grant to approval to effect.
- [Fresh capture protocol](CAPTURE_PROTOCOL.md): declared cases, capture changes and actual source identities.
- [Computed results](RESULTS.md), `recomputed-results.json`, and `negative-controls.json`.
- `before/` and `after/`: 52 original public-safe records, preserved byte-for-byte from the fresh capture; each contains seven public role keys and evidence fields plus a signed final inventory. Approval, permit and journal chains can be empty for denied or pre-entry cases; the signed inventory authenticates those empty counts.

The native grant uses an HMAC. Its key is not published. Public Ed25519 approval signatures bind the full grant and attest the native decision and observed SQL row; an outsider cannot independently recompute the native HMAC. Signing establishes authentic role statements under the pinned keys, not independent wall-clock truth or a physical SQLite COMMIT timestamp.

All roles ran on one host under the same OS UID, with separate signing configurations/processes. This does not establish independent OS custody, resistance to a fully compromised host, production ToolHub integration, canonical observer runtime qualification, or production delivery. Build hashes are signed capture claims, not an independent execution attestation.

Titan implementation, private harness, private configuration, signing keys, databases and private Git history are not released. Outsiders can authenticate and recalculate the evidence and run verifier tamper controls; they cannot rerun the private experiment implementation from this package. `make reproduce` explicitly fails for that reason.

**Training eligibility remains false. Qualified training examples and independent training roots remain zero; the original 18 benchmark rows remain quarantined.**
