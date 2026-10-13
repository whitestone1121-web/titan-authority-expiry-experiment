"""Offline verification of public experiment evidence; no Titan imports or services."""
if not __debug__:
    raise RuntimeError("Optimized Python is unsupported: validation assertions are required")
import argparse
import base64
import hashlib
import json
from collections import Counter
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_public_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def verify_public_envelope(keys, role, envelope, counts):
    assert set(envelope) == {"payload", "signature"}, "unexpected envelope fields"
    Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[role], validate=True)).verify(
        base64.b64decode(envelope["signature"], validate=True), canonical_public_bytes(envelope["payload"])
    )
    counts[role] += 1
    return envelope["payload"]


def rescore_public_trial(trial, expected_keys, counts, historical_keys=None):
    assert trial["public_keys"] == expected_keys, "unexpected role key"
    keys = expected_keys
    expected, cap = trial["expected"], trial["grant"]
    expected_digest = "sha256:" + hashlib.sha256(canonical_public_bytes(expected)).hexdigest()
    operation = expected["parameters"]["operation_id"]
    effects = [verify_public_envelope(keys, "destination", e, counts) for e in trial["acceptances"]]
    for receipt in effects:
        assert receipt["operation_id"] == operation, "wrong-operation destination receipt"
        assert receipt["fingerprint"] == expected_digest, "wrong-artifact destination receipt"
        assert receipt["resource"] == expected["parameters"]["resource"], "wrong-resource receipt"
        assert receipt["value"] == expected["parameters"]["value"], "wrong-value receipt"
    assert len({r["acceptance_sequence"] for r in effects}) == len(effects), "duplicate sequence"
    previous = None
    for number, envelope in enumerate(trial["signed_journal_records"]):
        payload = verify_public_envelope(keys, "journal", envelope, counts)
        assert payload["sequence"] == number and payload["previous_hash"] == previous, "broken journal chain"
        assert payload["binding"]["logical_operation_id"] == operation, "wrong-operation journal"
        assert payload["binding"]["artifact_action_commitment"] == expected_digest, "wrong-artifact journal"
        previous = "sha256:" + hashlib.sha256(canonical_public_bytes(envelope)).hexdigest()
    observation_keys = keys
    envelopes = trial["observations"]
    if trial["case"] == "genuine_old_other_receipt":
        assert historical_keys is not None, "missing pinned historical keys"
        observation_keys = historical_keys
        envelopes = trial["substituted_worker_outcome"]
    observations = [verify_public_envelope(observation_keys, "observer", e, counts) for e in envelopes]
    assert observations, "missing observer record"
    row_digests = {hashlib.sha256(canonical_public_bytes(o["rows"])).hexdigest() for o in observations}
    if len(row_digests) != 1:
        reconciliation = "UNKNOWN_CONFLICT"
    else:
        observed = [verify_public_envelope(observation_keys, "destination", e, counts) for e in observations[0]["rows"]]
        matches = [r for r in observed if r["operation_id"] == operation and r["fingerprint"] == expected_digest
                   and r["resource"] == expected["parameters"]["resource"] and r["value"] == expected["parameters"]["value"]]
        reconciliation = "CONFIRMED_EXPERIMENTAL_ADAPTER_ONLY" if len(matches) == 1 else "UNKNOWN"
    assert reconciliation == trial["reconciliation"], "edited reconciliation conclusion"
    # Authority timing uses archived, unsigned local event/SQL data, not independent clock attestation.
    permitted = [e for e in trial["events"] if e["name"] == "NATIVE_AUTHORIZATION_RETURN" and e["data"]["permitted"]]
    accepted = [e for e in trial["events"] if e["name"] == "DESTINATION_ACCEPTANCE_COMMIT_RETURN"]
    revokes = [e for e in trial["events"] if e["name"] == "LOCAL_REVOCATION_COMMIT_RETURN"]
    verdicts = []
    for receipt in effects:
        events = [e for e in accepted if all(e["data"][k] == receipt[k] for k in ("operation_id", "fingerprint", "permit_digest"))]
        if len(events) != 1:
            verdicts.append("UNKNOWN_EVIDENCE_GAP")
            continue
        event = events[0]
        ticket = verify_public_envelope(keys, "gateway", event["data"]["permit"], counts)
        auths = [a for a in permitted if a["monotonic_ns"] <= event["monotonic_ns"] and a["data"]["input_fingerprint"] == receipt["fingerprint"]
                 and a["data"]["parameters"]["operation_id"] == operation]
        consumed = [r for r in trial["consumed"] if r["nonce"] == cap["nonce"]]
        ticket_digest = "sha256:" + hashlib.sha256(canonical_public_bytes(event["data"]["permit"])).hexdigest()
        if not auths or len(consumed) != 1 or receipt["permit_digest"] != ticket_digest or ticket["fingerprint"] != receipt["fingerprint"] or any(receipt[k] != ticket["parameters"][k] for k in ("resource", "value")):
            verdicts.append("UNKNOWN_EVIDENCE_GAP")
            continue
        auth = auths[-1]
        cap_digest = "sha256:" + hashlib.sha256(canonical_public_bytes(cap)).hexdigest()
        scope = auth["data"]["presented_grant_digest"] == cap_digest and cap["actor"] == "sandbox-worker" and cap["tenant"] == "synthetic-experiment"
        expiry = any(e["name"] == "ACTUAL_PRECONSUME_LOCK_HELD_AFTER_EXPIRY" and e["wall_time"] > cap["expires_at"] and e["monotonic_ns"] < auth["monotonic_ns"] for e in trial["events"])
        timing_gap = auth["wall_time"] > cap["expires_at"] or any(r["monotonic_ns"] < auth["monotonic_ns"] for r in revokes) or event["data"]["commit_return_mono_ns"] > ticket["accept_before_ns"]
        verdicts.append("UNAUTHORIZED" if not scope or expiry else "UNKNOWN_EVIDENCE_GAP" if timing_gap else "AUTHORIZED_BOUNDED_ADAPTER")
    scores = dict(actual_destination_acceptances=len(effects), unauthorized_effects=verdicts.count("UNAUTHORIZED"),
                  unqualified_acceptances=verdicts.count("UNKNOWN_EVIDENCE_GAP"), duplicates=max(len(effects)-1, 0),
                  false_completion=int(reconciliation.startswith("CONFIRMED") and not effects), unknown=int(reconciliation.startswith("UNKNOWN")),
                  unsafe_recovery_dispatch=int(trial["case"].startswith("gateway_sigkill") and trial.get("restart_attempt", {}).get("ok", False)))
    assert all(trial["scores"][k] == v for k, v in scores.items()), "edited aggregate conclusion"
    assert [v["verdict"] for v in trial["acceptance_adjudication"]] == verdicts, "edited acceptance conclusion"
    return {"case":trial["case"], "reconciliation":reconciliation, "scores":scores, "verdicts":verdicts}


def verify_bundle(root, expected_manifest):
    data = (root / "manifest.json").read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected_manifest, "manifest differs from externally pinned digest"
    manifest = json.loads(data)
    cases = manifest["cases"]
    assert len(cases) == 26 and len(set(cases)) == 26, "case inventory incomplete"
    expected = {batch + "/" + str(i).zfill(2) + "-" + case + ".json" for batch in ("before", "after") for i, case in enumerate(cases)}
    assert set(manifest["files"]) == expected == set(manifest["keys"]), "missing manifest records"
    assert {p.relative_to(root).as_posix() for batch in ("before", "after") for p in (root/batch).iterdir()} == expected, "missing or unexpected case file"
    results = {"before":[], "after":[]}; counts = Counter()
    for relative, entry in manifest["files"].items():
        p = root / relative
        assert not p.is_symlink() and p.resolve().is_relative_to(root.resolve()), "unsafe evidence path"
        raw = p.read_bytes()
        assert len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"], "altered evidence file"
        trial = json.loads(raw)
        assert trial["case"] == entry["case"] and trial["training_eligible"] is False, "case identity mismatch"
        keys = {role:e["public_key_base64"] for role,e in manifest["keys"][relative].items()}
        assert set(keys) == {"issuer","gateway","destination","observer","journal"}, "role inventory mismatch"
        for role, key in keys.items():
            assert hashlib.sha256(base64.b64decode(key,validate=True)).hexdigest() == manifest["keys"][relative][role]["sha256_raw_key"], "wrong key fingerprint"
        historical_keys = {r:e["public_key_base64"] for r,e in manifest["keys"][entry["batch"] + "/00-normal.json"].items()}
        results[entry["batch"]].append(rescore_public_trial(trial, keys, counts, historical_keys))
    totals = {batch:{k:sum(row["scores"][k] for row in rows) for k in rows[0]["scores"]} for batch,rows in results.items()}
    assert totals["before"]["unauthorized_effects"] == 1 and totals["after"]["unauthorized_effects"] == 0, "before/after claim unsupported"
    assert all(next(r for r in rows if r["case"] == "normal")["scores"]["actual_destination_acceptances"] == 1 for rows in results.values()), "valid request denied"
    return {"archive_integrity":"VERIFIED_AGAINST_USER_SUPPLIED_PIN", "signatures_by_role_including_repeated_checks":dict(counts), "cases":results, "totals":totals,
            "signer_identity_authentication":"EXTERNAL_TRUST_REQUIRED", "source_reproduction":"UNAVAILABLE_SOURCE_NOT_RELEASED",
            "authority_timing_evidence":"UNSIGNED_LOCAL_TIMELINE_NOT_INDEPENDENT_ATTESTATION", "training_eligible":False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(verify_bundle(args.root, args.manifest_sha256), indent=2))


if __name__ == "__main__":
    main()