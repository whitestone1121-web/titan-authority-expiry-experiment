#!/usr/bin/env python3
"""Source-free signed approval evidence checker. No Titan imports or expected totals.

Signatures authenticate same-host role statements, not independent clock truth,
physical SQLite COMMIT time, production isolation, or execution of public build hashes.
The native HMAC grant is bound by the Ed25519 authorizer; it is not itself publicly
HMAC-verifiable. Pin the manifest hash through a separately trusted channel.
"""
import argparse
import base64
import hashlib
import json
import math
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_signed_bytes(value):
    if sys.flags.optimize:
        raise ValueError("optimized Python is not supported")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def signed_digest(value):
    return "sha256:" + hashlib.sha256(canonical_signed_bytes(value)).hexdigest()


def verify_role_record(envelope, role, keys):
    if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
        raise ValueError("invalid signed envelope")
    if type(envelope["payload"]) is not dict or type(envelope["signature"]) is not str:
        raise ValueError("invalid signed payload or signature")
    key = base64.b64decode(keys[role], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    if len(key) != 32 or len(signature) != 64:
        raise ValueError("invalid Ed25519 key or signature length")
    Ed25519PublicKey.from_public_bytes(key).verify(
        signature, canonical_signed_bytes(envelope["payload"])
    )
    return envelope["payload"]


def verify_native_approval(envelope, context, keys):
    p = verify_role_record(envelope, "approval", keys)
    fields = {
        "schema",
        "decision_id",
        "context",
        "context_digest",
        "operation_id",
        "input_fingerprint",
        "parameters",
        "full_grant",
        "grant_digest",
        "grant_expires_at",
        "nonce",
        "native_permitted",
        "reason_codes",
        "first_consumption_at",
        "consumption_row",
        "observed_return_utc",
        "time_scope",
        "legacy_unqualified",
    }
    if set(p) != fields or p["schema"] != "experimental.native_approval.v1":
        raise ValueError("approval schema differs")
    if p["context"] != context or p["context_digest"] != signed_digest(context):
        raise ValueError("approval context differs")
    if (
        type(p["native_permitted"]) is not bool
        or type(p["legacy_unqualified"]) is not bool
    ):
        raise ValueError("approval boolean fields differ")
    if p["legacy_unqualified"] != (context["case"] == "legacy_self_asserted"):
        raise ValueError("legacy profile differs")
    if p["time_scope"] != "SAME_HOST_OBSERVED_RETURN_NOT_PHYSICAL_COMMIT":
        raise ValueError("approval clock scope differs")
    if not isinstance(p["decision_id"], str) or not p["decision_id"]:
        raise ValueError("missing approval decision identity")
    if type(p["reason_codes"]) is not list or any(
        type(x) is not str for x in p["reason_codes"]
    ):
        raise ValueError("invalid approval reasons")
    params = p["parameters"]
    if type(params) is not dict or set(params) != {"operation_id", "resource", "value"}:
        raise ValueError("operation parameters differ")
    if (
        p["operation_id"] != params["operation_id"]
        or type(p["operation_id"]) is not str
    ):
        raise ValueError("approval operation differs")
    if p["input_fingerprint"] != signed_digest(
        {"query": "bounded synthetic mutation", "parameters": params}
    ):
        raise ValueError("approval input differs")
    grant, row = p["full_grant"], p["consumption_row"]
    if p["grant_digest"] != signed_digest(grant):
        raise ValueError("approval grant digest differs")
    if grant is not None and type(grant) is not dict:
        raise ValueError("invalid grant")
    if p["grant_expires_at"] != (grant.get("expires_at") if grant else None) or p[
        "nonce"
    ] != (grant.get("nonce") if grant else None):
        raise ValueError("signed expiry or nonce differs from full grant")
    for value in (
        p["observed_return_utc"],
        p["first_consumption_at"],
        p["grant_expires_at"],
        grant.get("issued_at") if grant else None,
    ):
        if value is not None and (
            type(value) not in (int, float) or not math.isfinite(value)
        ):
            raise ValueError("invalid signed timestamp")
    if row is not None:
        if not grant or type(row) is not dict:
            raise ValueError("consumption without grant")
        if (
            row.get("nonce") != grant.get("nonce")
            or row.get("capability_id") != grant.get("capability_id")
            or row.get("signature_sha256")
            != hashlib.sha256(str(grant.get("sig") or "").encode()).hexdigest()
            or row.get("key_id") != grant.get("sig_key_id")
            or row.get("action") != grant.get("action")
            or row.get("stage") != "toolhub.execute"
            or p["first_consumption_at"] != row.get("consumed_at")
        ):
            raise ValueError("durable consumption identity or timing differs")
        if p["first_consumption_at"] is None:
            raise ValueError("consumption without signed time")
    elif p["first_consumption_at"] is not None:
        raise ValueError("signed time without consumption")
    if p["native_permitted"] and not p["legacy_unqualified"]:
        if (
            row is None
            or p["grant_expires_at"] is None
            or grant.get("issued_at") is None
        ):
            raise ValueError("permitted approval lacks signed authority chain")
        if (
            grant.get("actor") != "sandbox-worker"
            or grant.get("action") != "tool.execute"
            or grant.get("destination") != "titan:toolhub:code_executor"
            or "toolhub.execute" not in grant.get("allowed_stages", [])
            or "args-sha256:"
            + hashlib.sha256(
                json.dumps(
                    {"query": "bounded synthetic mutation", "parameters": params},
                    sort_keys=True,
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            not in grant.get("artifact_scope", [])
        ):
            raise ValueError("permitted authority scope differs")
    return p


def verify_signed_trial(raw, historical=None):
    context, keys = raw["context"], raw["public_keys"]
    roles = {
        "issuer",
        "operator",
        "approval",
        "gateway",
        "journal",
        "destination",
        "observer",
    }
    if set(keys) != roles or len(set(keys.values())) != len(roles):
        raise ValueError("missing or overlapping role keys")
    fingerprints = {
        role: "sha256:"
        + hashlib.sha256(base64.b64decode(key, validate=True)).hexdigest()
        for role, key in keys.items()
    }
    if (
        context["schema"] != "experimental.case_context.v1"
        or context["case"] != raw["case"]
        or context["root_scenario_id"] != signed_digest(raw["case"])
        or context["key_fingerprints"] != fingerprints
        or raw["training_eligible"] is not False
    ):
        raise ValueError("case context, role pins or eligibility differs")
    inventory = context["case_inventory"]
    if (
        type(inventory) is not list
        or any(type(x) is not str for x in inventory)
        or len(set(inventory)) != len(inventory)
        or raw["case"] not in inventory
    ):
        raise ValueError("signed case inventory differs")
    cd = signed_digest(context)
    final = verify_role_record(raw["signed_final_inventory"], "operator", keys)
    if (
        final["schema"] != "experimental.final_inventory.v1"
        or final["context"] != context
        or final["context_digest"] != cd
    ):
        raise ValueError("final inventory context differs")
    unsealed = {k: v for k, v in raw.items() if k != "signed_final_inventory"}
    if (
        final["public_record_digest"] != signed_digest(unsealed)
        or final["training_eligible"] is not False
    ):
        raise ValueError("final public record commitment differs")
    for name, field in (
        ("signed_approvals", "approval"),
        ("signed_permits", "permit"),
        ("acceptances", "acceptance"),
        ("observations", "observation"),
    ):
        if (
            type(raw[name]) is not list
            or final[field + "_count"] != len(raw[name])
            or final[field + "_digests"] != [signed_digest(x) for x in raw[name]]
        ):
            raise ValueError("signed inventory completeness differs: " + field)
    journal = raw["signed_journal_records"]
    if (
        final["journal_count"] != len(journal)
        or final["journal_head"] != (signed_digest(journal[-1]) if journal else None)
        or final["journal_phases"] != [x["payload"]["phase"] for x in journal]
        or final["unsigned_timeline_digest"] != signed_digest(raw["events"])
        or final["unsigned_timing_scope"]
        != "ARCHIVED_LOCAL_DATA_NOT_INDEPENDENT_CLOCK_ATTESTATION"
        or final["finality"] != raw.get("reconciliation", "UNKNOWN")
    ):
        raise ValueError("signed journal, timeline or finality completeness differs")
    approvals = {}
    decisions = set()
    for envelope in raw["signed_approvals"]:
        p = verify_native_approval(envelope, context, keys)
        if p["decision_id"] in decisions:
            raise ValueError("duplicate approval decision")
        decisions.add(p["decision_id"])
        approvals[signed_digest(envelope)] = p
    permits = {}
    for envelope in raw["signed_permits"]:
        p = verify_role_record(envelope, "gateway", keys)
        if set(p) != {
            "parameters",
            "approval",
            "approval_digest",
            "context_digest",
            "fingerprint",
            "authorized_mono_ns",
            "accept_before_ns",
        }:
            raise ValueError("permit schema differs")
        approval = verify_native_approval(p["approval"], context, keys)
        expected_grant = (
            None if context["case"] == "legacy_self_asserted" else raw["grant"]
        )
        if approval["grant_digest"] != signed_digest(expected_grant) or approval[
            "input_fingerprint"
        ] != signed_digest(raw["expected"]):
            raise ValueError("permit approval differs from journal grant/effect unit")
        ad = signed_digest(p["approval"])
        if (
            ad not in approvals
            or p["approval_digest"] != ad
            or not approval["native_permitted"]
            or p["parameters"] != approval["parameters"]
            or p["fingerprint"] != approval["input_fingerprint"]
            or p["context_digest"] != cd
        ):
            raise ValueError("permit approval linkage differs")
        if (
            type(p["authorized_mono_ns"]) is not int
            or type(p["accept_before_ns"]) is not int
            or p["accept_before_ns"] - p["authorized_mono_ns"] != 1_000_000_000
        ):
            raise ValueError("permit timing scope differs")
        permits[signed_digest(envelope)] = p
    previous = None
    phases = []
    for number, envelope in enumerate(journal):
        p = verify_role_record(envelope, "journal", keys)
        binding = p["binding"]
        if (
            p["schema"] != "titan.forge.effect_entry.v1"
            or p["sequence"] != number
            or p["previous_hash"] != previous
        ):
            raise ValueError("broken signed journal chain")
        expected = raw["expected"]
        if (
            binding["authority_ref"]
            != signed_digest(
                raw["grant"] if context["case"] != "legacy_self_asserted" else None
            )
            or binding["artifact_action_commitment"] != signed_digest(expected)
            or binding["logical_operation_id"] != expected["parameters"]["operation_id"]
            or binding["attempt_id"] != expected["parameters"]["operation_id"]
            or binding["root_scenario_id"] != context["root_scenario_id"]
            or binding["request_id"] != "experiment:" + cd.removeprefix("sha256:")
            or binding["candidate_commit"] != context["native_source_commit"]
            or binding["candidate_tree"] != context["native_source_tree"]
        ):
            raise ValueError("journal authority, effect or context linkage differs")
        previous = signed_digest(envelope)
        phases.append(p["phase"])
    if phases not in (
        [],
        ["PRE_ENTRY"],
        ["PRE_ENTRY", "ENTERED"],
        ["PRE_ENTRY", "ENTERED", "RESPONSE_RECEIVED"],
        ["PRE_ENTRY", "ENTERED", "RESPONSE_LOST"],
    ):
        raise ValueError("invalid journal state transition")
    verdicts, receipts = [], []
    receipt_digests, operations, acceptance_sequences = set(), set(), set()
    for envelope in raw["acceptances"]:
        r = verify_role_record(envelope, "destination", keys)
        rd = signed_digest(envelope)
        if (
            rd in receipt_digests
            or r["operation_id"] in operations
            or r["acceptance_sequence"] in acceptance_sequences
        ):
            raise ValueError(
                "duplicate destination receipt, operation or acceptance sequence"
            )
        if type(r["acceptance_sequence"]) is not int or r["acceptance_sequence"] < 1:
            raise ValueError("invalid acceptance sequence")
        receipt_digests.add(rd)
        operations.add(r["operation_id"])
        acceptance_sequences.add(r["acceptance_sequence"])
        if set(r) != {
            "operation_id",
            "resource",
            "value",
            "fingerprint",
            "permit_digest",
            "approval_digest",
            "context_digest",
            "before_version",
            "after_version",
            "acceptance_sequence",
            "accepted_mono_ns",
        }:
            raise ValueError("destination receipt schema differs")
        if r["permit_digest"] not in permits or r["approval_digest"] not in approvals:
            raise ValueError("effect lacks mandatory signed permit/approval")
        permit, approval = permits[r["permit_digest"]], approvals[r["approval_digest"]]
        if (
            permit["approval_digest"] != r["approval_digest"]
            or r["context_digest"] != cd
            or r["fingerprint"] != permit["fingerprint"]
            or r["operation_id"] != approval["operation_id"]
            or any(
                r[k] != permit["parameters"][k]
                for k in ("operation_id", "resource", "value")
            )
            or r["fingerprint"] != signed_digest(raw["expected"])
            or "ENTERED" not in phases
        ):
            raise ValueError("effect/grant/approval linkage differs")
        if (
            type(r["accepted_mono_ns"]) is not int
            or not permit["authorized_mono_ns"]
            <= r["accepted_mono_ns"]
            <= permit["accept_before_ns"]
            or type(r["before_version"]) is not int
            or r["after_version"] != r["before_version"] + 1
        ):
            raise ValueError("destination permit bound or version differs")
        if approval["legacy_unqualified"]:
            verdict = "EXPLICIT_LEGACY_UNQUALIFIED"
        elif approval["first_consumption_at"] > approval["grant_expires_at"]:
            verdict = "SIGNED_EXPIRED_FIRST_CONSUMPTION_VIOLATION"
        elif approval["first_consumption_at"] < approval["full_grant"]["issued_at"]:
            verdict = "SIGNED_BEFORE_ISSUANCE_CONSUMPTION_VIOLATION"
        else:
            verdict = "SIGNED_APPROVAL_WITHIN_GRANT_WINDOW"
        receipts.append(envelope)
        verdicts.append(
            {
                "operation_id": r["operation_id"],
                "approval_digest": r["approval_digest"],
                "grant_digest": approval["grant_digest"],
                "first_consumption_at": approval["first_consumption_at"],
                "expires_at": approval["grant_expires_at"],
                "verdict": verdict,
            }
        )
    for envelope in raw["observations"]:
        p = verify_role_record(envelope, "observer", keys)
        if (
            p["schema"] != "experimental.exact_observation.v1"
            or p["context_digest"] != cd
        ):
            raise ValueError("observer context differs")
        for row in p["rows"]:
            verify_role_record(row, "destination", keys)
            if row not in receipts:
                raise ValueError("observer contains unlinked effect")
    if "substituted_worker_outcome" in raw:
        if (
            historical is None
            or raw["substituted_worker_outcome"] != historical["observations"]
        ):
            raise ValueError(
                "historical observation is not pinned to this batch normal case"
            )
        if raw["actual_current_destination_observation"] != raw["observations"]:
            raise ValueError("current observer alias differs")
        for envelope in raw["substituted_worker_outcome"]:
            p = verify_role_record(envelope, "observer", historical["public_keys"])
            if (
                p["context_digest"] != signed_digest(historical["context"])
                or p["context_digest"] == cd
            ):
                raise ValueError("historical context differs")
            for row in p["rows"]:
                verify_role_record(row, "destination", historical["public_keys"])
    if raw.get("status") == "HARNESS_SETUP_FAILURE":
        raise ValueError("capture contains setup failure")
    return {
        "case": raw["case"],
        "batch_id": context["batch_id"],
        "effects": len(receipts),
        "signed_approvals": len(approvals),
        "verdicts": verdicts,
        "signed_late_consumption_decisions": sum(
            p["native_permitted"]
            and not p["legacy_unqualified"]
            and p["first_consumption_at"] > p["grant_expires_at"]
            for p in approvals.values()
        ),
        "expiry_violations": sum(
            x["verdict"] == "SIGNED_EXPIRED_FIRST_CONSUMPTION_VIOLATION"
            for x in verdicts
        ),
        "legacy_unqualified_effects": sum(
            x["verdict"] == "EXPLICIT_LEGACY_UNQUALIFIED" for x in verdicts
        ),
        "training_eligible": False,
    }


def verify_signed_package(directory, manifest_sha256):
    directory = Path(directory).resolve()
    content = (directory / "manifest.json").read_bytes()
    if hashlib.sha256(content).hexdigest() != manifest_sha256.removeprefix("sha256:"):
        raise ValueError("manifest trust pin differs")
    manifest = json.loads(content)
    if manifest["schema"] != "titan.signed_approval_public_package.v2":
        raise ValueError("package schema differs")
    for name in manifest["files"]:
        parts = Path(name).parts
        if (
            len(parts) != 2
            or parts[0] not in ("before", "after")
            or Path(name).is_absolute()
            or not name.endswith(".json")
        ):
            raise ValueError("unsafe or undeclared manifest record path")
    cases = manifest["cases"]
    if (
        type(cases) is not list
        or len(set(cases)) != len(cases)
        or "normal" not in cases
    ):
        raise ValueError("case inventory differs")
    batches, results, all_keys = {}, [], set()
    for label in ("before", "after"):
        records = {}
        for name, spec in manifest["files"].items():
            if not name.startswith(label + "/"):
                continue
            path = directory / name
            if (
                path.is_symlink()
                or path.resolve().parent != directory / label
                or path.suffix != ".json"
            ):
                raise ValueError("unsafe public record path")
            data = path.read_bytes()
            if (
                len(data) != spec["bytes"]
                or hashlib.sha256(data).hexdigest() != spec["sha256"]
            ):
                raise ValueError("public record hash differs")
            raw = json.loads(data)
            case = spec["case"]
            if (
                case in records
                or raw["case"] != case
                or raw["context"]["batch_label"] != label
            ):
                raise ValueError("duplicate or swapped case/batch")
            records[case] = raw
        if set(records) != set(cases):
            raise ValueError("incomplete case inventory")
        batchids = {x["context"]["batch_id"] for x in records.values()}
        if len(batchids) != 1 or batchids.intersection(batches.values()):
            raise ValueError("mixed or replayed batch context")
        batches[label] = next(iter(batchids))
        builds = {
            signed_digest(
                {
                    k: v
                    for k, v in x["context"].items()
                    if k not in {"case", "root_scenario_id", "key_fingerprints"}
                }
            )
            for x in records.values()
        }
        if len(builds) != 1:
            raise ValueError("mixed build contexts")
        for case in cases:
            raw = records[case]
            for key in raw["public_keys"].values():
                if key in all_keys:
                    raise ValueError("role key reused across capture cases")
                all_keys.add(key)
            if raw["context"]["case_inventory"] != cases:
                raise ValueError("outer case inventory differs from signed context")
            result = verify_signed_trial(raw, records["normal"])
            result["batch"] = label
            results.append(result)
    return {
        "schema": "titan.signed_approval_verification.v2",
        "results": results,
        "totals": {
            label: {
                field: sum(x[field] for x in results if x["batch"] == label)
                for field in (
                    "effects",
                    "signed_approvals",
                    "signed_late_consumption_decisions",
                    "expiry_violations",
                    "legacy_unqualified_effects",
                )
            }
            for label in ("before", "after")
        },
        "scope": "SAME_HOST_EXPERIMENTAL_ROLE_STATEMENTS_NOT_PRODUCTION_RUNTIME_ATTESTATION",
        "training_eligible": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            verify_signed_package(args.directory, args.manifest_sha256),
            indent=2,
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
