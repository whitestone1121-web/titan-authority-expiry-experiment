"""Public tamper tests: no private signing keys, Titan imports or expected totals."""

import argparse
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--manifest-sha256", required=True)
parser.add_argument("--verifier-sha256", required=True)
args = parser.parse_args()
if sys.flags.optimize:
    raise ValueError("optimized Python is not supported")
root = args.directory.resolve()
checker_path = root / "verify_signed_approval_evidence.py"
if hashlib.sha256(checker_path.read_bytes()).hexdigest() != args.verifier_sha256:
    raise ValueError("checker trust pin differs")
spec = importlib.util.spec_from_file_location("public_signed_checker", checker_path)
if spec is None or spec.loader is None:
    raise ValueError("checker loader unavailable")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
positive = checker.verify_signed_package(root, args.manifest_sha256)
manifest = json.loads((root / "manifest.json").read_bytes())
normal_name = next(
    name
    for name, entry in manifest["files"].items()
    if name.startswith("before/") and entry["case"] == "normal"
)
expiry_name = next(
    name
    for name, entry in manifest["files"].items()
    if name.startswith("before/")
    and entry["case"] == "native_expiry_between_verify_and_consume"
)
controls = []
with tempfile.TemporaryDirectory(prefix="signed-approval-public-controls-") as temp:
    target = Path(temp)
    for label in ("before", "after"):
        (target / label).mkdir()
    for name in manifest["files"]:
        parts = Path(name).parts
        source_file = root / name
        if (
            len(parts) != 2
            or parts[0] not in ("before", "after")
            or Path(name).is_absolute()
            or source_file.suffix != ".json"
            or source_file.is_symlink()
            or not source_file.is_file()
            or source_file.resolve().parent != root / parts[0]
        ):
            raise ValueError("unsafe public control copy path")
        (target / name).write_bytes(source_file.read_bytes())
    for control in (
        "approval_expiry",
        "first_consumption_at",
        "native_decision",
        "grant_expiry",
        "operation_id",
        "parameters",
        "grant_digest",
        "missing_approval",
        "missing_permit",
        "truncated_journal",
        "wrong_role_key",
        "batch_relabel",
        "case_relabel",
        "timing_violation_relabelled_gap",
        "whole_case_omission",
    ):
        changed_manifest = copy.deepcopy(manifest)
        name = (
            expiry_name if control == "timing_violation_relabelled_gap" else normal_name
        )
        trial = json.loads((root / name).read_bytes())
        if control == "whole_case_omission":
            omitted_case = "native_expiry_between_verify_and_consume"
            changed_manifest["cases"].remove(omitted_case)
            changed_manifest["files"] = {
                path: entry
                for path, entry in changed_manifest["files"].items()
                if entry["case"] != omitted_case
            }
        elif control == "approval_expiry":
            trial["signed_approvals"][0]["payload"]["grant_expires_at"] += 10000
        elif control == "first_consumption_at":
            trial["signed_approvals"][0]["payload"]["first_consumption_at"] -= 10000
        elif control == "native_decision":
            trial["signed_approvals"][0]["payload"]["native_permitted"] = False
        elif control == "grant_expiry":
            trial["signed_approvals"][0]["payload"]["full_grant"]["expires_at"] += 10000
        elif control == "operation_id":
            trial["signed_approvals"][0]["payload"][
                "operation_id"
            ] = "substituted-operation"
        elif control == "parameters":
            trial["signed_approvals"][0]["payload"]["parameters"]["value"] += 1
        elif control == "grant_digest":
            trial["signed_approvals"][0]["payload"]["grant_digest"] = (
                "sha256:" + "0" * 64
            )
        elif control == "missing_approval":
            trial["signed_approvals"] = []
        elif control == "missing_permit":
            trial["signed_permits"] = []
        elif control == "truncated_journal":
            trial["signed_journal_records"] = trial["signed_journal_records"][:-1]
        elif control == "wrong_role_key":
            trial["public_keys"]["approval"] = trial["public_keys"]["gateway"]
        elif control == "batch_relabel":
            trial["context"]["batch_label"] = "after"
        elif control == "case_relabel":
            trial["case"] = "worker_sigkill"
        else:
            trial["status"] = "UNKNOWN_EVIDENCE_GAP"
            trial["scores"]["unauthorized_acceptances"] = 0
        if control != "whole_case_omission":
            data = checker.canonical_signed_bytes(trial)
            (target / name).write_bytes(data)
            changed_manifest["files"][name]["sha256"] = hashlib.sha256(data).hexdigest()
            changed_manifest["files"][name]["bytes"] = len(data)
        content = checker.canonical_signed_bytes(changed_manifest)
        (target / "manifest.json").write_bytes(content)
        changed_pin = hashlib.sha256(content).hexdigest()
        try:
            checker.verify_signed_package(target, changed_pin)
        except Exception as error:
            controls.append(
                {
                    "control": control,
                    "rejected": True,
                    "exception": type(error).__name__,
                    "reason": str(error),
                    "outer_manifest_repinned": True,
                }
            )
        else:
            raise ValueError("tamper was accepted: " + control)
        if control != "whole_case_omission":
            (target / name).write_bytes((root / name).read_bytes())
optimized = subprocess.run(
    [
        sys.executable,
        "-O",
        "-I",
        "-B",
        str(checker_path),
        str(root),
        "--manifest-sha256",
        args.manifest_sha256,
    ],
    capture_output=True,
    text=True,
    timeout=30,
)
if (
    optimized.returncode == 0
    or "optimized Python is not supported" not in optimized.stderr
):
    raise ValueError("optimized checker accepted")
controls.append(
    {
        "control": "optimized_python",
        "rejected": True,
        "returncode": optimized.returncode,
    }
)
print(
    json.dumps(
        {
            "schema": "titan.signed_approval_negative_controls.v2",
            "positive_package_verified": True,
            "controls": controls,
            "private_signing_keys_used": False,
            "expected_result_totals_used": False,
            "computed_totals": positive["totals"],
        },
        indent=2,
    )
)
