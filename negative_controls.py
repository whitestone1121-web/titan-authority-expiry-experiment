"""Public evidence negative controls; Python plus real cryptography, no Titan source."""
import argparse
import collections
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--package-root", type=Path, required=True)
parser.add_argument("--manifest-sha256", required=True)
parser.add_argument("--verifier-sha256", required=True)
args = parser.parse_args()
if not __debug__:
    raise RuntimeError("Assertions must remain enabled")
source = args.package_root.resolve(strict=True)
assert hashlib.sha256((source / "manifest.json").read_bytes()).hexdigest() == args.manifest_sha256
assert hashlib.sha256((source / "verify_public_evidence.py").read_bytes()).hexdigest() == args.verifier_sha256
with tempfile.TemporaryDirectory(prefix="public-evidence-negative-") as temporary:
    root = Path(temporary) / "export"
    root.mkdir()
    for relative in ("manifest.json", "verify_public_evidence.py"):
        (root / relative).write_bytes((source / relative).read_bytes())
    for batch in ("before", "after"):
        (root / batch).mkdir()
        for path in (source / batch).glob("*.json"):
            (root / batch / path.name).write_bytes(path.read_bytes())
    command = [sys.executable, "-I", "-B", str(root / "verify_public_evidence.py"),
               "--root", str(root), "--manifest-sha256", args.manifest_sha256]
    positive = subprocess.run(command, capture_output=True, text=True, check=True)
    report = json.loads(positive.stdout)
    spec = importlib.util.spec_from_file_location("offline_public_verifier", root / "verify_public_evidence.py")
    assert spec is not None and spec.loader is not None
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    normal = json.loads((root / "before" / "00-normal.json").read_text())
    keys = normal["public_keys"]
    results = []
    for name in ("altered_payload", "unexpected_key", "missing_required_record",
                 "valid_signed_wrong_operation", "wrong_role_signature", "edited_summary"):
        trial = copy.deepcopy(normal)
        if name == "altered_payload":
            trial["acceptances"][0]["payload"]["value"] += 1
        elif name == "unexpected_key":
            trial["public_keys"]["gateway"] = trial["public_keys"]["observer"]
        elif name == "missing_required_record":
            trial["observations"] = []
        elif name == "valid_signed_wrong_operation":
            trial["expected"]["parameters"]["operation_id"] = "different-operation"
        elif name == "wrong_role_signature":
            trial["acceptances"][0]["signature"] = trial["observations"][0]["signature"]
        else:
            trial["scores"]["actual_destination_acceptances"] += 1
        try:
            verifier.rescore_public_trial(trial, keys, collections.Counter(), keys)
        except Exception as error:
            results.append({"control": name, "rejected": True, "error_type": type(error).__name__,
                            "error": str(error), "layer": "direct semantic API deliberately bypasses archive integrity"})
        else:
            raise AssertionError("Negative accepted: " + name)
    altered = root / "after" / "00-normal.json"
    original = altered.read_bytes()
    altered.write_bytes(original + b" ")
    try:
        verifier.verify_bundle(root, args.manifest_sha256)
    except AssertionError as error:
        results.append({"control": "altered_archive_bytes", "rejected": True, "error": str(error)})
    else:
        raise AssertionError("Altered archive accepted")
    altered.write_bytes(original)
    missing = root / "after" / "01-legacy_self_asserted.json"
    original = missing.read_bytes()
    missing.unlink()
    try:
        verifier.verify_bundle(root, args.manifest_sha256)
    except AssertionError as error:
        results.append({"control": "missing_archive_file", "rejected": True, "error": str(error)})
    else:
        raise AssertionError("Missing archive accepted")
    missing.write_bytes(original)
    optimized = subprocess.run([sys.executable, "-I", "-O", *command[3:]], capture_output=True, text=True)
    assert optimized.returncode != 0 and "RuntimeError" in optimized.stderr, "Optimized verifier did not refuse"
    assert not any(name.startswith("agi_os_backend") for name in sys.modules), "Unexpected Titan import"
    print(json.dumps({"manifest_sha256": args.manifest_sha256, "verifier_sha256": args.verifier_sha256,
                      "positive_case_count": sum(len(rows) for rows in report["cases"].values()),
                      "signature_checks": report["signatures_by_role_including_repeated_checks"],
                      "negative_controls": results, "optimized_refused": True,
                      "source_reproduction": "UNAVAILABLE_SOURCE_NOT_RELEASED",
                      "scope": "public offline export integrity/signature/semantic controls only"}, indent=2))
