"""Prove a run cannot read the manifest or the rest of the repository.

Host check: the pod uid, while the repository is root-only, must fail to open
eval/ground_truth.yaml. Bubblewrap check: a process whose mount tree contains
only that run directory plus the runtime must fail the same open.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = [
    "/workspace/eval/ground_truth.yaml",
    "/workspace/results/metrics.json",
    "/workspace/eval/relationships.md",
    "/tmp/security-audit-skill/skills/security-audit/SKILL.md",
]


def attempt(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            handle.read(16)
        return {"path": path, "readable": True}
    except FileNotFoundError as exc:
        return {"path": path, "readable": False, "error": "FileNotFoundError", "errno": exc.errno}
    except PermissionError as exc:
        return {"path": path, "readable": False, "error": "PermissionError", "errno": exc.errno}
    except OSError as exc:
        return {"path": path, "readable": False, "error": type(exc).__name__, "errno": exc.errno}


def host_probe(extra_paths):
    checks = [attempt(path) for path in FORBIDDEN + extra_paths]
    return {
        "kind": "host_uid",
        "uid": os.getuid(),
        "passed": all(item["readable"] is False for item in checks),
        "checks": checks,
    }


def bwrap_probe(run_dir):
    script = r"""
import json, os
paths = [
    "/workspace/eval/ground_truth.yaml",
    "/audit/../../workspace/eval/ground_truth.yaml",
    "/etc/passwd",
]
checks = []
for path in paths:
    try:
        open(path).read(16)
        checks.append({"path": path, "readable": True})
    except OSError as exc:
        checks.append({"path": path, "readable": False, "error": type(exc).__name__, "errno": exc.errno})
inside = os.path.isdir("/audit/app") and os.path.isdir("/audit/skill")
print(json.dumps({"inside_run_visible": inside, "checks": checks}))
"""
    command = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--ro-bind",
        str(run_dir),
        "/audit",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/audit",
        "python3",
        "-c",
        script,
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0 and not completed.stdout.strip():
        return {
            "kind": "bwrap",
            "passed": False,
            "error": completed.stderr[-500:],
            "returncode": completed.returncode,
        }
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    forbidden_hidden = all(item["readable"] is False for item in payload["checks"])
    return {
        "kind": "bwrap",
        "passed": bool(payload["inside_run_visible"] and forbidden_hidden),
        "returncode": completed.returncode,
        **payload,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir")
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--extra", action="append", default=[])
    args = parser.parse_args()
    if args.host:
        report = host_probe(args.extra)
    elif args.run_dir:
        report = bwrap_probe(args.run_dir)
    else:
        parser.error("choose --host or --run-dir")
    json.dump(report, sys.stdout)
    sys.stdout.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
