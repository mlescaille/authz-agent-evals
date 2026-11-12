"""The audited tree must not name the planted defects."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
CONTEXT = ROOT / "eval" / "relationships.md"

BANNED_APP = [
    "idor",
    "bola",
    "vuln",
    "exploit",
    "household",
    "ground_truth",
    "planted",
    "backdoor",
    "fixme",
    "todo",
    "bug",
    "bypass",
    "stale",
    "cloudflare",
]

BANNED_CONTEXT = [
    "idor",
    "bola",
    "vulnerability",
    "exploit",
    "planted",
    "bug",
    "missing check",
    "household",
]


def main():
    failures = []
    for path in sorted(APP.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix != ".py":
            continue
        text = path.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                failures.append(f"{path.relative_to(ROOT)} contains a comment")
                break
        lowered = text.casefold()
        for word in BANNED_APP:
            if word in lowered:
                failures.append(f"{path.relative_to(ROOT)} contains {word!r}")
    context = CONTEXT.read_text().casefold()
    for word in BANNED_CONTEXT:
        if word in context:
            failures.append(f"eval/relationships.md contains {word!r}")
    if failures:
        print("\n".join(failures))
        return 1
    print("no hint strings in app/ or the relationship note")
    return 0


if __name__ == "__main__":
    sys.exit(main())
