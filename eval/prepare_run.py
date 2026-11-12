import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def prepare(dest, condition):
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    target = dest / "target"
    shutil.copytree(
        ROOT / "app",
        target / "app",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    if condition == "B":
        shutil.copy(ROOT / "eval" / "relationships.md", target / "relationships.md")
    (dest / "output").mkdir(parents=True)
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--condition", required=True, choices=["A", "B", "C"])
    parser.add_argument("--dest", required=True)
    args = parser.parse_args()
    target = prepare(args.dest, args.condition)
    print(target)


if __name__ == "__main__":
    main()
