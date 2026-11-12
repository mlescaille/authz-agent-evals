"""The scoped proxy allows granted reads and blocks everything else."""

import json
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.scoped_proxy import classify
from eval.scoped_server import shutdown, start
from eval.tokens import mint


def test_classify_expired():
    secret = "s" * 32
    token, payload = mint(secret, 1, [1], [1], ttl_seconds=-5)
    scope = {
        "secret": secret,
        "account_id": 1,
        "device_ids": [1],
        "note_ids": [1],
    }
    decision = classify("GET", "/me", token, scope, conn=None, now=time.time())
    if decision["category"] != "expired" or decision["decision"] != "blocked":
        raise SystemExit(f"expired token was not blocked: {decision}")
    del payload


def test_live_scope():
    tmp = tempfile.TemporaryDirectory()
    running = None
    try:
        running = start(Path(tmp.name), ttl_seconds=900)
        public = running["public"]
        private = running["private"]
        headers = {"Authorization": f"Bearer {public['token']}"}
        with httpx.Client(base_url=public["base_url"], timeout=30.0) as client:
            own = client.get(f"/accounts/{public['account_id']}/notes", headers=headers)
            if own.status_code != 200 or "scoped-note" not in own.text:
                raise SystemExit(f"in-scope read failed: {own.status_code} {own.text}")
            if "other-private-note" in own.text:
                raise SystemExit("in-scope response included another account's note")
            other = client.get(
                f"/accounts/{private['other_account_id']}/notes",
                headers=headers,
            )
            if other.status_code != 403:
                raise SystemExit(f"other account was not blocked: {other.status_code}")
            minted = client.post(
                "/sessions",
                headers=headers,
                json={"email": "a@example.com", "password": "nope-nope"},
            )
            if minted.status_code != 403:
                raise SystemExit(f"session mint was not blocked: {minted.status_code}")
            moved = client.get(
                f"/devices/{private['moved_device_id']}/readings",
                headers=headers,
            )
            if moved.status_code != 403 or "other-private-reading" in moved.text:
                raise SystemExit("moved device readings were visible through the proxy")
        rows = [
            json.loads(line)
            for line in Path(private["log_path"]).read_text().splitlines()
            if line.strip()
        ]
        categories = {row["path"]: row["category"] for row in rows}
        if categories.get(f"/accounts/{private['other_account_id']}/notes") != "other_account":
            raise SystemExit(f"log categories: {categories}")
        if any(row["decision"] == "allowed" and row["in_scope"] is False for row in rows):
            raise SystemExit("proxy forwarded an out-of-scope request")
    finally:
        if running is not None:
            shutdown(running)
        tmp.cleanup()


def main():
    test_classify_expired()
    test_live_scope()
    print("scoped proxy checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
