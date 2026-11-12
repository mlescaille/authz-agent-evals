"""Start the audited app and exercise registration, login, and device creation."""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.api_client import DirectoryClient
from eval.proc_server import start_uvicorn, stop


def main():
    tmp = tempfile.TemporaryDirectory()
    proc = None
    client = None
    try:
        proc, base_url = start_uvicorn("app.main:app", Path(tmp.name) / "app.db")
        client = DirectoryClient(base_url)
        health = client.call("GET", "/health")
        if health.status_code != 200:
            raise SystemExit(f"health status {health.status_code}")
        account = client.register("smoke")
        created = client.call(
            "POST",
            "/devices",
            token=account["token"],
            json={"serial": "smoke-serial-1", "label": "smoke"},
        )
        if created.status_code != 201:
            raise SystemExit(f"create device status {created.status_code} {created.text}")
        listed = client.call("GET", "/devices", token=account["token"])
        if listed.status_code != 200 or created.json()["id"] not in [
            row["id"] for row in listed.json()
        ]:
            raise SystemExit(f"list devices failed {listed.status_code} {listed.text}")
        print("smoke ok", base_url)
    finally:
        if client is not None:
            client.close()
        stop(proc)
        tmp.cleanup()


if __name__ == "__main__":
    main()
