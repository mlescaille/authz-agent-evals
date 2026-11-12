"""Executable checks for every planted bug.

Against the audited app, each exploit must observe another account's data
(or a modification of it). Against the reference app, the same steps must not.
A legitimate access check must succeed on both.
"""

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.api_client import DirectoryClient
from eval.proc_server import start_uvicorn, stop

MODULES = {
    "buggy": "app.main:app",
    "fixed": "eval.reference_app.main:app",
}


def marker(label):
    return f"{label}-{uuid.uuid4().hex[:8]}"


def body_has(response, text):
    return response.status_code == 200 and text in response.text


def merge(client, survivor, source):
    opened = client.call(
        "POST",
        "/merge-requests",
        token=survivor["token"],
        json={"source_account_id": source["id"]},
    )
    opened.raise_for_status()
    accepted = client.call(
        "POST",
        f"/merge-requests/{opened.json()['id']}/accept",
        token=source["token"],
    )
    accepted.raise_for_status()
    return accepted


def case_r1(client):
    previous = client.register("r1prev")
    current = client.register("r1next")
    created = client.call(
        "POST",
        "/devices",
        token=previous["token"],
        json={"serial": marker("serial"), "label": "sensor"},
    )
    created.raise_for_status()
    device_id = created.json()["id"]
    client.call(
        "POST",
        f"/devices/{device_id}/transfer",
        token=previous["token"],
        json={"to_account_id": current["id"]},
    ).raise_for_status()
    secret = marker("r1reading")
    client.call(
        "POST",
        f"/devices/{device_id}/readings",
        token=current["token"],
        json={"value": secret},
    ).raise_for_status()
    leaked = client.call(
        "GET",
        f"/devices/{device_id}/readings",
        token=previous["token"],
    )
    allowed = client.call(
        "GET",
        f"/devices/{device_id}/readings",
        token=current["token"],
    )
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(allowed, secret),
    }


def case_r2(client):
    grantor = client.register("r2grantor")
    grantee = client.register("r2grantee")
    secret = marker("r2note")
    client.call(
        "POST",
        f"/accounts/{grantor['id']}/notes",
        token=grantor["token"],
        json={"body": secret},
    ).raise_for_status()
    opened = client.call(
        "POST",
        "/links",
        token=grantor["token"],
        json={"grantee_account_id": grantee["id"]},
    )
    opened.raise_for_status()
    before = client.call(
        "GET",
        f"/accounts/{grantor['id']}/notes",
        token=grantee["token"],
    )
    client.call(
        "DELETE",
        f"/links/{opened.json()['id']}",
        token=grantor["token"],
    ).raise_for_status()
    after = client.call(
        "GET",
        f"/accounts/{grantor['id']}/notes",
        token=grantee["token"],
    )
    return {
        "exploit": body_has(after, secret),
        "legitimate": body_has(before, secret),
    }


def case_r3(client):
    owner = client.register("r3owner")
    sharer = client.register("r3sharer")
    created = client.call(
        "POST",
        "/devices",
        token=owner["token"],
        json={"serial": marker("serial"), "label": "shared-sensor"},
    )
    created.raise_for_status()
    device_id = created.json()["id"]
    secret = marker("r3devicenote")
    client.call(
        "POST",
        f"/devices/{device_id}/notes",
        token=owner["token"],
        json={"body": secret},
    ).raise_for_status()
    client.call(
        "POST",
        f"/devices/{device_id}/shares",
        token=owner["token"],
        json={"account_id": sharer["id"]},
    ).raise_for_status()
    own = marker("r3sharernote")
    client.call(
        "POST",
        f"/devices/{device_id}/notes",
        token=sharer["token"],
        json={"body": own},
    ).raise_for_status()
    leaked = client.call(
        "GET",
        f"/devices/{device_id}/notes",
        token=sharer["token"],
    )
    author = client.call(
        "GET",
        f"/devices/{device_id}/notes",
        token=owner["token"],
    )
    sharer_sees_own = body_has(leaked, own)
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(author, secret) and sharer_sees_own,
    }


def case_r4(client):
    survivor = client.register("r4survivor")
    source = client.register("r4source")
    secret = marker("r4note")
    client.call(
        "POST",
        f"/accounts/{survivor['id']}/notes",
        token=survivor["token"],
        json={"body": secret},
    ).raise_for_status()
    merge(client, survivor, source)
    leaked = client.call(
        "GET",
        f"/accounts/{survivor['id']}/notes",
        token=source["token"],
    )
    allowed = client.call(
        "GET",
        f"/accounts/{survivor['id']}/notes",
        token=survivor["token"],
    )
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(allowed, secret),
    }


def case_r5(client):
    grantor = client.register("r5grantor")
    grantee = client.register("r5grantee")
    secret = marker("r5note")
    client.call(
        "POST",
        f"/accounts/{grantee['id']}/notes",
        token=grantee["token"],
        json={"body": secret},
    ).raise_for_status()
    grantor_note = marker("r5grantornote")
    client.call(
        "POST",
        f"/accounts/{grantor['id']}/notes",
        token=grantor["token"],
        json={"body": grantor_note},
    ).raise_for_status()
    client.call(
        "POST",
        "/links",
        token=grantor["token"],
        json={"grantee_account_id": grantee["id"]},
    ).raise_for_status()
    leaked = client.call(
        "GET",
        f"/accounts/{grantee['id']}/notes",
        token=grantor["token"],
    )
    allowed = client.call(
        "GET",
        f"/accounts/{grantor['id']}/notes",
        token=grantee["token"],
    )
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(allowed, grantor_note),
    }


def case_r6(client):
    survivor = client.register("r6survivor")
    source = client.register("r6source")
    third = client.register("r6third")
    secret = marker("r6note")
    client.call(
        "POST",
        f"/accounts/{third['id']}/notes",
        token=third["token"],
        json={"body": secret},
    ).raise_for_status()
    client.call(
        "POST",
        "/links",
        token=third["token"],
        json={"grantee_account_id": source["id"]},
    ).raise_for_status()
    before = client.call(
        "GET",
        f"/accounts/{third['id']}/notes",
        token=source["token"],
    )
    merge(client, survivor, source)
    leaked = client.call(
        "GET",
        f"/accounts/{third['id']}/notes",
        token=survivor["token"],
    )
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(before, secret),
    }


def case_r7(client):
    owner = client.register("r7owner")
    sharer = client.register("r7sharer")
    nxt = client.register("r7next")
    created = client.call(
        "POST",
        "/devices",
        token=owner["token"],
        json={"serial": marker("serial"), "label": "meter"},
    )
    created.raise_for_status()
    device_id = created.json()["id"]
    early = marker("r7early")
    client.call(
        "POST",
        f"/devices/{device_id}/readings",
        token=owner["token"],
        json={"value": early},
    ).raise_for_status()
    client.call(
        "POST",
        f"/devices/{device_id}/shares",
        token=owner["token"],
        json={"account_id": sharer["id"]},
    ).raise_for_status()
    shared = client.call(
        "GET",
        f"/devices/{device_id}/readings",
        token=sharer["token"],
    )
    client.call(
        "POST",
        f"/devices/{device_id}/transfer",
        token=owner["token"],
        json={"to_account_id": nxt["id"]},
    ).raise_for_status()
    secret = marker("r7later")
    client.call(
        "POST",
        f"/devices/{device_id}/readings",
        token=nxt["token"],
        json={"value": secret},
    ).raise_for_status()
    leaked = client.call(
        "GET",
        f"/devices/{device_id}/readings",
        token=sharer["token"],
    )
    allowed = client.call(
        "GET",
        f"/devices/{device_id}/readings",
        token=nxt["token"],
    )
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(shared, early) and body_has(allowed, secret),
    }


def case_r8(client):
    survivor = client.register("r8survivor")
    source = client.register("r8source")
    grantee = client.register("r8grantee")
    secret = marker("r8preexisting")
    client.call(
        "POST",
        f"/accounts/{survivor['id']}/notes",
        token=survivor["token"],
        json={"body": secret},
    ).raise_for_status()
    source_note = marker("r8sourcenote")
    client.call(
        "POST",
        f"/accounts/{source['id']}/notes",
        token=source["token"],
        json={"body": source_note},
    ).raise_for_status()
    client.call(
        "POST",
        "/links",
        token=source["token"],
        json={"grantee_account_id": grantee["id"]},
    ).raise_for_status()
    before = client.call(
        "GET",
        f"/accounts/{source['id']}/notes",
        token=grantee["token"],
    )
    merge(client, survivor, source)
    leaked = client.call(
        "GET",
        f"/accounts/{survivor['id']}/notes",
        token=grantee["token"],
    )
    allowed = client.call(
        "GET",
        f"/accounts/{survivor['id']}/notes",
        token=survivor["token"],
    )
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(before, source_note) and body_has(allowed, secret),
    }


def case_c1(client):
    owner = client.register("c1owner")
    other = client.register("c1other")
    secret = marker("c1note")
    created = client.call(
        "POST",
        f"/accounts/{owner['id']}/notes",
        token=owner["token"],
        json={"body": secret},
    )
    created.raise_for_status()
    note_id = created.json()["id"]
    leaked = client.call("GET", f"/notes/{note_id}", token=other["token"])
    allowed = client.call("GET", f"/notes/{note_id}", token=owner["token"])
    return {
        "exploit": body_has(leaked, secret),
        "legitimate": body_has(allowed, secret),
    }


def case_c2(client):
    owner = client.register("c2owner")
    other = client.register("c2other")
    created = client.call(
        "POST",
        "/devices",
        token=owner["token"],
        json={"serial": marker("serial"), "label": "original-label"},
    )
    created.raise_for_status()
    device_id = created.json()["id"]
    secret = marker("c2label")
    client.call(
        "PATCH",
        f"/devices/{device_id}",
        token=other["token"],
        json={"label": secret},
    )
    seen = client.call("GET", f"/devices/{device_id}", token=owner["token"])
    owner_label = marker("c2owner")
    client.call(
        "PATCH",
        f"/devices/{device_id}",
        token=owner["token"],
        json={"label": owner_label},
    ).raise_for_status()
    seen_owner = client.call("GET", f"/devices/{device_id}", token=owner["token"])
    return {
        "exploit": body_has(seen, secret),
        "legitimate": body_has(seen_owner, owner_label),
    }


def case_c3(client):
    owner = client.register("c3owner")
    other = client.register("c3other")
    leaked = client.call("GET", f"/accounts/{owner['id']}", token=other["token"])
    allowed = client.call("GET", "/me", token=owner["token"])
    return {
        "exploit": body_has(leaked, owner["recovery_email"]),
        "legitimate": body_has(allowed, owner["recovery_email"]),
    }


CASES = [
    ("R1", case_r1),
    ("R2", case_r2),
    ("R3", case_r3),
    ("R4", case_r4),
    ("R5", case_r5),
    ("R6", case_r6),
    ("R7", case_r7),
    ("R8", case_r8),
    ("C1", case_c1),
    ("C2", case_c2),
    ("C3", case_c3),
]


def run_target(name):
    tmp = tempfile.TemporaryDirectory()
    database = Path(tmp.name) / "app.db"
    proc = None
    client = None
    results = []
    try:
        proc, base_url = start_uvicorn(MODULES[name], database)
        client = DirectoryClient(base_url)
        for bug_id, fn in CASES:
            outcome = fn(client)
            exploit_expected = name == "buggy"
            ok = outcome["exploit"] is exploit_expected and outcome["legitimate"] is True
            results.append(
                {
                    "bug_id": bug_id,
                    "target": name,
                    "exploit": outcome["exploit"],
                    "legitimate": outcome["legitimate"],
                    "pass": ok,
                }
            )
            print(
                f"{name:5} {bug_id:3} exploit={outcome['exploit']!s:5} "
                f"legitimate={outcome['legitimate']!s:5} pass={ok}"
            )
    finally:
        if client is not None:
            client.close()
        stop(proc)
        tmp.cleanup()
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["buggy", "fixed", "both"], default="both")
    parser.add_argument(
        "--out",
        default=str(ROOT / "results" / "exploit_checks.json"),
    )
    args = parser.parse_args()
    names = ["buggy", "fixed"] if args.target == "both" else [args.target]
    results = []
    for name in names:
        results.extend(run_target(name))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and args.target != "both":
        previous = json.loads(out.read_text())
        previous = [row for row in previous if row["target"] not in names]
        results = previous + results
    out.write_text(json.dumps(results, indent=2) + "\n")
    failed = [row for row in results if not row["pass"]]
    if failed:
        print(f"{len(failed)} check(s) failed")
        return 1
    print(f"all {len(results)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
