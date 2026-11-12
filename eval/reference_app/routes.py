import secrets
import sqlite3

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from eval.reference_app import access
from app.db import now
from app.passwords import hash_password, verify_password


class AccountCreate(BaseModel):
    email: str
    display_name: str
    recovery_email: str
    password: str


class SessionCreate(BaseModel):
    email: str
    password: str


class NoteCreate(BaseModel):
    body: str


class DeviceCreate(BaseModel):
    serial: str
    label: str


class DeviceUpdate(BaseModel):
    label: str


class TransferCreate(BaseModel):
    to_account_id: int


class ReadingCreate(BaseModel):
    value: str


class ShareCreate(BaseModel):
    account_id: int


class LinkCreate(BaseModel):
    grantee_account_id: int


class MergeCreate(BaseModel):
    source_account_id: int


def fail(status, detail):
    raise HTTPException(status_code=status, detail=detail)


def current(request: Request):
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        fail(401, "missing token")
    token = header[7:].strip()
    if not token:
        fail(401, "missing token")
    account = access.account_for_token(request.app.state.conn, token)
    if account is None:
        fail(401, "invalid token")
    return account


def account_json(row, include_recovery):
    body = {
        "id": row["id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "status": row["status"],
    }
    if include_recovery:
        body["recovery_email"] = row["recovery_email"]
    return body


def note_json(row):
    return {
        "id": row["id"],
        "account_id": row["account_id"],
        "origin_account_id": row["origin_account_id"],
        "body": row["body"],
        "created_at": row["created_at"],
    }


def device_json(row):
    return {
        "id": row["id"],
        "serial": row["serial"],
        "label": row["label"],
        "owner_account_id": row["owner_account_id"],
        "created_at": row["created_at"],
    }


def reading_json(row):
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "author_account_id": row["author_account_id"],
        "value": row["value"],
        "created_at": row["created_at"],
    }


def device_note_json(row):
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "author_account_id": row["author_account_id"],
        "body": row["body"],
        "created_at": row["created_at"],
    }


def link_json(row):
    return {
        "id": row["id"],
        "grantor_account_id": row["grantor_account_id"],
        "grantee_account_id": row["grantee_account_id"],
        "created_at": row["created_at"],
        "revoked_at": row["revoked_at"],
    }


def active_account(conn, account_id):
    row = conn.execute(
        "SELECT * FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    if row is None or row["status"] != "active":
        return None
    return row


def has_text(value):
    return isinstance(value, str) and value.strip() != ""


def build_router():
    router = APIRouter()

    @router.get("/health")
    def health():
        return {"status": "ok"}

    @router.post("/accounts", status_code=201)
    def create_account(body: AccountCreate, request: Request):
        email = body.email.strip().lower()
        recovery = body.recovery_email.strip().lower()
        display_name = body.display_name.strip()
        if "@" not in email or "@" not in recovery or not display_name:
            fail(400, "invalid account")
        if len(body.password) < 8:
            fail(400, "invalid account")
        conn = request.app.state.conn
        try:
            cur = conn.execute(
                """
                INSERT INTO accounts (
                    email, display_name, recovery_email, password_hash, status, created_at
                ) VALUES (?, ?, ?, ?, 'active', ?)
                """,
                (email, display_name, recovery, hash_password(body.password), now()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            fail(409, "email already registered")
        row = conn.execute(
            "SELECT * FROM accounts WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return account_json(row, include_recovery=False)

    @router.post("/sessions", status_code=201)
    def create_session(body: SessionCreate, request: Request):
        email = body.email.strip().lower()
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM accounts WHERE email = ?",
            (email,),
        ).fetchone()
        if row is None or row["status"] != "active":
            fail(401, "invalid credentials")
        if not verify_password(body.password, row["password_hash"]):
            fail(401, "invalid credentials")
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, account_id, created_at) VALUES (?, ?, ?)",
            (token, row["id"], now()),
        )
        conn.commit()
        return {"token": token, "account_id": row["id"]}

    @router.get("/me")
    def read_me(request: Request):
        account = current(request)
        return account_json(account, include_recovery=True)

    @router.get("/accounts/{account_id}")
    def read_account(account_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if int(account["id"]) != int(row["id"]) and not access.may_read_account(
            conn, account["id"], row["id"]
        ):
            fail(403, "forbidden")
        return account_json(row, include_recovery=int(account["id"]) == int(row["id"]))

    @router.post("/accounts/{account_id}/notes", status_code=201)
    def create_note(account_id: int, body: NoteCreate, request: Request):
        account = current(request)
        conn = request.app.state.conn
        if not has_text(body.body):
            fail(400, "invalid note")
        if active_account(conn, account_id) is None:
            fail(404, "not found")
        if not access.may_read_account(conn, account["id"], account_id):
            fail(403, "forbidden")
        cur = conn.execute(
            """
            INSERT INTO notes (account_id, origin_account_id, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (account_id, account_id, body.body, now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM notes WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return note_json(row)

    @router.get("/accounts/{account_id}/notes")
    def list_notes(account_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        if conn.execute(
            "SELECT id FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone() is None:
            fail(404, "not found")
        if not access.may_read_account(conn, account["id"], account_id):
            fail(403, "forbidden")
        rows = conn.execute(
            "SELECT * FROM notes WHERE account_id = ? ORDER BY id",
            (account_id,),
        ).fetchall()
        return [note_json(row) for row in rows]

    @router.get("/notes/{note_id}")
    def read_note(note_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if not access.may_read_account(conn, account["id"], row["account_id"]):
            fail(403, "forbidden")
        return note_json(row)

    @router.post("/devices", status_code=201)
    def create_device(body: DeviceCreate, request: Request):
        account = current(request)
        serial = body.serial.strip()
        label = body.label.strip()
        if not serial or not label:
            fail(400, "invalid device")
        conn = request.app.state.conn
        try:
            cur = conn.execute(
                """
                INSERT INTO devices (serial, label, owner_account_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (serial, label, account["id"], now()),
            )
            conn.execute(
                """
                INSERT INTO device_bindings (device_id, account_id, bound_at, released_at)
                VALUES (?, ?, ?, NULL)
                """,
                (cur.lastrowid, account["id"], now()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            fail(409, "serial already registered")
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return device_json(row)

    @router.get("/devices")
    def list_devices(request: Request):
        account = current(request)
        rows = access.devices_for(request.app.state.conn, account["id"])
        return [device_json(row) for row in rows]

    @router.get("/devices/{device_id}")
    def read_device(device_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if not access.may_view_device(conn, account["id"], device_id):
            fail(403, "forbidden")
        return device_json(row)

    @router.patch("/devices/{device_id}")
    def update_device(device_id: int, body: DeviceUpdate, request: Request):
        account = current(request)
        label = body.label.strip()
        if not label:
            fail(400, "invalid device")
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if int(row["owner_account_id"]) != int(account["id"]):
            fail(403, "forbidden")
        conn.execute(
            "UPDATE devices SET label = ? WHERE id = ?",
            (label, device_id),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        return device_json(updated)

    @router.post("/devices/{device_id}/transfer")
    def transfer(device_id: int, body: TransferCreate, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if int(row["owner_account_id"]) != int(account["id"]):
            fail(403, "forbidden")
        if int(body.to_account_id) == int(account["id"]):
            fail(400, "invalid transfer")
        if active_account(conn, body.to_account_id) is None:
            fail(404, "not found")
        access.transfer_device(conn, device_id, body.to_account_id)
        updated = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        return device_json(updated)

    @router.post("/devices/{device_id}/readings", status_code=201)
    def create_reading(device_id: int, body: ReadingCreate, request: Request):
        account = current(request)
        if not has_text(body.value):
            fail(400, "invalid reading")
        conn = request.app.state.conn
        if conn.execute(
            "SELECT id FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone() is None:
            fail(404, "not found")
        if not access.may_view_device(conn, account["id"], device_id):
            fail(403, "forbidden")
        cur = conn.execute(
            """
            INSERT INTO readings (device_id, author_account_id, value, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (device_id, account["id"], body.value, now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM readings WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return reading_json(row)

    @router.get("/devices/{device_id}/readings")
    def list_readings(device_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        if conn.execute(
            "SELECT id FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone() is None:
            fail(404, "not found")
        if not access.may_view_device(conn, account["id"], device_id):
            fail(403, "forbidden")
        rows = conn.execute(
            "SELECT * FROM readings WHERE device_id = ? ORDER BY id",
            (device_id,),
        ).fetchall()
        return [reading_json(row) for row in rows]

    @router.post("/devices/{device_id}/notes", status_code=201)
    def create_device_note(device_id: int, body: NoteCreate, request: Request):
        account = current(request)
        if not has_text(body.body):
            fail(400, "invalid note")
        conn = request.app.state.conn
        if conn.execute(
            "SELECT id FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone() is None:
            fail(404, "not found")
        if not access.may_view_device(conn, account["id"], device_id):
            fail(403, "forbidden")
        cur = conn.execute(
            """
            INSERT INTO device_notes (device_id, author_account_id, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (device_id, account["id"], body.body, now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM device_notes WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return device_note_json(row)

    @router.get("/devices/{device_id}/notes")
    def list_device_notes(device_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        if conn.execute(
            "SELECT id FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone() is None:
            fail(404, "not found")
        rows = access.device_notes_for(conn, account["id"], device_id)
        if rows is None:
            fail(403, "forbidden")
        return [device_note_json(row) for row in rows]

    @router.post("/devices/{device_id}/shares", status_code=201)
    def create_share(device_id: int, body: ShareCreate, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if int(row["owner_account_id"]) != int(account["id"]):
            fail(403, "forbidden")
        if int(body.account_id) == int(account["id"]):
            fail(400, "invalid share")
        if active_account(conn, body.account_id) is None:
            fail(404, "not found")
        existing = conn.execute(
            """
            SELECT id FROM device_shares
            WHERE device_id = ? AND account_id = ?
            """,
            (device_id, body.account_id),
        ).fetchone()
        if existing is not None:
            fail(409, "share already exists")
        cur = conn.execute(
            """
            INSERT INTO device_shares (device_id, account_id, created_at)
            VALUES (?, ?, ?)
            """,
            (device_id, body.account_id, now()),
        )
        conn.commit()
        return {
            "id": cur.lastrowid,
            "device_id": device_id,
            "account_id": body.account_id,
        }

    @router.delete("/devices/{device_id}/shares/{account_id}")
    def delete_share(device_id: int, account_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if int(row["owner_account_id"]) != int(account["id"]):
            fail(403, "forbidden")
        conn.execute(
            "DELETE FROM device_shares WHERE device_id = ? AND account_id = ?",
            (device_id, account_id),
        )
        conn.commit()
        return {"device_id": device_id, "account_id": account_id, "removed": True}

    @router.post("/links", status_code=201)
    def create_link(body: LinkCreate, request: Request):
        account = current(request)
        conn = request.app.state.conn
        if int(body.grantee_account_id) == int(account["id"]):
            fail(400, "invalid link")
        if active_account(conn, body.grantee_account_id) is None:
            fail(404, "not found")
        existing = conn.execute(
            """
            SELECT id FROM account_links
            WHERE grantor_account_id = ? AND grantee_account_id = ? AND revoked_at IS NULL
            """,
            (account["id"], body.grantee_account_id),
        ).fetchone()
        if existing is not None:
            fail(409, "link already exists")
        cur = conn.execute(
            """
            INSERT INTO account_links (
                grantor_account_id, grantee_account_id, created_at, revoked_at
            ) VALUES (?, ?, ?, NULL)
            """,
            (account["id"], body.grantee_account_id, now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM account_links WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return link_json(row)

    @router.get("/links")
    def list_links(request: Request):
        account = current(request)
        rows = request.app.state.conn.execute(
            """
            SELECT * FROM account_links
            WHERE grantor_account_id = ? OR grantee_account_id = ?
            ORDER BY id
            """,
            (account["id"], account["id"]),
        ).fetchall()
        return [link_json(row) for row in rows]

    @router.delete("/links/{link_id}")
    def delete_link(link_id: int, request: Request):
        account = current(request)
        conn = request.app.state.conn
        row = conn.execute(
            "SELECT * FROM account_links WHERE id = ?",
            (link_id,),
        ).fetchone()
        if row is None:
            fail(404, "not found")
        if int(row["grantor_account_id"]) != int(account["id"]):
            fail(403, "forbidden")
        if row["revoked_at"] is None:
            conn.execute(
                "UPDATE account_links SET revoked_at = ? WHERE id = ?",
                (now(), link_id),
            )
            conn.commit()
        updated = conn.execute(
            "SELECT * FROM account_links WHERE id = ?",
            (link_id,),
        ).fetchone()
        return link_json(updated)

    @router.post("/merge-requests", status_code=201)
    def create_merge(body: MergeCreate, request: Request):
        account = current(request)
        conn = request.app.state.conn
        if int(body.source_account_id) == int(account["id"]):
            fail(400, "invalid merge")
        if active_account(conn, body.source_account_id) is None:
            fail(404, "not found")
        existing = conn.execute(
            """
            SELECT id FROM merge_requests
            WHERE survivor_account_id = ? AND source_account_id = ? AND status = 'pending'
            """,
            (account["id"], body.source_account_id),
        ).fetchone()
        if existing is not None:
            fail(409, "merge already pending")
        cur = conn.execute(
            """
            INSERT INTO merge_requests (
                survivor_account_id, source_account_id, status, created_at
            ) VALUES (?, ?, 'pending', ?)
            """,
            (account["id"], body.source_account_id, now()),
        )
        conn.commit()
        return {
            "id": cur.lastrowid,
            "survivor_account_id": account["id"],
            "source_account_id": body.source_account_id,
            "status": "pending",
        }

    @router.post("/merge-requests/{request_id}/accept")
    def accept_merge(request_id: int, request: Request):
        account = current(request)
        result = access.accept_merge(request.app.state.conn, account["id"], request_id)
        if result == "missing":
            fail(404, "not found")
        if result == "forbidden":
            fail(403, "forbidden")
        if result == "conflict":
            fail(409, "merge is not pending")
        return {"id": request_id, "status": "accepted"}

    return router
