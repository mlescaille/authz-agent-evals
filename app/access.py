from app.db import now


def account_for_token(conn, token):
    row = conn.execute(
        "SELECT account_id FROM sessions WHERE token = ?",
        (token,),
    ).fetchone()
    if row is None:
        return None
    account = conn.execute(
        "SELECT * FROM accounts WHERE id = ?",
        (row["account_id"],),
    ).fetchone()
    if account is None:
        return None
    if account["merged_into_id"] is not None:
        survivor = conn.execute(
            "SELECT * FROM accounts WHERE id = ?",
            (account["merged_into_id"],),
        ).fetchone()
        if survivor is not None:
            return survivor
    return account


def links_grant(conn, caller_id, account_id):
    row = conn.execute(
        """
        SELECT id FROM account_links
        WHERE (grantor_account_id = ? AND grantee_account_id = ?)
           OR (grantor_account_id = ? AND grantee_account_id = ?)
        """,
        (account_id, caller_id, caller_id, account_id),
    ).fetchone()
    return row is not None


def may_read_account(conn, caller_id, account_id):
    if caller_id == account_id:
        return True
    return links_grant(conn, caller_id, account_id)


def may_view_device(conn, caller_id, device_id):
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ?",
        (device_id,),
    ).fetchone()
    if device is None:
        return False
    if int(device["owner_account_id"]) == int(caller_id):
        return True
    binding = conn.execute(
        """
        SELECT id FROM device_bindings
        WHERE device_id = ? AND account_id = ?
        """,
        (device_id, caller_id),
    ).fetchone()
    if binding is not None:
        return True
    share = conn.execute(
        """
        SELECT id FROM device_shares
        WHERE device_id = ? AND account_id = ?
        """,
        (device_id, caller_id),
    ).fetchone()
    return share is not None


def devices_for(conn, caller_id):
    return conn.execute(
        """
        SELECT DISTINCT d.*
        FROM devices d
        LEFT JOIN device_bindings b
          ON b.device_id = d.id AND b.account_id = ?
        LEFT JOIN device_shares s
          ON s.device_id = d.id AND s.account_id = ?
        WHERE d.owner_account_id = ?
           OR b.id IS NOT NULL
           OR s.id IS NOT NULL
        ORDER BY d.id
        """,
        (caller_id, caller_id, caller_id),
    ).fetchall()


def device_notes_for(conn, caller_id, device_id):
    if not may_view_device(conn, caller_id, device_id):
        return None
    return conn.execute(
        "SELECT * FROM device_notes WHERE device_id = ? ORDER BY id",
        (device_id,),
    ).fetchall()


def transfer_device(conn, device_id, to_account_id):
    conn.execute(
        "UPDATE devices SET owner_account_id = ? WHERE id = ?",
        (to_account_id, device_id),
    )
    conn.execute(
        """
        INSERT INTO device_bindings (device_id, account_id, bound_at, released_at)
        VALUES (?, ?, ?, NULL)
        """,
        (device_id, to_account_id, now()),
    )
    conn.commit()


def accept_merge(conn, source_id, request_id):
    req = conn.execute(
        "SELECT * FROM merge_requests WHERE id = ?",
        (request_id,),
    ).fetchone()
    if req is None:
        return "missing"
    if int(req["source_account_id"]) != int(source_id):
        return "forbidden"
    if req["status"] != "pending":
        return "conflict"
    survivor_id = int(req["survivor_account_id"])
    conn.execute(
        "UPDATE notes SET account_id = ? WHERE account_id = ?",
        (survivor_id, source_id),
    )
    conn.execute(
        "UPDATE readings SET author_account_id = ? WHERE author_account_id = ?",
        (survivor_id, source_id),
    )
    conn.execute(
        "UPDATE device_notes SET author_account_id = ? WHERE author_account_id = ?",
        (survivor_id, source_id),
    )
    devices = conn.execute(
        "SELECT id FROM devices WHERE owner_account_id = ?",
        (source_id,),
    ).fetchall()
    for device in devices:
        transfer_device(conn, int(device["id"]), survivor_id)
    conn.execute(
        """
        UPDATE account_links
        SET grantee_account_id = ?
        WHERE grantee_account_id = ?
        """,
        (survivor_id, source_id),
    )
    conn.execute(
        """
        UPDATE account_links
        SET grantor_account_id = ?
        WHERE grantor_account_id = ?
        """,
        (survivor_id, source_id),
    )
    conn.execute(
        """
        UPDATE accounts
        SET status = 'merged', merged_into_id = ?
        WHERE id = ?
        """,
        (survivor_id, source_id),
    )
    conn.execute(
        "UPDATE merge_requests SET status = 'accepted' WHERE id = ?",
        (request_id,),
    )
    conn.commit()
    return "ok"
