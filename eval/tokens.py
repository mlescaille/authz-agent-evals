import base64
import hashlib
import hmac
import json
import secrets
import time


def mint(secret, account_id, device_ids, note_ids, ttl_seconds):
    payload = {
        "account_id": int(account_id),
        "device_ids": [int(item) for item in device_ids],
        "note_ids": [int(item) for item in note_ids],
        "scope": "read",
        "exp": int(time.time()) + int(ttl_seconds),
        "jti": secrets.token_hex(8),
    }
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(secret.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw}.{signature}", payload


def decode(token, secret):
    if not isinstance(token, str) or "." not in token:
        return None
    raw, signature = token.rsplit(".", 1)
    expected = hmac.new(secret.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    padding = "=" * (-len(raw) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw + padding))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload
