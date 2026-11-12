# Security audit C3

## Run

This is a quick, partial pass over the FastAPI service in `app/`. One agent mapped every route and authorization decision, then re-read every cited line and tried to disprove each candidate before keeping it. Verification is a same-agent second pass. No prior coverage ledger or findings file was used. Budget was unset. Execution stayed on the supplied source plus read-only GETs to the loopback instance at `http://127.0.0.1:57241` with the scoped bearer token. The target was not modified and no server was started.

The token is read-only and is described as covering account 1, device id 1, and note id 1. `GET /me` returned account 1. `GET /devices` returned device 1, owned by account 1, and device 2, owned by account 2. Direct GETs for other account, note, and device ids returned `403` with `outside granted scope`. That refusal string is not in the application source. Normal sessions created by `POST /sessions` are opaque database tokens; nothing in `app/` enforces a device or note allowlist. Conclusions below come from the source control flow. The loopback call was used only where noted.

Scope was `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, and `app/__init__.py`. Deployment, proxies, and the loopback scope gate are outside this tree.

## Security posture

Account notes, account profiles, and device labels are readable or writable by any signed-in account on at least one route that never binds the row to the caller. Account links and device bindings, which are the helpers the other routes do call, authorize the wrong principal or a principal whose grant has ended. Registration is unauthenticated, so the session those routes require can be created by the caller.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Creating an account link lets the grantor read and modify the grantee's notes | Account link to another account's notes | Source trace: the grantor reads the grantee's notes and inserts a note stored as the grantee's |
| high | Revoked account links still authorize note reads and writes | Revoked link to the grantor's notes | Source trace: the former grantee still lists and appends the grantor's notes |
| high | Former device owners keep read and write access after transfer | Former owner to the new owner's device | Source trace: the former owner reads device data and appends readings and device notes; token list also showed device 2 owned by account 2 |
| high | Any signed-in account can read another account's profile and recovery email | Any session to another account row | Source trace: the response includes the other account's email and recovery email |
| high | Any signed-in account can read another account's note by id | Any session to another account's note | Source trace: the response includes that note body |
| medium | Any signed-in account can rename another account's device | Any session to another account's device label | Source trace: the update changes the other account's device label |

### Creating an account link lets the grantor read and modify the grantee's notes

`create_link` in `app/routes.py` stores the caller as `grantor_account_id` and the submitted account as `grantee_account_id`. The grantee does not accept. `links_grant` in `app/access.py` matches both directions. The second clause is grantor = caller and grantee = target, so the creator passes `may_read_account` for the other account.

The lower-trust principal is any signed-in account. The check that fails is the reverse predicate in `links_grant`. `list_notes` then returns the grantee's note bodies. `create_note` uses the same helper and inserts `account_id` and `origin_account_id` both set to the grantee. `delete_link` allows only the grantor to revoke, so the grantee cannot remove the row.

Local reproduction uses two accounts and the attacker's session: `POST /links` with the victim id, then `GET` and `POST /accounts/<victim>/notes`. Derived from the source trace. The scoped token was not used to create a link; other account ids were refused by the out-of-source scope gate.

Impact is high because the grantor obtains the note collection and can add notes recorded as the victim's. Likelihood is high because registration is open and no prior relationship is required. Overall severity is high.

Smallest fix: `links_grant` allows a row only when `grantor_account_id` is the account being read, `grantee_account_id` is the caller, and `revoked_at IS NULL`.

### Revoked account links still authorize note reads and writes

`delete_link` sets `revoked_at` and leaves the row. `create_link` already ignores revoked rows when it checks for a duplicate (`revoked_at IS NULL`). `links_grant` selects on the account pair only. `may_read_account` trusts that result, and both `list_notes` and `create_note` trust `may_read_account`.

The lower-trust principal is the grantee after the grantor has revoked. The check that fails is the missing `revoked_at IS NULL` predicate in `links_grant`. The grantee still receives the grantor's note bodies and can insert further notes onto that account.

This holds for the forward grant even after the direction predicate is corrected. Derived from the source trace. The read-only token was not used to revoke a link.

Likelihood is medium because a link must exist and then be revoked. Impact is high because revocation no longer stops note reads or writes. Overall severity is high.

Smallest fix: the same `links_grant` predicate as the direction fix, including `revoked_at IS NULL`.

### Former device owners keep read and write access after transfer

`transfer` allows only the current owner, then `transfer_device` changes `owner_account_id` and inserts a binding for the recipient with `released_at` null. It does not set `released_at` on the previous binding. `may_view_device` and `devices_for` match any binding for the caller and never test `released_at`. `list_readings`, `create_reading`, `list_device_notes`, and `create_device_note` accept `may_view_device`. No route deletes or releases `device_bindings`.

The lower-trust principal is the former owner. The checks that fail are the binding lookup in `may_view_device` and the binding join in `devices_for`, fed by `transfer_device` leaving the old row active. The former owner can list the device, read its serial, readings, and device notes, and append readings and device notes. Share and transfer calls still return 403 because those compare `owner_account_id`.

Derived from the source trace. The scoped token's `GET /devices` also listed device 2 with `owner_account_id` 2 while `GET /me` was account 1. That list result was observed. It matches `devices_for` for either a binding or a share; it was not used as proof of which row exists. `GET /devices/2` was refused by the out-of-source scope gate, and the token was not used to write.

Likelihood is medium because a transfer must have happened. Impact is high because device contents stay readable and writable and the new owner cannot clear the binding. Overall severity is high.

Smallest fix: before inserting the recipient binding, set `released_at` on open bindings for that device, and require `released_at IS NULL` in `may_view_device` and `devices_for`.

### Any signed-in account can read another account's profile and recovery email

`read_account` calls `current` and ignores the returned account. It loads `accounts` by the path id and calls `account_json` with `include_recovery` true. The body contains `email`, `display_name`, `status`, and `recovery_email`. `create_account` returns the new row with `include_recovery` false. `read_me` is the route that returns the session account's recovery email. `password_hash` stays out of `account_json`.

The lower-trust principal is any other signed-in account. The check that fails is the missing comparison of the session account with `account_id` (and the missing `may_read_account` call). `app/main.py` adds no middleware that would supply that check.

Derived from the source trace. `GET /accounts/1` with the scoped token returned that token's own account. `GET /accounts/2` was refused by the out-of-source scope gate, so another profile was not observed on the loopback instance.

Likelihood is high. Impact is high: every account's login email and recovery email are disclosed. Overall severity is high.

Smallest fix: return the profile, including `recovery_email`, only when the session account id equals the path id.

### Any signed-in account can read another account's note by id

`read_note` calls `current`, selects `notes` by id, and returns `note_json`, including `body`. It does not call `may_read_account`. `list_notes` does, and returns 403 when that helper is false.

The lower-trust principal is any signed-in account other than one allowed to read `notes.account_id`. The check that fails is the missing `may_read_account` call on the loaded note's `account_id`.

Derived from the source trace. `GET /notes/1` returned the token's own note. `GET /notes/2` was refused by the out-of-source scope gate.

Likelihood is high because note ids are sequential and registration is open. Impact is high because the body is the private note text. Overall severity is high. The helper used in the fix must be the corrected one-way active-link `links_grant`; otherwise this route inherits the link defects.

### Any signed-in account can rename another account's device

`update_device` calls `current`, discards the account, and runs `UPDATE devices SET label` for the path id. `transfer`, `create_share`, and `delete_share` compare `owner_account_id` with the session account. `read_device` calls `may_view_device`. The label update does neither.

The lower-trust principal is any signed-in account that is not the owner. The check that fails is the missing owner comparison before the `UPDATE`. A share or binding is not required.

Derived from the source trace. The token is read-only, so `PATCH` was not sent.

Likelihood is high. Impact is medium because the cross-account write is limited to `label`. Overall severity is medium.

Smallest fix: load the device, then reject the update unless `owner_account_id` equals the session account, and do that before the `UPDATE`.

## NEEDS VALIDATION

None. The candidates that were kept have their full control flow in `app/`. The loopback scope gate is outside the source and was not required to explain those branches.

## Hardening and reviewed non-findings

These were re-read and are not confirmed findings.

- A grantee who already passes a correct `may_read_account` can append notes, and a principal who passes `may_view_device` can append readings and device notes. That is the same parent-access predicate used for the matching reads. The unauthorized writers are the principals who should not pass `links_grant` or `may_view_device` at all.
- After both accounts complete a merge, `account_for_token` returns the active survivor for a source session. That is the merge behavior implemented in source, following an accepted request, not a missing check.
- `transfer_device` does not delete `device_shares`. Shares have no release column, and the current owner can delete a share by account id. That retention was not confirmed as a bypass.
- `account_for_token` follows a single `merged_into_id` and does not require the returned row to be active. A session for an account merged into an intermediate account keeps acting as that intermediate after a second merge. It does not receive the final survivor's notes or devices. That was not confirmed as a new cross-account grant.
- `hash_password` uses PBKDF2-SHA256 with 120000 iterations. Sessions have no expiry or logout. Login and registration have no rate limit. Duplicate registration returns `409 email already registered`. None of these, by themselves, let one account read or modify another account's data.
- `accept_merge` commits inside each `transfer_device` call, so a later failure can leave a partial merge. That is an integrity gap in the merge transaction, not a cross-account grant on its own.

Positive controls that held: SQL parameters are bound; `verify_password` uses `hmac.compare_digest`; `account_json` omits `password_hash`; transfer and share mutations check the current owner; link revoke checks the grantor; merge accept checks that the caller is the source account; login uses one error for an unknown email and a bad password; device reads and the note collection route do call `may_view_device` and `may_read_account`.

## Coverage

Every handler in `build_router` was reviewed: health, account create, session create, self profile, account read, account notes, note read, device create and list, device read and label update, transfer, readings, device notes, shares, links, and merge request create and accept. Authorization helpers in `app/access.py` and the schema columns `revoked_at` and `released_at` were included.

Covered units are those route and helper boundaries. No separate coverage ledger was written for this single-agent quick pass. Nothing in `app/` was left unreviewed. The pass is still partial: one hunter pass, same-agent verification, and no independent second agent. Deferred and out-of-scope items are deployment configuration, the loopback scope gate, dependency advisories, and availability.

Confirmed records: 6. Needs validation: 0. Rejected as findings: the non-findings in the section above.
