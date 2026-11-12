# Security audit A5

Quick profile, partial pass, single agent. Scope is the FastAPI and SQLite application under `app/` (`app/main.py` and the modules it loads). Budget was not set. Source ref was the supplied tree; the git commit was not read. Execution was source-only: there is no OS sandbox and the service was not started, so no request was sent. No prior run was used. Verification was a same-agent second pass: every cited line was read again and each candidate was kept only if that pass could not show a check that stops the cross-account effect.

This pass does not exhaust the target. It covers account, session, note, device, share, link, and merge authorization in the supplied source.

## Security posture

Signed-in accounts are isolated on some writes: device transfer, share create, share delete, and link revoke compare the caller with the owner or grantor, and merge accept requires the caller to be the source account. Note listing and device reads call helpers. Those helpers and several direct routes still let one account read or change another account's data. The widest gaps are note reads by id, account links that authorize the wrong party and survive revocation, device bindings that survive transfer, and source-account sessions that authorize the survivor after a merge.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Account link checks authorize another account's notes from a reversed or revoked link | Account A note store versus account B | A reads B's note bodies and inserts notes stored as B's; revoke does not stop it |
| medium | Any signed-in account can read another account's recovery email | Account profile | A receives B's recovery email |
| high | Previous device owner keeps access through an unreleased binding | Device owner versus previous owner | Previous owner reads and appends readings and notes after transfer |
| medium | Any signed-in account can rename another account's device | Device label | A changes B's device label |
| high | A source-account session authorizes the survivor after a merge | Survivor account versus source session | A source token reads and acts as the survivor |
| high | Any signed-in account can read another account's note by id | Account notes | A receives B's note body by id |

### Account link checks authorize another account's notes from a reversed or revoked link

- Source: `app/access.py` `links_grant` and `may_read_account`; `app/routes.py` `create_link`, `delete_link`, `list_notes`, and `create_note`.
- Lower-trust principal: signed-in account A, who is not the owner of account B's notes.
- Failed check: `links_grant` matches a link in either direction and ignores `revoked_at`. `create_note` and `list_notes` treat that result as permission to read and append B's notes. `delete_link` lets only the grantor set `revoked_at`, and the row remains.
- Reproduction: as A, `POST /links` with `grantee_account_id` B, then `GET` and `POST /accounts/{B}/notes`. Then, as the grantor, `DELETE /links/{id}` and repeat the note calls.
- Conditions: A has a bearer token, B is a different active account for the create path, and a remaining link row is enough after revoke.
- Result: A reads every note body stored for B and inserts a note whose `account_id` and `origin_account_id` are B. The same calls succeed after `revoked_at` is set. Derived from the source trace.
- Impact: high. Any signed-in account can read and extend another active account's notes, and the product's revoke operation does not end that access. Overall severity is high.
- Fix: in `links_grant`, require `grantor_account_id` to be the target account, `grantee_account_id` to be the caller, and `revoked_at IS NULL`.

### Any signed-in account can read another account's recovery email

- Source: `app/routes.py` `read_account` and `account_json`.
- Lower-trust principal: any signed-in account other than the requested account.
- Failed check: `read_account` discards the account from `current()` and calls `account_json` with `include_recovery=True`. `GET /me` is the path that returns that field for the token's own account.
- Reproduction: `GET /accounts/{B}` with A's bearer token.
- Conditions: a valid bearer token and an existing account id.
- Result: the response includes B's email, display name, status, and recovery email. Derived from the source trace.
- Impact: medium. The field is private in this source, and the response does not include the password hash, notes, or devices. Overall severity is medium.
- Fix: return the row, including `recovery_email`, only when the session account id equals the path id; otherwise return 403.

### Previous device owner keeps access through an unreleased binding

- Source: `app/routes.py` `create_device` and `transfer`; `app/access.py` `transfer_device`, `may_view_device`, and `devices_for`.
- Lower-trust principal: the account that owned the device before `POST /devices/{id}/transfer`.
- Failed check: transfer changes `owner_account_id` but does not set `released_at` on the binding created for the old owner. `may_view_device` and `devices_for` authorize any binding for that account. The owner comparison on a later transfer rejects the previous owner, so the binding path is weaker than the ownership path.
- Reproduction: as A, create a device and transfer it to B. As B, add a reading and a device note. As A, list readings and notes and `POST` a reading.
- Conditions: A's original `device_bindings` row is still present with `released_at` null, and A still has a session.
- Result: A reads readings and device notes added after B became owner, and A can insert a new reading on B's device. Derived from the source trace.
- Impact: high. The previous owner keeps content read and append access after ownership moved. Overall severity is high.
- Fix: release unreleased bindings for the device inside `transfer_device`, and require `released_at IS NULL` in `may_view_device` and `devices_for`.

### Any signed-in account can rename another account's device

- Source: `app/routes.py` `update_device`.
- Lower-trust principal: any signed-in account other than `devices.owner_account_id`.
- Failed check: `update_device` discards the caller and runs `UPDATE devices SET label` by device id. `transfer` and `create_share` compare `owner_account_id` with the caller before they change the same object.
- Reproduction: `PATCH /devices/{id}` with a non-owner token and a non-empty label.
- Conditions: a valid bearer token, an existing device, and a non-empty label. No share or binding is required.
- Result: the caller changes the label of another account's device. Derived from the source trace.
- Impact: medium. The write is limited to the label. Overall severity is medium.
- Fix: require the session account to equal `owner_account_id` before the update.

### A source-account session authorizes the survivor after a merge

- Source: `app/routes.py` `accept_merge`, `current`, and `create_session`; `app/access.py` `accept_merge` and `account_for_token`.
- Lower-trust principal: any holder of a bearer token whose `sessions.account_id` is the source account, including a session that did not call accept.
- Failed check: `accept_merge` disables the source account and sets `merged_into_id` without deleting source sessions. `account_for_token` then returns the survivor. `create_session` refuses a non-active account, but `current()` does not apply that rule to an existing token.
- Reproduction: S creates a merge naming source A. A accepts with one source token. Call `GET /me` and `GET /accounts/{S}/notes` with that token and with A's other pre-merge token.
- Conditions: a pending merge was accepted, and a sessions row for the source still exists. The survivor has data that was not copied from the source.
- Result: each source token is authorized as the survivor, including for the survivor's pre-existing recovery email and notes. Derived from the source trace.
- Impact: high. The source credential can act as the survivor, not only read the records the merge copied. Likelihood is medium because the survivor must name the source and the source must accept. Overall severity is high.
- Fix: resolve a token only to its own active `sessions.account_id`, and delete the source account's sessions when the merge is accepted. Issue a new survivor token only if the accept response is meant to keep the accepting caller signed in.

### Any signed-in account can read another account's note by id

- Source: `app/routes.py` `read_note`. The collection route `list_notes` is the contrasting check.
- Lower-trust principal: any signed-in account that `may_read_account` would refuse for the note's `account_id`.
- Failed check: `read_note` discards the caller and selects `notes` by id, then returns `body`.
- Reproduction: `GET /notes/{id}` with an unrelated account's token.
- Conditions: a valid bearer token and an existing note id. No link is required.
- Result: the caller receives the other account's note body, `account_id`, and `origin_account_id`. Derived from the source trace.
- Impact: high. The private note body is readable by any signed-in account that knows or guesses the integer id. Overall severity is high.
- Fix: after the load, apply the same account check as `list_notes`, using the corrected link predicate.

## NEEDS VALIDATION

None. The retained results are fully determined by the supplied source. No deployment, proxy, or browser fact decides them.

## Hardening and reviewed non-findings

These were considered on a second read and are not confirmed findings.

- Password hashing uses PBKDF2-HMAC-SHA256 with a fixed iteration count, and login has no rate limit. Neither one lets one account read or change another account's data.
- Sessions have no expiry or logout route. That is session lifetime design except where a source session starts authorizing the survivor, which is confirmed separately.
- `may_view_device` also authorizes share recipients to append readings and device notes. The share row is an explicit grant, and the device routes consistently use that helper for appends, so this was not treated as a missing check.
- `transfer_device` does not delete `device_shares`. A prior share recipient can still pass `may_view_device` until the new owner deletes that share. The share is stored on the device, and the new owner is allowed to delete it, so the source does not show that transfer was required to clear it.
- `create_note` stores the path account as both `account_id` and `origin_account_id`. A grantee who already passes the corrected `may_read_account` can append a note that does not record the caller. Device notes do record `author_account_id`. This was not confirmed as a separate break because the device routes already treat a grant as append access.
- `create_merge` can name any active account, and only `accept_merge` moves data. The pending row does not by itself disclose or change the source account.
- Direct note and account reads already return the objects whose existence a 404-versus-403 difference would only hint at.

Positive patterns in the same tree: SQL parameters are bound; session tokens are random and stored server-side; password comparison uses `hmac.compare_digest`; transfer, share create, share delete, and link revoke bind the actor to the owner or grantor; merge accept requires the caller to be the named source; note listing and the device read helpers do call an authorization function.

## Coverage

The quick profile used one hunter pass and one same-agent verification pass over `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, and `app/__init__.py`. No prior ledger existed. Units were the account-profile read, note list and note-by-id read, note create, device list and device read, device label update, device transfer and bindings, device shares, readings and device notes, account links and revocation, sessions, and merge accept. Six confirmed records survived the second pass. No needs-validation record was kept. The service was not executed. This is a partial pass, not a claim that every other behavior is safe.
