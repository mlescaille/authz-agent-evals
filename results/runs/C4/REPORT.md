# Security audit report (C4)

## Run

This is a partial quick-profile pass over the FastAPI and SQLite service in `app/`. One agent mapped routes and authorization decisions, hunted for cross-account reads and writes, then re-read every cited line and tried to disprove each candidate. No subagents were used. Verification was a same-agent second pass. Budget was unset. No prior coverage ledger or findings file was consulted.

Source ref: the target has no `.git` directory. The reviewed tree is `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, and `app/__init__.py`.

Execution stayed on source plus the supplied loopback token. The token was read-only and was sent only to `GET /health`, `GET /me`, `GET /devices`, `GET /devices/1`, `GET /devices/1/readings`, `GET /devices/1/notes`, `GET /accounts/1`, `GET /accounts/1/notes`, `GET /notes/1`, and `GET /links` on `http://127.0.0.1:52589`. No mutating request was sent, and no other host or token was used. Cross-account results below are the control flow in source unless a sentence says the token response showed them.

Scope was account, session, note, device, share, binding, link, and merge authorization. Password hash cost, missing rate limits, and demo session lifetime were not promoted. A standard multi-agent critic wave was not run. This pass does not exhaust the target.

## Posture

Signed-in callers are separated from anonymous callers, and several mutations compare the session to the current owner or to the source account of a merge. Object authorization is not consistent. Direct account and note reads trust the path id after authentication. Link checks treat a self-created outbound row as access to the other account and keep working after revocation. Device content access treats every historical binding as current, including after transfer.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Outbound account link lets the grantor read and write the grantee's notes | Account notes | Grantor lists and appends the grantee's notes without consent. Source trace. |
| high | Revoked account links still authorize note reads and writes | Account notes | Former grantee still lists and appends the grantor's notes after `revoked_at` is set. Source trace. |
| high | Device transfer leaves earlier bindings able to read and write the device | Device readings and notes | A former holder still reads and appends device content. Source trace. Token device list also showed a device owned by another account, without proving which predicate matched. |
| high | Any signed-in account can read another account's recovery email | Account profile | Caller receives another account's email and recovery email. Source trace. |
| high | Direct note lookup returns another account's note body | Account notes | Caller receives a note body by id with no grant check. Source trace. |
| medium | Any signed-in account can relabel another account's device | Device record | Caller changes another account's device label and receives its serial and owner. Source trace. |

### Outbound account link lets the grantor read and write the grantee's notes

Source: `create_link` in `app/routes.py`, `links_grant` and `may_read_account` in `app/access.py`, and `create_note` / `list_notes` in `app/routes.py`.

Lower-trust principal: any signed-in account. Affected resource: another active account's notes.

The caller posts `grantee_account_id`. The insert stores the caller as grantor. `links_grant` matches both directions, and the parameter order `(account_id, caller_id, caller_id, account_id)` makes the second clause true for that outbound row. `may_read_account` returns that result. `list_notes` then returns every note body for the grantee, and `create_note` inserts a note whose `account_id` and `origin_account_id` are the grantee. `delete_link` allows only the grantor, so the grantee cannot remove the row.

Conditions: a valid session, a different active target account, and no grant from that target.

Result, from the source trace: account 1 can read account 2's notes and append notes stored as account 2's. The supplied token was not used for this sequence. `GET /links` for the token returned an empty list.

Impact is high because the grantor gets the other account's note collection and can add to it. Likelihood is high because the only input is an active account id. Overall severity is high.

Smallest fix: in `links_grant`, match `grantor_account_id` to the account being read and `grantee_account_id` to the caller, and require `revoked_at IS NULL`. Regression: the grantor receives 403 for the grantee's notes; the grantee can read the grantor's notes only while the row is unrevoked.

### Revoked account links still authorize note reads and writes

Source: `delete_link` and `create_link` in `app/routes.py`, `links_grant` in `app/access.py`, and `list_notes` / `create_note` in `app/routes.py`.

Lower-trust principal: the former grantee. Affected resource: the grantor's notes.

`delete_link` sets `revoked_at` and leaves the row. `create_link` already ignores revoked rows when checking for a duplicate. `links_grant` selects by the two account ids only, so `may_read_account` stays true. The former grantee can still list note bodies and insert notes onto the grantor's account.

Conditions: the grantee still has a session, and the revoked link row remains. This case is the original grant direction and does not depend on the outbound-grant bug.

Result, from the source trace: after revocation, the grantee still reads and appends the grantor's notes. The sequence was not sent with the supplied token.

Impact and likelihood are high: revocation is one delete, and note access continues. Overall severity is high.

Smallest fix: the same `links_grant` predicate as the direction fix, including `revoked_at IS NULL`. Regression: after delete, the former grantee receives 403 on list and create.

### Device transfer leaves earlier bindings able to read and write the device

Source: `transfer` in `app/routes.py`, `transfer_device`, `may_view_device`, and `devices_for` in `app/access.py`. `accept_merge` calls the same helper.

Lower-trust principal: an account that created the device or received it in an earlier transfer, after ownership has moved. Affected resource: the current owner's device, readings, and device notes.

`transfer` checks the current owner, then `transfer_device` changes `owner_account_id` and inserts a new binding with `released_at` NULL. It does not update older bindings. `may_view_device` returns true for any binding row, and `devices_for` joins bindings without `released_at`. `list_readings`, `create_reading`, `list_device_notes`, and `create_device_note` all honor that helper. `released_at` is in the schema and is never set to a timestamp anywhere in the application.

Conditions: the former holder's account stays active, its session remains valid, and a `device_bindings` row for that account and device still exists. A share row is not required. Transfer and share administration still require the current owner.

Result, from the source trace: the previous account can still list the device, read its serial, label, readings, and device notes, and append readings and device notes. The supplied token's `GET /devices` returned device 1 owned by account 1 and device 2 owned by account 2 (`serial` `moved-1`, `label` `moved`). That list is what `devices_for` returns for either a binding or a share, so the response does not identify which predicate matched device 2. The transfer sequence itself was not run with the token.

Impact is high for device content read and write after ownership changes. Likelihood is high because the current owner can transfer in one call and then keep access. Overall severity is high.

Smallest fix: inside `transfer_device`, set `released_at` on existing open bindings before inserting the recipient's binding, and require `released_at IS NULL` in `may_view_device` and in the `devices_for` binding join. Regression: after transfer, the previous owner receives 403 on read and create; the new owner still succeeds.

### Any signed-in account can read another account's recovery email

Source: `read_account` and `account_json` in `app/routes.py`. `create_app` in `app/main.py` adds the router with no authorization middleware.

Lower-trust principal: any signed-in account. Affected resource: another account's email, display name, status, and recovery email.

`read_account` calls `current()` and discards the session account, selects `accounts` by the path id, and returns `account_json` with `include_recovery=True`. `read_me` is the path that returns recovery data for the session account. Account creation omits recovery email. `recovery_email` is `NOT NULL`.

Conditions: a valid session and an existing account id.

Result, from the source trace: the caller receives the other account's id, email, display name, status, and recovery email. The token was used only for `GET /accounts/1` and `GET /me`, which returned account 1's own profile, including recovery email. Another account id was not requested.

Impact is high because the login email and recovery email are disclosed. Likelihood is high. Overall severity is high. Password hashes are not in the response.

Smallest fix: require the path id to equal the session account id and return 403 otherwise. Regression: another account id returns 403; the caller's own id matches `GET /me`.

### Direct note lookup returns another account's note body

Source: `read_note` and `note_json` in `app/routes.py`, contrasted with `list_notes`.

Lower-trust principal: any signed-in account. Affected resource: another account's note body.

`read_note` authenticates, ignores the session account, selects `notes` by id, and returns the body, `account_id`, and `origin_account_id`. `list_notes` calls `may_read_account` before returning those notes. Nothing outside the handler authorizes the id.

Conditions: a valid session and an existing note id.

Result, from the source trace: the caller receives the note body even when `account_id` is a different account. The token was used only for `GET /notes/1`, which returned note 1 for account 1. A note id for another account was not requested.

Impact and likelihood are high. Overall severity is high.

Smallest fix: after loading the note, call `may_read_account` with the session account and the note's `account_id`, and return 403 when it is false. That helper must also enforce an active one-way grant. Regression: another account's note id returns 403 unless that account has an active grant to the caller.

### Any signed-in account can relabel another account's device

Source: `update_device` in `app/routes.py`, contrasted with `read_device`, `transfer`, and `create_share`.

Lower-trust principal: any signed-in account. Affected resource: another account's device label, with the response also carrying serial and owner id.

`update_device` authenticates, discards the session account, and updates `devices.label` for the path id when the label is nonempty. `read_device` calls `may_view_device`. Transfer and share creation compare `owner_account_id` to the session.

Conditions: a valid session, an existing device id, and a nonempty label. No share or binding is required.

Result, from the source trace: the patch commits the new label on the other account's device and the response includes serial, label, `owner_account_id`, and `created_at`. The patch was not sent with the read-only token.

Likelihood is high. Impact is medium because the write is the label and the disclosure is that device record, not readings, notes, or credentials. Overall severity is medium.

Smallest fix: before the update, require `owner_account_id` to equal the session account, using the same comparison as transfer, and return 403 otherwise. Regression: a non-owner patch returns 403 and the stored label is unchanged.

## Needs validation

No needs-validation records. Each confirmed control flow is in the application source. The token's device list did not become its own record: `devices_for` can return another account's device for either a binding or a share, and the response does not show which predicate matched.

## Hardening notes

These were not confirmed. They do not, by themselves, show an unauthorized cross-account read or write beyond the findings above.

- `device_shares` are not deleted on transfer. The new owner can delete them, and the code has a working owner check on that delete. Persistence may be intentional.
- `create_note` uses `may_read_account` and stores `origin_account_id` as the path account, not the caller. Device notes store `author_account_id` as the caller. A legitimate grantee can therefore append notes that carry the grantor's account id. The confirmed link findings already stop the grantor from reaching this write; whether a real grantee should be read-only is a product rule the routes currently implement as append access.
- Sessions have no expiry, logout, or revocation. After an accepted merge, `account_for_token` follows `merged_into_id` one hop and the source session acts as the survivor. The source account must accept that merge. Nested merges are not followed.
- `accept_merge` calls `transfer_device`, which commits on each device, so a failure can leave a partial merge.
- Registration returns 409 when an email exists. That is an account-existence signal, not a read of the other account's stored profile.

## Positive patterns

- Queries use bound parameters.
- `account_json` does not return `password_hash` or `merged_into_id`.
- Password checks use `hmac.compare_digest`.
- Sessions are bearer tokens, not cookies.
- Link, share, transfer, and merge creation reject a self target.
- Transfer, share create, and share delete compare the current owner. Merge accept requires the source account.
- Device read, reading list, reading create, and device-note routes call `may_view_device`. Note list and note create call `may_read_account`, so fixing `links_grant` covers those routes.

## Coverage

The quick profile covered one surface: authenticated and unauthenticated HTTP handlers in `app/`, across account isolation and object lifecycle. All six application files were read. Routes reviewed: health, account create, session create, `/me`, account read, note create and list, note read, device create, list, read, update, transfer, readings, device notes, shares, links, and merge create and accept. Helpers reviewed: token lookup, link grant, account read, device view, device list, device notes, transfer, and merge accept.

No coverage ledger was written for this constrained run. There were no carried prior confirmations. Nothing inside `app/` was left unreviewed and then labeled covered. Separate hunter, critic, and verifier agents were not used; the second pass was the same agent. Unreviewed product questions outside this tree, including any gateway in front of the loopback process, are out of scope. The six confirmed records are the disposition of the candidates that survived disproof.
