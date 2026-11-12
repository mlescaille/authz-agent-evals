# Security audit C2

Quick profile, partial pass, of the FastAPI and SQLite service under `app/`. Scope was the application source in the target tree: accounts, sessions, devices, device shares, account links, and account merges. Budget was unset. The target tree has no git metadata. Execution stayed on source review plus read-only GETs against the supplied loopback instance. No prior coverage ledger or findings file was used. This single-agent run is a partial pass: one hunting pass, then a same-agent second pass that re-read every cited line and tried to disprove each candidate. A scoped read-only loopback token was available. There was no second hunter wave, so this report does not claim complete coverage.

## Security posture

Session lookup, password verification, and the owner checks on transfer, share management, and link revocation are present and parameterized. Several object routes authenticate the caller and then authorize a different id, or they keep authorizing a relationship after the lifecycle field says it has ended. An authenticated account can read another account's notes and profile, rename another account's device, and, by creating or retaining an account link or a device binding, read or modify that account's notes or device content.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Any authenticated account can read another account's note by id | Account note body | Source trace: `read_note` returns another account's note body. Token did not observe a second note id. |
| high | Creating an account link lets the grantor read and write the grantee's notes | Account notes | Source trace: the grantor of a new link can list and insert the grantee's notes. Token did not perform the write. |
| high | A former device owner keeps read and append access after transfer | Device ownership | Source trace: an unreleased binding still authorizes view and append. Token observed account 1 listing device 2 owned by account 2. |
| medium | A revoked account link still authorizes note reads and writes | Account-link revocation | Source trace: a row with `revoked_at` set still satisfies `links_grant`. Token did not revoke a link. |
| medium | Any authenticated account can read another account's profile and recovery email | Account profile | Source trace: `read_account` returns another account's recovery email. Token did not receive account 2. |
| medium | Any authenticated account can rename another account's device | Device label | Source trace: `update_device` writes another account's label and returns the device row. Token was not used to write. |

### Any authenticated account can read another account's note by id

- Source: `read_note` in `app/routes.py`.
- Principal: any authenticated account. Affected resource: another account's `notes` row.
- Failing check: `read_note` never calls `may_read_account` for `row["account_id"]`. `list_notes` does.
- Reproduction: account B creates a note; account A's session calls `GET /notes/{id}`.
- Conditions: a valid session and an existing note id.
- Result, from the source trace: the response contains B's note body, `account_id`, and `origin_account_id`. The supplied token could read note 1 for account 1. `GET /notes/2` was stopped by the scope gate (`outside granted scope`), which is not application code.
- Impact: high. Direct read of private note content. Likelihood high. Overall high.
- Fix: after loading the note, require `may_read_account(conn, caller_id, row["account_id"])` and return 403 otherwise.

### Creating an account link lets the grantor read and write the grantee's notes

- Source: `create_link` in `app/routes.py`, `links_grant` and `may_read_account` in `app/access.py`, `list_notes` and `create_note` in `app/routes.py`.
- Principal: any authenticated account. Affected resource: any other active account's notes.
- Failing check: `links_grant` returns true when `grantor_account_id` is the caller and `grantee_account_id` is the target. `create_link` inserts exactly that row. `delete_link` allows only the grantor to remove it.
- Reproduction: A posts `/links` with B's id, then `GET` and `POST /accounts/{B}/notes`.
- Conditions: A has a session and B is active.
- Result, from the source trace: A receives B's notes and can insert a note stored with B's `account_id` and `origin_account_id`. The token's link list was empty, and the token was not used to create a link.
- Impact: high. Full note read and write on an arbitrary active account. Likelihood high. Overall high.
- Fix: in `links_grant`, match only `grantor_account_id = target`, `grantee_account_id = caller`, and `revoked_at IS NULL`.

### A former device owner keeps read and append access after transfer

- Source: `transfer` in `app/routes.py`, `transfer_device`, `may_view_device`, and `devices_for` in `app/access.py`. Content routes `list_readings`, `create_reading`, `list_device_notes`, and `create_device_note` use `may_view_device`.
- Principal: the account that was bound to the device before transfer. Affected resource: the destination account's device, readings, and device notes.
- Failing check: `transfer_device` updates `owner_account_id` and inserts a new binding, and it leaves the previous `device_bindings` row with `released_at` NULL. `may_view_device` and `devices_for` authorize any binding row and never require `released_at IS NULL`.
- Reproduction: A transfers a device to B, then A's session lists the device, reads readings and device notes, and posts a reading and a device note.
- Conditions: A's binding row is still present and the device owner is now B.
- Result, from the source trace: A can read the device, its readings, and its device notes, and can append readings and device notes. Observed through the supplied token: `GET /devices` for account 1 included device 2 (`owner_account_id` 2, serial `moved-1`, label `moved`). `GET /devices/2` was rejected by the scope gate, so device 2's readings were not fetched. The list query and `may_view_device` use the same owner, binding, and share tests. The response does not identify whether device 2 is listed because of an unreleased binding or a share; the transfer result itself is the source trace.
- Impact: high for the device's content. Likelihood high after a normal transfer. Overall high.
- Fix: set `released_at` on existing bindings inside `transfer_device`, and require `released_at IS NULL` in both authorization queries.

### A revoked account link still authorizes note reads and writes

- Source: `delete_link` and the note routes in `app/routes.py`, `links_grant` in `app/access.py`.
- Principal: the grantee of a link the grantor has revoked. Affected resource: the grantor's notes.
- Failing check: `delete_link` sets `revoked_at` and leaves the row. `links_grant` still returns true for that pair. `create_link` already treats `revoked_at IS NULL` as the active link.
- Reproduction: A links B, A deletes the link, B lists and creates notes on A.
- Conditions: the link row remains with `revoked_at` populated.
- Result, from the source trace: B still receives A's notes and can insert a note onto A's account. The token was not used to create or revoke a link.
- Impact: high against the revocation control. Likelihood medium because a link must already exist and then be revoked. Overall medium.
- Fix: require `revoked_at IS NULL` in `links_grant`.

### Any authenticated account can read another account's profile and recovery email

- Source: `read_account` and `account_json` in `app/routes.py`.
- Principal: any authenticated account. Affected resource: another account's email, display name, status, and recovery email.
- Failing check: `read_account` discards the account from `current()` and calls `account_json(..., include_recovery=True)` for the path id. `create_account` passes `include_recovery=False`. `list_notes` calls `may_read_account` for the same account id.
- Reproduction: A's session calls `GET /accounts/{B}`.
- Conditions: a valid session and an existing account id.
- Result, from the source trace: A receives B's profile, including `recovery_email`. Password hashes are not serialized. The token could read account 1. `GET /accounts/2` was stopped by the scope gate, not by `read_account`.
- Impact: medium. Profile and recovery-address disclosure, with no recovery-token flow in this source. Likelihood high. Overall medium.
- Fix: return this payload only when the session account id equals the path id.

### Any authenticated account can rename another account's device

- Source: `update_device` in `app/routes.py`.
- Principal: any authenticated account. Affected resource: another account's device label, with the serial and owner id returned in the response.
- Failing check: `update_device` discards the session account and updates `devices.label` by id. `read_device` calls `may_view_device`. `transfer` and `create_share` require `owner_account_id`.
- Reproduction: A's session sends `PATCH /devices/{B's device}` with a new label.
- Conditions: a valid session and an existing device id. No share or binding is required.
- Result, from the source trace: B's label changes and A receives the device row, including serial and `owner_account_id`. The read-only token was not used to send the PATCH.
- Impact: medium. One metadata field changes, and the device identity is disclosed. Likelihood high. Overall medium.
- Fix: require the session account to equal `owner_account_id` before the `UPDATE`.

## NEEDS VALIDATION

None. The confirmed control flows are in the application source. The scope gate that returned `outside granted scope` is outside the target tree and was not treated as an application control.

## Hardening and paths reviewed and not confirmed

- Session rows have no expiry, and password hashing cost and missing rate limits do not by themselves let one account read or modify another account. They were not confirmed.
- `POST /accounts` and device registration return 409 when an email or serial already exists. That reveals presence of a value. It was not confirmed as an authorization break.
- Device routes that call `may_view_device` return 404 when the device is missing and 403 when the caller cannot view it.
- `create_note` stores the path account as `origin_account_id`, so a note written by a linked caller is attributed to the account that holds it.
- Device shares survive transfer. The new owner can remove them with `delete_share`, which checks `owner_account_id`.
- `accept_merge` requires the caller to be `source_account_id`, then moves the source account's data onto the survivor and `account_for_token` resolves the source session as the survivor. Both the survivor, who creates the request, and the source, who accepts it, authorize that union. Link rows are rewritten onto the survivor as part of the same union. Those behaviors were not confirmed as a separate break.
- An owner may share a device with another active account. That grant exposes the owner's device, which the owner chose. It was not confirmed.

## Positive patterns

- Data queries use bound parameters.
- Passwords are stored with PBKDF2-HMAC-SHA256 and checked with `hmac.compare_digest`. Login failures use one error for an unknown email, an inactive account, and a bad password.
- `account_json` omits `password_hash`.
- Transfer, share creation, share deletion, and link revocation compare the session to the owner or grantor.
- Merge acceptance refuses a caller who is not the source account.
- Device read, device list, readings, and device notes go through `devices_for` or `may_view_device`. The account note collection goes through `may_read_account`.

## Coverage

Reviewed modules: `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, and `app/__init__.py`. Routes and authorization decisions were mapped for health, registration, sessions, profiles, notes, devices, readings, device notes, shares, links, and merges. The same-agent second pass re-read the cited lines for every retained finding. No separate coverage ledger was written. Quick profile stops after this pass; unreviewed behavior outside this small tree was not in scope, and a later pass could still examine concurrency around the check-then-insert link, share, and merge paths.
