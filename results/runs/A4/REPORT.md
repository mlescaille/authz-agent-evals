# Security audit A4

## Run

Quick profile, partial pass, single agent. Scope is the FastAPI and SQLite service under `app/` (accounts, sessions, devices, device shares, account links, and account merges). Budget was not set. No prior run was used. The service was not started and no network request was sent. Confirmation uses the in-source control flow only. Verification was a same-agent second pass: every cited line was re-read and each candidate was attacked again before it was kept.

Out of scope for confirmation: password-hash cost, login rate limits, session expiry, and the absence of a logout route. Those do not by themselves cross an account boundary. HTTP parsing is the framework's, and the target has no proxy or deployment configuration.

## Posture

Authentication is a bearer session looked up in `sessions`. Object authorization is inconsistent. List and share routes call `may_read_account` or compare `owner_account_id`, but several direct reads and writes authenticate and then use the caller's id as an object key. Link and device-transfer state is also reused after the relationship that justified it has ended.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Grantor can read and append the grantee's notes | Account link versus the grantee's notes | Grantor receives the grantee's note bodies and can insert a note stored as the grantee's. Derived from the source trace. |
| high | Revoked account links still authorize note access | Revoked link versus note reads and writes | After `revoked_at` is set, note list and note create still succeed. Derived from the source trace. |
| medium | Any account can read another account's recovery email | Session versus another account profile | Response includes the other account's `recovery_email`. Derived from the source trace. |
| medium | Any account can change another account's device label | Session versus another account's device | `devices.label` is updated for a device the caller does not own. Derived from the source trace. |
| high | Device transfer keeps the previous owner's and sharees' access | Former owner or sharee versus the new owner's device | Readings and device notes remain readable and writable after `owner_account_id` changes. Derived from the source trace. |
| medium | Account merge rewrites links and exposes the other party's notes | Survivor or link peer versus the other account's notes | Rewritten `account_links` rows authorize `list_notes` on the other party. Derived from the source trace. |
| high | Any account can read another account's note by id | Session versus another account's note | `GET /notes/{note_id}` returns the other account's note body. Derived from the source trace. |

### Grantor can read and append the grantee's notes

`create_link` in `app/routes.py` stores the session account as `grantor_account_id` and the body account as `grantee_account_id`. The grantee does not accept. `links_grant` in `app/access.py` matches that row when the caller is the grantor and the account being accessed is the grantee. `may_read_account` then returns true. `list_notes` returns the grantee's bodies, and `create_note` inserts a note with both `account_id` and `origin_account_id` set to the grantee. `delete_link` allows only the grantor to set `revoked_at`, so the grantee cannot remove the row.

Principal: any authenticated grantor. Affected resource: the grantee's notes. Failing check: the swapped pair in `links_grant`.

Reproduction, from source: account 10 posts `/links` with `grantee_account_id` 20, then calls `GET /accounts/20/notes` and `POST /accounts/20/notes`. Conditions: account 20 is active when the link is created. Result: account 10 reads account 20's notes and appends a note stored on account 20. Derived from the source trace.

Priority is high because any logged-in account can open this against any active account id, and the effect is note disclosure plus a write into the other account's note list.

Smallest fix: `links_grant` should match only `grantor_account_id = account being accessed`, `grantee_account_id = caller`, and `revoked_at IS NULL`.

### Revoked account links still authorize note access

`delete_link` sets `revoked_at`. `create_link` already uses `revoked_at IS NULL` to decide that a link is active. `links_grant` does not. `may_read_account` stays true for `list_notes` and `create_note`.

Principal: a former grantee, and also a grantor while the swapped predicate remains. Affected resource: the other account's notes. Failing check: `links_grant` ignores `revoked_at`.

Reproduction, from source: the grantor calls `DELETE /links/{id}`, then the other party calls `GET /accounts/{grantor}/notes`. Result: the note bodies are still returned. Derived from the source trace.

Priority is high because revocation is the product's explicit control and it does not change later authorization.

Smallest fix: require `revoked_at IS NULL` in `links_grant`.

### Any account can read another account's recovery email

`read_account` calls `current` and discards the account, loads `accounts` by id, and calls `account_json` with `include_recovery` true. That adds `recovery_email`. `read_me` is the path that returns this projection for the session account.

Principal: any authenticated account. Affected resource: another account's profile, including `recovery_email`. Failing check: `read_account` does not require the session id to equal `account_id`.

Reproduction, from source: `GET /accounts/20` with account 10's bearer token. Result: the body contains account 20's email, display name, status, and recovery email. The password hash is not serialized. Derived from the source trace.

Priority is medium because the read is cross-account and unconditional, and the data is the recovery contact rather than notes, credentials, or devices.

Smallest fix: return that projection only when the session account id equals the path id; otherwise respond 403.

### Any account can change another account's device label

`update_device` authenticates, loads the device, and runs `UPDATE devices SET label`. `transfer`, `create_share`, and `delete_share` all compare `owner_account_id` with the session account.

Principal: any authenticated account other than the owner. Affected resource: the owner's device label. Failing check: `update_device` never reads `owner_account_id` for authorization.

Reproduction, from source: account 10 sends `PATCH /devices/70` for a device owned by account 20. Result: the label is replaced. Derived from the source trace.

Priority is medium because the missing owner check is total, and the write is limited to the label.

Smallest fix: keep the session account and apply the same owner comparison used by `transfer`.

### Device transfer keeps the previous owner's and sharees' access

`transfer` checks the current owner, then `transfer_device` changes `owner_account_id` and inserts a binding for the destination. Previous `device_bindings` rows stay, with `released_at` still null, and `device_shares` stay. `may_view_device` returns true for any of those rows and does not read `released_at`. `list_readings`, `create_reading`, `device_notes_for`, and `create_device_note` use that helper. `accept_merge` moves owned devices through the same helper.

Principal: the previous owner, and any account that already has a share row. Affected resource: readings and device notes on the device now owned by the destination account. Failing check: `transfer_device` does not end the old grants, and `may_view_device` still honors them.

Reproduction, from source: account 10 transfers device 70 to account 20, then calls `GET /devices/70/readings` and `POST /devices/70/readings`. Result: account 10 still receives every reading and can insert another. A pre-transfer sharee follows the same helper. Derived from the source trace.

Priority is high because every transfer leaves this access in place, and the retained capability is read and write of the device's readings and notes.

Smallest fix: on transfer, set `released_at` on existing bindings, delete `device_shares` for the device, bind only the new owner, and ignore released bindings in `may_view_device` and `devices_for`.

### Account merge rewrites links and exposes the other party's notes

`accept_merge` allows only the source account. It moves notes by updating `notes.account_id` and does not change `origin_account_id`. It then sets `grantee_account_id` or `grantor_account_id` to the survivor wherever the column was the source, including links with a third party. `list_notes` returns every note for an account once `may_read_account` is true.

Principal: the survivor, for notes a peer shared with the source; and that peer, for the survivor's notes. Failing check: the link rewrites in `accept_merge`, followed by `may_read_account` with no `origin_account_id` limit.

Reproduction, from source: a link grantor 30, grantee 20 becomes grantor 30, grantee 10 when source 20 accepts a merge into survivor 10. Account 10's `GET /accounts/30/notes` then matches `links_grant` and returns account 30's notes. The opposite original direction lets account 30 list account 10's notes, including notes whose origin is account 10. `create_note` uses the same check. Derived from the source trace.

Priority is medium overall. The note disclosure is a full cross-account read, and it requires an existing third-party link plus a completed merge.

Smallest fix: do not rewrite `account_links` onto the survivor. If peers must retain access only to notes that moved, key that access on `origin_account_id`, not on the survivor's account id.

### Any account can read another account's note by id

`read_note` authenticates, selects `notes` by id, and returns `note_json`, which includes `body`. `list_notes` calls `may_read_account` before it returns those bodies.

Principal: any authenticated account. Affected resource: another account's note. Failing check: `read_note` does not call `may_read_account` or compare `account_id`.

Reproduction, from source: account 10 calls `GET /notes/501` for a note stored on account 20. Result: the body is returned even though `list_notes` for account 20 would be forbidden. Derived from the source trace.

Priority is high because the list route already defines the control and this route skips it for every note id.

Smallest fix: pass the session account into `may_read_account` with the loaded note's `account_id`, and return 403 when it is false.

## NEEDS VALIDATION

None. The kept results are determined by the handlers and SQL in `app/`. No external identity, proxy, or deployment fact decides them.

## Hardening and reviewed behavior

Password storage uses PBKDF2-HMAC-SHA256, a per-password salt, and `hmac.compare_digest`. Login returns the same error for an unknown email, an inactive account, and a bad password. Iteration count and missing login rate limits were not confirmed.

Sessions have no expiry and there is no logout route. That was not confirmed.

`account_for_token` returns the survivor when the session account's `merged_into_id` is set. That runs only after the source account accepts a merge the survivor requested. Fresh login as the merged account is refused because its status is no longer `active`. This was not confirmed: acceptance is the authorizing action, and the survivor redirect is an explicit branch rather than a missing object check.

A grantee appending notes on a grantor who created the link was not confirmed as its own issue. `create_note` calls `may_read_account`, which is the link's implemented capability. The unconsented and post-revocation cases are the findings above.

Registration's 409 on a duplicate email reveals that an email is registered. That existence signal was not confirmed as an object-access finding.

## Positive patterns

SQL statements use bound parameters. `transfer`, `create_share`, and `delete_share` compare `owner_account_id` with the session account. `delete_link` compares `grantor_account_id`. `accept_merge` returns forbidden unless the caller is the source account on the request. `list_notes` calls `may_read_account`. Device read, reading list, and device-note list call `may_view_device` or `device_notes_for`. `devices_for` constrains bindings and shares to the caller. The credential is a bearer token, not a cookie.

## Coverage

Reviewed paths: `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, and `app/__init__.py`. Every route was mapped to its authentication and object check. The second pass re-read the cited lines of the seven kept findings and the merge-session branch that was dropped.

This quick pass did not use a separate coverage-critic agent. It is not a complete multi-wave audit. No ledger from an earlier run was read.
