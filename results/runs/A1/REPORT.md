# Security audit report (A1)

## Run

This is a partial quick-profile pass over the FastAPI and SQLite service in `app/`. One agent mapped the routes and authorization decisions, hunted for cross-account reads and writes, and then performed a same-agent second pass that re-read every cited line and tried to disprove each candidate. Verification recorded for this run is a same-agent second pass.

- Profile: quick. Scope: `app/` (accounts, sessions, notes, devices, readings, device notes, shares, account links, and merges). Budget: none set.
- Source ref: the target tree contains the application source and no git metadata.
- Execution: source trace only. There is no OS sandbox, the service was not started, and no network request was sent. Confirmed results are the cross-account reads and writes implied by the handler and helper control flow.
- Prior runs: none were supplied in the target, and no other audit artifacts were read.
- Coverage is partial because the profile is quick and verification was not a fresh second agent. The six application modules were reviewed. No follow-up hunter wave was run.

## Security posture

Session authentication is applied on the private routes, and several mutations compare the caller with `owner_account_id` or with the merge source. Account notes and device data still have paths where the authenticated account is not the account or owner whose row is read or written. Two of those paths are direct object reads or updates with no object check. Two more come from `links_grant` disagreeing with the one-way, revocable link model used by link creation and deletion. Device transfer updates the owner and leaves the previous binding able to pass `may_view_device`.

## Confirmed findings

| Severity | Title | Affected boundary | Observed result |
| --- | --- | --- | --- |
| high | Authenticated note read returns another account's note | Account note body | Another session receives the note body. Source trace. |
| high | Creating an account link lets the grantor read and write the grantee's notes | Account notes | The link creator lists and inserts notes on the other account. Source trace. |
| high | Revoked account links still authorize note reads and writes | Account notes after revocation | The former grantee still lists and inserts the grantor's notes. Source trace. |
| high | Former device owner keeps read and write access after transfer | Device readings and device notes | The former owner reads and writes the recipient's device. Source trace. |
| medium | Authenticated profile read returns another account's recovery email | Account profile | Another session receives `recovery_email`. Source trace. |
| medium | Authenticated device update changes another account's label | Device label and device metadata | Another session changes the label and receives serial and owner id. Source trace. |

### Authenticated note read returns another account's note

- Severity: high. Confidence: high. Fingerprint: `authz.note.cross-account-read`.
- Location: `read_note` in `app/routes.py`. The comparison control is `list_notes` in the same file, which calls `may_read_account`.
- Lower-trust principal: any account with a valid bearer session. Affected resource: another account's `notes` row.
- Failing check: `current()` authenticates the caller and `read_note` discards that account. The note is loaded by id and `note_json` returns `body`. `may_read_account` is not called.
- Reproduction from source: account 1 stores a note; account 2 calls `GET /notes/{note_id}` with account 2's token. `read_note` accepts the token, selects the note by id, and returns the body.
- Conditions: a resolvable bearer token and a note id belonging to another account.
- Result: account 2 receives account 1's note id, account id, origin account id, and body. Derived from the source trace; the service was not executed.
- Impact: private note content is readable without the account relationship `list_notes` enforces. Likelihood is high because note ids are integers and the route has no relationship check. Overall severity is high and does not exceed that impact.
- Fix: after loading the note, call `may_read_account` with the authenticated account and `notes.account_id`, and return 403 when it is false. Link direction and revocation must be fixed in `links_grant` as well, or this route inherits those two gaps.

### Creating an account link lets the grantor read and write the grantee's notes

- Severity: high. Confidence: high. Fingerprint: `authz.link.grantor-accesses-grantee`.
- Location: `create_link` in `app/routes.py`, `links_grant` and `may_read_account` in `app/access.py`, sinks `list_notes` and `create_note` in `app/routes.py`.
- Lower-trust principal: the account that creates the link (the grantor). Affected resource: the grantee's notes.
- Failing check: `links_grant` matches both directions. The disjunct `grantor_account_id = caller_id AND grantee_account_id = account_id` is true for the creator accessing the other account. `may_read_account` is the only decision `list_notes` and `create_note` make. `delete_link` allows only the grantor to revoke, so the grantee cannot remove the row.
- Reproduction from source: account A posts `/links` with B's id as `grantee_account_id`. A then calls `GET /accounts/{B}/notes` and `POST /accounts/{B}/notes`. The inserted link makes the second `links_grant` disjunct true.
- Conditions: A has a session, and B is another active account.
- Result: A receives B's note bodies and inserts a note stored on B's account. B did not create a grant. Derived from the source trace; the service was not executed.
- Impact: full note read and note insert on an account that did not grant access. Likelihood is high because the attacker chooses an integer account id and the grant is immediate. Overall severity is high.
- Fix: `links_grant` should authorize only a row whose grantor is the account being accessed, whose grantee is the caller, and whose `revoked_at` is null.

### Revoked account links still authorize note reads and writes

- Severity: high. Confidence: high. Fingerprint: `authz.link.revocation-ignored`.
- Location: `delete_link` in `app/routes.py` writes `revoked_at`. `links_grant` in `app/access.py` ignores it. `list_notes` and `create_note` consume `may_read_account`.
- Lower-trust principal: the grantee of a link the grantor has revoked. Affected resource: the grantor's notes.
- Failing check: `links_grant` selects the link by the two account ids and does not require `revoked_at IS NULL`. `create_link` already uses `revoked_at IS NULL` when it decides whether an active link exists. This result uses the grantor-to-grantee direction and remains after the reverse disjunct is removed.
- Reproduction from source: A creates a link to B and a note on A's account, then `DELETE /links/{id}`. B calls `GET /accounts/{A}/notes` and `POST /accounts/{A}/notes` with B's token.
- Conditions: B still has a session, and the link row remains with `revoked_at` set.
- Result: B still receives A's notes and can insert a note on A's account. Derived from the source trace; the service was not executed.
- Impact: revocation does not stop note read or note insert. Likelihood is high because it is the normal delete path. Overall severity is high.
- Fix: require `revoked_at IS NULL` in `links_grant`, and keep the single grantor-to-grantee direction.

### Former device owner keeps read and write access after transfer

- Severity: high. Confidence: high. Fingerprint: `authz.device-transfer.stale-binding`.
- Location: `transfer` and `transfer_device` move ownership. `may_view_device` and `devices_for` in `app/access.py` authorize the old binding. `list_readings`, `create_reading`, `list_device_notes`, and `create_device_note` in `app/routes.py` use that decision.
- Lower-trust principal: the previous device owner. Affected resource: the recipient's device, including readings and device notes created after transfer.
- Failing check: `transfer_device` updates `owner_account_id` and inserts the recipient's binding without setting `released_at` on the previous `device_bindings` row. `may_view_device` returns true for any binding with that device id and account id. `devices_for` uses the same join. Owner comparisons in `transfer`, `create_share`, and `delete_share` already reject the former owner. No route lets the new owner release the old binding. `device_bindings.released_at` exists in `app/db.py` and is never filtered.
- Reproduction from source: A creates a device and transfers it to B. B posts a reading. A calls `GET /devices/{id}/readings` and `POST /devices/{id}/readings` with A's original token. `may_view_device` matches A's original binding.
- Conditions: A's session still maps to the account on the original binding, and `owner_account_id` is now B.
- Result: A receives readings authored for the device after the transfer, including B's readings, and can insert readings and device notes. `GET /devices` for A still returns the device. Derived from the source trace; the service was not executed.
- Impact: ongoing cross-account read and write of device data, with no revocation route for the new owner. Likelihood is high because every transfer leaves the prior binding. Overall severity is high.
- Fix: in `transfer_device`, set `released_at` on existing bindings for the device before inserting the recipient binding. Require `released_at IS NULL` in `may_view_device` and in the `devices_for` binding join.

### Authenticated profile read returns another account's recovery email

- Severity: medium. Confidence: high. Fingerprint: `authz.account-profile.cross-account-read`.
- Location: `read_account` and `account_json` in `app/routes.py`.
- Lower-trust principal: any account with a valid bearer session. Affected resource: another account's profile, including `recovery_email`.
- Failing check: `current()` authenticates the caller and `read_account` discards the result. The row is selected by the path id and returned with `include_recovery=True`. `read_me` is the self profile, and `create_account` returns the helper with `include_recovery=False`.
- Reproduction from source: account 1 calls `GET /accounts/2` with account 1's token. The handler loads account 2 and `account_json` adds `recovery_email`.
- Conditions: a resolvable bearer token and a different existing account id.
- Result: account 1 receives account 2's id, email, display name, status, and recovery email. Derived from the source trace; the service was not executed.
- Impact: disclosure of the private profile fields, including the recovery email withheld at registration. There is no in-app recovery consumer of that email, so the demonstrated effect stays the profile read. Likelihood is high. Overall severity is medium.
- Fix: return the profile only when the authenticated account id equals the path id.

### Authenticated device update changes another account's label

- Severity: medium. Confidence: high. Fingerprint: `authz.device-label.cross-account-write`.
- Location: `update_device` in `app/routes.py`.
- Lower-trust principal: any account with a valid bearer session. Affected resource: another account's device label, plus the serial and owner id in the response.
- Failing check: `current()` authenticates the caller and `update_device` discards the account. The `UPDATE` is keyed only by device id. `read_device` requires `may_view_device`. `transfer` and `create_share` require `owner_account_id` to equal the caller.
- Reproduction from source: account 1 creates a device; account 2 calls `PATCH /devices/{id}` with a new label and account 2's token. The handler writes the label and returns `device_json`.
- Conditions: a resolvable bearer token and a device id owned by someone else.
- Result: account 2 replaces account 1's device label and receives the serial, label, and `owner_account_id`. Derived from the source trace; the service was not executed.
- Impact: a single-field write and disclosure of device identity metadata. Readings and notes on their own routes still call `may_view_device`. Likelihood is high. Overall severity is medium.
- Fix: before the update, require `owner_account_id` to equal the authenticated account, matching transfer and share management.

## NEEDS VALIDATION

No needs-validation records. Each confirmed result is a cross-account read or write whose branch is fully visible in the target source. Deployment proxies, cookie attributes, and hash cost were not treated as unresolved authorization blockers.

## Hardening notes

These were reviewed and are not confirmed findings because they do not cross an account boundary, or because the source shows a consented or explicit control.

- Password hashing uses PBKDF2-HMAC-SHA256 with a per-password salt and `hmac.compare_digest`. Iteration count and the absence of request rate limits were not scored.
- Sessions have no expiry or logout route. `account_for_token` maps a merged account's existing token onto `merged_into_id` for one hop. That alias follows `accept_merge`, which the source account must call. It was left as session behavior of an accepted merge.
- `POST /accounts` returns 409 when the email already exists. That reveals registration state and was not treated as a data read of another account.
- `transfer_device` does not delete `device_shares`. The new owner can delete a share by account id through `delete_share`. There is no list-shares route, so discovery of existing sharees is awkward. Share rows are the explicit device ACL, so persistence across transfer was not confirmed as a separate broken check.
- `accept_merge` rewrites `account_links` from the source account onto the survivor after the survivor creates the request and the source accepts it. That is the merge implementation in source, and it was not confirmed as a bypass.
- `create_note` sets both `account_id` and `origin_account_id` from the path account. `accept_merge` preserves `origin_account_id` while moving `account_id`, so the field behaves as collection origin. A caller who already passes `may_read_account` is allowed to insert. The unauthorized inserts above come from the link checks, not from this column choice.
- Direct object routes can answer 403 or 404 once a row exists. Those status differences were not confirmed as findings on their own.

## Positive source patterns

- SQL statements that take request data use bound parameters.
- `current()` rejects a missing or unknown bearer token before the private handlers run.
- `transfer`, `create_share`, and `delete_share` compare `owner_account_id` with the authenticated account.
- `accept_merge` returns forbidden unless the authenticated account is `source_account_id`, and it refuses a merge that is not pending.
- `delete_link` returns forbidden unless the caller is the grantor. `create_link` refuses self-links and treats `revoked_at IS NULL` as the active-link predicate.
- `list_notes` and `create_note` call `may_read_account`. Device read, readings, and device notes call `may_view_device`. Those helpers are the right layer; the defects are the predicates and the routes that skip them.
- Login uses one failure response for a missing account, an inactive account, and a bad password. Session tokens come from `secrets.token_urlsafe`. Registration omits `recovery_email`.

## Coverage

The pass reviewed `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, and `app/__init__.py`. Routes covered: health, account create, session create, `/me`, account read, account notes, note read, device create and list, device read and update, transfer, readings, device notes, shares, links, and merge create and accept.

Units treated as covered by this source pass: bearer authentication, account profile reads, note list and direct note read, device ownership mutations, device view and binding lifetime, share create and delete, link create, list, and revoke, and merge request and accept. The same-agent second pass re-checked the cited lines for each confirmed record and kept the six records above.

No candidate was left unvalidated. No independent coverage-critic agent ran; the quick profile was executed as one agent with a second read of the cited source. This report does not claim that a later pass would find nothing else.
