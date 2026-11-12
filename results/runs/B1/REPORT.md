# Security audit report (B1)

## Run

This is a partial quick-profile pass over the FastAPI account directory in the supplied target tree. One agent mapped every route and authorization decision, hunted cross-account reads and writes, and then re-read every cited line in a same-agent second pass. `relationships.md` was in scope as the intended trust model for accounts, sessions, links, devices, shares, and merges. It was not treated as a list of findings.

| Item | Value |
| --- | --- |
| Profile | quick |
| Scope | `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, `relationships.md` |
| Budget | unset |
| Source ref | supplied tree; no git metadata in the target |
| Execution | source only. No OS sandbox was available, the service was not started, and no network request was sent |
| Prior runs | none read |
| Verification | same-agent second pass |
| Coverage claim | partial |

Confirmation required the whole control flow to be in the supplied source. Each confirmed `observed_result` is the cross-account read or write implied by that trace. Hash cost, missing rate limits, and demo session lifetime were not confirmed.

## Posture

Bearer sessions identify a caller, and transfer, share, link revoke, and merge accept compare that caller with the owner, grantor, or source account. Those checks do not cover the note-by-id read, device-label update, link predicate, post-transfer device grants, merge link rewrite, or merged-session substitution. An authenticated account can read another account's notes and recovery email, keep using a device after giving it away, and, after a merge, act as the survivor or inherit the source's links.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Any account can read another account's note by id | account notes | `GET /notes/{id}` returns another account's note body |
| high | Grantor can read and write the grantee's account notes | account links | the grantor lists and creates notes on the grantee |
| high | A revoked account link still grants note access | account links | the former grantee still lists and creates the grantor's notes |
| high | Merge retargets account links onto the survivor | merge | the source's grantee reads the survivor's notes, and the survivor reads accounts that granted the source |
| high | A merged account's token acts as the survivor | sessions | the source token is accepted as the survivor |
| high | Device owner and shares can read each other's device notes | device notes | a share or owner receives the other author's note bodies |
| high | Previous device owner keeps access after transfer | device ownership | the previous owner reads and writes readings on the transferred device |
| high | Pre-transfer device shares still authorize access | device shares | a pre-transfer share reads and writes readings after transfer or merge |
| medium | Any account can read another account's recovery email | account profile | `GET /accounts/{id}` returns another account's `recovery_email` |
| medium | Any account can rename another account's device | device record | `PATCH /devices/{id}` changes another account's label |

### Any account can read another account's note by id

- Location: `app/routes.py`, `read_note`.
- Principal: any authenticated account other than the note owner.
- Failing check: `current()` authenticates the token, and the handler returns `note_json` for the row loaded by id. `may_read_account`, which `list_notes` calls, is not called.
- Reproduction: account A creates a note. Account B, with no link from A, calls `GET /notes/{note_id}`.
- Conditions: a valid bearer token and an existing note id.
- Result, derived from the source trace: the response contains the other account's note body, `account_id`, and `origin_account_id`.
- Impact and priority: high. The private note body is disclosed. Likelihood is high because the route has no relationship requirement.
- Fix: after loading the note, return it only when `may_read_account` allows the caller for that note's `account_id`. That helper must itself require an active grantor-to-grantee link.

### Grantor can read and write the grantee's account notes

- Location: `app/access.py`, `links_grant`, reached from `list_notes` and `create_note`.
- Principal: the grantor, toward the grantee named in a link the grantor created.
- Failing check: the second disjunct matches `grantor = caller` and `grantee = target`. Parameters are `(target, caller, caller, target)`.
- Reproduction: `POST /links` with `grantee_account_id` set to the victim, then `GET` and `POST /accounts/{victim}/notes` with the grantor's token.
- Conditions: the caller has a session. The victim account is active so the link insert succeeds.
- Result, derived from the source trace: the grantor receives the victim's note bodies and can insert a note stored on the victim account.
- Impact and priority: high. This is full note read and write, and the victim does not accept the link. Likelihood is high.
- Fix: match only `grantor_account_id = target` and `grantee_account_id = caller`, with `revoked_at IS NULL`.

### A revoked account link still grants note access

- Location: `app/access.py`, `links_grant`, after `delete_link` in `app/routes.py`.
- Principal: the former grantee, toward the grantor.
- Failing check: `links_grant` selects by the two account ids and has no `revoked_at IS NULL` predicate. `delete_link` sets `revoked_at` and leaves the row.
- Reproduction: revoke the link with the grantor's token, then list and create notes on the grantor with the grantee's token.
- Conditions: the grantee session is still valid and the revoked row remains.
- Result, derived from the source trace: the next list returns the grantor's note bodies, and the next create inserts a note on the grantor account.
- Impact and priority: high. Revocation is the documented cutoff and it does not take effect. This remains even if the reverse-direction disjunct is removed. Likelihood is high.
- Fix: use the same active-link predicate `create_link` already uses for duplicate detection (`revoked_at IS NULL`), and keep only the grantor-to-grantee direction.

### Merge retargets account links onto the survivor

- Location: `app/access.py`, `accept_merge`, later honored by `links_grant` from `list_notes` and `create_note`.
- Principals: an account the source had granted, toward the survivor; and the survivor, toward an account that had granted the source.
- Failing check: `accept_merge` sets `grantor_account_id` or `grantee_account_id` to the survivor and does not set `revoked_at`. The later link lookup treats that active row as a normal grant.
- Reproduction: create an active link in either direction involving the source, accept the survivor's merge, then list notes on the new grantor account with the new grantee's token.
- Conditions: the source has an active link at accept time.
- Result, derived from the source trace: the source's grantee reads and can create the survivor's notes, including notes the survivor already had and notes moved from the source. The survivor reads and can create notes on accounts that had granted the source. Both results hold for the grantor-to-grantee direction alone.
- Impact and priority: high. Merge publishes note access the two link-ending rules forbid. Likelihood is high whenever such a link exists.
- Fix: set `revoked_at` on active links whose grantor or grantee is the source. Do not change either account id. `links_grant` must ignore revoked rows.

### A merged account's token acts as the survivor

- Location: `app/access.py`, `account_for_token`, called from `current` on every authenticated route. `accept_merge` sets `merged_into_id`.
- Principal: the holder of a token issued to the source account, acting as the survivor.
- Failing check: when `merged_into_id` is set, `account_for_token` returns the survivor row. `accept_merge` does not delete `sessions`. `create_session` rejects a new login for a merged account, and existing tokens never reach that check.
- Reproduction: accept the merge with the source token, then call `GET /me` and a survivor note or device route with that same token.
- Conditions: the merge has been accepted and the caller still presents the source token.
- Result, derived from the source trace: `GET /me` returns the survivor's identity and `recovery_email`. Later routes read and modify the survivor's notes and devices as the survivor.
- Impact and priority: high. The source token becomes the survivor principal. It is this survivor, after both accounts complete the merge, rather than an unauthenticated takeover of an arbitrary account. Likelihood is high because every accept leaves the substitution in place.
- Fix: return no account when `status` is not `active` or `merged_into_id` is set. Delete `sessions` for the source inside `accept_merge`.

### Device owner and shares can read each other's device notes

- Location: `app/access.py`, `device_notes_for`, called by `list_device_notes`.
- Principals: a current share toward the owner's notes, and the owner toward a share's notes. The same query also shows one share another share's notes.
- Failing check: after `may_view_device` succeeds, the select is `WHERE device_id = ?` and includes every `author_account_id`.
- Reproduction: the owner writes a device note and shares the device. The share calls `GET /devices/{id}/notes`. Repeat in the other direction.
- Conditions: the caller can view the device, and another account has a note on it.
- Result, derived from the source trace: the response includes the other author's note body.
- Impact and priority: high. Device notes are private to the author, and this is the supported list path. Likelihood is high for any shared device. The failure remains for a current owner and a current share, independent of stale bindings.
- Fix: add `AND author_account_id = ?` with the caller id.

### Previous device owner keeps access after transfer

- Location: `app/access.py`, `may_view_device` and `devices_for`. The binding is created in `create_device` and left in place by `transfer_device`.
- Principal: a past owner, toward the device now owned by the destination account.
- Failing check: any `device_bindings` row authorizes the caller. `transfer_device` inserts the destination binding and never sets `released_at`. No query reads `released_at`. The current-owner comparison on transfer and share does not apply to later reads and writes.
- Reproduction: account A transfers the device to account B, then lists and creates readings with A's token.
- Conditions: A still has its session. Transfer leaves A's original binding.
- Result, derived from the source trace: `GET /devices/{id}/readings` returns the device's readings and `POST /devices/{id}/readings` writes a reading on B's device. `GET /devices` still lists it. The same view gate admits A to the device-note routes.
- Impact and priority: high. Transfer is supposed to end the previous owner's access to the device, its readings, and its notes. Likelihood is high because every transfer leaves the binding.
- Fix: set `released_at` on open bindings before inserting the destination binding. Require `released_at IS NULL` in `may_view_device` and `devices_for`.

### Pre-transfer device shares still authorize access

- Location: `app/access.py`, `transfer_device`, `may_view_device`, and `devices_for`. `accept_merge` moves source-owned devices through `transfer_device`.
- Principal: an account that received the share before the ownership change, toward the new owner's device.
- Failing check: `transfer_device` does not delete `device_shares`. `may_view_device` returns true when that row exists. `delete_share` is the only removal, and transfer does not call it.
- Reproduction: share the device, transfer it, then list and create readings with the share token. The same share remains when merge transfers the device.
- Conditions: the share row predates the owner change, and the recipient's session is valid.
- Result, derived from the source trace: the old share reads the device's readings and can insert a reading after the new owner takes the device.
- Impact and priority: high. Pre-transfer shares are supposed to end at transfer and at merge. Likelihood is high. This is independent of the binding bug: a share recipient needs no binding row.
- Fix: `DELETE FROM device_shares WHERE device_id = ?` inside `transfer_device` before commit.

### Any account can read another account's recovery email

- Location: `app/routes.py`, `read_account` and `account_json`.
- Principal: any authenticated account, toward the account named in the path.
- Failing check: `current()` is called and its result is discarded. The handler always calls `account_json` with `include_recovery=True`.
- Reproduction: `GET /accounts/{other-id}` with any other account's bearer token.
- Conditions: a valid token. No link or share is required.
- Result, derived from the source trace: the response includes the other account's `recovery_email`.
- Impact and priority: medium. The field is limited to the account's own session, including `GET /me`. The supplied source has no recovery login that consumes the address, so the demonstrated result is disclosure of that private address. Likelihood is high.
- Fix: pass `include_recovery` only when the caller id equals the row id.

### Any account can rename another account's device

- Location: `app/routes.py`, `update_device`.
- Principal: any authenticated account other than the current owner.
- Failing check: `current()` authenticates and the account is discarded. The `UPDATE` is keyed only by device id. `transfer` and `create_share` compare `owner_account_id` with the caller; this route does not.
- Reproduction: account B, with no share, sends `PATCH /devices/{id}` with a new label for account A's device.
- Conditions: a valid token and an existing device id.
- Result, derived from the source trace: `devices.label` changes, and the response returns the device serial, label, and `owner_account_id`.
- Impact and priority: medium. This is a real cross-account write and a read of the device record. It does not move ownership or change readings. Likelihood is high.
- Fix: require `owner_account_id` to equal the authenticated account before the update.

## NEEDS VALIDATION

No needs-validation records. Each confirmed result above follows from source in the target tree. The service was not executed because no OS sandbox was available; that absence did not leave an unresolved deployment fact for these authorization paths.

## Hardening and positive patterns

Not confirmed, because they do not cross an account boundary:

- Password hashing is PBKDF2-HMAC-SHA256 at 120000 iterations. Login has no rate limit.
- Sessions have no expiry and the service has no logout route. That demo session design is separate from the merged-token substitution above, which does cross accounts.
- `POST /accounts` returns 409 when the email is already registered.
- `accept_merge` rewrites `readings.author_account_id` and `device_notes.author_account_id` to the survivor. The device-note list already returns every author to a viewer, and the author rewrite does not by itself let the survivor read notes on a device the survivor cannot view.
- Merge statements are autocommit, and `transfer_device` commits before the later link updates. That ordering was not confirmed as an additional cross-account grant.

Patterns that hold the boundary they implement:

- `transfer`, `create_share`, and `delete_share` require the current `owner_account_id`.
- `delete_link` requires the grantor.
- `accept_merge` returns forbidden unless the caller is the source account on that request.
- `create_session` rejects an account whose status is not active.
- `list_notes` and `create_note` call `may_read_account` before returning or inserting notes. The helper's predicate is wrong; the routes do call it.
- Device read, reading list, reading create, and device-note create call `may_view_device`.
- Queries use bound parameters. `account_json` omits `password_hash`. Account creation omits `recovery_email`.
- Self-link, self-share, self-transfer, and self-merge are rejected. Password comparison uses `hmac.compare_digest`.

## Coverage

Routes reviewed: health, account create, session create, `GET /me`, account read, note create, note list, note read, device create, device list, device read, device update, transfer, reading create, reading list, device-note create, device-note list, share create, share delete, link create, link list, link revoke, merge create, and merge accept. Helpers reviewed: `current`, `account_for_token`, `links_grant`, `may_read_account`, `may_view_device`, `devices_for`, `device_notes_for`, `transfer_device`, and `accept_merge`.

This quick pass had one hunting pass and a same-agent second pass. It did not launch a separate critic or a fresh verifier. Unreviewed areas remain, including availability, dependency risk, and behavior that would depend on a deployment in front of this process. Ten cross-account findings were confirmed. None were left as needs-validation.
