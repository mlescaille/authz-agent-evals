# Security audit C5

## Run

This is a **quick**, partial pass over `/tmp/authz-runs/C5/target` (`app/main.py` and the account, session, device, share, link, and merge routes). One agent mapped the routes, hunted cross-account reads and writes, then did a same-agent second pass that re-read every cited line and tried to disprove each candidate. No prior ledger was supplied. Budget was unset. Execution stayed on the supplied source and on read-only GETs to the supplied loopback token at `http://127.0.0.1:37675`. A scoped loopback token was available; its secret is not recorded. The token covers account 1, device id 1, and note id 1. Writes were not sent. Requests outside that scope came back `403` with detail `outside granted scope`, a response string that does not exist in the target source, so those responses were not treated as application authorization.

Coverage is the six route groups above. The pass is partial because the profile is quick and the second look was the same agent, not an independent reviewer.

## Posture

Signed-in callers are isolated on some owner operations: device transfer, share create, and share delete compare `owner_account_id`, and merge acceptance requires the source account. Note listing and device reads call helpers, but those helpers and several direct routes still let one account read or change another account's data. Six such breaks are confirmed below. Five are high because they expose note bodies, recovery email, or post-transfer device content. The device-label write is medium.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Signed-in account can read any note by id | account notes | Any session receives another account's note body. Source trace. |
| high | Link grantor can read and add the grantee's notes | account links to notes | Grantor reads and inserts the grantee's notes. Source trace. |
| high | Revoked account link still grants note access | revoked link to notes | Former grantee keeps note read and create. Source trace. |
| high | Signed-in account can read any account's recovery email | account profile | Any session receives another account's recovery email. Source trace. |
| high | Previous device owner keeps access after transfer | device ownership to readings and notes | Previous owner still receives the device and can read and append its data. Device list also observed for account 1. |
| medium | Signed-in account can rename any device | device label | Any session updates another account's device label. Source trace. |

### Signed-in account can read any note by id

- Source: `read_note` in `app/routes.py` (line 264), returning `note_json` at line 273. `list_notes` (line 255) is the check that this route skips.
- Lower-trust principal: any signed-in account other than the note owner.
- Failed check: `read_note` calls `current()` and selects `notes` by id. It never calls `may_read_account`.
- Reproduction: with account A's session, `GET /notes/{note_owned_by_B}`.
- Conditions: a valid session and an existing note owned by B. No link is required. Note ids are integer primary keys.
- Result: the response contains B's note `body`, `account_id`, and `origin_account_id`. Derived from the source trace. The supplied token could read note 1 for account 1 only.
- Impact and priority: full note disclosure across accounts, high. The list route already shows notes are account-scoped, and this path bypasses that scope entirely.
- Fix: after the lookup, call the corrected `may_read_account` with the session account and `row["account_id"]`, and return 403 on failure.

### Link grantor can read and add the grantee's notes

- Source: `create_link` in `app/routes.py` (line 518) and `links_grant` in `app/access.py` (line 27). The sinks are `list_notes` (line 261) and `create_note` (line 230).
- Lower-trust principal: the grantor, acting on the grantee's notes.
- Failed check: `links_grant` is true when `grantor_account_id` is the caller and `grantee_account_id` is the account being read. `create_link` writes that row after checking only that the grantee is active. `delete_link` (line 572) allows only the grantor to remove it, so the grantee cannot end the exposure.
- Reproduction: as A, `POST /links` with `grantee_account_id` B, then `GET` and `POST /accounts/{B}/notes`.
- Conditions: A's session and B's account status `active` for link creation and note creation. Listing needs only an existing account row.
- Result: A receives every note stored for B and can insert a note whose `account_id` and `origin_account_id` are B. Derived from the source trace. The token's `GET /links` for account 1 was an empty list, and no link write was sent.
- Impact and priority: high. One call opens another account's entire note collection and allows forged notes on that account. The second SQL disjunct is not required for an account to read itself; `may_read_account` already returns true when the ids match.
- Fix: in `links_grant`, match only `grantor_account_id = account being read` and `grantee_account_id = caller`, and require `revoked_at IS NULL`.

### Revoked account link still grants note access

- Source: `delete_link` in `app/routes.py` (line 575) and `links_grant` in `app/access.py` (line 29). Sink: `list_notes` and `create_note` through `may_read_account`.
- Lower-trust principal: the grantee after the grantor has revoked the link. The same query also keeps a reverse match alive.
- Failed check: `delete_link` sets `revoked_at` and leaves the row. `links_grant` selects the pair with no `revoked_at` predicate. `create_link` (line 528) already treats `revoked_at IS NULL` as the active link when blocking duplicates.
- Reproduction: A creates a link to B, A deletes it, then B calls `GET` and `POST /accounts/{A}/notes`.
- Conditions: the link row remains with `revoked_at` set, and B's session still exists.
- Result: B still receives A's note bodies and can insert notes onto A's account. Derived from the source trace. Not observed live; account 1 had no links.
- Impact and priority: high. Revocation is visible to the grantor and does not change note access. Likelihood is medium because a link has to exist and then be revoked.
- Fix: add `revoked_at IS NULL` to `links_grant`. Combine it with the one-direction match from the previous finding.

### Signed-in account can read any account's recovery email

- Source: `read_account` in `app/routes.py` (line 211), `account_json` (line 81).
- Lower-trust principal: any signed-in account other than the row owner.
- Failed check: `current()` authenticates, the returned account is discarded, and the handler always calls `account_json(row, include_recovery=True)`. `read_me` is the path that shows this field for the session account. Registration returns `include_recovery` false.
- Reproduction: `GET /accounts/{B}` with A's bearer token.
- Conditions: A's session and an existing account B. Status is not checked.
- Result: A receives B's email, display name, status, and `recovery_email`. Derived from the source trace. The token was allowed to read account 1 and was refused for other account ids by the external scope gate.
- Impact and priority: high. The recovery address is the private contact stored for the account, and the route has no relationship test at all.
- Fix: return this representation only when the session account id equals the row id. Any other caller gets 403.

### Previous device owner keeps access after transfer

- Source: `transfer_device` in `app/access.py` (line 100), `devices_for` (line 78), `may_view_device` (line 54). Entry used by the former owner: `list_devices` in `app/routes.py` (line 308). The same predicate gates `list_readings` (line 410), `create_reading` (line 385), `device_notes_for` (line 91), and the device-note routes.
- Lower-trust principal: the previous owner, after `owner_account_id` names the recipient.
- Failed check: `transfer` allows the move only for the current owner (line 361), but `transfer_device` never sets `released_at` on the binding created by `create_device` (line 291). Later reads treat any `device_bindings` row as current access.
- Reproduction: A creates a device, transfers it to B, then uses A's original session to list devices, read readings and device notes, and POST a new reading and device note.
- Conditions: A's binding row still exists, which is how both create and transfer leave it, and A's session remains valid.
- Result: derived from the source trace, A receives the device now owned by B, including later readings and notes, and can append readings and notes. Observed through the supplied token: `GET /devices` for account 1 returned device 2 with `owner_account_id` 2, label `moved`, and serial `moved-1`, plus account 1's own device. Direct device 2 routes were refused by the external scope gate, so reading and note bodies for device 2 were not fetched. The list result matches a retained binding; the token response does not include the binding row itself.
- Impact and priority: high. Ownership transfer stops further transfer and share management by A, and it does not stop A from reading or extending the device B now owns. The new owner has no request that releases A's binding. Likelihood is medium because a transfer has to happen first.
- Fix: in `transfer_device`, set `released_at` on every open binding for the device, then insert the recipient's binding. Require `released_at IS NULL` in `may_view_device` and in the `devices_for` binding join.

### Signed-in account can rename any device

- Source: `update_device` in `app/routes.py` (line 328), update at line 340.
- Lower-trust principal: any signed-in account other than the device owner.
- Failed check: the handler discards `current()` and updates `devices.label` by id. `read_device` calls `may_view_device`. `transfer` and `create_share` compare `owner_account_id` with the session account. This patch does neither.
- Reproduction: `PATCH /devices/{B's device}` with A's token and a new label.
- Conditions: A's session, an existing device, and a non-empty label.
- Result: B's device label becomes A's value, and the response includes the device serial and owner. Derived from the source trace. The read-only token was not used to send the patch.
- Impact and priority: medium. The crossed boundary is real and the owner control used next to this route is skipped, and the write is limited to the label.
- Fix: keep the session account and return 403 unless `owner_account_id` equals that account, matching `transfer`.

## Needs validation

None. Each confirmed issue is decided by the handlers and helpers in `app/`. The external scope gate on the loopback token is outside the target and was not used as a control.

## Hardening and paths reviewed without a confirmed break

- Password hashing uses PBKDF2-SHA256 with a fixed iteration count, login has no rate limit, and sessions have no expiry or logout route. Those do not by themselves let one account read or change another account. They are not confirmed findings.
- `device_shares` has no read/write flag. A share recipient who passes `may_view_device` can append readings and device notes. The owner creates that share on purpose, and the schema has no narrower grant to violate.
- `accept_merge` moves the source account's notes, devices, and link endpoints onto the survivor, and only the source account can accept. That is the merge both sides complete. It is not a separate confirmed break. Revoked links that are retargeted stay dangerous because `links_grant` ignores `revoked_at`, which is the revoked-link finding.
- `account_for_token` follows `merged_into_id` one hop after a merge the source accepted. The source's session then acts as the survivor, which is the merged identity produced by `accept_merge`.
- SQL statements that carry caller data use bound parameters. `account_json` omits `password_hash`. Login failures share one message. Share and transfer management compare the current owner. Merge acceptance compares `source_account_id` with the session account.

## Coverage

Reviewed paths: `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`. Units covered in this pass: session authentication, account read, account notes, direct note read, device list and read, device update, transfer, readings, device notes, shares, link create/list/revoke, and merge create/accept. The same-agent second pass closed those candidates. No further unit was left blocked inside this tree. Quick-profile follow-up hunting was not started. Counts for this partial pass: covered route groups 6, confirmed findings 6, needs validation 0, deferred 0.
