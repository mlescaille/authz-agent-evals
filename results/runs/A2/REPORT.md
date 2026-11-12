# Security audit report (A2)

## Run

This is a partial quick-profile pass over the FastAPI and SQLite service in `app/`. The scope is account, session, note, device, device-share, account-link, and account-merge handling. Budget was unset. One agent performed the route and authorization review and then re-read every cited line as a same-agent second pass. Subagents were not used. No prior coverage ledger or findings file was used.

The target was not executed. No OS sandbox was available, and the service was not started. Confirmed results below are the cross-account reads and writes implied by the handler and helper control flow, not a live response.

Source ref: the supplied tree under the target root, with no git revision read. Out of scope: deployment topology, dependency advisories, and anything outside `app/`. A fresh second verifier and a coverage-critic wave were not run.

## Security posture

Authentication is a bearer token resolved through `sessions` and `account_for_token`. Several mutations compare that account with `owner_account_id` or `grantor_account_id`, and note listing plus device reads call shared helpers. Those helpers and three direct object routes still let one account read or modify another account's data: unscoped account and note reads, an unscoped device rename, an account link that authorizes the grantor against the grantee, a revoke flag that authorization ignores, device bindings that survive transfer, and a merge path that presents the source session as the survivor.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Previous device owner retains read and write access after transfer | Former device owner to current owner | Former owner reads the new owner's readings and can insert readings and device notes |
| high | Account link creation lets the grantor read and write the grantee's notes | Link grantor to grantee | Grantor lists the grantee's notes and inserts notes under the grantee's account |
| high | Revoked account links still authorize note reads and writes | Grantee to grantor after revoke | Grantee still lists and creates the grantor's notes |
| high | Merged source session authenticates as the survivor account | Merge source to survivor | Source bearer token reads the survivor profile and acts as the survivor |
| high | Authenticated caller can read any account recovery email | Any signed-in account to any account | Caller receives the other account's recovery email |
| high | Authenticated caller can read any note by id | Any signed-in account to note owner | Caller receives the other account's note body |
| medium | Authenticated caller can rename any device | Any signed-in account to device owner | Caller updates the other account's device label |

### Previous device owner retains read and write access after transfer

- Location: `app/routes.py` `transfer`, `list_readings`, `create_reading`, `create_device_note`; `app/access.py` `transfer_device`, `may_view_device`, `devices_for`.
- Lower-trust principal: the account that owned the device before `transfer_device` ran.
- Affected resource: the device now owned by the recipient, including its readings and device notes.
- Control that fails: `may_view_device` and `devices_for` treat any `device_bindings` row as current access. `transfer_device` changes `owner_account_id` and inserts a binding for the recipient, and it never sets `released_at` on the previous owner's row. `transfer` and share management already require the current owner.
- Conditions: the caller still has that account's session, and the original binding row remains.
- Result derived from the source trace: the previous owner can list the device, read readings authored by the new owner, and insert readings and device notes. No route lets the new owner release that binding.
- Priority: high. The transfer needs no acceptance from the recipient, and the leftover binding is permanent in this source.
- Smallest fix: release current bindings inside `transfer_device`, and require `released_at IS NULL` in `may_view_device` and `devices_for`.

### Account link creation lets the grantor read and write the grantee's notes

- Location: `app/routes.py` `create_link`, `list_notes`, `create_note`, `delete_link`; `app/access.py` `links_grant`, `may_read_account`.
- Lower-trust principal: the authenticated grantor.
- Affected resource: the grantee's `notes` rows.
- Control that fails: `links_grant` matches a row where the caller is `grantor_account_id` and the target is `grantee_account_id`. `create_link` inserts that row for any other active account and does not require the grantee to accept. `delete_link` allows only the grantor to revoke it.
- Conditions: the caller has a session, and the grantee account is active.
- Result derived from the source trace: the grantor receives every note body for the grantee and can insert a note stored with the grantee's `account_id`. The grantee receives 403 from `delete_link`.
- Priority: high. One session and an account id are enough, and the write lands in the other account's note collection.
- Smallest fix: in `links_grant`, authorize only `grantor_account_id = account being accessed` and `grantee_account_id = caller`, with `revoked_at IS NULL`.

### Revoked account links still authorize note reads and writes

- Location: `app/routes.py` `delete_link`, `list_notes`, `create_note`; `app/access.py` `links_grant`.
- Lower-trust principal: the grantee, after the grantor has revoked the link.
- Affected resource: the grantor's notes.
- Control that fails: `delete_link` only sets `revoked_at`. `create_link` already ignores revoked rows when deciding that a link exists. `links_grant` still returns the revoked row.
- Conditions: a link row between the two accounts remains with `revoked_at` set, and the caller is the grantee.
- Result derived from the source trace: the grantee can still list the grantor's notes and insert notes under the grantor's `account_id`.
- Priority: high. Likelihood is medium because a grant has to exist and then be revoked; the revoke control is fully bypassed for note read and write.
- Smallest fix: require `revoked_at IS NULL` on the authorization lookup, in the granted direction.

### Merged source session authenticates as the survivor account

- Location: `app/routes.py` `accept_merge`, `current`, `read_me`, `create_session`; `app/access.py` `accept_merge`, `account_for_token`.
- Lower-trust principal: the source account on a merge request, using the bearer token minted before acceptance.
- Affected resource: the survivor account, including `recovery_email` and every action `current()` authorizes.
- Control that fails: `accept_merge` checks that the caller is the source and then sets `merged_into_id` without deleting `sessions`. `account_for_token` returns the survivor row for that token. `create_session` rejects a merged account, so password login does not provide this path.
- Conditions: the survivor created a pending merge naming this source, the source accepts it, and a pre-merge session for the source still exists.
- Result derived from the source trace: the same token reads the survivor's profile and recovery email through `GET /me`, and later note, device, link, and merge handlers receive the survivor id as the caller.
- Priority: high. The survivor must open the merge, and acceptance then gives the source the survivor's authority without the survivor's credential.
- Smallest fix: `account_for_token` returns an account only when `status` is active, and it must not follow `merged_into_id`. Delete the source account's sessions inside `accept_merge`.

### Authenticated caller can read any account recovery email

- Location: `app/routes.py` `read_account`, `account_json`.
- Lower-trust principal: any account with a valid bearer token.
- Affected resource: another account's profile, including `recovery_email`.
- Control that fails: `read_account` calls `current()` and ignores the result. The query is `SELECT * FROM accounts WHERE id = ?`, and the serializer is called with `include_recovery=True`. `create_account` uses `include_recovery=False`. `read_me` serializes only the session account.
- Conditions: the path id is some other existing account.
- Result derived from the source trace: the caller receives that account's id, email, display name, status, and recovery email. The password hash is not copied into the JSON.
- Priority: high. The route is a normal authenticated GET and the ids are integers.
- Smallest fix: return the row only when the authenticated id equals the path id.

### Authenticated caller can read any note by id

- Location: `app/routes.py` `read_note`, `note_json`; the missing call is `may_read_account`, which `list_notes` does use.
- Lower-trust principal: any account with a valid bearer token.
- Affected resource: a note whose `account_id` is a different account.
- Control that fails: `read_note` discards the authenticated account and returns `note_json` for the row loaded by id. `list_notes` returns 403 when `may_read_account` is false.
- Conditions: the note id exists and belongs to another account.
- Result derived from the source trace: the caller receives that note's body, `account_id`, and `origin_account_id`.
- Priority: high. Note ids are integers and the collection route shows the body is access-controlled.
- Smallest fix: after the load, call the corrected `may_read_account` with the row's `account_id` and return 403 on failure. The link helper must be corrected as well or a bad link would satisfy this check.

### Authenticated caller can rename any device

- Location: `app/routes.py` `update_device`.
- Lower-trust principal: any account with a valid bearer token.
- Affected resource: `devices.label` on a device owned by another account.
- Control that fails: `update_device` discards the authenticated account. `transfer` and `create_share` both require `owner_account_id` to equal the caller. `read_device` calls `may_view_device`. The label update does neither.
- Conditions: the device exists and is owned by someone else.
- Result derived from the source trace: the caller's label is written onto that device. Ownership, shares, and readings stay as they were.
- Priority: medium. The missing owner check is reliable, and the write is limited to the label.
- Smallest fix: compare `owner_account_id` with the authenticated id and return 403 on a mismatch, using the same comparison as `transfer`.

## NEEDS VALIDATION

None. The confirmed control flow is entirely in the supplied handlers and helpers. No candidate was left blocked on a deployment or runtime fact.

## Hardening and reviewed controls

These were reviewed and are not confirmed findings. They do not, by themselves, let one account read or modify another account's data.

- Password storage uses PBKDF2-SHA256, a per-password salt, and `hmac.compare_digest`. Iteration count and the absence of a login rate limit were not confirmed.
- Sessions are random bearer tokens with no expiry and no logout. That session shape was not confirmed. The merge substitution above is separate: it changes which account a token represents.
- `POST /accounts` returns 409 when the email is already registered.
- Some routes that do authorize return 404 for a missing row and 403 for a failed check.
- An active, correctly directed link lets the grantee append notes, and an explicit device share lets the recipient append readings and device notes. Those writes reuse `may_read_account` and `may_view_device`. They were not confirmed as separate breaks: the owner or grantor created the grant, device child rows store the caller as author, and the schema has no narrower permission bit. The confirmed link findings are the inverted direction and the ignored `revoked_at` flag, where the caller should have no access.
- `device_shares` rows are not removed by `transfer_device`. They are device-scoped, have no grantor column, and the new owner can delete them. That retention was not confirmed as access beyond the share.
- SQL statements that take request data use bound parameters. `account_json` does not copy `password_hash`.

Positive controls observed in source: `transfer`, share create, and share delete compare `owner_account_id`; link revoke compares `grantor_account_id`; merge accept compares `source_account_id`; password login uses one 401 for a missing, inactive, or wrong-password account; registration omits `recovery_email`.

## Coverage

Reviewed units, all inside `app/`: `main.py` (app wiring, no extra auth dependency), `routes.py` (all 24 routes), `access.py` (token resolution, link grant, account read, device view, device list, transfer, merge accept), `db.py` (schema and connection), `passwords.py` (hash and verify).

Disposition of this pass: the seven records above are confirmed after a same-agent second pass that tried to refute each trace. No needs-validation records. No coverage ledger was written. This quick pass does not claim that every future change or unreviewed deployment control is clean.
