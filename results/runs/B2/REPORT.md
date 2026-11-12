# Security audit report (B2)

## Run

This is a **quick**, partial, source-only pass over `/tmp/authz-runs/B2/target`. One agent mapped every route and authorization helper, then performed a same-agent second pass that re-read every cited line and tried to disprove each candidate. No budget was set. No prior coverage ledger or findings file was read. `relationships.md` was in scope as the intended trust model, not as a list of defects.

The target has no `.git` directory. The reviewed source is the unversioned tree under `app/` plus `relationships.md`.

Execution policy was sandboxed source and local only. No OS sandbox was available, the service was not started, and no network requests were sent. Confirmed records are authorization failures whose entire control flow is in the supplied source. Each `observed_result` states the cross-account read or write implied by that trace.

Scope was accounts, sessions, notes, devices, device shares, device notes, account links, and merges. Password-hash cost, missing rate limits, and bearer-session lifetime were not confirmed.

## Security posture

Authentication is present on every data route, and several mutations check the current owner or grantor. The failures are in what those checks treat as authority. A bearer token is not always the account that owns the data: merged source tokens are rewritten to the survivor, note and device reads trust an id without the caller's relationship, link grants are symmetric and ignore revocation, and device transfer does not end the previous owner's binding or the previous shares.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Any authenticated account can read another account's note by id | Account notes | Account A receives account B's note body. |
| high | An account link lets the grantor read and write the grantee's notes | Account link direction | The grantor lists and inserts notes on the grantee's account. |
| high | Revoked account links still authorize note access | Link revocation | The former grantee still lists and inserts the grantor's notes. |
| high | Device note list returns notes written by other accounts | Device-note authorship | The owner reads a sharer's note and the sharer reads the owner's note. |
| high | Former device owner keeps access through historical bindings | Device transfer | The previous owner still reads and writes readings on the transferred device. |
| high | Device shares keep access after ownership transfer | Device share lifetime | A pre-transfer share still reads and writes readings under the new owner. |
| high | A merged source session acts as the survivor account | Merge and session identity | The source token reads and writes the survivor's account. |
| high | Account merge rewrites links instead of ending them | Merge and account links | The source's grantee reads the survivor's notes, and the survivor reads notes granted only to the source. |
| medium | Any authenticated account can read another account's recovery email | Account profile | Account A receives account B's recovery email. |
| medium | Any authenticated account can rename another account's device | Device label | Account A changes account B's device label and receives the device record. |

### Any authenticated account can read another account's note by id

- Source: `read_note` in `app/routes.py`.
- Principal: any authenticated account other than the note owner.
- Failed check: `current()` is discarded. The handler never calls `may_read_account` for `notes.account_id`.
- Reproduction: with account A's bearer token, `GET /notes/{note_id}` for a note account B created.
- Conditions: a bearer token. No link is required. Note ids are sequential integers.
- Result: the response contains B's note body. Derived from the source trace.
- Impact: full read of another account's notes. Priority is high because the list route's account check is bypassed by the direct id route.
- Fix: after loading the note, require `may_read_account` for the note's `account_id`, and make that helper directional and revocation-aware.

### An account link lets the grantor read and write the grantee's notes

- Source: `links_grant` in `app/access.py`, used by `list_notes` and `create_note` in `app/routes.py`.
- Principal: the grantor.
- Failed check: the grant query matches both orientations of the pair. The stored link names the caller only as grantor.
- Reproduction: A creates a link to B, then `GET` and `POST /accounts/{B}/notes` as A.
- Conditions: an `account_links` row with A as grantor and B as grantee.
- Result: A receives B's note bodies and can insert a note stored on B's account. Derived from the source trace.
- Impact: read and write of the grantee's notes, which the link must not grant. Priority is high because creating a link is enough.
- Fix: match only `grantor_account_id = account being read` and `grantee_account_id = caller`, with `revoked_at IS NULL`.

### Revoked account links still authorize note access

- Source: `delete_link` in `app/routes.py` and `links_grant` in `app/access.py`.
- Principal: the former grantee.
- Failed check: revocation sets `revoked_at` and leaves the row. The grant query does not require `revoked_at IS NULL`.
- Reproduction: the grantor deletes the link, then the grantee lists and creates notes on the grantor's account.
- Conditions: the link row exists with `revoked_at` set, and the caller is that grantee.
- Result: the grantee still receives the grantor's notes and can insert a new one. Derived from the source trace.
- Impact: revocation does not end note access. Priority is high because the next request is the request the spec says must fail.
- Fix: require `revoked_at IS NULL` in `links_grant`.

### Device note list returns notes written by other accounts

- Source: `device_notes_for` in `app/access.py`, called by `list_device_notes`.
- Principal: the current owner, toward a sharer's notes, and a current share, toward the owner's notes.
- Failed check: after `may_view_device`, the query selects every `device_notes` row for the device and does not constrain `author_account_id`.
- Reproduction: owner and share each post a device note, then each calls `GET /devices/{id}/notes`.
- Conditions: the caller can currently view the device, and another account has authored a note on it.
- Result: each caller receives the other author's note body. Derived from the source trace.
- Impact: device-note privacy is not enforced. Priority is high for any shared device that has notes.
- Fix: add `author_account_id = caller` to the note query, and keep the view check so former owners and former shares stay excluded.

### Former device owner keeps access through historical bindings

- Source: `may_view_device` and `devices_for` in `app/access.py`. `transfer_device` never releases the previous binding.
- Principal: the account that owned the device before transfer.
- Failed check: any `device_bindings` row grants access. The binding query does not use `released_at`, and transfer does not set it on the old row.
- Reproduction: A creates a device, transfers it to B, B records a reading, and A lists and posts readings.
- Conditions: the original binding from device creation is still present, which transfer leaves in place.
- Result: A still lists the device, reads B's readings, and writes readings. Derived from the source trace.
- Impact: past ownership still grants device use. Priority is high because every transfer leaves the old binding.
- Fix: authorize only the current `owner_account_id` and current `device_shares`. Do not grant access from `device_bindings`.

### Device shares keep access after ownership transfer

- Source: `transfer_device` in `app/access.py`, called by `transfer` and by `accept_merge`.
- Principal: an account that held a share before the transfer or before the merge moved the device.
- Failed check: transfer changes the owner and does not delete `device_shares`. `may_view_device` still honors that row. The only share delete is the explicit unshare route.
- Reproduction: A shares a device with C, A transfers it to B, and C lists and posts readings.
- Conditions: a `device_shares` row exists before transfer or before merge calls `transfer_device`.
- Result: C still reads readings on B's device and can insert new readings. Derived from the source trace.
- Impact: pre-transfer shares survive ownership change, including shares on devices a merge moves to the survivor. Priority is high for every shared device that is transferred.
- Fix: delete `device_shares` for the device inside `transfer_device` before commit.

### A merged source session acts as the survivor account

- Source: `account_for_token` and `accept_merge` in `app/access.py`. `current` uses the returned account for every later route.
- Principal: the holder of a bearer token issued to the source account.
- Failed check: when `merged_into_id` is set, `account_for_token` returns the survivor. Merge does not delete `sessions`. New logins already reject a merged account; existing tokens do not.
- Reproduction: the source accepts the merge, then calls `GET /me`, `GET /accounts/{survivor}/notes`, and `POST /accounts/{survivor}/notes` with the same token.
- Conditions: the merge has set `merged_into_id`, and the source session row still exists.
- Result: the source token reads the survivor's recovery email and notes and writes notes as the survivor. The same substitution applies to device, link, and merge routes. Derived from the source trace.
- Impact: the source account remains a principal and acts as the survivor. Priority is high because the token used to accept the merge is enough.
- Fix: return no account when status is not active or `merged_into_id` is set. Do not follow the survivor pointer. Delete the source account's sessions during merge.

### Account merge rewrites links instead of ending them

- Source: the two `account_links` updates in `accept_merge`.
- Principal: a third account the source had granted, and the survivor when a third account had granted the source.
- Failed check: merge assigns the source's grantor and grantee roles to the survivor instead of ending those links. Note list then authorizes the rewritten pair.
- Reproduction: S grants G, V merges S, and G lists V's notes. Reversed, G grants S, and after the merge V lists G's notes.
- Conditions: a link names the source and a third account, and the merge is accepted.
- Result: G receives V's notes, including notes V already had. V receives G's notes. Derived from the source trace. This holds for a one-direction grant check; it does not depend on the bidirectional bug.
- Impact: merge expands note access to accounts outside the source and survivor pair. Priority is high when links exist at merge time.
- Fix: set `revoked_at` on links that name the source, and do not change the other endpoint to the survivor. Leave the survivor's other links unchanged. `links_grant` must honor `revoked_at`.

### Any authenticated account can read another account's recovery email

- Source: `read_account` in `app/routes.py`.
- Principal: any authenticated account other than the account being read.
- Failed check: `current()` is discarded, and `account_json` is called with `include_recovery=True`.
- Reproduction: `GET /accounts/{B}` with A's bearer token.
- Conditions: a bearer token. No relationship to B is required.
- Result: the body includes B's `recovery_email`. Derived from the source trace. `GET /me` remains the path that returns the caller's own recovery email.
- Impact: disclosure of the session-private recovery address. The password hash is not returned. Priority is medium because the field is private and the route is open to every account, while the rest of the account's notes are not on this response.
- Fix: pass `include_recovery` only when the loaded account id is the caller's id.

### Any authenticated account can rename another account's device

- Source: `update_device` in `app/routes.py`.
- Principal: any authenticated account that is not the current owner.
- Failed check: `current()` is discarded. The label `UPDATE` is keyed only by device id. Transfer on the next route does compare `owner_account_id`.
- Reproduction: `PATCH /devices/{B's device}` with A's bearer token and a new label.
- Conditions: a bearer token and a device id.
- Result: B's device label becomes A's value, and the response returns serial, label, and owner. Derived from the source trace.
- Impact: unauthorized change of one device field, plus disclosure of that device record. Readings and ownership are not changed by this route. Priority is medium.
- Fix: require `owner_account_id` to equal the authenticated account before updating the label.

## NEEDS VALIDATION

None. The confirmed control flows are contained in `app/routes.py`, `app/access.py`, and `app/db.py`. No deployed proxy, identity provider, or runtime policy decides these checks.

## Hardening notes

These were reviewed and are not confirmed findings:

- PBKDF2-HMAC-SHA256 at 120000 iterations and the lack of login rate limits do not, by themselves, cross an account boundary.
- Sessions have no expiry or logout. New login already refuses a merged account. The confirmed session defect is the survivor substitution, not the lack of a general expiry design.
- `GET /accounts/{id}` returns email, display name, and status to any authenticated caller. The spec restricts `recovery_email`, not those fields.
- Device transfer does not ask the destination to consent. The spec describes transfer as an owner action.
- `transfer_device` commits before `accept_merge` finishes the account and link updates. A crash can leave devices moved before the source is marked merged. That is a durability gap, not a successful-path grant.
- `create_note` stores `origin_account_id` as the target account, so a grantee's note is recorded with the grantor's id. The spec does not define that column as an authorization boundary.
- `delete_share` reports `removed: true` when no share row existed. The response does not disclose another account's data.

## Positive patterns

- Query values are bound parameters.
- Password verification uses `hmac.compare_digest`.
- Session tokens are created with `secrets.token_urlsafe(32)`.
- `create_session` rejects accounts whose status is not active, so a merged account cannot mint a new token.
- Share create, share delete, and transfer compare the caller with `owner_account_id`.
- Link revoke compares the caller with `grantor_account_id`.
- Merge accept compares the caller with `source_account_id` before applying the merge.
- Self-link, self-share, self-transfer, and self-merge are rejected.
- Account creation omits `recovery_email`. `GET /me` is the handler that correctly returns the caller's own recovery email.

## Coverage

Reviewed paths: `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, `app/__init__.py`, and `relationships.md`. Every route in `build_router` was mapped to its principal and object check.

Quick-profile limits: one hunting pass, no second hunter wave, no separate verifier process, and no dynamic execution. The same agent re-read the cited lines and rejected two candidates:

- `authz.device-note.share-author-write`: a current share inserting a note it authors is consistent with the rule that the owner must not read a sharer's notes.
- `authz.merge.author-reattribution.not-an-access-grant`: rewriting the source's author id to the survivor does not grant device access, because no authorization query uses `author_account_id`.

No `needs_validation` records remain. This pass does not claim that a later review of a changed tree would find nothing else.
