# Security audit A3

## Run

This is a partial quick-profile pass over the FastAPI and SQLite service in `app/`. One agent mapped the routes and authorization decisions, hunted for cross-account reads and writes, and then re-read every cited line and tried to disprove each candidate. Verification was a same-agent second pass. No prior audit ledger was used. Budget was unset. No subagents were launched, and the quick profile's follow-up hunter wave was not run.

The target is the source under `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, and `app/passwords.py`. No git revision was available in the reviewed tree. Execution policy was sandboxed source and local only. This environment had no OS sandbox, so the service was not started and no requests were sent. Each confirmed result below is the cross-account read or write implied by the source trace.

Coverage is partial. The pass reviewed account sessions, account profiles, notes, devices, device bindings, device shares, account links, and account merges. Deployment, proxies, dependency advisories, and availability were out of scope. Nothing in this run shows that unreviewed behavior outside this tree is safe.

## Security posture

Authentication is a bearer token looked up in `sessions`. Several later decisions never bind that account to the object being read or written. The weakest note path is a link the caller creates for itself: `links_grant` treats it as access to the other account's notes. Direct object routes for notes, account profiles, and device labels authenticate the caller and then skip the check used by the neighboring handler. Device transfer and link revocation update ownership or `revoked_at` without making the authorization queries honor that new state. A completed account merge also retargets outbound links onto the survivor.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Grantor can read and write the grantee's notes through a self-created link | Account A to account B's notes | A reads B's notes and inserts notes stored as B's |
| high | Revoked account links still allow note reads and writes | Former grantee to grantor's notes | Grantee still reads and creates the grantor's notes after `revoked_at` is set |
| high | Authenticated callers can read any note by id | Any session to another account's note | Caller receives the note body |
| high | Previous device owners retain device access after transfer | Former owner to the new owner's device data | Former owner reads and appends readings after transfer |
| medium | Merging accounts gives the source's grantees the survivor's notes | Source grantee to survivor notes | Grantee reads and creates the survivor's notes, including pre-merge notes |
| medium | Authenticated callers can read any account's recovery email | Any session to another account profile | Caller receives the other account's `recovery_email` |
| medium | Authenticated callers can rename any device | Any session to another account's device | Caller changes the device label |

### Grantor can read and write the grantee's notes through a self-created link

`app/routes.py` `create_link` and `app/access.py` `links_grant`. Account A, signed in, posts a link with `grantee_account_id` of account B. B does not accept. `links_grant` is true when the caller is the grantor and the target is the grantee. `list_notes` and `create_note` call `may_read_account` and then read or insert B's notes. `delete_link` allows only the grantor to revoke, so B cannot remove the row.

Reproduction uses two active dummy accounts. A calls `POST /links` with B's id, then `GET /accounts/{B}/notes` and `POST /accounts/{B}/notes`. The source trace shows the inserted row matching the second predicate of `links_grant`, so both handlers proceed. Impact is high because the note collection is fully readable and writable. Likelihood is high because the only precondition is a normal session and an active target id. The fix is to authorize a link only when the target is the grantor and the caller is the grantee.

### Revoked account links still allow note reads and writes

`app/routes.py` `delete_link` and `app/access.py` `links_grant`. The grantor can set `revoked_at`, and the row stays. `links_grant` matches on the two account ids and does not require `revoked_at IS NULL`. The grantee still passes `may_read_account`, so `list_notes` returns the grantor's notes and `create_note` inserts another. `create_link` already treats a non-null `revoked_at` as "not a current link" when checking duplicates. The authorization query does not.

Reproduction: grantor A links grantee B, A deletes the link, and B lists and creates A's notes. The source trace shows the revoked row still satisfying `links_grant`. Impact and likelihood are high: revocation is the supported control, and it leaves note read and write in place. The fix is to require `revoked_at IS NULL` in `links_grant`.

### Authenticated callers can read any note by id

`app/routes.py` `read_note`. A signed-in account calls `GET /notes/{note_id}`. The handler loads the note by primary key and returns `note_json`, including the body. It never calls `may_read_account`. `list_notes` does call that helper for the same table.

Reproduction: account B creates a note, and unrelated account A requests that note id. The source trace has no owner or link check between authentication and the response. Impact is high because the protected note body is disclosed. Likelihood is high because note ids are sequential. The fix is to keep the caller from `current` and reject the read when `may_read_account` is false for the note's `account_id`. The link-predicate fixes still have to make that helper enforce the intended grant.

### Previous device owners retain device access after transfer

`app/routes.py` `transfer` and `app/access.py` `transfer_device`, `may_view_device`, and `devices_for`. The owner check on transfer is real: only the current owner can transfer. `transfer_device` then changes `owner_account_id` and inserts a binding for the recipient. The binding created for the previous owner, including the row `create_device` inserted, stays with `released_at` null. `may_view_device` returns true for any binding on that device and account. The previous owner can list the device, read readings and device notes, and append new readings and device notes.

Reproduction: A creates a device, transfers it to B, B adds a reading, and A lists and creates readings. The source trace shows A's binding still matching `may_view_device` after the owner column changes. Impact is high because device content created after the transfer is readable and writable by the previous owner. Likelihood is high because this is the normal transfer path. The fix is to set `released_at` on active bindings during transfer and to ignore released bindings in `may_view_device` and `devices_for`.

### Merging accounts gives the source's grantees the survivor's notes

`app/routes.py` `accept_merge` and `app/access.py` `accept_merge`. The source account must accept; the survivor cannot accept alone. On acceptance, notes move to the survivor and every outbound link of the source is rewritten so `grantor_account_id` becomes the survivor. `links_grant` then allows that grantee to read and create notes for the whole survivor account, including notes whose `account_id` was already the survivor.

Reproduction: V has a note, S has a note and a link to G, V opens a merge of S, and S accepts. G then lists and creates V's notes. The source trace shows the grantor rewrite creating a link `links_grant` accepts for V and G. Impact is high for V's note collection. Likelihood is medium because G cannot force V and S to complete the merge. Overall severity is medium. The fix is to stop assigning the survivor as grantor of the source's outbound links; revoke those rows instead, and honor `revoked_at` in `links_grant`. The second pass did not treat the inbound rewrite as this defect: that statement moves access the source already held onto the account the source agreed to join.

### Authenticated callers can read any account's recovery email

`app/routes.py` `read_account` and `account_json`. `GET /accounts/{account_id}` authenticates any session, loads the account by id, and calls `account_json` with `include_recovery` true. `read_me` includes recovery email for the caller. `create_account` passes `include_recovery` false. The cross-account field confirmed here is `recovery_email`. The handler does not return the password hash.

Reproduction: A calls `GET /accounts/{B}` with A's bearer token. The source trace shows the path id selected and `recovery_email` added because the flag is true. Likelihood is high. Impact is medium because the disclosed secret is the recovery address and the profile fields returned with it, not notes or credentials. The fix is to pass `include_recovery` only when the authenticated id equals the requested id.

### Authenticated callers can rename any device

`app/routes.py` `update_device`. `PATCH /devices/{device_id}` authenticates the caller, discards that account, and updates `devices.label` for the path id. `transfer` and `create_share` compare `owner_account_id` with the caller. `read_device` calls `may_view_device`. The patch route does none of those.

Reproduction: B creates a device, and A patches its label. The source trace shows the update committed with no owner predicate. Likelihood is high. Impact is medium because the write is limited to the label and does not transfer the device or disclose readings. The fix is to require the authenticated account to be the current owner before the update.

## NEEDS VALIDATION

No needs-validation records. Each confirmed control flow is fully present under `app/`. Claims that would have depended on a proxy, browser, or deployed configuration were not raised.

## Hardening notes

These were reviewed and are not confirmed findings.

- Password hashing cost, missing rate limits, and sessions without expiry, rotation, or logout do not by themselves let one account read or modify another account.
- `device_shares` rows remain after `transfer_device`. Shares have no release column, and the current owner can delete a share by account id. The source does not state that transfer must clear shares, so share persistence was not confirmed. There is no list-shares route, which leaves the new owner without an API way to discover existing grantees.
- `may_view_device` is also the gate for appending readings and device notes. An owner-created share therefore allows append. That follows the helper the owner-facing share path already uses, so it was not confirmed as a separate bypass.
- `account_for_token` follows `merged_into_id` one hop and can return a merged account when an older source session points at an intermediate account. Further access to a later survivor's device content depends on the stale-binding finding above.
- `create_note` stores `origin_account_id` as the path account. That write is the effect of `may_read_account` and is covered by the link findings.

## Positive patterns

- Queries use bound parameters.
- Session tokens come from `secrets.token_urlsafe(32)` and are looked up as exact primary keys.
- Password verification uses `hmac.compare_digest`.
- The API uses an `Authorization` bearer token.
- Login returns the same failure for an unknown email, an inactive account, and a bad password.
- Device transfer, share creation, share deletion, and link revocation check the current owner or grantor.
- Merge acceptance requires the source account named on the request.
- Account creation omits `recovery_email` from its response.
- Note listing calls `may_read_account` before returning a collection.

## Coverage

Reviewed in this pass: session authentication, account create and profile reads, notes, devices, bindings, shares, readings, device notes, links, and merges. Covered attack classes were access control, object isolation, and stale authorization after revoke, transfer, and merge. No separate ledger file was produced. The same-agent second pass is the verification record. Deferred follow-up hunting was not started. This remains a partial quick pass.
