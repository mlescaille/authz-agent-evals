# Security audit C1

Quick profile, partial pass, single agent. Scope is the FastAPI service under `app/` (accounts, sessions, devices, device shares, account links, and account merges). Budget was unset. Source was the supplied target tree; git metadata was not read. No prior coverage ledger was supplied, and other audit runs were not searched. Execution stayed on source plus the supplied read-only loopback token. The token was not used to send a cross-account request or a mutation. Verification was a same-agent second pass: every cited line was re-read and each candidate was tested against the surrounding checks before it was kept.

This is not a complete review of the service. It is the one quick pass requested for authorization and object access.

## Posture

Authentication is a bearer session looked up in `sessions`. Several later decisions do not bind that account to the object. Two direct reads return another account's data after authentication only. Device rename does the same for a write. Account links authorize both directions and ignore revocation. Device transfer leaves the previous owner's binding in force. An accepted merge rewrites link endpoints onto accounts that were not parties to the original grant.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Accepted merge retargets account links and discloses another account's notes | Source account's grantee, and the survivor, versus a third account's notes | Grantee reads and adds notes on the survivor; survivor reads notes of accounts that granted access to the source. Source trace. |
| high | Creating an account link lets the caller read and modify the grantee's notes | Link creator versus the grantee account | Creator lists the grantee's notes and inserts a note stored on that account. Source trace. |
| high | Revoked account links continue to authorize note access | Either party to a revoked link versus the other account's notes | List and create still succeed after `revoked_at` is set. Source trace. |
| high | Former device owner keeps read and write access after transfer | Previous owner versus the recipient's device readings and device notes | Previous owner lists the device, reads readings, and appends readings and device notes. Source trace. |
| high | Authenticated callers can read any account profile including recovery email | Any session versus any account row | Response includes email, display name, status, and recovery email. Source trace. Own-account shape also seen with the token. |
| high | Authenticated callers can read any note by id | Any session versus any note row | Response includes the note body and account id. Source trace. Own note id was fetched with the token. |
| medium | Authenticated callers can rename any device | Any session versus any device row | Label is updated and the response includes serial and owner id. Source trace. Token was not used to PATCH. |

### Accepted merge retargets account links and discloses another account's notes

`accept_merge` in `app/access.py` requires the caller to be the source account, moves that account's notes, and then sets both `grantor_account_id` and `grantee_account_id` to the survivor wherever they still name the source. `list_notes` and `create_note` in `app/routes.py` authorize the whole account through `may_read_account` and `links_grant`.

Lower-trust principals: a grantee of the source, and the survivor with respect to accounts that granted access to the source. The failing check is the unconditional link rewrite; `links_grant` then accepts the new pair.

Reproduction on a local fixture: A opens a merge of B, B accepts, D was B's grantee, and C had granted B a link. D calls `GET /accounts/A/notes` and `POST /accounts/A/notes`. A calls `GET /accounts/C/notes`.

Result, from the source trace: D receives A's notes, including notes that never belonged to B, and can insert a note with `account_id` A. A receives C's notes. The supplied token did not perform this sequence.

Impact is high because the grant becomes account-wide note read and create for a party the original grantor did not name. Likelihood is medium because a link and an accepted merge must both exist. Overall severity is high.

Smallest fix: stop updating `account_links` inside `accept_merge`. Continue moving the source account's own rows. If grantees must keep the moved notes, authorize only the note ids whose `account_id` that merge changed.

### Creating an account link lets the caller read and modify the grantee's notes

`create_link` in `app/routes.py` stores the caller as grantor and the supplied account as grantee. `links_grant` in `app/access.py` matches either direction. `may_read_account` then allows `list_notes` and `create_note`.

Lower-trust principal: the authenticated link creator. Affected principal: the grantee. The failing check is the second `OR` in `links_grant`, which treats the creator as allowed to read the grantee. `create_link` also has no grantee acceptance step. `delete_link` lets only the grantor revoke, so the roles are not symmetric elsewhere.

Reproduction: as A, `POST /links` with B's id, then `GET /accounts/B/notes` and `POST /accounts/B/notes`.

Result, from the source trace: A receives B's note bodies and inserts a note stored on B. The token's `GET /links` for account 1 was empty, and the token was not used to create a link.

Likelihood and impact are high. Overall severity is high.

Smallest fix: in `links_grant`, require `grantor_account_id` to be the account being read, `grantee_account_id` to be the caller, and `revoked_at IS NULL`.

### Revoked account links continue to authorize note access

`delete_link` sets `revoked_at` and leaves the row. `links_grant` never reads `revoked_at`. `create_link` already ignores revoked rows when it checks for a duplicate. `list_notes` and `create_note` still pass `may_read_account` for either party.

Lower-trust principal: either account named on the revoked row. The failing check is the missing `revoked_at IS NULL` predicate in `links_grant`.

Reproduction: revoke the link as the grantor, then list and create notes on the other account as both the grantor and the grantee.

Result, from the source trace: both parties still read the other account's notes and can insert notes onto that account. The token was not used to revoke a link.

Likelihood and impact are high because the only revoke operation does not change later authorization. Overall severity is high.

Smallest fix: use the same active, grantor-to-grantee predicate in `links_grant` as in the direction fix above.

### Former device owner keeps read and write access after transfer

`transfer_device` in `app/access.py` updates `owner_account_id` and inserts a binding for the recipient. Device creation has already inserted the original owner's binding with `released_at` NULL, and transfer does not change that column. `may_view_device` and `devices_for` match any binding. `list_readings`, `create_reading`, `list_device_notes`, and `create_device_note` all use that decision. `delete_share` deletes `device_shares` only, so the new owner cannot drop the old binding.

Lower-trust principal: the previous owner, after the transfer. Affected data: the recipient's device, readings, and device notes. The failing check is the binding query in `may_view_device` and `devices_for`, which does not require an unreleased binding, together with `transfer_device` never releasing the old row.

Reproduction: A transfers a device to B, B adds a reading, and A then lists the device, lists readings, posts a reading, and posts a device note.

Result, from the source trace: A still receives the device and its reading values and can append a reading and a device note. The token was not used to transfer a device.

Likelihood is medium because a transfer must happen first. Impact is high because the read and append continue and the new owner has no revoke for the binding. Overall severity is high.

Smallest fix: set `released_at` on the device's current bindings during transfer, then insert the recipient binding. Require `released_at IS NULL` in both access queries.

The allowed `GET /devices` response for the scoped token included a device whose `owner_account_id` was not the caller, along with the caller's own device. That response does not say whether a binding or a share produced the row, so it is not evidence for this transfer defect.

### Authenticated callers can read any account profile including recovery email

`read_account` in `app/routes.py` calls `current`, ignores the result, and returns `account_json(..., include_recovery=True)` for the path id. `read_me` is the route that returns the caller's own profile. Registration uses `include_recovery=False`.

Lower-trust principal: any authenticated account. Affected principal: the account named in the path. The failing check is the absent comparison between the caller and `account_id`, and the absent `may_read_account` call.

Reproduction: as A, `GET /accounts/{B}`.

Result, from the source trace: the body contains B's email, display name, status, and recovery email. The password hash is not serialized. The token confirmed that `GET /accounts/1` returns `recovery_email` for the caller's own id. A different account id was not requested.

Likelihood and impact are high. Overall severity is high.

Smallest fix: require the caller id to equal the row, or an explicit helper to allow the row, and include `recovery_email` only for the caller's own row.

### Authenticated callers can read any note by id

`read_note` in `app/routes.py` loads `notes` by primary key and returns `note_json`. `list_notes` calls `may_read_account` before it returns those fields. `app/main.py` adds no router-level authorization dependency.

Lower-trust principal: any authenticated account. Affected principal: the note's `account_id`. The failing check is the missing `may_read_account` decision on the loaded note.

Reproduction: as A, `GET /notes/{id}` for a note stored on B, including when `GET /accounts/B/notes` is forbidden.

Result, from the source trace: the response contains the note body, `account_id`, and `origin_account_id`. The token was used only for `GET /notes/1`, the allowed own note id.

Likelihood and impact are high. Overall severity is high.

Smallest fix: return the note only when `may_read_account` is true for `note.account_id`, and use one not-found result for a missing note and an unreadable note.

### Authenticated callers can rename any device

`update_device` in `app/routes.py` authenticates, then updates `devices.label` for the path id. `transfer` and `create_share` compare `owner_account_id` with the caller. `read_device` calls `may_view_device` before returning a device. The patch route does neither, and its response includes `serial` and `owner_account_id`.

Lower-trust principal: any authenticated account. Affected principal: the device owner. The failing check is the missing owner comparison before the `UPDATE`.

Reproduction: as A, `PATCH /devices/{id}` for a device owned by B.

Result, from the source trace: B's label changes to A's value, and the response carries the serial and owner id. The token was not used to send a PATCH.

Likelihood is high. Impact is medium because the write is the label and the extra disclosure is device identity, not readings or notes. Overall severity is medium.

Smallest fix: keep the account returned by `current` and reject the update unless `owner_account_id` equals that account.

## Needs validation

None. The confirmed control flows are entirely in the supplied source. The scoped token was not required to establish them.

## Hardening and positive patterns

Not confirmed, because they do not by themselves cross an account boundary or because a visible control still matches the implemented rule:

- Password hashing uses PBKDF2-HMAC-SHA256 at 120000 iterations. Hash cost was out of confirmation scope.
- Sessions have no expiry, logout, or rotation. That is demo session design, not a demonstrated cross-account bypass. Login stores `secrets.token_urlsafe(32)` and looks the token up as an opaque session key.
- Login and registration have no rate limit.
- `create_note` reuses `may_read_account`, so a principal who is allowed to list an account's notes may also insert one. The shared helper is applied on both routes. The unauthorized principals are the ones already covered by the link, revocation, and merge findings.
- `may_view_device` also authorizes reading and device-note appends for an explicit share. Share rows are owner-created and owner-deleted. That single permission level was not treated as a separate defect.
- `transfer_device` does not delete `device_shares`. The new owner can still remove those rows through `delete_share`.
- `accept_merge` commits inside each `transfer_device` call before the final merge commit.
- `account_for_token` follows a single `merged_into_id` hop.
- Account registration returns 409 when the email already exists.

Positive controls observed in source: SQL uses bound parameters; `password_hash` is not serialized; password comparison uses `hmac.compare_digest`; transfer, share create, share delete, and link delete check the owner or grantor; merge acceptance requires the source account; device read, device list, and reading routes call the device helper; note listing calls the account helper; inactive accounts cannot log in.

## Coverage

Routes reviewed: health, account create, session create, self profile, account read, account notes, note read, device create, device list, device read, device update, transfer, readings, device notes, shares, links, and merge requests.

Covered boundary: authenticated account versus another account's profile, notes, devices, readings, shares, links, and merge result. The second pass kept the seven records above.

Deferred by the quick profile: a second independent hunter, a separate critic agent, and any class outside this account-isolation pass. No subagents were used. Validator status is recorded by the findings validator run for this output.
