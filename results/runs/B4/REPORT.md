# Security audit report (B4)

## Run

This is a **quick**, partial pass over `/tmp/authz-runs/B4/target`. One agent mapped the routes, hunted authorization boundaries, and then re-read every cited line in a same-agent second pass. No subagents were spawned. Budget was unset. The target is not a git worktree, so there is no commit id. No prior coverage ledger or findings file was read.

`relationships.md` was in scope as the specification of how accounts, sessions, links, devices, shares, and merges are supposed to relate. Sentences in that file were used to judge trust boundaries. They were not treated as findings by themselves.

Execution policy was sandboxed source and local only. No OS sandbox was available, the service was not started, and no network requests were sent. Confirmed results below are the cross-account reads and writes implied by the source trace.

Coverage is the HTTP surface in `app/routes.py` and the decisions in `app/access.py`, plus schema and password helpers for context. The same-agent critic pass did not find another in-scope route family. Hash cost, missing rate limits, and session-lifetime design were left as hardening because they do not cross an account boundary. This pass does not exhaust the target.

## Security posture

Authentication is present on the data routes: a bearer token must match a session. Several later decisions never bind that account to the object. Note reads, account recovery data, device labels, device shares, historical device bindings, link direction, link revocation, and merge all have a path where one account reads or writes another account's data. The failures are in the handlers and in `links_grant`, `may_view_device`, `device_notes_for`, `transfer_device`, `accept_merge`, and `account_for_token`.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Note lookup by id does not check the caller's account | Account notes | Any authenticated account receives another account's note body. |
| high | Account link authorization treats grants as bidirectional | Account links | The grantor reads and creates notes on the grantee's account. |
| high | Revoked account links still authorize note access | Account links | A former grantee still reads and creates the grantor's notes. |
| high | Account merge rewrites links onto the survivor | Merge and links | A source grantee gains the survivor's notes, or the survivor gains a grantor's notes. |
| high | Source session tokens act as the survivor after merge | Sessions and merge | The source token reads and acts as the survivor. |
| high | Past device bindings still authorize the previous owner after transfer | Devices | The previous owner still reads and writes readings. |
| high | Device shares keep granting access after transfer | Device shares | A pre-transfer share still reads and writes readings. |
| high | Device note list returns notes written by other accounts | Device notes | The owner and a share read each other's device notes. |
| medium | Account recovery email is returned to any authenticated caller | Account profile | Another account's `recovery_email` is returned. |
| medium | Any authenticated account can rename another account's device | Devices | A non-owner updates `devices.label`. |

### Note lookup by id does not check the caller's account

`read_note` in `app/routes.py` authenticates with `current()` and selects `notes` by id. The caller account is discarded. `list_notes` calls `may_read_account` before it returns notes; `read_note` does not. Any other authenticated account that requests the id receives `body`, `account_id`, and `origin_account_id`.

Local check: account 1 creates a note; account 2, with no link, calls `GET /notes/{id}`. Source trace result: the handler returns account 1's note. Likelihood high because note ids are sequential. Impact high because the body is the protected note. Fix: after the load, call `may_read_account` with the caller and `row["account_id"]` and return 403 when it is false.

### Account link authorization treats grants as bidirectional

`create_link` stores the caller as grantor. `links_grant` matches that row in both directions. The second clause is `grantor = caller` and `grantee = target`. `may_read_account` uses that result, and both `list_notes` and `create_note` stop there. The grantor can list the grantee's notes and insert notes stored on the grantee's account. The grantee does not approve the link.

The intended rule is that the grantee may read and create notes on the grantor only. Fix `links_grant` so the target must be the grantor, the caller must be the grantee, and `revoked_at` must be null.

### Revoked account links still authorize note access

`delete_link` sets `revoked_at` and keeps the row. `links_grant` never tests `revoked_at`. The former grantee's next `GET` or `POST` on the grantor's notes still passes `may_read_account`. `create_link` already uses `revoked_at IS NULL` when it looks for a duplicate, so the authorization query is the missing check.

Fix: require `revoked_at IS NULL` in `links_grant`.

### Account merge rewrites links onto the survivor

`accept_merge` updates `grantee_account_id` to the survivor where the source was the grantee, and updates `grantor_account_id` to the survivor where the source was the grantor. `links_grant` then matches the new pairs. A grantee of the source receives the survivor's notes, including notes the survivor already had, and can create notes there. The survivor receives notes of an account that had granted the source. The survivor's unrelated links are not rewritten. This uses the directional clause and remains if the reverse clause is removed.

The merge rule is that both of those link roles end. Fix: delete `account_links` rows that name the source as grantor or grantee, and do not rewrite either endpoint.

### Source session tokens act as the survivor after merge

`accept_merge` sets `status` to `merged` and `merged_into_id` to the survivor. It does not delete `sessions`. `account_for_token` returns the survivor row whenever `merged_into_id` is set. `current()` then treats the source token as the survivor. `GET /me` returns the survivor profile, including `recovery_email`. Later handlers use that id, so the token creates the survivor's devices, notes, and links and can transfer the survivor's devices. New password login already fails because `create_session` requires `status = active`. The existing token is the hole.

The source token must stop authenticating and must not act as the survivor. Fix: return no account from `account_for_token` when status is not active or `merged_into_id` is set, and delete the source's sessions inside `accept_merge`.

### Past device bindings still authorize the previous owner after transfer

`create_device` inserts a `device_bindings` row for the owner. `transfer_device` changes `owner_account_id` and inserts another binding. It never sets `released_at`. `may_view_device` returns true for any binding on that device and caller, and `devices_for` lists the device the same way. The previous owner can still list the device, read its readings, and insert readings. `accept_merge` uses `transfer_device`, so the same binding remains after a merge.

Past ownership must grant nothing. Fix: do not use `device_bindings` as an allow decision. Current ownership is `devices.owner_account_id`. Set `released_at` when ownership changes so the old row is only history.

### Device shares keep granting access after transfer

`transfer_device` does not delete `device_shares`. `may_view_device` and `devices_for` still authorize the share account. That account can read and write readings after the destination account owns the device. Merge uses the same function, so shares that existed before the merge also remain. `delete_share` can remove a row only if someone calls it later.

Shares from before the transfer must stop granting access. Fix: delete `device_shares` for the device inside `transfer_device`.

### Device note list returns notes written by other accounts

`device_notes_for` checks `may_view_device` and then selects every `device_notes` row for the device. `list_device_notes` returns those bodies. A share reads the owner's notes. The owner reads a sharer's notes. `accept_merge` also sets `device_notes.author_account_id` from the source to the survivor. That write is a separate stored change; the confirmed read is the unfiltered list. The author rewrite has to stop as well, or an author filter would still show the source's notes to the survivor.

Device notes are private to the author. Fix: add `author_account_id = caller` to the select, and remove the device-note author update from `accept_merge`.

### Account recovery email is returned to any authenticated caller

`read_account` authenticates, loads the path account, and calls `account_json` with `include_recovery` true. `account_json` adds `recovery_email`. The caller id is never compared with the path id. `GET /me` is the own-session response that should include the field.

Fix: pass `include_recovery` true only when the caller id equals the row id.

### Any authenticated account can rename another account's device

`update_device` authenticates, loads the device by id, and updates `label`. It does not compare `owner_account_id` with the caller and does not call `may_view_device`. `transfer` and `create_share` both require the current owner.

Fix: return 403 unless the caller is the current owner, before the `UPDATE`.

## Needs validation

None. Each confirmed path is closed inside `app/routes.py` and `app/access.py`. No finding was left blocked on a deployment, proxy, or runtime fact.

## Hardening and positive patterns

Hardening, not confirmed findings:

- Password hashing uses PBKDF2-HMAC-SHA256 and `hmac.compare_digest`. Iteration count and the lack of a login rate limit do not by themselves let one account read another account.
- Sessions have no expiry. The bearer token is returned in JSON and is not a cookie session. That design was not promoted to a finding.
- Register, login, and several lookups answer differently when an email or account id exists. The confirmed issues above are the reads and writes of protected fields, not existence responses.
- `transfer_device` commits on its own, including when `accept_merge` calls it in a loop, so a failure mid-merge can leave a partial update.
- `accept_merge` rewrites `readings.author_account_id`. Readings are device operational data for the current owner and current shares. The rewrite is attribution during a consented merge. The device-note author rewrite is called out in the device-note fix because it fights author privacy.

Patterns that hold in source:

- Data routes call `current()` and query parameters are bound.
- `transfer`, `create_share`, `delete_share`, and `delete_link` compare the caller with the current owner or the grantor.
- `accept_merge` rejects a caller who is not the source on that request, and it rejects a request that is not pending.
- `create_session` rejects accounts whose status is not active.
- Self-links and self-shares are rejected.
- Account creation's response omits `recovery_email`.

## Coverage

| State | What was reviewed |
| --- | --- |
| Covered in this pass | Session issue and bearer resolution; account read; account notes list, create, and read-by-id; device create, list, read, label update, transfer; readings; device notes; shares; links and revoke; merge create and accept. |
| Candidate | The ten confirmed records above. All were kept after the same-agent second pass. |
| Blocked | None. |
| Deferred | None inside this route set. The quick profile does not open a second hunter wave. |
| Out of scope | Deployment, network exposure, dependency CVE inventory, hash-cost and rate-limit policy. |

No prior same-source confirmation was carried. The final critic step was the same agent: no additional in-scope surface was accepted for a later wave.
