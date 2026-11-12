# Security audit report: account directory

## Run

This is a partial quick-profile pass over the FastAPI and SQLite service in `app/`. One agent mapped the routes and authorization helpers, hunted for cross-account reads and writes, and then re-read every cited line. Verification was a same-agent second pass. `relationships.md` was in scope as the specification of intended account, device, link, and merge behavior.

No prior audit ledger was in scope. The target directory has no git metadata, so the reviewed source is the working tree. The service was not started and no network requests were sent. There is no OS sandbox here, so no target process was executed. Each confirmed result below is the cross-account read or write implied by the source trace.

Budget was unset. A separate coverage-critic agent was not run. This pass does not claim critic-clean coverage.

Scope was `app/main.py`, `app/routes.py`, `app/access.py`, `app/db.py`, `app/passwords.py`, `app/__init__.py`, and `relationships.md`. Attack classes used were access control, account-link and merge state, tenant and object isolation, stale authorization after transfer and revocation, and session binding after merge. Injection, browser CSRF, cache framing, and cryptography cost were reviewed only far enough to see that they do not cross an account boundary in this tree.

## Security posture

Authentication is a bearer token resolved by `account_for_token`. Collection routes for account notes and device readings call shared helpers, and transfer, share management, and link revocation compare the caller with the current owner or grantor. Those helpers and several direct routes still grant one account the notes, recovery email, device readings, device notes, or device label of another account. Merge completion both aliases the source session to the survivor and retargets the source's links onto the survivor.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Accepted merge retargets the source account's links onto the survivor | Account links after merge | A source grantee reads and writes the survivor's notes, and the survivor reads notes of accounts that granted the source |
| high | A merged source session authenticates as the survivor | Session after merge | The source token reads the survivor's notes and acts as the survivor |
| high | Device note listing returns notes written by other accounts | Device notes | The owner and a share each receive the other's device-note bodies |
| high | An account link lets the grantor read and write the grantee's notes | Account link direction | The grantor reads the grantee's notes and inserts notes onto that account |
| high | A revoked account link still grants note access | Link revocation | The grantee still reads and writes the grantor's notes after `revoked_at` is set |
| high | A previous device owner keeps access through historical bindings | Device transfer | The previous owner reads and writes readings on the destination's device |
| high | Device shares keep access after ownership transfer | Device shares | A pre-transfer share still reads and writes readings after transfer or merge |
| medium | Any authenticated account can read another account's recovery email | Account profile | Another account's `recovery_email` is returned |
| high | Any authenticated account can read another account's note by id | Account notes | An unrelated account receives the note body |
| medium | Any authenticated account can rename another account's device | Device label | An unrelated account updates the owner's device label |

### Accepted merge retargets the source account's links onto the survivor

`access.accept_merge` rewrites `account_links` so the survivor replaces the source as grantor or grantee. The lower-trust principal is the source's grantee, or the survivor when another account had granted the source access. `links_grant` then matches the rewritten row on the grantor-to-grantee predicate, and `list_notes` and `create_note` follow that result.

The source must accept a pending merge while a link names the source. Derived from the source trace, the original grantee receives the survivor's notes, including notes the survivor already held, and can insert a note on the survivor. In the other direction the survivor receives notes of the source's former grantors. Impact is high because those are full note bodies and writes. The smallest fix is to delete, inside the merge, every link row that names the source, and to leave the survivor's own links unchanged.

### A merged source session authenticates as the survivor

`access.account_for_token` returns the survivor when the session's account has `merged_into_id` set. The lower-trust principal is the holder of the source account's existing bearer token. `accept_merge` sets the alias and does not delete `sessions`. `create_session` rejects a merged account, and `current` does not repeat that check.

The source must have accepted the merge and still hold its token. Derived from the source trace, that token lists the survivor's notes, and the same caller id satisfies owner checks on the survivor's devices and links. `GET /me` also returns the survivor profile. Impact is high: the source principal operates the survivor account. The smallest fix is to return no account from `account_for_token` when status is not active or `merged_into_id` is set, and to delete the source sessions in the merge.

### Device note listing returns notes written by other accounts

`access.device_notes_for` allows the caller through `may_view_device` and then selects every `device_notes` row for the device. `list_device_notes` returns those bodies. The lower-trust principal is the current owner reading a share's note, or a current share reading the owner's note. The failing check is the missing `author_account_id` predicate.

The device must already contain a note written by the other party. Shares are allowed to write their own device notes, so that state is a normal use of the device. Derived from the source trace, each party receives the other's note body. Impact is high. The smallest fix is to return only rows whose author is the caller.

### An account link lets the grantor read and write the grantee's notes

`create_link` stores the caller as grantor. `access.links_grant` matches that row in both directions, and `may_read_account` is what `create_note` and `list_notes` enforce. The lower-trust principal is the grantor. The failing check is the reverse OR predicate.

The grantor only needs to create the link. The grantee does not approve it. Derived from the source trace, the grantor receives the grantee's notes and inserts a note stored on the grantee's account. Impact is high. The smallest fix is to authorize only a caller who is the grantee of an active link whose grantor is the account being read, or the account itself.

### A revoked account link still grants note access

`delete_link` sets `revoked_at` and leaves the row. `links_grant` matches `grantor_account_id` and `grantee_account_id` and never reads `revoked_at`. The lower-trust principal is the former grantee. This match is the forward predicate, so it stands even if the reverse predicate is removed. `create_link`'s duplicate check already requires `revoked_at IS NULL`, which shows revocation is stored and then ignored on the authorization path.

The grantor must have revoked the link. Derived from the source trace, the grantee's next list and create still succeed against the grantor's notes. Impact is high. The smallest fix is to require `revoked_at IS NULL` in `links_grant`.

### A previous device owner keeps access through historical bindings

Creating a device inserts a `device_bindings` row. `transfer_device` inserts a new binding for the destination and does not release the old one. `may_view_device` and `devices_for` treat any binding row as access, and no query reads `released_at`. The lower-trust principal is the previous owner, still using that account's own token. The failing check is the binding lookup.

The device must have been transferred. Derived from the source trace, the previous owner lists the device, reads readings recorded by the new owner, inserts a reading on that device, and, because `device_notes_for` returns every note once visibility passes, receives the device's notes. Impact is high. The smallest fix is to authorize from `devices.owner_account_id` and current share rows only, and to stop using bindings as a grant.

### Device shares keep access after ownership transfer

`transfer_device` changes `owner_account_id` and does not delete `device_shares`. `may_view_device` and `devices_for` still match the share. `accept_merge` moves the source's devices by calling `transfer_device`, so the same rows survive a merge. The lower-trust principal is an account that received the share before the ownership change and is not the new owner. The failing check is the share lookup, which has no owner-generation predicate. Share removal exists only on the owner's explicit delete route.

A share must exist from before the transfer or merge. Derived from the source trace, that account still lists the device, reads later readings, and inserts readings. Impact is high. The smallest fix is to delete `device_shares` for the device inside `transfer_device`, which covers both the transfer route and merge.

### Any authenticated account can read another account's recovery email

`read_account` authenticates the caller, loads the path account, and calls `account_json` with `include_recovery` true. The caller id is discarded. The lower-trust principal is any other authenticated account. The failing check is the unconditional inclusion of `recovery_email`. `GET /me` is the own-session response that is supposed to include it, and account creation omits it.

No relationship to the target account is required. Derived from the source trace, the response contains the other account's `recovery_email`. Impact is medium because the disclosed field is the recovery email and the response does not include the password hash or note bodies. The smallest fix is to set `include_recovery` only when the caller id equals the row id.

### Any authenticated account can read another account's note by id

`read_note` authenticates the caller, selects `notes` by id, and returns `note_json`, including the body. It does not call `may_read_account`. The collection route for the same table does. The lower-trust principal is any authenticated account other than the note's account and other than an active grantee of that account. The failing check is the absent account binding.

A note id must exist. Derived from the source trace, the unrelated caller receives the note body. Impact is high. The smallest fix is to call `may_read_account` with the caller and the note's `account_id` before returning the row. That helper still has to enforce link direction and revocation for the grantee case.

### Any authenticated account can rename another account's device

`update_device` authenticates the caller, loads the device by id, and updates `label`. The caller is discarded. Transfer and share creation compare the caller with `owner_account_id`, and the device read route calls `may_view_device`. The lower-trust principal is an authenticated account that is neither the current owner nor a share. The failing check is the missing owner comparison.

The device must exist and the label must be non-empty. Derived from the source trace, the patch writes the new label onto the owner's device and returns the serial and owner id. Impact is medium because the write is the label. The smallest fix is to require the caller to be the current owner, the same comparison transfer uses.

## Needs validation

None. The confirmed records above close on the supplied source. No candidate was left blocked on a deployment, proxy, or runtime fact.

## Hardening and paths not confirmed

These were reviewed and are not confirmed findings:

- Password hashing uses PBKDF2-HMAC-SHA256 with a per-password salt and `hmac.compare_digest`. Iteration count and the lack of a login rate limit do not by themselves let one account read or modify another account.
- Sessions have no expiry, rotation, or logout. New login already refuses a merged account. The confirmed session defect is the survivor alias in `account_for_token`.
- `transfer_device` commits before `accept_merge` marks the source merged. A crash or overlapping request can observe a partial merge. The confirmed merge results are the state after the function completes.
- `accept_merge` does not require the survivor to still be active. A stale accept still falls under the session alias and the link rewrite already recorded.
- `accept_merge` rewrites `author_account_id` on readings and device notes for the source principal. That follows the source ceasing to be a principal. It was not confirmed as a separate grant of another account's protected content.
- Queries are parameterized. State-changing routes require an `Authorization` bearer token, not an ambient cookie. Account and device id oracles that differ only by 404 and 403 were not confirmed as disclosure of a protected field.
- `main.py` installs no extra middleware. `GET /health` returns a static status.

Positive controls that held on review: registration omits `recovery_email`; login uses one failure response for an unknown, inactive, or wrong-password account; self-link, self-share, self-transfer, and self-merge are rejected; link revocation and share deletion are limited to the grantor or current owner; merge accept requires the authenticated account to be the source named on the request.

## Coverage

All seven application modules and `relationships.md` were read. Every route in `build_router` was traced through `current` or its public unauthenticated entry, then through the helper or SQL that decides the account, device, link, or merge effect.

The second pass re-opened each cited line and tried to refute the claim. Refutations that held were the non-findings above. The ten records stayed confirmed because each failing check is in the handler or helper that performs the read or write, and a sibling check does not run on that path.

No coverage ledger was written for this single-agent run. Counts for this pass: 10 confirmed records, 0 needs-validation records, 0 rejected records retained. Unreviewed areas outside this tree were out of scope. A later standard run would still add an independent verifier and a coverage critic; their absence is why this quick pass remains partial.
