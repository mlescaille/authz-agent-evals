# Security audit B3

## Run

Quick profile, partial pass, one agent. Scope was `/tmp/authz-runs/B3/target`: the FastAPI service under `app/` and `relationships.md`. `relationships.md` was in scope as the specification of how accounts, devices, links, and merges are supposed to relate. It was not treated as a list of findings.

The target directory is not a git repository, so there is no reviewed commit. The files on disk were the source. Budget was unset. One agent spent the hunt and the verification. Verification was a same-agent second pass: every cited line was re-read and each candidate was attacked before it was kept. No prior audit run was consulted.

Execution policy was source-and-local only. No OS sandbox was available, the service was not started, and no network request was sent. Confirmed results are the cross-account reads and writes implied by the source trace.

This is a partial pass. A separate coverage-critic agent and a second independent verifier were not used. Deferred and out-of-scope items are listed in the coverage summary.

## Security posture

Sessions bind a bearer token to one account, and most collection routes then check ownership, a device share, or an account link. Those checks disagree with the specification in a few places, and several direct routes authenticate the caller and then skip the object check. The failures let one account read or write another account's notes, recovery email, device label, readings, or device notes, and they let a merged source token act as the survivor.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
| --- | --- | --- | --- |
| high | Authenticated account can read another account's note by id | account notes | Another account receives the note body. |
| high | Account link grantor can read and create the grantee's notes | account link direction | The grantor reads and writes the grantee's notes. |
| high | Revoked account links still authorize note reads and writes | link revocation | The former grantee reads and writes the grantor's notes. |
| high | Device viewers can read another author's device notes | device-note author | A share or owner receives the other author's note body. |
| high | Previous device owner retains device access after transfer | device ownership | The previous owner reads and writes the new owner's device. |
| high | Device shares remain authorized after transfer | device share lifetime | A pre-transfer share reads and writes the new owner's device. |
| high | Account merge retargets links and exposes the other account's notes | merge link lifetime | A third account reads the survivor's notes, or the survivor reads a third account's notes. |
| high | Merged source session authenticates as the survivor account | session after merge | The source token reads the survivor's notes and recovery email. |
| medium | Authenticated account can read another account's recovery email | account profile | Another account receives `recovery_email`. |
| medium | Authenticated account can rename another account's device | device label | Another account replaces the device label. |

### Authenticated account can read another account's note by id

- Location: `read_note` in `app/routes.py`.
- Principal: any authenticated account other than the note's account, with no link required.
- Failing check: after `current()` the handler selects `notes` by id and returns `note_json`. It does not call `may_read_account`.
- Reproduction: account A stores a note. Account B calls `GET /notes/{note_id}` with B's bearer token. The trace returns A's body.
- Conditions: a valid session and an existing note id. Note ids are SQLite integer primary keys.
- Result: B receives A's note body. Derived from the source trace.
- Impact and priority: high. The collection route's account check is bypassed for the full note body.
- Fix: keep the caller and require `may_read_account` for the note's `account_id`. The link helper must also enforce one active direction, which is a separate fix.

### Account link grantor can read and create the grantee's notes

- Location: `links_grant` in `app/access.py`, used by `list_notes` and `create_note` in `app/routes.py`.
- Principal: the grantor account.
- Failing check: the second `OR` clause matches a link whose grantor is the caller and whose grantee is the account being accessed. `may_read_account` returns that result.
- Reproduction: the grantor creates a link to the grantee, then calls `GET /accounts/{grantee}/notes` and `POST /accounts/{grantee}/notes`.
- Conditions: the grantor's session and an `account_links` row in that direction.
- Result: the grantor reads the grantee's note bodies and inserts a note on the grantee's account. Derived from the source trace.
- Impact and priority: high. The grantee did not grant access to their notes.
- Fix: in `links_grant`, match only `grantor_account_id = account being accessed`, `grantee_account_id = caller`, and `revoked_at IS NULL`.

### Revoked account links still authorize note reads and writes

- Location: `links_grant` in `app/access.py`, after `delete_link` in `app/routes.py`.
- Principal: the former grantee.
- Failing check: `links_grant` selects a link by the two account ids and ignores `revoked_at`. `delete_link` sets `revoked_at` and leaves the row.
- Reproduction: the grantor revokes the link. The grantee's next `GET` and `POST` on `/accounts/{grantor}/notes` still pass `may_read_account`.
- Conditions: the grantee's session and a revoked link row. This direction matches the first clause of `links_grant`, so the result stands even if the reverse clause is removed.
- Result: the former grantee reads the grantor's notes and inserts a note on the grantor's account. Derived from the source trace.
- Impact and priority: high. Revocation does not end access.
- Fix: require `revoked_at IS NULL` in `links_grant`.

### Device viewers can read another author's device notes

- Location: `device_notes_for` in `app/access.py`, returned by `list_device_notes` in `app/routes.py`.
- Principal: a current share reading the owner's notes, or the owner reading a share's notes.
- Failing check: once `may_view_device` is true, the query selects every `device_notes` row for the device and does not require `author_account_id` to be the caller.
- Reproduction: the owner shares a device and writes a device note. The share calls `GET /devices/{id}/notes`. The same query returns a share's note to the owner.
- Conditions: the caller can already view the device, and another account has a note on it.
- Result: the other author's note body is returned. Derived from the source trace.
- Impact and priority: high. Device and reading access is not note access.
- Fix: add `author_account_id = caller` to the note query.

### Previous device owner retains device access after transfer

- Location: `may_view_device` and `devices_for` in `app/access.py`, after `transfer_device`.
- Principal: the account that owned the device before `POST /devices/{id}/transfer`.
- Failing check: `may_view_device` returns true for any `device_bindings` row for the caller and device. `transfer_device` changes `owner_account_id` and does not release the previous binding. `released_at` is never read.
- Reproduction: account A transfers the device to account B, then A's session calls `POST /devices/{id}/readings` and `GET /devices/{id}/readings`.
- Conditions: A's session is still valid and A's binding row remains.
- Result: A inserts a reading on B's device and can read B's readings. Derived from the source trace.
- Impact and priority: high. Past ownership still uses the device.
- Fix: authorize ownership only from `devices.owner_account_id`, and remove the binding branch from `may_view_device` and `devices_for`.

### Device shares remain authorized after transfer

- Location: `transfer_device` and `may_view_device` in `app/access.py`. `accept_merge` moves source-owned devices through `transfer_device`.
- Principal: an account that holds a `device_shares` row created before the transfer.
- Failing check: `transfer_device` never deletes `device_shares`. `may_view_device` returns true when that row exists. `delete_share` can remove a share, and transfer does not call it.
- Reproduction: the owner shares the device, transfers it, and the share account calls `GET` and `POST /devices/{id}/readings`.
- Conditions: a share row exists and the device's owner is now a different account.
- Result: the pre-transfer share reads the new owner's readings and inserts a reading. The merge path leaves the same rows in place. Derived from the source trace.
- Impact and priority: high. A share from the previous owner keeps using the device.
- Fix: delete `device_shares` for the device inside `transfer_device` before commit.

### Account merge retargets links and exposes the other account's notes

- Location: `accept_merge` in `app/access.py`. The later read is `list_notes` through `links_grant`.
- Principal: a third account that was the grantee of the source, or the survivor when a third account had granted access to the source.
- Failing check: `accept_merge` sets `grantor_account_id` or `grantee_account_id` to the survivor and leaves `revoked_at` unset. `links_grant` then treats the rewritten row as an active grant. This survivor-note read uses the directional clause, so it does not depend on the bidirectional defect.
- Reproduction: the source grants a third account access, the survivor opens a merge, and the source accepts it. The third account calls `GET /accounts/{survivor}/notes`. The opposite link lets the survivor call `GET /accounts/{original_grantor}/notes`.
- Conditions: a completed merge and a pre-merge link between the source and a third account. `GET /links` returns the rewritten account id to that party.
- Result: the former grantee reads the survivor's notes, including notes the survivor already had. The survivor reads notes of an account that had granted access only to the source. Derived from the source trace.
- Impact and priority: high. The merge creates a note grant the specification ends.
- Fix: set `revoked_at` on every still-active link where the source is grantor or grantee. Do not copy either id onto the survivor.

### Merged source session authenticates as the survivor account

- Location: `account_for_token` in `app/access.py`, called by `current` in `app/routes.py`. `accept_merge` sets `merged_into_id` and does not change `sessions`.
- Principal: any holder of a bearer token issued to the source account, including the token used to accept the merge.
- Failing check: when `merged_into_id` is set, `account_for_token` returns the survivor row. `current()` does not reject a merged account. `create_session` refuses a new login for a non-active account, and stored tokens skip that check.
- Reproduction: accept the merge with the source token, then call `GET /accounts/{survivor}/notes` and `GET /me` with that same token.
- Conditions: the source session row still exists and `merged_into_id` points at the survivor.
- Result: the source token reads the survivor's notes, including notes the survivor already had, and `GET /me` returns the survivor's `recovery_email`. Later owner checks see the survivor id. Derived from the source trace.
- Impact and priority: high. The source credential becomes the survivor principal.
- Fix: return no account from `account_for_token` when `status` is not active or `merged_into_id` is set. Delete the source account's sessions inside `accept_merge`.

### Authenticated account can read another account's recovery email

- Location: `read_account` in `app/routes.py`.
- Principal: any authenticated account requesting a different account id.
- Failing check: the handler calls `account_json` with `include_recovery=True` and does not compare the session account with the row.
- Reproduction: account B calls `GET /accounts/{A}` with B's token.
- Conditions: B's session and an existing account A.
- Result: the response includes A's `recovery_email`. Derived from the source trace.
- Impact and priority: medium. The field is limited to the recovery address. This service has no recovery-login route.
- Fix: pass `include_recovery` only when the caller id equals the row id. `GET /me` remains the own-session response.

### Authenticated account can rename another account's device

- Location: `update_device` in `app/routes.py`.
- Principal: any authenticated account that is not the current owner.
- Failing check: `current()` is called and its account is discarded. The label `UPDATE` is keyed only by device id. `transfer` and the share routes compare `owner_account_id` with the caller before they mutate a device.
- Reproduction: account B calls `PATCH /devices/{A's device}` with a new label.
- Conditions: B's session and an existing device id.
- Result: B replaces the label on A's device. Derived from the source trace.
- Impact and priority: medium. The write is the label, not ownership, readings, or notes.
- Fix: reject the update unless the caller is `owner_account_id`.

## NEEDS VALIDATION

None. The confirmed control flow is in the supplied source. No record is waiting on a deployment, proxy, or runtime fact.

## Hardening and patterns that were not confirmed

These do not cross an account boundary as an authorization break, or a second pass could not separate them from a confirmed root cause:

- Password hashing cost, login rate limits, session expiry, and the absence of logout are hardening. New logins already reject a merged account. The cross-account effect of an old source token is the confirmed session-substitution finding.
- `accept_merge` commits inside `transfer_device` before the rest of the merge writes. Both parties have already agreed to the merge. Partial commit is not, by itself, a grant to a third principal.
- `accept_merge` rewrites `device_notes.author_account_id` and `readings.author_account_id` from the source to the survivor. Today's device-note disclosure is the missing author filter. Account notes are specified to become the survivor's notes. The author rewrite was not confirmed as a separate cross-account grant.
- Accepting a merge request returns 404, 403, or 409. That distinguishes a missing id from an existing id and does not return the other accounts' data.
- Registration returns 409 when an email already exists. Public account existence is not a confirmed data-boundary finding.

Positive source patterns:

- Data routes call `current()` and require a bearer token. `GET /health`, account creation, and session creation are the unauthenticated routes.
- `transfer`, `create_share`, and `delete_share` compare the current `owner_account_id` with the caller.
- `delete_link` allows only the grantor to revoke.
- `accept_merge` allows only the source account named on a pending request. Self-link, self-share, self-merge, and self-transfer are rejected.
- SQL values are bound parameters. Password verification uses `hmac.compare_digest`. Account creation omits `recovery_email`.
- The first clause of `links_grant` is the directional grant the specification allows, once `revoked_at` is honored and the reverse clause is removed.

## Coverage

The route map in `app/routes.py` and the helpers in `app/access.py` were reviewed, along with `app/db.py`, `app/passwords.py`, and `app/main.py`. Surfaces covered: session issue and bearer resolution, account profile reads, account notes, account links, devices, transfer, shares, readings, device notes, and merge open/accept.

No ledger file was requested. Counts for this single pass: the confirmed records above are the candidate set that survived the second read. Nothing inside the target tree was left as a blocked or deferred authorization surface. Out of scope: running the service, network calls, deployment configuration, and a separate critic or verifier agent.

The final critic required by an unmodified quick profile did not run as a second agent. This report makes no complete-coverage claim beyond the route and helper map above.
