# How accounts, devices, links, and merges relate

This note is the intended behavior of the account directory. It describes invariants. It does not describe defects.

## Accounts and sessions

An account is a principal. `POST /sessions` issues a bearer token to that account. A request carrying the token acts only as that account.

`recovery_email` is visible only on the account's own session, including `GET /me`.

## Account links

A link is directional. The grantor grants the grantee access to the grantor's account notes. The link does not let the grantor read the grantee's notes, and it does not let the grantee read any account except the grantor.

While the link is active, the grantee may read and create notes on the grantor's account. When the grantor revokes the link, that access ends on the next request. A revoked link authorizes nothing.

## Devices

A device has one current owner. The owner may record readings, write device notes, and share the device with other accounts.

A current share lets that account read the device and its readings, and write readings. Readings are operational data of the device and are visible to the current owner and to current shares.

Device notes are private to the author. A share does not reveal another account's device notes. The owner does not read a sharer's device notes through the device, and a sharer does not read the owner's device notes.

Transfer gives the destination account current ownership. After the transfer completes:

- the previous owner no longer reads or writes the device, its readings, or its notes
- shares that existed before the transfer no longer grant access
- past ownership does not grant access

Only the current owner and current shares can use the device.

## Merges

A merge folds a source account into a survivor account. The survivor opens the request and the source accepts it. Both steps are required.

After the merge:

- the source account is no longer a principal
- tokens issued to the source no longer authenticate, and they do not act as the survivor
- devices owned by the source move to the survivor and follow the transfer rules, so previous shares end
- notes that belonged to the source become notes of the survivor
- links in which the source was the grantor end. Someone the source had granted access to does not gain the survivor's notes, including notes the survivor already had
- links in which the source was the grantee end. The survivor does not gain access to accounts that had granted access to the source
- links the survivor already had are unchanged
