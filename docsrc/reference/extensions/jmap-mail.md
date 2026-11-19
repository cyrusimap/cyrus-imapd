# JMAP for Mail extensions

**Capability URI**: `https://cyrusimap.org/ns/jmap/mail`

Requires `jmap_nonstandard_extensions` to be enabled in the Cyrus
configuration.

## Mailbox/markAllEmailRead

Marks every email delivered so far to the given mailboxes as `$seen` for the
authenticated user, in one call however many emails the mailboxes hold.  It
applies only to mailboxes in another user's account, where the user's seen
state is their own.

**Arguments**:

- **accountId**: `Id`  The account of the mailboxes.  It must not be the
  authenticated user's own account.
- **mailboxIds**: `Id[]`  The mailboxes to mark.

**Response**:

- **accountId**: `Id`  The account used for the call.
- **marked**: `Id[]`  The mailboxes whose emails are now all `$seen`.
- **notMarked**: `Id[SetError]|null`  The mailboxes that weren't marked, with
  a `notFound` or `forbidden` error each.  A mailbox is `forbidden` if the
  user lacks the `maySetSeen` right, or if its seen state is shared by all
  users.

**Method-level errors**:

- `accountNotSupportedByMethod`: the account is the user's own.

Email delivered after the call is unaffected.  Every affected email gets a
new modseq, so `Email/changes` (and IMAP CONDSTORE) report it for all users
of the mailboxes, as when a user changes `$seen` with `Email/set`.  Unlike
`Email/set`, it leaves threads alone, so `Thread/changes` doesn't report
them: `$seen` isn't part of a Thread.  One `auditlog.touched.bulk` line logs
each mailbox's change, in place of an `auditlog.touched` line per email.
