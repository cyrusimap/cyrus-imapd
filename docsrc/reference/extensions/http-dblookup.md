# /dblookup HTTP API

The `/dblookup` endpoint is an internal Cyrus HTTP API for querying contact and
mailbox databases.  It is used primarily by Cyrus components to perform
CardDAV-backed lookups without going through the full JMAP or CardDAV protocol
stack.

**This API is not guaranteed to be stable between releases.**  If you use this
interface, be careful when upgrading!  The API may change without warning.  If
you need stable APIs for performing any of this work, please tell the Cyrus
team.  This specification is here for the developers to refer to, *not* as a
guarantee to individual installs!

## Authentication

This endpoint does **not** require HTTP authentication.  All requests must
identify the target user via the `User` header.  Because of this, the endpoint
is intended for use only by trusted internal callers (e.g., other Cyrus
processes communicating over a local socket).

## Common Request Format

All endpoints use the `GET` method.  Parameters are passed as HTTP headers:

- **User**: `String` (required)  The Cyrus user ID to query.
- **Key**: `String` (required)  The lookup key; its meaning depends on the
  endpoint.

Providing multiple values for either `User` or `Key` is not permitted and will
result in a `405 Not Allowed` response.

## Response Codes

| Code              | Meaning                                              |
|-------------------|------------------------------------------------------|
| `200 OK`          | Lookup succeeded; body is a JSON value.              |
| `204 No Content`  | Lookup succeeded but produced no results.            |
| `400 Bad Request` | A required header is missing.                        |
| `404 Not Found`   | Unknown path *or* referenced mailbox does not exist. |
| `405 Not Allowed` | A header was supplied more than once.                |

---

## Endpoints

### `GET /dblookup/email`

Checks whether any vCard in the user's CardDAV database has the given email
address, and returns the UIDs of any contact **groups** whose members include
a card with that address.

**Key**: an email address.

**Response** (`200 OK`): a JSON array of vCard UIDs of groups that contain a
card with the given email.  The array may be empty if the email exists on a
card that is not a member of any group.

```json
["group-uid-1", "group-uid-2"]
```

Returns `204 No Content` if no card in the database has the given email.

---

### `GET /dblookup/email2uids`

Returns the vCard UIDs of cards in the specified addressbook that have the
given email address.

**Key**: an email address.

**Additional headers:**

- **Mailbox**: `String` (optional, default `"Default"`)  The name of the
  addressbook collection to search.

**Response** (`200 OK`): a JSON array of vCard UIDs.

```json
["uid-1", "uid-2"]
```

Returns `204 No Content` if the addressbook does not exist or no card matches.

---

### `GET /dblookup/email2details`

Like `/dblookup/email2uids`, but also reports whether any matching card is
marked as pinned.

**Key**: an email address.

**Additional headers:**

- **Mailbox**: `String` (optional, default `"Default"`)  The addressbook to
  search.

**Response** (`200 OK`): a JSON object.

```json
{"uids": ["uid-1", "uid-2"], "isPinned": true}
```

- **uids**: `String[]`  The vCard UIDs of matching cards.
- **isPinned**: `Boolean`  True if any matching card carries the pinned flag.

Returns `204 No Content` if the addressbook does not exist or no card matches.

---

### `GET /dblookup/uid2groups`

Returns the contact groups in the specified addressbook that contain the given
vCard UID as a member.

Before returning results, the server verifies that the vCard UID is accessible
to `User` (either in their own addressbooks or in a shared addressbook belonging
to `OtherUser`).  If the UID is not accessible, an empty object is returned.

**Key**: a vCard UID.

**Additional headers:**

- **Mailbox**: `String` (optional, default `"Default"`)  The addressbook to
  search for groups.
- **OtherUser**: `String` (optional)  When provided, accessibility is checked
  against this user's shared addressbooks rather than `User`'s own addressbooks.

**Response** (`200 OK`): a JSON object mapping each group's vCard UID to its
display name.

```json
{"group-uid-1": "Family", "group-uid-2": "Work"}
```

Returns `200 OK` with an empty object `{}` if the UID is inaccessible or
belongs to no groups.  Returns `204 No Content` if the addressbook does not
exist.

---

### `GET /dblookup/expandcard`

Expands a card — which may be a contact group — into the preferred email
addresses of the card itself and all of its members, across all addressbooks
accessible to `User` (including shared addressbooks).

**Key**: a vCard UID.

**Response** (`200 OK`): a JSON object keyed by Cyrus user accountId.  Each
value is an object mapping vCard UIDs to each card's preferred email address
(or `null` if no email is recorded).

```json
{
  "account123": {
    "card-uid-of-alice": "alice@example.com"
  },
  "accountXYZ": {
    "card-uid-of-bob": "bob@example.com",
    "card-uid-of-carol": null
  }
}
```

When the key UID identifies a plain contact card (not a group), only that
card's entry appears.  When it identifies a group card, the group card's own
entry is included along with one entry for each group member found in
accessible addressbooks.

Returns `204 No Content` if the UID is not found in any accessible addressbook.

---

### `GET /dblookup/mbpath`

Returns filesystem path information for a mailbox.

**Key**: controls how `User` is interpreted:

- `"mboxname"` — `User` is treated as an external (client-visible) mailbox
  name.
- Any other value — `User` is treated as a Cyrus user ID, and the lookup
  targets that user's INBOX.

**Response** (`200 OK`): a JSON object containing:

- **mbname**: `Object`  Parsed components of the internal mailbox name:
  - **intname**: `String`  The full internal mailbox name.
  - **userid**: `String` (if applicable)
  - **localpart**: `String` (if applicable)
  - **domain**: `String` (if applicable)
  - **boxes**: `String[]`  Mailbox path components below the user root.
  - **isdeleted**: `Integer` (if the mailbox is in the deleted namespace)

- **user**: `Object` (present when the mailbox belongs to a user)  Paths to
  per-user metadata files:
  - **conversations**: `String`
  - **counters**: `String`
  - **dav**: `String`
  - **seen**: `String`
  - **sieve**: `String`
  - **sub**: `String`
  - **xapianactive**: `String` (present only when Xapian support is compiled in)

- **xapian**: `Object` (present when Xapian support is compiled in)  A map
  from search tier name to the Xapian index base directory for that tier.

- **archive**: `String`  Path to the mailbox archive data directory.
- **data**: `String`  Path to the mailbox data directory.
- **meta**: `String`  Path to the mailbox metadata directory.

Returns `404 Not Found` if the mailbox does not exist.
