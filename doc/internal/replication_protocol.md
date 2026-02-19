# Cyrus Replication Protocol

## Introduction

The Cyrus Replication protocol in versions 2.4+ was created to
replace the earlier replication protocol built by David Carter
at Cambridge University.  It's based on the same underlying
principle of "edge trigger to say that something changed"
followed by "resolve the differences to update the replica".

## The DList Format

The Cyrus Replication protocol uses a format called 'DList'.
A DList is similar to the IMAP wire protocol, but has two
additional datatypes:

* kvlist
* file


### Types

```
dlist = dlist-atom / dlist-flag / dlist-num / dlist-hex /
        dlist-list / dlist-kvlist / dlist-file
```

#### atom

An atom is actually a sequence of any character other than '\0',
the NULL byte.  Character encoding is not specified, but it can
contain 8 bit characters, and is probably utf8.

On the wire, this is encoded as an astring.

```
dlist-atom = astring 
               ; from rfc3501
```

#### flag

Flag is a horrible special case of atom to allow \word to be
represented as an IMAP atom on the wire.  This is one of many
special cases in the IMAP protocol, and is duplicated into dlist
just to make it easier to read.

```
dlist-flag = flag
               ; from rfc3501
```

#### num32/num

Both stored as 64 bit integers internally, and sent as decimal
numbers over the wire, this type exists only in the API, it just
looks like an atom on the wire.

```
dlist-num = number / number64
             ; number from rfc3501
number64  = 1*DIGIT
             ; Unsigned 63-bit integer
             ; (0 <= n <= 9,223,372,036,854,775,807)
```

#### hex32/hex

Stored like num internally, but sent as an 8 or 16 character
hexadecimal string on the wire.

```
dlist-hex = 8HEXDIG | 16HEXDIG
```

#### map

Like atom, but can contain NULL.  All values are parsed off
the wire as 'map' type and then converted on demand into the
requested type.

NOTE: this is maybe bogus and should be using literal8 from RFC3516
but it doesn't.

```
dlist-map = dlist-atom
```

#### list

A list contains zero or more items, each of which can be any of the
DList datatypes.

In particular, a list type can be nested inside other lists: (item (sub sub) item)

Lists are encoded in parentheses like so (item item item), separated
by a single space character, and with no space before the first item
or after the last item.


```
dlist-list = "(" [dlist \*(SP dlist)] ")"
```

#### kvlist

A kvlist allows named parameters, and is indicated with a leading
% character.  % is invalid in atoms, so parsing is unambiguous, e.g:
`%(key1 value1 key2 (list of values) key3 value3)`

```
dlist-kvlist = "%" "(" [atom SP dlist \*(SP atom SP dlist)] ")"
```

#### file

Finally the ugly one.  These look like a literal, but with a leading %
and two more fields:  `%{partition sha1 size}\r\n`.

```
dlist-file = "%" "{" atom SP atom SP number "}" CRLF *CHAR8
             ; Number represents the number of CHAR8s
```

## The Replication Protocol

The replication protocol is available in the Cyrus IMAP server with two separate servers: the
standalone "sync\_server" process, and as the commands "SYNCGET" and "SYNCAPPLY" in the imapd
when running as an admin user.

There are two broad classes of commands: "GET" which fetches information from a replica, and
"APPLY" which sends changes to bring the replica up-to-date.

### GET commands

SYNTAX: "GET" get-type dlist-kvlist

```
sync-get = "GET" get-type dlist-kvlist
get-type = "ANNOTATION" / "FETCH" / "FETCH_SIEVE" / "FULLMAILBOX" / 
           "MAILBOXES" / "UNIQUEIDS" / "META" / "QUOTA" / "USER"
```

The kvlist contains the ar

#### GET USER

This expands into:

* GET MAILBOX (for every mailbox in the user's tree, including the DELETED namespace and tombstones)
* GET QUOTA (for every quotaroot for those mailboxes)
* GET SIEVE (for the userid)
* GET META (for the userid)

#### GET MAILBOXES mboxname-list

Gets a list of mboxnames in dlist-list.

Fetches data for each of the named mailboxes:

Example:


#### GET UNIQUEIDS uniquid-list

An alternative form of GET MAILBOXES which takes uniqueids instead of mboxnames.

#### GET FULLMAILBOX mboxname

Fetches the data for the single named mailbox, with the UID records filled in.

This is used for split-brain recovery, to allow the client to compare the entire state of the mailbox at both ends.

Example:



#### GET QUOTA quotaroot

Gets the quota for the named quotaroot:

Example:


### GET SIEVE userid

Gets the list of sieve scripts for the user (if not using the `#sieve` mailbox).

Example:


#### GET META userid

Gets the per-user seen data for the user (by uniqueid, for the mailboxes for which the seen data is non-internal) and
the list of subscribed mailboxes for the user (in internal namespace).

This is the content of the user.sub file.


#### GET FETCH mboxname uid

Returns the content of a single email file.

Used by split-brain recovery when an email only exists on the replica.

#### GET FETCH\_SIEVE userid scriptname

Returns the content of the named sieve script for the named user.

Used by split-brain recovery when a script only exists on the replica.
