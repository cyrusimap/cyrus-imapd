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

#### GET 
