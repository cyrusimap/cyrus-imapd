# Cyrus Replication Protocol

## Introduction

The Cyrus Replication protocol in versions 2.4+ was created to
replace the earlier replication protocol built by David Carter
at Cambridge University.  It's based on the same underlying
principle of "edge trigger to say that something changed"
followed by "resolve the differences to update the replica".

### Terminology

The following terms are used throughout this document:

* **master** — the authoritative server that holds the primary copy of mailbox data.  Changes are made here first.
* **replica** — the server that receives updates from the master.  In normal operation it is read-only (or at least not authoritative).
* **sync\_client** — the process on the master that drives replication.  It reads the master's state, compares it with the replica, and sends the necessary APPLY commands.
* **sync\_server** — the process on the replica that accepts replication commands.  It can run as a standalone daemon (via `cyrus-master`) or be embedded in `imapd`.
* **channel** — a named replication stream.  Multiple channels allow a single master to replicate to several replicas, each with its own sync\_log.
* **rolling replication** — continuous, event-driven replication.  sync\_client runs as a daemon, tailing the sync\_log and replicating changes within seconds.
* **one-shot replication** — a single invocation of sync\_client to sync specific users or all users, then exit.  Typically run by an administrator or from a script.

### Design Philosophy

The protocol follows an **edge-triggered** design: the master logs
the *name* of the object that changed (a user, a mailbox, a quota
root, etc.) but not what the change was.  The sync\_client then
fetches the current state from both sides, computes the delta, and
applies it.  This makes the protocol self-healing — if a sync is
missed or fails partway through, the next attempt will still
converge to the correct state.

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

## Session Lifecycle

A replication session begins when sync\_client connects to sync\_server
(or, in IMAP-embedded mode, when an admin issues SYNCGET/SYNCAPPLY
commands within an authenticated IMAP session).

### Server Banner

Upon connection, sync\_server sends an untagged banner advertising
its capabilities, followed by an OK greeting:

```
* SASL PLAIN LOGIN DIGEST-MD5
* STARTTLS
* COMPRESS DEFLATE
* SIEVE-MAILBOX
* REPLICATION-ARCHIVE
* OK servername Cyrus sync server v3.12.0-...
```

Each `* CAPABILITY` line is optional and depends on server configuration:

| Capability | Condition |
|---|---|
| SASL *mechanism-list* | Advertised when SASL mechanisms are available |
| STARTTLS | Advertised when TLS is configured and not yet active |
| COMPRESS DEFLATE | Advertised when zlib support is compiled in and compression is not yet active |
| SIEVE-MAILBOX | Always advertised; indicates sieve scripts can be synced as a `#sieve` mailbox |
| REPLICATION-ARCHIVE | Advertised when `archive_enabled` is set in imapd.conf |

### AUTHENTICATE

```
C: AUTHENTICATE PLAIN {20+}
C: <base64 initial-response>
S: * OK AUTHENTICATE
```

Standard SASL negotiation.  sync\_client typically authenticates as an
admin user.  On success the server responds with OK; on failure, BAD.

### STARTTLS

```
C: STARTTLS
S: * OK STARTTLS
```

After TLS negotiation completes, the server re-issues the banner
(without the STARTTLS capability) so the client can discover any
capabilities that are only available under encryption.

### COMPRESS

```
C: COMPRESS DEFLATE
S: * OK COMPRESS
```

Enables DEFLATE compression on the connection (per RFC 4978).
Only DEFLATE is supported.

### NOOP

```
C: NOOP
S: * OK Noop completed
```

Does nothing.  Can be used as a keepalive.

### RESTART

```
C: RESTART
S: * OK Restarting
```

Resets the server-side session state without dropping the connection.
In particular, it deletes all staged message files from previous
APPLY RESERVE / APPLY MESSAGE commands (the `sync./<pid>/` staging
directories) and frees the reserve list.  The server re-issues the
banner after restart.  sync\_client uses this to start a fresh sync
pass without reconnecting.

### EXIT

```
C: EXIT
S: * OK Finished
```

Cleanly terminates the session.  The server closes the connection
after sending the response.

## Command/Response Framing

### Tagged Commands (Standalone sync\_server)

In standalone mode, the sync\_client generates sequential tags of the
form `S0`, `S1`, `S2`, etc.  Each command is prefixed with its tag:

```
S0 GET MAILBOXES (user.cassandane)
S1 APPLY MAILBOX %(UNIQUEID ...)
```

### Untagged Data

GET commands return zero or more untagged data lines before the
final tagged response.  Each untagged line is prefixed with `* `:

```
* %(MAILBOX %(UNIQUEID abc123 MBOXNAME user.cassandane ...))
```

### Tagged Responses

The final response to every command is a tagged line:

```
S0 OK Success
S0 NO IMAP_MAILBOX_NONEXISTENT Mailbox does not exist
```

The response format is:

```
tag SP response-code [SP error-code SP message]
response-code = "OK" / "NO" / "BYE"
```

On NO responses, the error-code is a string representation of the
internal Cyrus error constant.

### Error Codes

The following error codes are commonly seen in replication:

| Error Code | Meaning |
|---|---|
| IMAP\_SYNC\_CHECKSUM | CRC mismatch between master and replica — data inconsistency |
| IMAP\_SYNC\_CHANGED | Mailbox changed during sync (e.g. rename race) |
| IMAP\_SYNC\_BADSIEVE | Sieve script failed compilation on the replica |
| IMAP\_MAILBOX\_LOCKED | Mailbox is locked by another process |
| IMAP\_MAILBOX\_NONEXISTENT | Mailbox does not exist |
| IMAP\_MAILBOX\_MOVED | Mailbox uniqueid exists but under a different name |
| IMAP\_AGAIN | Transient error — caller should retry |
| IMAP\_PROTOCOL\_ERROR | Malformed command |
| IMAP\_PROTOCOL\_BAD\_PARAMETERS | Invalid parameters |

### IMAP-Embedded Mode

When replication commands are issued within an authenticated IMAP
session (by an admin user), the command names are prefixed:

```
tag SYNCGET MAILBOXES (user.cassandane)
tag SYNCAPPLY MAILBOX %(UNIQUEID ...)
tag SYNCENABLE <capabilities>
```

Tags follow normal IMAP tag conventions (assigned by the IMAP client)
rather than the `S0`, `S1` sequence.  Responses use the same
untagged-data-then-tagged-response pattern.  This mode provides an
alternative to the standalone sync\_server, and is primarily used for
replication-based XFER in a Murder environment.

## The Replication Protocol

### GET Commands

SYNTAX: "GET" get-type dlist-kvlist

```
sync-get = tag SP "GET" SP get-type SP dlist-kvlist
get-type = "ANNOTATION" / "FETCH" / "FETCH_SIEVE" / "FULLMAILBOX" /
           "MAILBOXES" / "UNIQUEIDS" / "META" / "QUOTA" / "SIEVE" / "USER"
```

The kvlist contains the arguments specific to each GET subcommand.

#### GET USER

```
S0 GET USER %(USERID user.cassandane)
```

This expands into:

* GET MAILBOXES (for every mailbox in the user's tree, including the DELETED namespace and tombstones)
* GET QUOTA (for every quotaroot for those mailboxes)
* GET SIEVE (for the userid)
* GET META (for the userid)

The responses are interleaved as untagged data — first all MAILBOX
responses, then QUOTA, SIEVE, SEEN, and LSUB data — followed by a
single tagged OK.

#### GET MAILBOXES mboxname-list

Fetches metadata for each of the named mailboxes:

```
C: S0 GET MAILBOXES (user.cassandane)
S: * %(MAILBOX %(UNIQUEID 039a6391d3cc4a01 MBOXNAME user.cassandane
       MBOXTYPE 0 SYNC_CRC 3a1f7b20 SYNC_CRC_ANNOT 00000000
       LAST_UID 42 HIGHESTMODSEQ 107 RECENTUID 42
       RECENTTIME 1711234567 LAST_APPENDDATE 1711234560
       POP3_LAST_LOGIN 0 POP3_SHOW_AFTER 0
       UIDVALIDITY 1711200000 PARTITION default
       ACL "cassandane\tlrswipcda\t" OPTIONS ""
       QUOTAROOT user.cassandane
       CREATEDMODSEQ 1 FOLDERMODSEQ 107
       ANNOTATIONS () USERFLAGS ()))
S: S0 OK Success
```

The MAILBOX kvlist contains folder-level metadata but no per-message
RECORD entries (contrast with GET FULLMAILBOX).

**MAILBOX Response Fields:**

| Field | Type | Description |
|---|---|---|
| UNIQUEID | atom | Globally unique mailbox identifier |
| MBOXNAME | atom | Internal mailbox name |
| MBOXTYPE | atom | Mailbox type flags (0 for normal) |
| SYNC\_CRC | hex32 | CRC of message records (basic) |
| SYNC\_CRC\_ANNOT | hex32 | CRC of per-message annotations |
| LAST\_UID | num32 | Highest UID assigned |
| HIGHESTMODSEQ | num64 | Highest modification sequence |
| RECENTUID | num32 | UID of most recent message |
| RECENTTIME | num32 | Timestamp of most recent arrival |
| LAST\_APPENDDATE | num32 | Timestamp of last append |
| POP3\_LAST\_LOGIN | num32 | Last POP3 login timestamp |
| POP3\_SHOW\_AFTER | num32 | POP3 show-after timestamp |
| UIDVALIDITY | num32 | IMAP UIDVALIDITY value |
| PARTITION | atom | Storage partition name |
| ACL | atom | Tab-separated ACL string |
| OPTIONS | atom | Mailbox option flags |
| QUOTAROOT | atom | Quota root (if set) |
| CREATEDMODSEQ | num64 | Modseq at mailbox creation |
| FOLDERMODSEQ | num64 | Modseq of folder-level changes |
| XCONVMODSEQ | num64 | Conversation modseq (if conversations enabled) |
| RACLMODSEQ | num64 | Reverse-ACL modseq (if RACL enabled) |
| ANNOTATIONS | list | Mailbox-level annotations |
| USERFLAGS | list | Defined user flags |

#### GET UNIQUEIDS uniquid-list

An alternative form of GET MAILBOXES which takes uniqueids instead of mboxnames.

```
C: S0 GET UNIQUEIDS (039a6391d3cc4a01)
S: * %(MAILBOX %(UNIQUEID 039a6391d3cc4a01 MBOXNAME user.cassandane ...))
S: S0 OK Success
```

#### GET FULLMAILBOX mboxname

Fetches the data for the single named mailbox, with the UID records filled in.

This is used for split-brain recovery, to allow the client to compare the entire state of the mailbox at both ends.

Example:

```
C: S0 GET FULLMAILBOX %(MBOXNAME user.cassandane)
S: * %(MAILBOX %(UNIQUEID 039a6391d3cc4a01 MBOXNAME user.cassandane
       MBOXTYPE 0 SYNC_CRC 3a1f7b20 SYNC_CRC_ANNOT 00000000
       LAST_UID 3 HIGHESTMODSEQ 12 RECENTUID 3
       RECENTTIME 1711234567 LAST_APPENDDATE 1711234560
       POP3_LAST_LOGIN 0 POP3_SHOW_AFTER 0
       UIDVALIDITY 1711200000 PARTITION default
       ACL "cassandane\tlrswipcda\t" OPTIONS ""
       QUOTAROOT user.cassandane
       CREATEDMODSEQ 1 FOLDERMODSEQ 12
       ANNOTATIONS () USERFLAGS ()
       RECORD (%(UID 1 MODSEQ 3 LAST_UPDATED 1711234500
               FLAGS () INTERNALDATE 1711234500
               SIZE 1234 GUID 0123456789abcdef0123456789abcdef01234567
               ANNOTATIONS ())
              %(UID 2 MODSEQ 7 LAST_UPDATED 1711234530
               FLAGS (\Seen) INTERNALDATE 1711234530
               SIZE 5678 GUID fedcba9876543210fedcba9876543210fedcba98
               ANNOTATIONS ())
              %(UID 3 MODSEQ 12 LAST_UPDATED 1711234560
               FLAGS (\Flagged) INTERNALDATE 1711234560
               SIZE 910 GUID abcdef0123456789abcdef0123456789abcdef01
               ANNOTATIONS ()))))
S: S0 OK Success
```

**RECORD Entry Fields:**

| Field | Type | Description |
|---|---|---|
| UID | num32 | Message UID |
| MODSEQ | num64 | Modification sequence |
| LAST\_UPDATED | num32 | Last update timestamp |
| FLAGS | list | System and user flags (e.g. `\Seen`, `\Deleted`, `\Expunged`) |
| INTERNALDATE | num32 | IMAP INTERNALDATE (seconds since epoch) |
| SIZE | num32 | RFC 822 message size |
| GUID | atom | Message GUID (SHA1 hex) |
| ANNOTATIONS | list | Per-message annotations |

#### GET QUOTA quotaroot

Gets the quota for the named quotaroot.

Example:

```
C: S0 GET QUOTA %(ROOT user.cassandane)
S: * %(QUOTA %(ROOT user.cassandane STORAGE 1048576 MESSAGE 100000
       MODSEQ 42))
S: S0 OK Success
```

**QUOTA Response Fields:**

| Field | Type | Description |
|---|---|---|
| ROOT | atom | Quota root name |
| STORAGE | num32 | Storage limit in KB (UINT\_MAX = unlimited) |
| MESSAGE | num32 | Message count limit |
| ANNOTATION-STORAGE | num32 | Annotation storage limit |
| MAILBOX | num32 | Mailbox count limit |
| MODSEQ | num64 | Quota modification sequence |

STORAGE is always present (for backwards compatibility).  All other
resource fields (MESSAGE, ANNOTATION-STORAGE, MAILBOX) are only
included when a limit is set (value >= 0).

#### GET SIEVE userid

Gets the list of sieve scripts for the user (if not using the `#sieve` mailbox).

Example:

```
C: S0 GET SIEVE %(USERID cassandane)
S: * %(SIEVE %(FILENAME default.script LAST_UPDATE 1711234567
       GUID 0123456789abcdef0123456789abcdef01234567 ISACTIVE 1))
S: * %(SIEVE %(FILENAME vacation.script LAST_UPDATE 1711230000
       GUID fedcba9876543210fedcba9876543210fedcba98 ISACTIVE 0))
S: S0 OK Success
```

**SIEVE Response Fields:**

| Field | Type | Description |
|---|---|---|
| FILENAME | atom | Script filename |
| LAST\_UPDATE | num32 | Last modification timestamp |
| GUID | atom | Script content GUID (SHA1 hex) |
| ISACTIVE | num32 | 1 if this is the active script, 0 otherwise |

#### GET META userid

Gets the per-user seen data for the user (by uniqueid, for the mailboxes for which the seen data is non-internal) and
the list of subscribed mailboxes for the user (in internal namespace).

Example:

```
C: S0 GET META %(USERID cassandane)
S: * %(SEEN %(UNIQUEID 039a6391d3cc4a01 LASTREAD 1711234567
       LASTUID 42 LASTCHANGE 1711234567 SEENUIDS 1:42))
S: * %(SEEN %(UNIQUEID b7e2f1a0c3d84e92 LASTREAD 1711230000
       LASTUID 10 LASTCHANGE 1711230000 SEENUIDS 1:8,10))
S: * %(LSUB (user.cassandane user.cassandane.Sent user.cassandane.Trash))
S: S0 OK Success
```

**SEEN Response Fields:**

| Field | Type | Description |
|---|---|---|
| UNIQUEID | atom | Mailbox unique identifier |
| LASTREAD | num32 | Timestamp of last read |
| LASTUID | num32 | UID of last read message |
| LASTCHANGE | num32 | Timestamp of last SEEN state change |
| SEENUIDS | atom | Sequence-set of seen UIDs (IMAP uid-set syntax) |

**LSUB Response:**

The LSUB response contains a list of internal mailbox names to which
the user is subscribed.

#### GET FETCH mboxname uid

Returns the content of a single email file as a file-literal.

Used by split-brain recovery when an email only exists on the replica.

```
C: S0 GET FETCH %(MBOXNAME user.cassandane UNIQUEID 039a6391d3cc4a01
       UID 42 GUID 0123456789abcdef0123456789abcdef01234567
       PARTITION default)
S: * %(MESSAGE %{default 0123456789abcdef0123456789abcdef01234567 1234}
S: <1234 bytes of message content>
S: )
S: S0 OK Success
```

#### GET FETCH\_SIEVE userid scriptname

Returns the content of the named sieve script for the named user.

Used by split-brain recovery when a script only exists on the replica.

```
C: S0 GET FETCH_SIEVE %(USERID cassandane SCRIPTNAME default.script)
S: * %(SIEVE %{sieve 0123456789abcdef0123456789abcdef01234567 256}
S: <256 bytes of sieve script>
S: )
S: S0 OK Success
```

#### GET ANNOTATION

Fetches all mailbox-level annotations for a mailbox (not per-message
annotations — those are included inline in MAILBOX RECORD entries).

```
C: S0 GET ANNOTATION user.cassandane
S: * %(ANNOTATION %(MBOXNAME user.cassandane
       ENTRY /vendor/cmu/cyrus-imapd/color
       USERID cassandane VALUE blue))
S: S0 OK Success
```

The request takes the mailbox name as a bare atom (not a kvlist).
The response returns one untagged ANNOTATION line per annotation
entry, each containing MBOXNAME, ENTRY, USERID, and VALUE fields.

### APPLY Commands

APPLY commands modify the state of the replica.  They are sent by
sync\_client after it has compared the master and replica states.

```
sync-apply = tag SP "APPLY" SP apply-type SP dlist-kvlist
apply-type = "ACTIVATE_SIEVE" / "ANNOTATION" / "CAPABILITIES" /
             "EXPUNGE" / "FORCE" / "LOCAL_MAILBOX" / "LOCAL_RENAME" /
             "LOCAL_UNMAILBOX" / "LOCAL_UNUSER" / "MAILBOX" / "MESSAGE" /
             "QUOTA" / "RENAME" / "RESERVE" / "SEEN" / "SIEVE" /
             "SUB" / "UNANNOTATION" / "UNACTIVATE_SIEVE" /
             "UNMAILBOX" / "UNQUOTA" / "UNSIEVE" / "UNSUB" / "UNUSER"
```

All APPLY commands return a tagged OK on success or NO with an error
code on failure.  Some APPLY commands return untagged data before the
tagged response (notably RESERVE returns MISSING).

#### APPLY RESERVE

Reserves message files for an upcoming APPLY MAILBOX.  The client
sends a list of GUIDs grouped by partition, along with the mailbox
names that might contain those messages on the replica.  The server
searches those mailboxes for matching GUIDs and links them into a
staging directory to ensure they persist even if a concurrent
`cyr_expire` deletes their original instance.  It returns a MISSING
list of GUIDs it could not find.

```
C: S0 APPLY RESERVE %(PARTITION default
       MBOXNAME (user.cassandane user.cassandane.Sent)
       GUID (0123456789abcdef0123456789abcdef01234567
             fedcba9876543210fedcba9876543210fedcba98
             abcdef0123456789abcdef0123456789abcdef01))
S: * %(MISSING (fedcba9876543210fedcba9876543210fedcba98))
S: S0 OK Success
```

In this example, the replica already has two of the three messages.
Only the GUID listed in the MISSING response needs to be uploaded
via APPLY MESSAGE.

If MISSING is empty (all GUIDs already present), the response is:

```
S: * %(MISSING ())
S: S0 OK Success
```

Up to 8192 GUIDs may be sent in a single RESERVE command.  If more
are needed, the client sends multiple RESERVE commands.

**Client-side selection:** The client identifies which GUIDs to
reserve by scanning the master's mailbox for messages with UIDs
between the replica's `last_uid + 1` and the master's `last_uid`.
Expunged and unlinked messages are skipped — only live messages
that the replica does not yet have are included.  GUIDs are grouped
by storage partition so that each RESERVE command targets a single
partition.

**Server-side search:** On receiving RESERVE, the replica searches
the listed mailboxes for each requested GUID.  It searches mailboxes
on the target partition first, then falls back to mailboxes on other
partitions.  For each message found, the replica:

1. Re-parses the message file and verifies that its SHA1 matches the
   GUID in the index — if the on-disk file is corrupt, the message
   is skipped and will appear in the MISSING response.
2. Copies the file to a staging directory at
   `<partition>/sync./<pid>/<guid>`.  This per-PID directory
   prevents collisions between concurrent sync processes.
3. Marks the GUID as found internally.  The search short-circuits
   as soon as all requested GUIDs have been located.

Any GUIDs not found in the listed mailboxes are returned in the
MISSING response.  The client must then upload those via
APPLY MESSAGE before the subsequent APPLY MAILBOX can reference
them.

#### APPLY MESSAGE

Uploads a single message file to the replica.  The message content
is sent as a file-literal within the dlist.

```
C: S1 APPLY MESSAGE %(MESSAGE %{default fedcba9876543210...fedcba98 5678}
C: <5678 bytes of message content>
C: )
S: S1 OK Success
```

Messages are uploaded in batches (up to 1024 per batch in current
implementations).  Each batch receives its own tagged response
before the next batch is sent.

#### APPLY MAILBOX

The primary command for synchronising a mailbox.  Sends the complete
mailbox metadata and the RECORD list of new or changed messages.

```
C: S2 APPLY MAILBOX %(UNIQUEID 039a6391d3cc4a01
       MBOXNAME user.cassandane MBOXTYPE 0
       SYNC_CRC 3a1f7b20 SYNC_CRC_ANNOT 00000000
       LAST_UID 45 HIGHESTMODSEQ 120
       RECENTUID 45 RECENTTIME 1711234567
       LAST_APPENDDATE 1711234560
       POP3_LAST_LOGIN 0 POP3_SHOW_AFTER 0
       UIDVALIDITY 1711200000 PARTITION default
       ACL "cassandane\tlrswipcda\t" OPTIONS ""
       QUOTAROOT user.cassandane
       CREATEDMODSEQ 1 FOLDERMODSEQ 120
       ANNOTATIONS () USERFLAGS ()
       SINCE_MODSEQ 107 SINCE_CRC 3a1f7b20 SINCE_CRC_ANNOT 00000000
       RECORD (%(UID 43 MODSEQ 110 LAST_UPDATED 1711234570
               FLAGS () INTERNALDATE 1711234570
               SIZE 2048 GUID fedcba9876543210fedcba9876543210fedcba98
               ANNOTATIONS ())
              %(UID 44 MODSEQ 115 LAST_UPDATED 1711234575
               FLAGS (\Seen) INTERNALDATE 1711234575
               SIZE 1024 GUID abcdef0123456789abcdef0123456789abcdef01
               ANNOTATIONS ())))
S: S2 OK Success
```

The SINCE\_MODSEQ, SINCE\_CRC, and SINCE\_CRC\_ANNOT fields tell the
replica what state the client believes the replica was in before this
update.  The replica uses these to detect conflicts — if the replica's
actual state does not match, it returns IMAP\_SYNC\_CHECKSUM.

The RECORD list contains only messages with modseq > SINCE\_MODSEQ
(i.e. incremental updates).  Messages with the `\Expunged` flag are
included so the replica can mark them as expunged.

**Partial Sync:** For large mailboxes, the client may send a partial
update covering only a range of UIDs up to an intermediate modseq.
In this case LAST\_UID and HIGHESTMODSEQ reflect the intermediate
boundary rather than the full mailbox state, and SYNC\_CRC is set
to 0 to suppress CRC checking.  Subsequent APPLY MAILBOX commands
cover the remaining ranges.

#### APPLY LOCAL\_MAILBOX

Identical to APPLY MAILBOX but sets the SYNC\_FLAG\_LOCALONLY flag,
meaning the change should not be further replicated.  Used in
multi-tier replication setups.

#### APPLY UNMAILBOX

Deletes a mailbox on the replica.

```
C: S3 APPLY UNMAILBOX %(MBOXNAME user.cassandane.OldFolder)
S: S3 OK Success
```

#### APPLY LOCAL\_UNMAILBOX

Like UNMAILBOX but local-only (not further replicated).

#### APPLY RENAME

Renames a mailbox on the replica.

```
C: S4 APPLY RENAME %(OLDMBOXNAME user.cassandane.Drafts
       NEWMBOXNAME user.cassandane.OldDrafts
       PARTITION default UIDVALIDITY 1711200000)
S: S4 OK Success
```

Required fields: OLDMBOXNAME, NEWMBOXNAME, PARTITION.
Optional field: UIDVALIDITY (if provided, sets the uidvalidity
on the renamed mailbox).

#### APPLY LOCAL\_RENAME

Like RENAME but local-only.

#### APPLY EXPUNGE

Expunges specific messages from a mailbox on the replica.

```
C: S5 APPLY EXPUNGE %(MBOXNAME user.cassandane
       UNIQUEID 039a6391d3cc4a01
       UID (1 5 12))
S: S5 OK Success
```

Required fields: MBOXNAME, UNIQUEID, and UID.  MBOXNAME is used to
open the mailbox; UNIQUEID is validated as a safety check to ensure
the correct mailbox is being modified.  UID is a list of individual
UIDs to expunge.

#### APPLY QUOTA

Sets quota limits on the replica.

```
C: S6 APPLY QUOTA %(ROOT user.cassandane STORAGE 1048576
       MESSAGE 100000 MODSEQ 42)
S: S6 OK Success
```

#### APPLY UNQUOTA

Removes a quota root from the replica.

```
C: S7 APPLY UNQUOTA %(ROOT user.cassandane)
S: S7 OK Success
```

#### APPLY SUB

Subscribes a user to a mailbox on the replica.

```
C: S8 APPLY SUB %(USERID cassandane MBOXNAME user.cassandane.Lists)
S: S8 OK Success
```

#### APPLY UNSUB

Unsubscribes a user from a mailbox on the replica.

```
C: S9 APPLY UNSUB %(USERID cassandane MBOXNAME user.cassandane.Lists)
S: S9 OK Success
```

#### APPLY ANNOTATION

Sets a mailbox annotation on the replica.

```
C: S10 APPLY ANNOTATION %(MBOXNAME user.cassandane
        ENTRY /vendor/cmu/cyrus-imapd/color USERID cassandane
        VALUE blue)
S: S10 OK Success
```

Required fields: MBOXNAME, ENTRY, USERID, VALUE.  MODSEQ is not
included — the replica assigns its own modseq when applying the
annotation.  Note: this is a mailbox-level annotation (not
per-message), so it does not affect SYNC\_CRC\_ANNOT, but it does
mean the annotation modseq will diverge between master and replica.
This is arguably a bug — the master's modseq should be propagated.

#### APPLY UNANNOTATION

Removes a mailbox annotation on the replica.

```
C: S11 APPLY UNANNOTATION %(MBOXNAME user.cassandane
        ENTRY /vendor/cmu/cyrus-imapd/color USERID cassandane)
S: S11 OK Success
```

#### APPLY SIEVE

Uploads a sieve script to the replica.

```
C: S12 APPLY SIEVE %(USERID cassandane FILENAME vacation.script
        LAST_UPDATE 1711234567
        CONTENT {256+}
        <256 bytes of sieve script content>)
S: S12 OK Success
```

Required fields: USERID, FILENAME, LAST\_UPDATE, CONTENT.
The script content is sent as a binary map (literal), not a
file-literal.  GUID is not included in the apply command — the
replica computes it from the content.

#### APPLY UNSIEVE

Deletes a sieve script from the replica.

```
C: S13 APPLY UNSIEVE %(USERID cassandane FILENAME vacation.script)
S: S13 OK Success
```

#### APPLY ACTIVATE\_SIEVE

Activates a sieve script on the replica.

```
C: S14 APPLY ACTIVATE_SIEVE %(USERID cassandane FILENAME default.script)
S: S14 OK Success
```

#### APPLY UNACTIVATE\_SIEVE

Deactivates the active sieve script on the replica.

```
C: S15 APPLY UNACTIVATE_SIEVE %(USERID cassandane)
S: S15 OK Success
```

#### APPLY SEEN

Updates the seen state for a user on the replica.

```
C: S16 APPLY SEEN %(USERID cassandane UNIQUEID 039a6391d3cc4a01
        LASTREAD 1711234567 LASTUID 42 LASTCHANGE 1711234567
        SEENUIDS 1:42)
S: S16 OK Success
```

#### APPLY UNUSER

Deletes an entire user account from the replica, including all
mailboxes, sieve scripts, seen state, and subscriptions.

```
C: S17 APPLY UNUSER %(USERID cassandane)
S: S17 OK Success
```

#### APPLY LOCAL\_UNUSER

Like UNUSER but local-only.

#### APPLY FORCE

Enables "force mode" for the remainder of the session.  In force
mode, certain safety checks are relaxed (e.g. CRC mismatches may
be overridden).

```
C: S18 APPLY FORCE
S: S18 OK Success
```

APPLY FORCE takes no arguments.  It sets a global flag for the
remainder of the session.

#### APPLY CAPABILITIES

Enables specific capabilities for the session.  Sent after the
client has inspected the banner and wants to opt in to features
like SIEVE-MAILBOX or REPLICATION-ARCHIVE.

```
C: S19 APPLY CAPABILITIES (SIEVE-MAILBOX REPLICATION-ARCHIVE)
S: * %(ENABLED (SIEVE-MAILBOX REPLICATION-ARCHIVE))
S: S19 OK Success
```

Capabilities are sent as a simple list of atoms (not a kvlist).
The server responds with an ENABLED list containing only the
capabilities it actually activated.  REPLICATION-ARCHIVE is only
enabled if `archive_enabled` is set in imapd.conf.

## The Sync Algorithm

This section describes the algorithm that sync\_client uses to
replicate data from master to replica.  Understanding this flow
explains *why* the commands are structured the way they are.

### Overview

The sync algorithm follows a three-phase pattern:

1. **Edge-trigger** — something changed on the master (logged to sync\_log or specified on the command line).
2. **Compare** — sync\_client fetches the current state from both master (local) and replica (remote), then computes the differences.
3. **Resolve** — sync\_client sends APPLY commands to bring the replica up-to-date.

### User-Level Sync Flow

When syncing an entire user (the typical case for one-shot
replication, and a fallback in rolling replication after error
promotion), the flow is:

1. **Lock** — acquire an exclusive sync lock for the user (prevents concurrent sync of the same user).
2. **GET USER** — fetch the replica's view of the user: all mailbox metadata, quota, sieve scripts, seen state, and subscriptions.
3. **Compare mailboxes** — enumerate the master's mailboxes for this user (including DELETED namespace and tombstones) and compare with the replica's list.
   - Detect new mailboxes (on master but not replica).
   - Detect deleted mailboxes (tombstones on master, or on replica but not master).
   - Detect renames (same uniqueid, different name).
4. **Reserve and upload messages** — for each mailbox with new messages, identify the GUIDs to upload (see Reserve-Then-Upload Flow below).
5. **Apply mailbox updates** — for each changed mailbox, send APPLY MAILBOX (or APPLY RENAME, APPLY UNMAILBOX as appropriate).
6. **Sync quota** — compare quota roots and send APPLY QUOTA / APPLY UNQUOTA.
7. **Sync subscriptions** — compare subscription lists and send APPLY SUB / APPLY UNSUB.
8. **Sync sieve scripts** — compare sieve script lists and send APPLY SIEVE / APPLY UNSIEVE / APPLY ACTIVATE\_SIEVE / APPLY UNACTIVATE\_SIEVE.
9. **Sync seen state** — compare per-mailbox seen data and send APPLY SEEN.
10. **Unlock** — release the sync lock.

If the user has no INBOX on the master (i.e. the user does not
exist), the entire user is deleted on the replica via APPLY UNUSER.

### Reserve-Then-Upload Flow

Before a mailbox update can be applied, the replica must have copies
of all message files that will be referenced.  The reserve-then-upload
flow ensures this efficiently:

1. **Collect GUIDs** — for each mailbox being synced, scan the
   master for messages with UIDs between the replica's `last_uid + 1`
   and the master's `last_uid`.  Expunged and unlinked messages are
   skipped.  Group the resulting GUIDs by storage partition.

2. **APPLY RESERVE** — for each partition, send up to 8192 GUIDs
   along with the list of mailbox names where those messages might
   exist on the replica.  The replica searches those mailboxes for
   matching GUIDs and links them into a staging directory to ensure
   they persist even if a concurrent `cyr_expire` deletes their
   original instance.  It returns a MISSING list of GUIDs it could
   not locate.  The search checks the target partition first, then
   falls back to other partitions.

3. **APPLY MESSAGE** — for each GUID in the MISSING list, upload
   the message file content from the master.  Messages are sent in
   batches of up to 1024.

4. **APPLY MAILBOX** — now that all referenced messages are staged
   on the replica (either linked locally via RESERVE or uploaded
   via MESSAGE), send the mailbox metadata and RECORD list.

This two-phase approach avoids uploading messages that the replica
already has.  Common cases where the replica already has a message
include: duplicated messages (same GUID copied into multiple
mailboxes), and previous partial syncs that succeeded in uploading
messages but failed before the MAILBOX apply completed.  Because
RESERVE can reference multiple mailboxes on the same partition,
shared messages are only staged (and potentially uploaded) once.

A key benefit of the local linking in RESERVE is saving disk space
and network bandwidth: when the replica already has a copy of a
message (even in a different mailbox), a hardlink into the staging
directory avoids both re-transmitting the data over the network and
duplicating it on disk.

### Sync CRCs

The sync CRC mechanism is central to the replication protocol's
efficiency.  A pair of CRC values summarises the entire contents
of a mailbox in just 8 bytes, allowing the master and replica to
detect whether they agree without transferring the full record list.

Both CRCs are computed by XOR-ing together per-message CRC32
values.  The XOR construction has two important properties:

1. **Order-independence** — messages can be processed in any order
   and the result is the same.
2. **Incremental update** — when a single message changes, the old
   per-message CRC is XOR-ed out and the new one XOR-ed in, without
   re-scanning the entire mailbox.

Expunged messages contribute 0 to both CRCs and are effectively
invisible.

#### SYNC\_CRC (basic)

Covers the core IMAP fields that existed when sync CRCs were
originally defined:

* UID
* MODSEQ
* LAST\_UPDATED (seconds)
* INTERNALDATE (seconds)
* System flags (`\Deleted`, `\Answered`, `\Flagged`, `\Draft`, `\Seen`)
* User-defined flags
* Message GUID

These fields are formatted into a string and hashed with CRC32.
The basic CRC is initialised to 0.

#### SYNC\_CRC\_ANNOT

Covers everything *not* in the basic CRC.  This includes:

* **Real per-message annotations** — entries from the annotation
  database, each contributing a CRC over (UID, entry-name, userid,
  value).

* **Synthetic annotations for fields added after the basic CRC was
  defined** — when new per-message fields were added to the index
  record in later mailbox format versions, they could not be folded
  into the basic CRC without changing its value for every existing
  mailbox (which would trigger unnecessary full resyncs across the
  entire deployment).  Instead, each new field is represented as a
  virtual annotation under the `/vendor/cmu/cyrus-imapd/` namespace
  and folded into SYNC\_CRC\_ANNOT:

  | Mailbox Version | Virtual Annotation | Field |
  |---|---|---|
  | 13+ | `thrid` | Conversation/thread ID |
  | 15+ | `savedate` | Message save timestamp |
  | 16+ | `createdmodseq` | Creation modification sequence |
  | 20+ | `internaldate.nsec` | Nanosecond portion of INTERNALDATE |
  | 20+ | `basethrid` | Base conversation ID |

SYNC\_CRC\_ANNOT is initialised to 12345678 (rather than 0) so that
a mailbox with no annotations is visually distinguishable from an
uninitialised CRC in protocol traces.

#### Incremental Maintenance

CRCs are stored in the mailbox index header and kept up-to-date
incrementally as the mailbox is modified:

* **Append** — XOR the new message's CRC into the running total.
* **Flag change / annotation change** — XOR out the old CRC for
  that message, compute the new CRC, and XOR it in.
* **Expunge** — XOR out the message's CRC (it now contributes 0).

This means the CRCs are always available in the index header
without a full scan — reading them is an O(1) operation.

#### Forced Recalculation

Sometimes the stored CRCs may be stale (e.g. after a crash, a
reconstruction, or a mailbox format upgrade).  In these cases a
forced recalculation iterates over every non-expunged message and
recomputes both CRCs from scratch.

During replication, forced recalculation is triggered when the
CRCs returned by the replica do not match what the master expected
(see "Retry Logic" below).  The sequence is:

1. Compare using the cached CRC values (fast path).
2. If they disagree, force a recalculation on the master and
   compare again.
3. If they *still* disagree after recalculation, the mailbox is
   genuinely inconsistent and a full record-level comparison is
   needed.

The same recalculation happens during `reconstruct` and during
mailbox repack (version upgrade/downgrade), which resets the CRCs
to match the actual on-disk state.

#### Change Detection and Convergence

When the master opens a mailbox for sync, it compares its CRCs
with the replica's (from the sync\_cache or from a GET MAILBOXES
response).  If both CRCs match *and* the folder-level metadata
(LAST\_UID, HIGHESTMODSEQ, ACL, FOLDERMODSEQ, etc.) is identical,
the mailbox is skipped entirely.

As a bootstrapping aid, a CRC value of 0 is treated as "don't
care" by the comparison function (`mailbox_crceq`).  This allows
a newly created replica, or a client without full local state, to
accept changes without having to compute a correct CRC first.

Because the CRCs are a deterministic function of the complete
mailbox state, a one-shot sync pass (`sync_client -u`) is
sufficient to *prove* convergence — if all CRCs match at the end,
every message, flag, annotation, and metadata field is guaranteed
to be identical on both sides.  This makes CRCs an efficient
post-incident verification tool: rather than diffing gigabytes
of mailbox data, the operator can check convergence with a few
bytes per mailbox.

### The sync\_cache

The sync\_cache is a client-side database (a cyrusdb, typically
twoskip) that stores the last known state of each mailbox on the
replica.  After every successful APPLY MAILBOX, sync\_client saves
the mailbox metadata (everything except the per-message RECORD
list) into this cache, keyed by mailbox name.

On the next sync pass, sync\_client checks the cache *before*
sending GET MAILBOXES to the replica.  For any mailbox that has a
cache entry, the round trip is skipped entirely — the cached state
is used as the replica's baseline.

The cache is invalidated (entry deleted) whenever a sync fails, or
when a mailbox is renamed or deleted.  If the cached state turns
out to be wrong (because the replica was modified outside of
replication), the replica will return IMAP\_SYNC\_CHECKSUM, and the
retry path will fall back to fetching fresh state from the replica.

#### Round-Trip Analysis

The cache, combined with the SINCE\_\* fields, determines how many
network round trips a sync operation requires:

**Flag change or metadata update (happy path: 1 round trip):**
The cache already has the replica's state.  sync\_client reads the
local mailbox, computes the delta against the cached baseline,
and sends APPLY MAILBOX with SINCE\_MODSEQ/SINCE\_CRC in a single
command.  No GET, no RESERVE, no MESSAGE — just one round trip.

**New message append (happy path: 2 round trips):**
sync\_client needs to ensure the replica has the message file
before sending APPLY MAILBOX.  The flow is:
1. APPLY RESERVE (with the new message's GUID) → replica responds
   with MISSING → APPLY MESSAGE to upload the file.
2. APPLY MAILBOX with the new RECORD entry and SINCE\_\* fields.

The GET MAILBOXES round trip is still skipped thanks to the cache.

**Cache miss or first sync (3+ round trips):**
Without a cache entry, sync\_client must first GET MAILBOXES (or
GET USER) to learn the replica's state, then proceed with
RESERVE/MESSAGE if needed, then APPLY MAILBOX.

In rolling replication, the cache is warm after the first
successful sync of each mailbox, so the common case for ongoing
changes is 1 round trip (flags) or 2 round trips (appends).

### SINCE\_MODSEQ and Incremental Sync

As described in the APPLY MAILBOX section, the client includes
SINCE\_MODSEQ, SINCE\_CRC, and SINCE\_CRC\_ANNOT fields representing
the replica's expected prior state (from the sync\_cache or a fresh
GET response).  The replica validates these against its actual
state and returns IMAP\_SYNC\_CHECKSUM on mismatch.

### Partial Sync for Large Mailboxes

When a mailbox has a large number of new messages (exceeding a
configurable batch size), sync\_client breaks the sync into
multiple rounds:

1. Find an intermediate modseq that covers approximately `batchsize`
   messages.
2. Send APPLY MAILBOX with LAST\_UID and HIGHESTMODSEQ set to the
   intermediate values and SYNC\_CRC set to 0 (to suppress CRC
   checking on the partial state).
3. On success, advance the baseline and repeat for the next batch.
4. The final batch sends the true LAST\_UID, HIGHESTMODSEQ, and
   SYNC\_CRC values, so the replica ends up with the correct
   final state.

This serves several purposes: it avoids excessively long locks on
the replica mailbox, prevents a single large mailbox from starving
replication of other changes, and avoids excessive memory usage.
By interleaving chunks of appends to the large mailbox with updates
from other mailboxes, the replica does not fall far behind for
everyone else while a big mailbox is being seeded.

### Retry Logic

Replication is inherently racy — mailboxes can be modified while
a sync is in progress.  The protocol handles this with a structured
retry strategy:

**First attempt:**
- Send APPLY MAILBOX with incremental RECORD list.
- If IMAP\_SYNC\_CHECKSUM is returned: log a notice, recalculate CRCs
  locally, and retry with corrected SINCE values.

**Second attempt (after checksum failure):**
- Perform a "full update" — fetch the complete replica state via
  GET FULLMAILBOX, compare every record, and send a complete
  APPLY MAILBOX with all records.  This is expensive but
  self-healing.

**IMAP\_AGAIN:**
- Returned when the replica detects a condition that requires
  starting over (e.g. uidvalidity mismatch, detected rename).
- The client retries the entire user sync, re-fetching all state.
- Maximum 3 retry attempts at the user level before giving up
  with IMAP\_SYNC\_CHANGED.

**IMAP\_MAILBOX\_LOCKED:**
- The mailbox is held by another process.
- In rolling replication, the action is re-logged to the sync\_log
  channel for retry on the next pass.

### GUID Conflicts and UID Renumbering

When replication encounters a conflict — the same UID exists on
both sides but refers to different message content (different GUIDs)
— the protocol must break one of IMAP's invariants to recover.
This section explains the strategy and why UID renumbering was
chosen over the alternatives.

#### IMAP Identity Invariants

A message in IMAP is uniquely identified by three properties:

1. Folder name
2. UIDVALIDITY
3. UID

If these three are unchanged, clients are entitled to assume the
message content is unchanged.  Any UID below UIDNEXT that was
previously reported MUST still refer to the same content, or the
client's cache becomes invalid.

This is extended by a fourth property:

4. MODSEQ — if unchanged, clients may assume the message's metadata
   (flags, annotations) is also unchanged.

Additionally, a message that has been expunged MUST NOT reappear.

These invariants must hold not just on a single server, but across
replicas — a fact previously observed on one server must remain
true when a client connects to the other server later.

#### Cases Where Invariants Break

**Reconstruct:**
- A message file exists on disk without a corresponding index record
  (orphan file).
- An index record is corrupted (CRC failure).

**Unexpunge:**
- An expunged record is restored (violates the "once expunged,
  always expunged" rule).

**Replication split-brain:**
- A message was delivered to the replica but not the master (e.g.
  during a failover).
- The same UID exists at both ends with different content (GUID
  mismatch).
- Flags/modseq were modified independently on both sides.

#### Why Not Bump UIDVALIDITY?

Changing UIDVALIDITY forces every IMAP client to discard its entire
cache for the mailbox and re-download all messages — even though
only one message has a problem.  For a large mailbox this is
extremely expensive.  Worse, it does not help with case 3.2 (same
UID, different content on master vs replica): both sides still
disagree about what that UID contains.

#### The UID Renumbering Strategy

Instead of changing UIDVALIDITY, the protocol changes the UID of
the conflicting message by appending it as a new record at
`last_uid + 1`.  This is fully IMAP-compliant: the old UID
appears to have been expunged and replaced by a new message at a
higher UID.  Clients that cache aggressively will re-fetch only
the affected messages rather than the entire mailbox.

The only visible side-effect is that sort-by-UID order may change
for the affected messages.  In practice most clients sort by date,
so this is rarely noticed.

**Reconstruct (orphan file or corrupted record):** Parse the
message file to rebuild the index fields, use the file's mtime as
INTERNALDATE, rename the file to `last_uid + 1`, and append a
fresh record.  A corrupted record is first overwritten with a
valid UNLINKED record (preserving the UID slot), then the same
append-at-end process is followed.

**Unexpunge:** Copy the old index record, clear the `\Expunged`
flag (and optionally `\Deleted`), rename the file to
`last_uid + 1`, and append.

**Replication — message only on replica:**
- If the replica's UID is above the master's `last_uid`, the
  message is copied to the master at its current UID.  The master
  has no conflicting record, so no renumbering is needed, and
  the replica's copy remains unchanged.  The master's `last_uid`
  is bumped to match.
- If the replica's UID is at or below the master's `last_uid`,
  the UID slot has already been used (or passed) on the master.
  If the replica message's modseq is below the master's
  `deletedmodseq`, it is considered stale and simply expunged.
  Otherwise, the message is fetched from the replica and appended
  at `last_uid + 1`; the old UID is expunged on the replica.

**Replication — same UID, different GUID:**
Both messages are renumbered.  The conflict resolution is
deterministic: GUIDs are compared lexicographically to decide
processing order (lower GUID first), but both messages end up
with new UIDs.  One message is renumbered locally on the master
(RENUMBER), the other is fetched from the replica (COPYBACK),
and both are appended at successive `last_uid + 1` values.  The
old UID is then marked expunged on both sides.

If one side has already expunged its copy, only the surviving
message needs a new UID.

**Replication — flag/modseq conflict (same GUID):**
This is the one case that does *not* require UID renumbering.
The replica wins if its modseq is strictly higher than the
master's AND its last\_updated timestamp is at least as recent.
If the replica wins, its flags are copied back to the master.
Otherwise the master's flags are kept.  Either way, the modseq
is bumped so the next sync pass propagates the resolved state to
the other side, restoring agreement.

#### Why This Works

UID renumbering is a protocol-compliant repair that never
invalidates a client's view of the server state.  All transitions
are legal IMAP:

* UIDs that were previously valid appear expunged — clients already
  handle this.
* New messages appear at higher UIDs — clients already handle this.
* UIDVALIDITY is unchanged — clients keep their caches for all
  unaffected messages.

The approach also generalises beyond two-server replication: it
handles multi-replica split-brain, IMAP-to-IMAP synchronisation,
and even reconstruct recovery, all with the same mechanism.

### Mailbox-Level Conflict Resolution

The previous section covered message-level conflicts within a
single mailbox.  This section covers the higher-level question:
what happens when the *set of mailboxes* differs between master
and replica?

During a user sync, sync\_client compares two lists:

* **master\_folders** — mailboxes enumerated from the local mboxlist.
* **replica\_folders** — mailboxes returned by GET USER from the replica.

Folders are matched by **uniqueid**, not by name.  This is critical
because renames change the name but preserve the uniqueid.

#### Mailbox on Both Sides (Normal Case)

If a folder with the same uniqueid exists on both sides, the names
and partitions are compared.  If they differ, the folder has been
renamed (or moved to a different partition) and the replica is
updated via APPLY RENAME.  Otherwise the mailbox contents are
synced as described in previous sections.

#### Mailbox on Master Only (New Mailbox)

If a folder exists on the master but has no matching uniqueid on
the replica, it is a new mailbox.  The normal APPLY MAILBOX flow
creates it on the replica.

#### Mailbox on Replica Only

If a folder exists on the replica but not in the master's active
mailbox list, sync\_client looks up the replica folder's uniqueid
in the local mailboxes.db (an "I" record — the uniqueid-keyed
entry).  There are three possible outcomes:

**Entry found, marked MBTYPE\_DELETED:** The mailbox was
intentionally deleted on the master.  sync\_client sends
APPLY UNMAILBOX to delete it from the replica.  This is the normal
case for deletions during rolling replication.

**Entry found, still active:** The uniqueid exists locally under a
different name — this is a rename detected from the replica's
perspective, and it is handled via APPLY RENAME.

**No entry found (split-brain):** The master has no record of this
mailbox ever existing.  The mailbox was created on the replica
while it was operating independently.

There are two behaviours depending on the `NO_COPYBACK` flag:

*Without NO\_COPYBACK (default):* The mailbox is left alone on
the replica.  A SYNCNOTICE is logged ("no tombstone for deleted
mailbox") but no action is taken.  This is conservative — the
replica may have data that should be preserved, and destroying it
could cause data loss.  The expectation is that an administrator
will review the situation.

[TODO: the code has an `XXX` comment asking whether the missing
mailbox should be copied back from the replica to the master.
This copyback is not currently implemented — verify whether this
is still the intended future direction or whether the current
"leave it alone" behaviour is considered correct.]

*With NO\_COPYBACK:* The mailbox is forcibly deleted from the
replica, even without a local entry.  A SYNCNOTICE is logged
("forcing delete of remote folder despite no tombstone").  This
mode treats the master as strictly authoritative and is used when
the operator knows the master state is correct.

#### Rename Chain Resolution

Renames can create ordering problems.  If mailbox A is renamed to
B, but the replica already has a mailbox named B (with a different
uniqueid), the rename would collide.  To handle this, sync\_client
consults the mailbox's **name history** — a list of former names
stored in the mboxlist entry.  It finds an intermediate name that
does not conflict with any existing mailbox on the replica and
creates a two-step rename chain: old-name → intermediate →
final-name.  This avoids rename collisions without requiring
mailbox deletion.

### Lock Ordering

When syncing multiple mailboxes for a user, sync\_client acquires
exclusive locks for all affected userids in sorted order.  This
prevents deadlock when multiple sync\_client processes run
concurrently (e.g. on different channels).

## Rolling Replication

Rolling replication is the primary operational mode for production
Cyrus deployments.  sync\_client runs as a long-lived daemon,
continuously tailing the sync\_log and replicating changes with
minimal delay.

### The sync\_log

Whenever Cyrus modifies an object that needs to be replicated, it
writes an entry to the sync\_log.  Each entry names the *type* of
object that changed and the object's identifier:

| Event Type | Arguments | Meaning |
|---|---|---|
| USER *userid* | userid | User-level change (new user, renamed user) |
| UNUSER *userid* | userid | User deleted |
| META *userid* | userid | User metadata changed (seen, sieve, subs) |
| APPEND *mboxname* | mboxname | Message appended to mailbox |
| MAILBOX *mboxname* | mboxname | Mailbox metadata changed |
| UNMAILBOX *mboxname* | mboxname | Mailbox deleted |
| QUOTA *root* | quotaroot | Quota changed |
| ANNOTATION *mboxname* | mboxname | Annotation changed |
| SEEN *userid* *mboxname* | userid, mboxname | Seen state changed |
| SUB *userid* *mboxname* | userid, mboxname | Subscription changed |
| SIEVE *userid* | userid | Sieve script changed |

When channels are configured, each channel has its own sync\_log
file.  A single master modification may write to multiple channel
logs if replicating to multiple replicas.

Note: the sync\_log records only *what* changed, not *how* it
changed.  This is the "edge trigger" — the actual delta is
computed at sync time by comparing master and replica state.

### sync\_log File Structure

Each channel's log lives under the Cyrus config directory:

```
<configdirectory>/sync/log                  (default channel)
<configdirectory>/sync/<channelname>/log    (named channel)
```

During processing, a second file appears:

```
<configdirectory>/sync/log-run              (default channel, active)
<configdirectory>/sync/<channelname>/log-run (named channel, active)
```

The `log` file is where writers append new entries.  The `log-run`
file is the batch currently being processed by the reader.  This
two-file design allows new events to accumulate in `log` while
the reader works through the previous batch in `log-run`.

### The Log/Log-Run Lock Dance

The handoff between writers and the reader must be carefully
synchronised to ensure no log entries are lost.  The protocol
works as follows:

**Writer side** (any Cyrus process logging a change):

1. Open `log` with `O_WRONLY|O_APPEND|O_CREAT`.
2. Acquire an exclusive `flock()` on the file descriptor.
3. **Inode check:** `fstat()` the open fd and `stat()` the path.
   If the inodes differ, the file was renamed out from under us —
   release the lock, close the fd, and retry from step 1. This
   loop runs up to 64 times.
4. Write the log entry and `fsync()`.
5. Release the lock and close.

**Reader side** (sync\_client or squatter in rolling mode):

1. Check if `log-run` already exists (from a previous crash or
   interrupted run).  If so, reprocess it first — no data was
   lost, the previous reader just didn't finish.
2. Otherwise, check if `log` exists.  If not, return
   IMAP\_AGAIN (nothing to do yet).
3. **Atomic rename:** `rename("log", "log-run")`.  After this
   point, any writer that opens `log` will create a *new* file.
4. Open `log-run` and acquire an exclusive `flock()`.  This
   serialises against any writer that held a lock on the old
   inode at the moment of the rename — once we acquire the lock
   we know that writer has finished.
5. **Immediately unlock.** This is safe because any writer that
   held the lock over the rename will `fstat()`/`stat()` on
   its next write attempt, see the inode mismatch, and retry
   against the new `log` file.  No future writer will append to
   the renamed file.
6. Read and process all entries from `log-run`.
7. Unlink `log-run` when done.

The key insight is that `flock()` locks are per-inode, not
per-path.  After the rename, the path `log` points to a new
(or not-yet-created) inode.  Writers that already have the old
inode open will detect the mismatch via the inode check in step 3
of the writer protocol and retry.  This guarantees that every
log entry is written either to the old file (which the reader is
about to process) or to the new file (which will be picked up on
the next pass).

### Other sync\_log Consumers

The sync\_log mechanism is not exclusive to replication.
**squatter** (the Cyrus search indexer) can also run in rolling
mode with its own channel, reading sync\_log entries to discover
which mailboxes need re-indexing.  It uses the same
sync\_log\_reader and the same `log`/`log-run` rename dance.
Channels are configured so that squatter and sync\_client each
have their own independent log stream.

### Channel Independence

Every Cyrus process that logs a change writes separately to *each*
configured channel's log file.  The channels are completely
independent of one another — each has its own `log` and `log-run`
files, its own reader, and its own position in the event stream.

This independence has several important consequences:

* **Readers progress at different speeds.** A fast replica can be
  fully caught up while a slower replica (or squatter) is still
  working through its backlog.  Neither blocks the other.

* **A down replica does not block anything.** If a replica is
  offline, events for its channel simply accumulate in the `log`
  file.  When the replica comes back and sync\_client reconnects,
  it renames the (possibly very large) `log` to `log-run` and
  processes the entire backlog.  Meanwhile, other channels
  continue operating normally.

* **No cross-channel coordination.** Writers do not wait for any
  reader to consume events.  The write path is fire-and-forget
  (with fsync for durability) — the only contention is the brief
  per-channel `flock()` between concurrent writers.

### Action Coalescing

sync\_client reads a batch of sync\_log entries and coalesces them
before processing, to avoid redundant work:

* **USER supersedes META, SEEN, SUB, SIEVE** — if a full user sync is
  queued, there is no need to separately sync metadata.
* **UNUSER supersedes everything** — if a user is being deleted, all
  per-user items are removed from the batch.
* **META supersedes SEEN and SUB** — a full metadata sync covers
  individual seen/subscription changes.
* **MAILBOX and APPEND coalesce** — multiple APPEND entries for the
  same mailbox become a single mailbox sync.

### Processing Order

After coalescing, the batch is processed in a specific order:

1. **Mailboxes** — sync changed mailboxes (grouped by user, batched
   in sets of ~1000 at user boundaries).
2. **Quota** — sync changed quota roots.
3. **Annotations** — sync changed annotations.
4. **Seen** — sync changed seen states.
5. **Subscriptions** — sync changed subscriptions.
6. **Unmailbox** — delete removed mailboxes.
7. **Meta** — full metadata syncs.
8. **User** — full user syncs.
9. **Unuser** — user deletions.

### Error Promotion

When a fine-grained sync fails, sync\_client promotes it to a
coarser-grained sync that is more likely to succeed:

| Failed Operation | Promoted To |
|---|---|
| Quota sync | Full USER sync |
| Annotation sync | Full USER sync |
| Seen sync | Full USER or META sync |
| Subscription sync | Full META sync |
| META sync | Full USER sync |

This ensures that transient inconsistencies are resolved by a
complete state comparison at the user level.

### Locked Mailbox Handling

When a sync attempt fails with IMAP\_MAILBOX\_LOCKED, the action
is re-logged to the sync\_log channel.  On the next pass through
the log, sync\_client will retry the action.  This avoids blocking
the entire replication pipeline while waiting for a lock to be
released.

### Daemon Loop

In rolling mode, sync\_client's main loop:

1. Reads available sync\_log entries.
2. Coalesces and processes them (as described above).
3. If processing took less than `sync_repeat_interval` (default 1s),
   sleeps for the remainder.
4. Periodically checks for a shutdown file and exits cleanly if found.
5. After `sync_reconnect_maxwait` seconds, sends RESTART to reset
   server-side state without reconnecting.
6. On connection errors, attempts to reconnect to the replica.

### One-Shot vs. Rolling

| Aspect | Rolling | One-Shot |
|---|---|---|
| Trigger | sync\_log events | Administrator / script |
| Granularity | Per-object | User, mailbox, meta, or all-users |
| Latency | Seconds | On demand |
| Mode | `sync_client -r` (daemon) | `sync_client -u user`, `-m mailbox`, `-s meta`, or `-A` |
| State | Tails sync\_log continuously | Single comparison, then exit |

In one-shot mode, sync\_client performs a comparison without
consulting the sync\_log.  It can operate at several granularities:
a single mailbox (`-m`), a user's metadata only (`-s`), an entire
user (`-u`), or all users (`-A`).  This is useful for initial
seeding, disaster recovery, or consistency checks.

## Debugging with Telemetry

To see the raw protocol traffic on the wire, enable telemetry
logging for the replication user (the admin user that sync\_client
authenticates as, typically configured as `sync_authname` in
imapd.conf).

Create a directory for the user under the Cyrus log directory:

```
mkdir -p <configdirectory>/log/<repluser>
```

Where `<configdirectory>` is the Cyrus configuration directory
(e.g. `/var/lib/cyrus`) and `<repluser>` is the replication admin
userid.

Once this directory exists, sync\_server will log all protocol
traffic — both input and output — to a file within it.  The
filename is `sync_server-<pid>` (or `sync_server-<sessionid>` if
`telemetry_bysessionid` is enabled in imapd.conf).  Each session
is delimited by a timestamp header.

This log contains the complete wire protocol: every GET command,
every APPLY command, every response, and the full content of
uploaded messages.  It is invaluable for diagnosing replication
issues, understanding sync behaviour, and verifying that the
protocol is working as expected.

**Warning:** Telemetry logs consume disk space quickly, especially
under rolling replication with active users.  Message uploads are
logged in full, so a single large mailbox sync can produce
gigabytes of log data.  Enable telemetry only for targeted
debugging, and remember to remove or rotate the log directory
when finished:

```
rm -rf <configdirectory>/log/<repluser>
```
