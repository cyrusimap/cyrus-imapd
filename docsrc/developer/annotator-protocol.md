# Cyrus Annotation Callout Protocol

*Internal developer reference for the Cyrus team.*

## Introduction

The *annotation callout* is an external program that Cyrus consults during
message append (most importantly, during local delivery) so it can decide
whether to attach IMAP keywords (flags) or annotations to the message before it
lands in a mailbox.  The protocol is one request/response round trip per
message.

It is enabled by setting the `annotation_callout` option in `imapd.conf` to
either:

* a path to an executable (Cyrus will `fork`/`exec` it for each callout, with
  the request on stdin and the reply read from stdout), or
* a path to a UNIX-domain `SOCK_STREAM` socket on which a long-running daemon
  is listening (Cyrus will `connect()` for each callout, sending the request
  and reading the reply on the same socket).

### When is the callout invoked?

When enabled, the callout fires from `append_run_annotator()` and from the
append machinery in `append_commit()`.  In practice this means:

* messages delivered locally via `lmtpd`,
* messages appended through other code paths that route through `append.c` and
  have not opted out via `as->disable_annotator`.

If the callout fails for any reason — bad config, connect refused, timeout,
malformed reply — Cyrus logs a warning and proceeds as if the callout had
returned an empty result.  A failed callout never fails the delivery.

### Terminology

* **callout** — the external program described by `annotation_callout`
* **request** — the single, framed payload Cyrus writes to the callout
* **reply** — the single dlist Cyrus reads back
* **system annotation** — an annotation set on Cyrus's behalf by the callout
  reply.  These are applied without an ACL check and are kept separate from
  user-supplied annotations in the calling code; failure to apply one is logged
  but does not fail the append
* **user annotation** — an annotation that the *caller* of
  `append_run_annotator` already wanted to set.  These are passed *into* the
  callout as context (in the `ANNOTATIONS` field of the request); if the
  callout's reply names the same entry/attrib, the user value is cleared in
  favor of the callout's value

## Transport protocol

The same wire format is used for both the executable and socket transports.
The executable reads from stdin and writes to stdout.

For the executable transport, Cyrus also `waitpid()`s for the child to exit
after reading the reply.  Its exit status is ignored.

## Annotator request

The request is sent using a simple chunked length-prefixed encoding, similar to
HTTP chunked transfer encoding.  Cyrus writes:

1. An ASCII decimal byte count, followed by a single `\n`.
2. Exactly that many bytes of payload.
3. The literal two-byte sequence `0\n` to mark end of message.

The payload is a DLIST.  It always contains exactly the following keys, in this
order:

```text
( FILENAME {nstring}
  ANNOTATIONS ( {entry} ( {attrib} {nstring} ... ) ... )
  FLAGS ( {atom} ... )
  BODY {body-with-extensions}
  GUID {hex-sha1} )
```

Each `nstring` is either

* the literal string `NIL` for a null value
* a quoted IMAP string `"..."` if the data is short and contains no special
  characters
* an IMAP literal `{N}\r\n` followed by N bytes for anything that doesn't fit
  the quoted form (long strings, anything with NUL, `\r`, `\n`, `"`, `%`, `\\`,
  or any high-bit byte).

Note that the request payload itself is *not* CRLF-terminated.  The only
`\r\n`s present are those embedded inside IMAP literals.

### FILENAME

An nstring giving the absolute path of the spool file holding the RFC 5322
message currently being appended.  The callout may open and read this file
directly.  It's the same file Cyrus will link into the mailbox.

### ANNOTATIONS

A list giving the annotations the *caller* has already chosen to attach to this
message.  The structure is:

```text
( {entry-1} ( {attrib-1a} {value-1a} {attrib-1b} {value-1b} ... )
  {entry-2} ( {attrib-2a} {value-2a} ... )
  ... )
```

Entry names look like `/comment` or `/vendor/cmu/cyrus-imapd/foo`.  Attribute
names are typically `value.shared` or `value.priv`.  Each value is an nstring.

If there are no annotations, an empty list (`()`) is sent.

### FLAGS

A space-separated list of atoms naming the IMAP keywords currently slated for
the message — both system flags (`\Seen`, `\Flagged`, …) and user keywords.
Flags here are written as bare atoms, *not* as nstrings; they will not contain
spaces or other awkward characters by construction.  An empty list (`()`) means
no flags.

### BODY

The parsed BODYSTRUCTURE of the message, encoded by `message_write_body(buf,
body, 2)`.  The "2" is significant: it asks for the IMAP `BODYSTRUCTURE` form
(extension data included) *plus* a Cyrus-specific extra trailer on every leaf
part.  That trailer is:

```text
(OFFSET {n} HEADERSIZE {n})
```

where `OFFSET` is the byte offset within the spool file at which the part's
content begins and `HEADERSIZE` is the size in bytes of the part's MIME
headers.  Together with the part's `Size` (already present in standard
BODYSTRUCTURE), this lets the callout seek directly to and read any individual
MIME part of the message without re-parsing the whole file.

The trailer is only emitted on leaf parts (not on `multipart/*` containers).

Multiparts, `message/rfc822` envelopes, and the rest of the structure follow
standard IMAP BODYSTRUCTURE encoding as defined in RFC 3501 §7.4.2.

### GUID

The GUID (digest) used internally to identify the message, as a bare atom (not
quoted).

## Annotator reply

The reply is **not** length-prefixed.  The callout simply writes the dlist
text, with a single newline after the closing parenthesis.  (If the callout is
an executable, it then exits.)

A callout that has not produced *any* readable bytes within ten seconds of the
request being sent is treated as failed.

Parse the reply from the callout.  This is similar to the arguments to STORE
command, except that we can have multiple items one after the other.

Recognized keys (case-insensitive):

| key          | value                              | meaning               |
|--------------|------------------------------------|-----------------------|
| `+FLAGS`     | atom or `(atom atom ...)`          | add these flags       |
| `-FLAGS`     | atom or `(atom atom ...)`          | remove these flags    |
| `ANNOTATION` | `(<entry> (<attrib> <value>) ...)` | set these annotations |

Flag matching is case-insensitive.

For `ANNOTATION`, each `(attrib value)` pair replaces any existing `(entry,
attrib)` annotation with the one provided by the callout.  This acts as a
*system* annotation, ignoring ACL checks.  That is: the annotator is a system
service with system permissions, not something acting on behalf of the user.

The empty list `()` is a perfectly legal "do nothing" reply.

An example reply:

```text
(+FLAGS \Flagged ANNOTATION (/comment (value.shared "Hello")))
(+FLAGS (\Flagged \Seen))
(-FLAGS \Flagged)
(ANNOTATION (/comment (value.shared "Hello World")))
()
```

If a reply can only be partially parsed, all successfully parsed actions are
applied.

## Worked Example

Suppose `lmtpd` is delivering a one-part `text/plain` message at
`/var/spool/imap/...msg.tmp`, with no flags or annotations pre-attached, and
the GUID `abf1c3d4...` (40 hex chars).  Cyrus writes (with the chunk framing,
literals shown inline for readability):

```text
123\n
(FILENAME "/var/spool/imap/...msg.tmp" ANNOTATIONS () FLAGS () BODY ("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 42 3 NIL NIL NIL NIL (OFFSET 240 HEADERSIZE 120)) GUID abf1c3d4...)0\n
```

The callout decides to flag the message and add a shared comment, and writes
back:

```text
(+FLAGS \Flagged ANNOTATION (/comment (value.shared "Hello")))
```

Cyrus parses that and, on commit, the message ends up in the user's mailbox
with `\Flagged` set and `/comment` (shared) set to `Hello`.
