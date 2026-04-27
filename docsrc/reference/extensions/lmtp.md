# LMTP extensions

Cyrus's LMTP server (`lmtpd`) implements LMTP as defined by {rfc}`2033`, plus
the SMTP service extensions applicable to LMTP: `8BITMIME`,
`ENHANCEDSTATUSCODES`, `PIPELINING`, `SIZE`, `STARTTLS`, and SASL `AUTH`.

The capabilities and behaviours described below are *Cyrus-specific* extensions
on top of those.  They are advertised in the multi-line `LHLO` response and,
where applicable, are honoured both by `lmtpd` (server side) and by Cyrus's
internal LMTP client when proxying delivery to a backend.

## `IGNOREQUOTA`

Advertised as the capability line:

```
250-IGNOREQUOTA
```

When this capability is in effect, the client may add the unparameterised
keyword `IGNOREQUOTA` to a `RCPT TO` command:

```
RCPT TO:<user@example.com> IGNOREQUOTA
```

The recipient's mailbox quota is then disregarded for that delivery: the
message is accepted and filed even if doing so would push the mailbox over
quota.

## `TRACE`

Advertised as the capability line:

```
250-TRACE
```

This adds a new `TRACE` command, which associates an opaque identifier with
the LMTP session for the lifetime of the current message transaction.  The
identifier is recorded alongside the per-session ID in audit log lines and is
forwarded to upstream LMTP servers that also advertise `TRACE`, so a single
delivery can be correlated across the components that handle it.

```
TRACE <traceid>
```

`<traceid>` must be at most 255 bytes and consist only of characters from the
base64url alphabet without padding -- that is, ASCII letters, digits, `-`,
and `_`.  Other characters or an over-length value yield:

```
501 5.5.4 Invalid TRACE id.
```

A successful `TRACE` is acknowledged with a reply of the form:

```
250 2.0.0 Ok SESSIONID=<...> TRACEID=<...>
```

The trace ID is cleared on `RSET`, on `STARTTLS`, and at the start of each
new session, so it must be re-sent for each message that should carry one.
`TRACE` may be sent before or between transactions; it does not affect the
acceptance or routing of mail.

## `SESSIONID` in responses

Cyrus tags several LMTP replies with a `SESSIONID=<...>` token containing the
server's per-connection session identifier.  The token appears on the final
line of many responses.

The value is the same string that appears in syslog under the `sessionid` key,
and is meant to be quoted back in bug reports and when correlating client- and
server-side logs.
