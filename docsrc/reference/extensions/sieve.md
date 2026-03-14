# Sieve extensions

This document lists Cyrus's nonstandard extensions to Cyrus IMAP's
Sieve implementation, found in the `sieve/` directory.

## `snooze`

Adds the `snooze` action, which defers handling a message until a later time.
The message is filed into a holding mailbox, then moved back to the target
mailbox at one of the specified times.

It takes a series of tagged arguments followed by a string list of times-of-day
to unsnooze.

The tagged arguments are:

- `:mailbox` - the mailbox to snooze into (defaults to INBOX)
- `:weekdays` - limit wake times to specific days of the week
- `:tzid` - time zone for interpreting the wake times
- `:addflags` / `:removeflags` - flags to add or remove on wake
- `:specialuse`, `:mailboxid` - alternative ways to specify the target mailbox

The legacy capability names `vnd.cyrus.snooze` and `x-cyrus-snooze` are also
accepted.

This extension was an Internet-Draft document,
[draft-ietf-extra-sieve-snooze](https://datatracker.ietf.org/doc/draft-ietf-extra-sieve-snooze/),
but is long since expired.

## `regex`

Requires `ENABLE_REGEX` at compile time.  Adds the `:regex` match type to
tests, allowing POSIX extended regular expression matching.

This extension was an Internet-Draft document,
[draft-ietf-sieve-regex](https://datatracker.ietf.org/doc/draft-ietf-sieve-regex/),
but is long since expired.

## `vnd.cyrus.jmapquery`

Requires `WITH_JMAP` at compile time.  Adds the `jmapquery` test, which takes
one argument: a JSON string containing a [JMAP Email query filter
object](https://datatracker.ietf.org/doc/html/rfc8621#section-4.4.1) and
evaluates it against the message.  This allows Sieve scripts to use the full
expressiveness of JMAP filtering (including complex boolean combinations and
JMAP-specific fields) in a single test.  The legacy name `x-cyrus-jmapquery` is
also accepted.

## `vnd.cyrus.implicit_keep_target`

Adds the `implicit_keep_target` action, which redirects the implicit keep (the
default delivery that occurs when a script ends without an explicit action) to
a mailbox other than the INBOX.  Accepts `:specialuse` and `:mailboxid`
arguments as alternative ways to identify the target.

## `vnd.cyrus.log`

Adds the `log` action, which writes a string to the server's log (syslog).
Useful for debugging Sieve scripts.  This capability is intentionally not
advertised to ManageSieve clients (it is considered an administrative tool
rather than an end-user feature).  The legacy name `x-cyrus-log` is also
accepted.

