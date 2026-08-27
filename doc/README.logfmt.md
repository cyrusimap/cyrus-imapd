# Structured logging with logfmt

Cyrus is converting its syslogging from prose to
[logfmt](https://metacpan.org/pod/Log::Fmt#The-logfmt-text-format), so that
logs can be parsed reliably instead of scraped with regular expressions.

This document is the rulebook for that conversion.  It covers how to emit an
event, how to name it, and how to name and format its fields.  The vocabulary
itself — the list of every key you're allowed to use — lives in
[`doc/logfmt-keys`](logfmt-keys) and is enforced by `tools/lint-logfmt-keys`.

## Why a rulebook

The value of structured logging is entirely in its consistency.  A log where
the same fact is called `mboxid` in one place, `mbox.uniqueid` in another and
`uniqueid` in a third is barely better than prose, because every consumer still
needs a table of special cases.

Cyrus has around 2700 logging call sites.  Converting them without an agreed
vocabulary would produce exactly that mess, so the vocabulary comes first and
the lint makes it stick.

## The shape of an event

A logfmt event is a single syslog line of `key=value` pairs:

```
event=login.good r.sessionid=fastmail-1723150181-3493991-1 r.clienthost=10.0.0.7 u.username=jbloggs login.mech=PLAIN login.tls=1
```

`event` always comes first, and every line has exactly one.  It is the name of
the thing that happened, and it is what a log consumer keys off.

Values are escaped by `lib/logfmt.c`, which quotes anything containing a space
or other awkward byte.  You never have to escape or quote a value yourself, and
you should never try — passing a pre-quoted string just gets it double-quoted.

The grammar the escaper implements is documented in a comment at the top of
`logfmt_escape_bytestring()` in `lib/logfmt.c`.

## Emitting an event

There are three ways to log, in increasing order of ceremony.  Pick the least
ceremonious one that fits.

### 1. `xsyslog_ev()` — for a one-off event

Most call sites are like this: something went wrong in one particular place,
and you want to say so with some context.

```c
xsyslog_ev(LOG_ERR, "mailbox.append.failed",
           lf_mailbox(mailbox),
           lf_msgrecord(record),
           lf_err("error", r));
```

This is the direct replacement for `syslog()` and `xsyslog()`, and it's what
the bulk of the conversion produces.

`xsyslog_ev()` adds some fields for you:

- `r.sessionid` and `r.tid`, when the process has them;
- `sys.error` (from `errno`) and `caller.file` / `caller.line` / `caller.func`,
  but *only* when the priority is not `LOG_NOTICE` or `LOG_INFO`.

That last rule exists so that routine operational events don't carry debugging
noise.  It does mean that if you log at `LOG_NOTICE` you will not get
`caller.*`, which is occasionally surprising.

### 2. A typed event module — for an event logged from several places

When the same event is logged from more than one file, don't repeat the field
list at each site.  Write a function that takes the event's data as arguments
and emits it, and put it next to its peers.  `imap/loginlog.c` and
`imap/auditlog.c` are the existing examples:

```c
loginlog_good(clienthost, userid, "PLAIN", /*tls*/ 1);
```

This is how we guarantee that `login.good` means the same thing and carries the
same fields whether it came from `imapd`, `pop3d` or `httpd`.  It is also the
unit that log-parsing code is written against, so a shared event that isn't in
a module will drift.

Rule of thumb: **two call sites is a coincidence, three is a module.**

### 3. `struct logfmt` directly — for events built up conditionally

The typed modules use this internally.  Reach for it when the field list
depends on control flow in a way that a single call can't express.

```c
struct logfmt lf = LOGFMT_INITIALIZER;

logfmt_init(&lf, "sync.mailbox.replicated");
logfmt_push_session(&lf);
logfmt_push_mailbox(&lf, mailbox);

if (renamed) logfmt_push(&lf, "old.mbox.name", oldname);

logfmt_emit(&lf, LOG_NOTICE);
```

Note that this form does *not* add `r.sessionid`, `sys.error` or `caller.*` for
you; call `logfmt_push_session()` and `logfmt_push_caller()` yourself if you
want them.

## Naming events

```
event = segment *( "." segment )
segment = 1*( lowercase / DIGIT / "_" )
```

Read the name as **`<subsystem>.<object>.<outcome>`**, from general to
specific, so that a prefix match selects a useful family:

| Good                     | Bad                      | Why                        |
| ------------------------ | ------------------------ | -------------------------- |
| `lmtp.deliver.rejected`  | `"message rejected"`     | a name, not a sentence     |
| `jmap.email.set.failed`  | `jmap.failed.email.set`  | general to specific        |
| `mailbox.append.failed`  | `mailbox.append_failed`  | outcome is its own segment |
| `dav.caldav.put.invalid` | `DAV.CalDAV.Put.Invalid` | lowercase only             |

Rules:

- **Never put data in the event name.** `event=jmap.email.get` with
  `jmap.accountid=...`, never `event=jmap.email.get.u123`.  The name must have
  low cardinality or it can't be counted or grouped.
- **Don't put the severity in the name.** `mailbox.append.failed` logged at
  `LOG_ERR` is right; `mailbox.append.error` is redundant.
- **Name the outcome, not the function.** `mailbox.append.failed` beats
  `append_setup_mbox_failed`.  Function names are refactoring debris and they
  tell a log consumer nothing about what actually broke.  The function name is
  already in `caller.func`.
- An event name is an interface.  Once something outside the tree parses it,
  renaming it is a breaking change; see "Changing an existing event" below.

## Naming keys

Keys are dotted too, and the first segment says what the value is *about*, not
which subsystem happened to log it.  A mailbox is `mbox.name` whether IMAP,
JMAP or the replication code logged it.

The registered namespaces:

| Prefix                             | For                                                               |
| ---------------------------------- | ----------------------------------------------------------------- |
| `r.`                               | the request or connection: `r.sessionid`, `r.tid`, `r.clienthost` |
| `u.`                               | the user: `u.username`                                            |
| `mbox.`                            | a mailbox: `mbox.name`, `mbox.uniqueid`, `mbox.mailboxid`         |
| `msg.`                             | a message: `msg.guid`, `msg.imapuid`, `msg.id`, `msg.size`        |
| `sys.`                             | the operating system: `sys.error`                                 |
| `caller.`                          | the C source location that logged it                              |
| `login.`                           | authentication                                                    |
| `send.`                            | outbound delivery                                                 |
| `quota.`, `sieve.`, `cal.`, `pop.` | those subsystems                                                  |
| `http.`, `jmap.`, `dav.`           | those protocols                                                   |
| `error`                            | why the operation failed (bare, no prefix — it's universal)       |

Two structural prefixes stack on top of the above:

- **`old.`** — the value before a change: `old.mbox.name`, `old.msg.sysflags`.
  Always paired with the unprefixed key carrying the new value.
- **`out.`** — a value on the way out, where the event also mentions one coming
  in: `msg.id` and `out.msg.id` in Sieve redirect logging.

Rules:

- **Every key must be registered** in `doc/logfmt-keys` before use.
  `tools/lint-logfmt-keys` fails the build otherwise.  Adding a key is meant
  to be easy — a one-line patch — but deliberate.
- **Same fact, same key, everywhere.** If you're about to invent a key for
  something that already has one, use the existing one even if you'd have
  spelled it differently.
- **Don't abbreviate inconsistently.** It's `mbox`, never `mailbox` or `mb`.
- A key is an interface, exactly like an event name.

## Values

Use the typed `lf_*` macros rather than formatting values yourself; they keep
the representation of a given type consistent across the whole log.

| Macro                              | Emits                                            |
| ---------------------------------- | ------------------------------------------------ |
| `lf_s(k, v)`                       | a byte string, escaped                           |
| `lf_utf8(k, v)`                    | a UTF-8 string, escaped per codepoint            |
| `lf_d`, `lf_ld`, `lf_lld`, `lf_zd` | integers                                         |
| `lf_u`, `lf_lu`, `lf_llu`, `lf_zu` | integers                                         |
| `lf_llx(k, v)`                     | hex, no `0x` prefix                              |
| `lf_f(k, v)`                       | a double, `%f`                                   |
| `lf_b(k, cond)`                    | `1` or `0`                                       |
| `lf_time(k, t)`                    | a `time_t` as epoch seconds                      |
| `lf_duration(k, secs)`             | a double as seconds, 3 decimal places            |
| `lf_err(k, r)`                     | a Cyrus error code as its `error_message()` text |
| `lf_buf(k, buf)`                   | a `struct buf`, escaped                          |
| `lf_s_opt(k, v)`                   | `lf_s`, or nothing at all if `v` is NULL         |
| `lf_flag(k, cond)`                 | `k=1` if true, nothing at all if false           |
| `lf_raw(k, fmt, ...)`              | anything else, `printf`-formatted                |

And these log a whole struct, contributing several fields at once:

| Macro                 | Emits                                                               | Declared in       |
| --------------------- | ------------------------------------------------------------------- | ----------------- |
| `lf_mailbox(mb)`      | `mbox.name`, `mbox.uniqueid`, `mbox.mailboxid`                      | `imap/mailbox.h`  |
| `lf_msgrecord(rec)`   | `msg.imapuid`, `msg.modseq`, `msg.sysflags`, `msg.guid`, `msg.size` | `imap/mailbox.h`  |
| `lf_mbentry(mbe)`     | as `lf_mailbox`, plus `mbox.type`                                   | `imap/mboxlist.h` |
| `lf_mbname(k, mb)`    | a mailbox name, under the key you give                              | `imap/mboxname.h` |
| `lf_intname(k, name)` | an internal mailbox name, in the admin namespace                    | `imap/mboxname.h` |
| `lf_strarray(k, sa)`  | each element as `k.0`, `k.1`, ...                                   | `lib/strarray.h`  |
| `lf_fn(k, fn, p)`     | whatever `fn` pushes — the generic form                             | `lib/util.h`      |

Prefer these to spelling the fields out.  They're the reason the same
mailbox is described the same way in every event, and adding a field to one
of them improves every call site at once.  To log a struct that doesn't have
one yet, write the push function next to the struct and give it an `lf_` macro
there.  It doesn't matter whether the struct is defined in `imap/` or `lib/` or
somewhere else, put the logging helper with the struct.

Conventions these encode, so you don't have to decide each time:

- **Booleans are `1` and `0`**, not `true`/`false` and not `yes`/`no`.  This
  matches what shipped in 3.13 for `login.tls` and friends.
- **Times are epoch seconds**, matching the existing `send.scheduled` and
  `send.time`.  Log the machine-readable form; let the reader localise it.
- **Durations are seconds**, as a decimal, so that `0.004` and `12.500` are
  directly comparable.  Never log milliseconds under a key that doesn't say so.
- **Text that came from a user is `lf_utf8`**, not `lf_s`: mailbox names,
  subjects, display names.  Protocol tokens, hostnames, GUIDs and error strings
  are `lf_s`.

### Absent values

`lf_s(k, NULL)` logs `k=~null~`, which says "we looked and there was nothing".
`lf_s_opt(k, NULL)` omits the key entirely, which says "not applicable here".

Both are legitimate; they mean different things.  Prefer `lf_s_opt` for fields
that only apply to some variants of an event, and plain `lf_s` where a missing
value is itself interesting.

### Lists

A list of values is logged as one indexed key per element, not as a joined
string:

    sched.addresses.0=cassandane@example.com sched.addresses.1=cass@example.net

`lf_strarray()` does this for you.  A reader gets the elements without having
to know which separator we picked, and without us having to promise that no
element ever contains that separator.

Register the base key — `sched.addresses` — not the indexed forms.  The lint
only ever sees the base key, because that's what the source says.

An empty list logs `k=""` and a NULL one `k=~null~`, so those two cases still
say something.  A non-empty list logs only the indexed keys, never the bare
one.

### Things not to log

- **Passwords and credentials.**  The one exception in the tree is
  `login.password` for a rejected anonymous login, where the "password" is an
  email address by convention.  Don't add more.
- **Message bodies**, or anything unbounded.  Log a GUID and a size.
- **Values you formatted into a sentence.**  `lf_s("error", "failed to open
  mailbox foo")` throws away the structure we're here to create.  It's
  `lf_mailbox(...)` plus `lf_err("error", r)`.

## Choosing a severity

The severity is not decoration: Cassandane fails any test whose log contains a
logfmt event at `err` or worse (see `_check_syslog` in
`cassandane/Cassandane/Instance.pm`).  Logging routine, expected conditions at
`LOG_ERR` will turn tests red.

| Priority      | Means                                                         |
| ------------- | ------------------------------------------------------------- |
| `LOG_ERR`     | the server malfunctioned, or lost data, or a bug was hit      |
| `LOG_WARNING` | something is wrong but the server coped                       |
| `LOG_NOTICE`  | a routine operational event worth keeping: logins, deliveries |
| `LOG_INFO`    | detail a busy operator might want                             |
| `LOG_DEBUG`   | detail only a developer wants                                 |

A client sending a malformed request is **not** `LOG_ERR` — the server worked
correctly by rejecting it.

## Adding to the vocabulary

1. Check `doc/logfmt-keys` for an existing key that means what you mean.
2. If there isn't one, add it there, in the same patch as the code that uses
   it, with a description that says what the value *is* — not what your one
   call site uses it for.
3. Run `tools/lint-logfmt-keys` (or just build; it runs as part of `make
   check`).

## Changing an existing event

Event names and keys are consumed by log-parsing code outside this repository.
Treat them as you would any other interface:

- Adding a new key to an existing event is safe.
- Renaming or removing a key, renaming an event, or changing a value's format
  or units is a **breaking change**.  It needs a `changes/next/` entry saying
  exactly what changed, so that operators find it in the release notes.

## Converting an existing call site

The mechanical part is turning the prose into a name and the interpolations
into fields:

```c
/* before */
syslog(LOG_ERR, "IOERROR: failed to append to %s uid %u: %s",
       mailbox_name(mailbox), record->uid, error_message(r));

/* after */
xsyslog_ev(LOG_ERR, "mailbox.append.failed",
           lf_mailbox(mailbox),
           lf_msgrecord(record),
           lf_err("error", r));
```

The judgement part is everything else:

- Does this event already exist somewhere else under another name?  Reuse it.
- Is the message actually two different events sharing a code path?  Split it.
- Is anything in the message text a *value*?  It becomes a field, not part of
  the name.
- Is there context available that the prose didn't bother with — a mailbox, a
  uid, a userid?  Add it.  The old message was constrained by what fit in a
  readable sentence; the new one isn't.

Note the `IOERROR:` prefix disappearing.  That prefix existed so operators
could grep for trouble; `event=` plus the syslog severity now does that job
properly.

## Where the code lives

| File                           | Contains                                                 |
| ------------------------------ | -------------------------------------------------------- |
| `lib/logfmt.c`, `lib/logfmt.h` | escaping, and the `struct logfmt` API                    |
| `lib/util.h`                   | `xsyslog_ev()` and the `lf_*` macros                     |
| `lib/util.c`                   | `_xsyslog_ev()`, which turns an arg list into a log line |
| `imap/auditlog.c`              | the `auditlog.*` event family                            |
| `imap/loginlog.c`              | the `login.*` event family                               |
| `doc/logfmt-keys`              | the registered key vocabulary                            |
| `tools/lint-logfmt-keys`       | the lint that enforces it                                |
| `cunit/logfmt.testc`           | tests for escaping and the push functions                |
| `cunit/xsyslog_ev.testc`       | tests for `xsyslog_ev()` and the `lf_*` macros           |

Data-type-specific push functions live next to the struct they log, not in
`logfmt.c`, since that module can't see them.  Find them with:

```
$ git grep 'void logfmt_push_'
```
