# Cross-user namespace lock ordering: two remaining fixes

Status as of 2026-08-25, branch `user-data-uniqueid-ownership` (7 commits on
top of `origin/master`, tree clean).  Both fixes below are **designed and
agreed but not written**.

## The rule

Two operations reaching for the same pair of user namespace locks in opposite
orders deadlock against each other.  The sanctioned ways to hold more than one
are:

* `user_nslock_lockmulti(userids, locktype)` (`imap/user.c`) - sorts, dedupes
  and locks in that order, so any two overlapping calls agree who goes first.
  `user_nslock_lockdouble()` is the two element case.  **You must know the
  whole set before taking the first lock.**
* Holding locks in a consistent order (alphabetically first user first) is
  explicitly allowed - only the reverse order is reported.
* Otherwise: finish with one user before starting on the next.

A shared mailbox (`NULL` owner, lock name `*U*`) is **not** a special case - it
is just another namespace, and `*U*` sorts before every user.

`user_nslock_lock()` reports an out-of-order acquisition, naming the function
which asked, the function still holding the other lock, and both lock names.
Asking for a lock already held is only a refcount and is never reported.

Note: the report only ever shows what the running tests exercise.  Widening the
suite set has repeatedly surfaced new callers - a full `dar test` has never
been run as a baseline.

## Fix 1: LMTP - group all appends by owner

**Symptom** `caller=<deliver_mailbox> heldlock=<*U*user.X>
heldby=<conversations_open_path_version>`

A Sieve `fileinto` whose target is outside the recipient's namespace opens that
mailbox while the recipient's lock is still held.

**Why the lock is held** `imap/lmtpd.c:888-892` opens the recipient's
conversations state before `run_sieve()`:

```c
// lock conversations for the duration of delivery, so nothing else can read
// the state of any mailbox while the delivery is half done
conversations_open_user(userid, 0/*shared*/, &state);
```

`conversations_open_user()` takes the recipient's exclusive user lock
(`imap/conversations.c:365-371`) and holds it until `conversations_commit()` at
`imap/lmtpd.c:924`.

**Why "lock up front in order" cannot work here** the target of a `fileinto`
can be any user's mailbox - `mboxname_from_external()` on an altnamespace
`Other Users/...` path resolves to `user.foo.bar`, so it is expressible today
even if no such rule is common.  The lock set therefore is not knowable until
the script has run.  This is the case that breaks the discover-first rule.

**Why the recipient keeps its lock across evaluation** `imap/lmtpd.c:900`
passes the cstate into the interpreter:

```c
struct sieve_interp_ctx ctx = { mbname_userid(mbname), state, NULL };
```

Sieve tests can read the recipient's conversations state during evaluation, so
a test against that state and the subsequent append must be under the same
lock or the answer can go stale between them.  Do **not** move the cstate open
out from around evaluation.

**The design**

* Recipient's group: cstate opened before evaluation exactly as now; the
  recipient's own tests and appends both happen inside it.
* Foreign groups (owner != recipient, shared included): queued during action
  execution, then delivered after the recipient's cstate commits, grouped by
  owner, one owner at a time, each under its own cstate so a multi-append to
  the same user is still atomic for that user.
* No lock is ever held while another owner's is taken.

The asymmetry is deliberate: the recipient is the user the script reasons
about, so its state must be pinned across evaluation; foreign users are only
ever write targets.

**What makes this safe**

* Sieve already evaluates to an action list and executes it afterwards -
  `do_action_list()` at `sieve/script.c:720`, `ACTION_FILEINTO` at `:764`.
* `implicit_keep` is decided from `a->cancel_keep` (`sieve/script.c:742`), a
  property carried from evaluation time, **not** from whether the append
  succeeded.  Deferring an append does not corrupt the keep decision.
* A failed delivery already falls back to normal INBOX delivery one level up,
  at `imap/lmtpd.c:918-920` (`if (r) r = deliver_local(...)`).  No new fallback
  is needed.

**To confirm while implementing**

1. Does `conversations_open_user()` refcount a repeat open for the same user
   via its global `open_conversations` list?  Per-owner atomicity leans on it.
2. The drain must sit where a failure can still reach the `:918` fallback -
   `conversations_commit()` is currently *after* it, at `:924`.
3. `deliver_mailbox()`'s duplicate-suppression mark has to move with the
   append, or a failed group cannot be retried because it is already marked.

## Fix 2: iTIP - lock the organizer and attendees together

**Symptom** `caller=<sched_deliver_local> heldlock=<*U*user.other>
heldby=<jmap_api>`

`sched_deliver_local()` (`imap/itip_support.c:1048`) opens the recipient's
Scheduling Inbox (`mailbox_open_iwl`, around `:1135`) while the account lock
taken by `jmap_api` (`imap/jmap_api.c:736-746`) is still held.  Two users
inviting each other concurrently deadlock.

**`lockmulti` is NOT the answer here** - the design in earlier drafts of this
document was wrong.  The recipient set is not just the attendees in the
submitted event: `sched_request(... oldical, ical ...)` also cancels attendees
*removed* by this update, and `oldical` can only be read from the organizer's
calendar, which means holding the organizer's lock first.  That breaks
`lockmulti`'s one precondition.  It would also hold N attendee namespaces for
the length of a scheduling operation, which includes iMIP `sendmail` and
iSchedule HTTP round-trips.

**The design: defer delivery until the organizer's lock is gone.**  Deliver to
each recipient in turn, each under its own lock, nothing held across.  This is
safe because `sched_deliver_local()` closes `inbox`, `mailbox` and `caldavdb`
at its `done:` (`imap/itip_support.c:1552-1554`), so recipient locks never nest
with each other; the REPLY cascade at `http_caldav_sched.c:1396-1408` already
runs after that return, unlocked.  The only nesting is the caller's organizer
lock, held by `mailbox_open`'s `mailbox->user_nslock`.

Do **not** try to do this with `mailbox_unlock_index()` + `mailbox_lock_index()`
inside `caldav_put`.  It looks like it works - relocking is supported and drops
the user nslock (`imap/mailbox.c:2560`) - but `meth_put` owns the mailbox, and a
second `mailbox_open_iwl` on the same name just hits `find_listitem` and shares
the struct and its lock state.  See `76626da8f2` for what was wrong with
`mailbox_relock()` itself.

So: one **deferral queue**, drained where the mailbox is closed and the lock
released.  Follow the existing precedent exactly -
`dav_schedule_notification()`/`dav_run_notifications()`
(`imap/http_dav_sharing.c:906-941`) already queues cross-user notification
writes for this same reason and drains at `imap/jmap_api.c:833`, right after
`user_nslock_release()`.  Drain points:

* `process_request()` (`imap/httpd.c:1961`), after `(*meth_t->proc)()` returns -
  covers PUT, DELETE and the attachment POST in one place.
* `imap/jmap_api.c:833`, beside `dav_run_notifications()`.

**The second write** (agreed 2026-08-25: worth it for the fact history).  CalDAV
runs `sched_request()` *before* `caldav_store_resource()` (`http_caldav.c:4219`
vs `:4333`; same shape at `:3236`/`:3254`) precisely so the per-attendee
`SCHEDULE-STATUS` lands in the stored copy.  Deferring means storing again after
delivery: re-open the organizer's calendar with `mailbox_open_iwl` (which
re-validates the mbentry, unlike `mailbox_relock`), check the record we stored
is still current, then store the patched iCalendar.  Roughly two index records
per scheduling PUT, one immediately expunged - accepted.

The ETag takes care of itself: the resource changes after the response, so the
response must not carry one.  `caldav_put` already does this for the
default-alarms case - `remove_etag = 1` at `http_caldav.c:4298`, applied at
`:4384-4391`, "always force the client to re-read the event".  A deferred
scheduling write sets the same flag.

JMAP needs no write-back: `setcalendarevents_schedule()` clones and frees
`newical` (`imap/jmap_calendar.c:4553`, `:4599`), so `SCHEDULE-STATUS` is
already discarded there today, and the event is committed before scheduling
runs (`:5210` is after the append).

**To confirm while implementing**

1. Resolving attendees to local userids goes through `caldav_sched_param`
   lookups - confirm these need mboxlist but no user lock, so they are legal
   before locking.
2. Other callers needing the same treatment: `caldav_delete_cal`
   (`http_caldav.c:1521`), the attachment POST path (`:3236`),
   `jmap_calendar.c:8775`, `jmap_backup.c:892`.  `http_ischedule.c:535` is
   inbound so probably holds nothing - check.
3. `jmap_create_caldaveventnotif()` is **not** one of these, despite appearances
   - `accountid = mbname_userid(calmboxname)` (`imap/jmap_notif.c:357`), so the
   notification goes into the calendar owner's own JMAP notification
   collection, which sharees read through their ACL on it.  Same user we are
   already writing, whose lock we already hold.

## Verifying either fix

```
dar build                     # confirm the trailing version line; a check-fast
                              # flake aborts the build BEFORE install, and a
                              # following dar test then silently uses the old
                              # binaries.  Workaround: dar run sudo make install -j8
dar run bash -c 'truncate -s 0 /var/log/syslog; rm -rf /dev/shm/cass /dev/shm/cyrus*'
dar test -j4 <suites>
dar run bash -c "grep -o 'caller=<[a-zA-Z0-9_]*> heldlock=<[^>]*> heldby=<[a-zA-Z0-9_]*>' /var/log/syslog | sort | uniq -c"
```

Compare counts only against a run of the *same* suite set with a *truncated*
syslog - cumulative or differing suite sets have produced misleading
comparisons more than once.

Known pre-existing failures, unrelated: `Sieve.badscript_sievec`,
`Sieve.badscript_timsieved`, `Sieve.enotify_text_variable_bad`.

## Also outstanding

* `changes/next/user-data-uniqueid-ownership` documents only the original
  data-loss fix.  The `mayReadFreeBusy` change (commit `122191448b`) needs a
  line: existing free/busy shares keep their old ACLs and must be re-shared or
  repaired to gain lookup.
* The squashed series was rebuilt as file-group snapshots, so individual
  commits are not guaranteed to compile - `eedd6fcefa` calls
  `user_nslock_islockedmb`, whose declaration fix lands in `fddafe8f7e`.
  Reordering the user/locking unit before the dav_db unit would fix bisect.
* `_namelock_name_from_userid()` (`imap/user.c`) guards `if (userid)` for the
  mailbox name but then calls `strcmp(config_skip_userlock, userid)`
  unguarded - segfaults on a NULL userid when `skip_userlock` is configured,
  reachable via the shared namespace.  Pre-existing, untouched.
