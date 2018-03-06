.. _imap-developer-thoughts-backup:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Notes for backup implementation
===============================

Backup index database (one per user):

chunk::

    int id
    timestamp ts
    int offset
    int length
    text file_sha1              -> sha1 of (compressed) data prior to this chunk
    text data_sha1              -> sha1 of (uncompressed) data contained in this chunk

mailbox::

    int id
    int last_chunk_id           -> chunk that knows the current state
    char uniqueid               -> unique
    char mboxname               -> altered by a rename
    char mboxtype
    int last_uid
    int highestmodseq
    int recentuid
    timestamp recenttime
    timestamp last_appenddate
    timestamp pop3_last_login
    timestamp pop3_show_after
    timestamp uidvalidity
    char partition
    char acl
    char options
    int sync_crc
    int sync_crc_annot
    char quotaroot
    int xconvmodseq
    char annotations
    timestamp deleted           -> time that it was unmailbox'd, or NULL if still alive

message::

    int id
    char guid
    char partition              -> this is used to set the spool directory for the temp file - we might not need it
    int chunk_id
    int offset                  -> offset within chunk of dlist containing this message
    int size                    -> size of this message (n.b. not length of dlist)

mailbox_message::

    int mailbox_id
    int message_id
    int last_chunk_id           -> chunk that has a RECORD in a MAILBOX for this
    int uid
    int modseq
    timestamp last_updated
    char flags
    timestamp internaldate
    int size
    char annotations
    timestamp expunged          -> time that it was expunged, or NULL if still alive

subscription::

    int last_chunk_id           -> chunk that knows the current state
    char mboxname               -> no linkage to mailbox table, users can be sub'd to nonexistent
    timestamp unsubscribed      -> time that it was unsubscribed, or NULL if still alive

seen::

    int last_chunk_id           -> chunk that knows the current state
    char uniqueid               -> mailbox (not necessarily ours) this applies to
    timestamp lastread
    int lastuid
    timestamp lastchange
    char seenuids               -> a uid sequence encoded as a string

sieve::

    int chunk_id
    timestamp last_update
    char filename
    char guid
    int offset                  -> offset within chunk of the dlist containing this script
    timestamp deleted           -> time that it was deleted, or NULL if still alive


sieve scripts and messages are both identified by a GUID
but APPLY SIEVE doesn't take a GUID, it seems to be generated locally?
the GUID in the response to APPLY SIEVE is generated in the process of
reading the script from disk (sync_sieve_list_generate)

can't activate scripts because only bytecode files are activated, but
we neither receive bytecode files over sync protocol nor do we compile
them ourselves.

possibly reduce index size by breaking deleted/expunged values into their
own tables, such that we only store a deleted value for things that are
actually deleted.  use left join + is null to find undeleted content

messages
--------

APPLY MESSAGE is a list of messages, not necessarily only one message.
Actually, it's a list of messages for potentially multiple users, but we avoid
this by rejecting GET MESSAGES requests that span multiple users (so that
sync_client retries at USER level, and so we only see APPLY MESSAGE requests
for a single user).

Cheap first implementation is to index the start/end of the entire APPLY
MESSAGE command identically for each message within it, and at restore time
we grab that chunk and loop over it looking for the correct guid.

Ideal implementation would be to index the offset and length of each message
exactly (even excluding the dlist wrapper), but this is rather complicated
by the dlist API.

For now, we just index the offset of the dlist entry for the message,
and we can parse the pure message data back out later from that, when
we need to.  Slightly less efficient on reads, but works->good->fast.  We
need to loop over the entries in the MESSAGE dlist to find the one with the
desired GUID.

The indexed length needs to be the length of the message, not the length of the
dlist wrapper, because we need to know this cheaply to supply RECORDs in
MAILBOX responses.

renames
-------

APPLY RENAME %(OLDMBOXNAME old NEWMBOXNAME new PARTITION p UIDVALIDITY 123)

We identify mboxes by uniqueid, so when we start seeing sync data for the same
uniqueid with a new mboxname we just transparently update it anyway, without
needing to handle the APPLY RENAME.  Not sure if this is a problem...  Do we
need to record an mbox's previous names somehow?

I think it's possible to use this to rename a USER though, something like:

APPLY RENAME %(OLDMBOXNAME example.com!user.smithj NEWMBOXNAME example.com!user.jsmith ...)

-- in which case, without special handling of the RENAME command itself, there
will be a backup for the old user that ends with the RENAME, and a backup of
the new user that (probably) duplicates everything again (except for stuff
that's been expunged).

And if someone else gets given the original name, like

APPLY RENAME %(OLDMBOXNAME example.com!user.samantha-mithj NEWMBOXNAME example.com!user.smithj ...)

Then anything that was expunged from the original user but still available in
backup disappears?  Or the two backups get conflated, and samantha can
"restore" the original smithj's old mail?

Uggh.

if there's a mailboxes database pointing to the backup files, then the backup
file names don't need to be based on the userid, they could e.g. be based on
the user's inbox's uniqueid.  this would make it easier to deal with user
renames because the backup filename wouldn't need to change.  but this depends
on the uniqueid(s) in question being present on most areas of the sync
protocol, otherwise when starting a backup of a brand new user we won't be
able to tell where to store it.  workaround in the meantime could be to make
some kind of backup id from the mailboxes database, and base the filename on
this.

actually, using "some kind of backup id from the mailboxes database" is probably
the best solution.  otherwise the lock complexity of renaming a user while making
sure their new backup filename doesn't already exist is frightful.

maybe do something with mkstemp()?

furthermore: what if a mailbox is moved from one user to another?  like:

APPLY RENAME %(OLD... example.com!user.foo.something NEW... example.com!user.bar.something ...)

when a different-uid rename IS a rename of a user (and not just a folder
being moved to a different user), what does it look like?
* does it do a single APPLY RENAME for the user, and expect their folders to shake out of that?
* does it do an APPLY RENAME for each of their folders?

in the latter case, we need to append each of those RENAMEs to the old backup
so they can take effect correctly, and THEN rename the backup file itself. but
how to tell when the appends are finished?

how can we tell the difference between folder(s) moved to a different user vs
user has been renamed?

there is a setting: 'allowusermoves: 0' which, when enabled, allows users to
be renamed via IMAP rename/xfer commands.  but the default is that this is
disabled.  we could initially require this to be disabled while using backups...

not sure what the workflow looks like for renaming a user if this is not enabled.

not sure what the sync flow looks like in either case.

looking at sync_apply_rename and mboxlist_renamemailbox, it seems like we'll
see an APPLY RENAME for each affected mbox when a recursive rename is occurring.

there doesn't seem to be anything preventing user/a/foo -> user/b/foo in the
general (non-INBOX) case.

renames might be a little easier to handle if the index replicated the mailbox
hierarchy rather than just being a flat structure.  though this adds complexity
wrt hiersep handling.  something like:

mailbox:

    mboxname
        # just the name of this mbox

    parent_id
        # fk to parent mailbox

    full_mboxname
        # cached value, parent.full_mboxname + mboxname

locking
-------

just use a normal flock/fcntl lock on the data file and only open the index
if that lock succeeded

*   backup:   needs to append foo and update foo.index
*   reindex:  only needs to read foo, but needs a write lock to prevent
              writes while it does so. needs to write to (replace) foo.index
*   compact:  needs to re-write foo and foo.index
*   restore:  needs to read


verifying index
---------------

how to tell whether the .index file is the correct one for the backup data it
ostensibly represents?

one way to do this would be to have backup_index_end() store a checksum of
the corresponding data contents in the index.

when opening a backup, verify this checksum against the data, and refuse to
load the index if it doesn't match.

- sha1sum of (compressed) contents of file prior to each chunk

how to tell whether the chunk data is any good?  store a checksum of the chunk
contents along with the rest of the chunk index

- sha1sum of (uncompressed) contents of each chunk


mailboxes database
------------------

bron reckons use twoskip for this
userid -> backup_filename

lib/cyrusdb module implements this, look into that

look at conversations db code to see how to use it

need a tool:
* given a user, show their backup filename
* dump/undump
* rebuild based on files discovered in backup directory

where does this fit into the locking scheme?


reindex
-------

* convert user mailbox name to backup name
* complain if there's no backup data file?
* lock, rename .index to .index.old, init new .index
* foreach file chunk:
*   timestamp is from first line in chunk
*   complain if timestamp has gone backwards?
*   index records from chunk
* unlock
* clean up .index.old

on error:
* discard partial new index
* restore .index.old
* bail out


backupd
-------

cmdloop:
* (periodic cleanup)
* read command, determine backup name
* already holding lock ? bump timestamp : obtain lock
* write data to gzname, flush immediately
* index data

periodic cleanup:
* check timestamp of each held lock
* if stale (define: stale?), release
* FIXME if we've appended more than the chunk size we would compact to, release

sync restart:
* release each held lock

exit:
* release each held lock

need a "backup_index_abort" to complete the backup_index_start/end set.
_start should create a transaction, _end should commit it, and _abort should
roll it back.  then, if backupd fails to write to the gzip file for some
reason, the (now invalid) index info we added can be discarded too.

flushing immediately on write results in poor gzip compression, but for
incremental backups that's not a problem.  when the compact process hits the
file it will recompress the data more efficiently.


questions
---------
* what does it look like when uidvalidity changes?


restore
-------

restoration is effectively a reverse-direction replication (replicating TO master),
which means we can't necessarily supply things like uid, modseq, etc without racing
against normal message arrivals.  so instead we add an extra command to the protocol
to restore a message to a folder but let the destination determine the tasty bits.

protocol flow looks something like:

c: APPLY RESERVE ... # as usual
s: * MISSING (foo bar)
s: OK
c: APPLY MESSAGE ... # as usual
s: OK
c: RESTORE MAILBOX ... # new sync proto command
s: OK

we introduce a new command, RESTORE MAILBOX, which is similar to the existing
APPLY MAILBOX.  it specifies, for a mailbox, the mailbox state plus the message
records relevant to the restore.

the imapd/sync_server receiving the RESTORE command creates the mailbox if necessary,
and then adds the message records to it as new records (i.e. generating new uid etc).
this will end up generating new events in the backup channel's sync log, and then the
messages will be backed up again with their new uids, etc.  additional wire transfer
of message data should be avoided by keeping the same guid.

if the mailbox already exists but its uniqueid does not match the one from the backup,
then what?  this probably means user has deleted folder and contents, then made new
folder with same name.  so it's probably v common for mailbox uniqueid to not match
like this.  so we don't care about special handling for this case.  just add any
messages that aren't already there.

if the mailbox doesn't already exist on the destination (e.g. if rebuilding a server
from backups) then it's safe and good to reuse uidvalidity, uniqueid, uid, modseq etc,
such that connecting clients can preserve their state.  so the imapd/sync_server
receiving the restore request accepts these fields as optional, but only preserves
them if it's safe to do so.

* restore: sbin program for selecting and restoring messages

restore command needs options:
+ whether or not to trim deletedprefix off mailbox names to be restored
+ whether or not to restore uniqueid, highestmodseq, uid and so on
+ whether or not to limit to/exclude expunged messages
+ whether or not to restore sub-mailboxes
+ sync_client-like options (servername, local_only, partition, ...)
+ user/mailbox/backup file(s) to restore from
+ mailbox to restore to (override location in backup)
+ override acl?

can we heuristically determine whether an argument is an mboxname, uniqueid or guid?
    => libuuid uniqueid is 36 bytes of hyphen (at fixed positions) and hex digits
    => non-libuuid uniqueid is 24 bytes of hex digits
    => mboxname usually contains at least one . somewhere
    => guid is 40 bytes of hex digits

usage:
    restore [options] server [mode] backup [mboxname | uniqueid | guid]...

options:
    -A acl              # apply specified acl to restored mailboxes
    -C alt_config       # alternate config file
    -D                  # don't trim deletedprefix before restoring
    -F input-file       # read mailboxes/messages from file rather than argv
    -L                  # local mailbox operations only (no mupdate)
    -M mboxname         # restore messages to specified mailbox
    -P partition        # restore mailboxes to specified partition
    -U                  # try to preserve uniqueid, uid, modseq, etc
    -X                  # don't restore expunged messages
    -a                  # try to restore all mailboxes in backup
    -n                  # calculate work required but don't perform restoration
    -r                  # recurse into submailboxes
    -v                  # verbose
    -w seconds          # wait before starting (useful for attaching a debugger)
    -x                  # only restore expunged messages (not sure if useful?)
    -z                  # require compression (abort if compression unavailable)

mode:
    -f                  # specified backup interpreted as filename
    -m                  # specified backup interpreted as mboxname
    -u                  # specified backup interpreted as userid (default)


compact
--------

# finding messages that are to be kept (either exist as unexpunged somewhere,
# or exist as expunged but more recently than threshold)
# (to get unique rows, add "distinct" and remove mm.expunged from fields)
sqlite> select m.*, mm.expunged from message as m join mailbox_message as mm on m.id = mm.message_id and (mm.expunged is null or mm.expunged > 1437709300);
id|guid|partition|chunk_id|offset|length|expunged
1|1c7cca361502dfed2d918da97e506f1c1e97dfbe|default|1|458|2159|
1|1c7cca361502dfed2d918da97e506f1c1e97dfbe|default|1|458|2159|1446179047
1|1c7cca361502dfed2d918da97e506f1c1e97dfbe|default|1|458|2159|1446179047

# finding chunks that are still needed (due to containing last state
# of mailbox or mailbox_message, or containing a message)
sqlite> select * from chunk where id in (select last_chunk_id from mailbox where deleted is null or deleted > 1437709300 union select last_chunk_id from mailbox_message where expunged is null or expunged > 1437709300 union select chunk_id from message as m join mailbox_message as mm on m.id = mm.message_id and (mm.expunged is null or mm.expunged > 1437709300));
id|timestamp|offset|length|file_sha1|data_sha1
1|1437709276|0|3397|da39a3ee5e6b4b0d3255bfef95601890afd80709|6836d0110252d08a0656c14c2d2d314124755491
3|1437709355|1977|2129|fee183c329c011ead7757f59182116500776eaaf|a5677cfa1f5f7b627763652f4bb9b99f5970748c
4|1437709425|2746|1719|3d9f02135bf964ff0b6a917921b862c3420e48f0|7b64ec321457715ee61fe238f178f5d72adaef64
5|1437709508|3589|2890|0cee599b1573110fee428f8323690cbcb9589661|90d104346ef3cba9e419461dd26045035f4cba02

remember: a single APPLY MESSAGE line can contain many messages!

thoughts:

* need a heuristic for quickly determining whether a backup needs to be compacted

    * sum(chunks to discard, chunks to combine, chunks to split) > threshold
    * can we detect chunks that are going to significantly reduce in size as result of discarding individual lines?

* "quick" vs "full" compaction

settings:

* backup retention period
* chunk combination size (byte length or elapsed time)

combining chunks:
* size threshold below which adjacent chunks can be joined
* size threshold above which chunks should be split
* duration threshold below which adjacent chunks can be joined
* duration threshold above which chunks should be split
backup_min_chunk_size: 0 for no minimum
backup_max_chunk_size: 0 for no maximum
backup_min_chunk_duration: 0 for no minimum
backup_max_chunk_duration: 0 for no maximum
priority: size or duration??

data we absolutely need to keep:

* the most recent APPLY MAILBOX for each mailbox we're keeping (mailbox state)
* the APPLY MAILBOX containing the most recent RECORD for each message we're keeping (record state)
* the APPLY MESSAGE for each message we're keeping (message data)

data that we should practically keep:

* all APPLY MAILBOXes for a given mailbox from the chunk identified as its last
* all APPLY MAILBOXes containing a RECORD for a given message from the chunk identified as its last
* the APPLY MESSAGE for each message we're keeping

four kinds of compaction (probably at least two simultaneously):

* removing unused chunks
* combining adjacent chunks into a single chunk (for better gz compression)
* removing unused message lines from within a chunk (important after combining)
* removing unused messages from within a message line

"unused messages"
    messages for which all records have been expunged for longer
    than the retention period

"unused chunks"
    chunks which contain only unused messages

algorithm:

*   open (and lock) backup and backup.new (or bail out)
*   use backup index to identify chunks we still need
*   create a chunk in backup.new
*   foreach chunk we still need:
*       foreach line in the chunk:
*           next line if we don't need to keep it
*           create new line
*           foreach message in line:
*               if we still need the message, or if we're not doing message granularity
*                   add the message to the new line
*           write and index tmp line to backup.new
*       if the new chunk is big enough, or if we're not combining
*           end chunk and start a new one
*   end the new chunk
*   rename backup->backup.old, backup.new->backup
*   close (and unlock) backup.old and backup


command line locking utility
----------------------------

command line utility to lock a backup (for e.g. safely poking around in the
.index on a live system).

example failure:
$ctl_backups lock -f /path/to/backup
* Trying to obtain lock on /path/to/backup...
NO some error
<EOF>

example success:
$ctl_backups lock -f /path/to/backup
* Trying to obtain lock on /path/to/backup...
[potentially a delay here if we need to wait for another process to release the lock]
OK locked
[waits for its stdin to close, then unlocks and exits]

if you need to rummage around in backup.index, run this program in another
shell, do your work, then ^D it when you're finished.

you could also call this from e.g. perl over a bidirectional pipe - wait to
read "OK locked", then you've got your lock.  close the pipe to unlock when
you're finished working.  if you don't read "OK locked" before the pipe closes
then something went wrong and you didn't get the lock.

specify backups by -f filename, -m mailbox, -u userid
default run mode as above
-s to fork an sqlite of the index (and unlock when it exits)
-x to fork a command of your choosing (and unlock when it exits)


reconstruct
-----------

rebuilding backups.db from on disk files

scan each backup partition for backup files:
  * skip timestamped files (i.e. backups from compact/reindex)
  * skip .old files (old backups from reindex)
  * .index files => skip???
  * skip unreadable files
  * skip empty files
  * skip directories etc

what's the correct procedure for repopulating a cyrus database?
keep copy of the previous (presumably broken) one?

trim off mkstemp suffix (if any) to find userid
can we use a recognisable character to delimit the mkstemp suffix?

what if there's multiple backup files for a given userid? precedence?

verify found backups before recording.  reindex?

locking? what if something has a filename and does stuff with it while
reconstruct runs?

backupd always uses db for opens, so as long as reconstruct keeps the db
locked while it works, the db won't clash.  but backupd might have backups
still open from before reconstruct started, which it will write to quite
happily, even though reconstruct might decide that some other file is the
correct one for that user...

a backup server would generally be used only for backups, and sync_client
is quite resilient when the destination isn't there, so it's actually
no problem to just shut down cyrus while reconstruct runs.  no outage to
user-facing services, just maybe some sync backlog to catch up on once
cyrus is restarted.


ctl_backups
-------------

sbin tool for mass backup/index/database operations

needs:
    * rebuild backups.db from disk contents
    * list backups/info
    * rename a backup
    * delete a backup
    * verify a backup (check all sha1's, not just most recent)

not sure if these should be included, or separate tools:
    * reindex a backup (or more)
    * compact a backup (or more)
    * lock a backup
    * some sort of rolling compaction?

usage:
    ctl_backups [options] reconstruct                       # reconstruct backups.db from disk files
    ctl_backups [options] list [list_opts] [[mode] backup...] # list backup info for given/all users
    ctl_backups [options] move new_fname [mode] backup      # rename a backup (think about this more)
    ctl_backups [options] delete [mode] backup              # delete a backup
    ctl_backups [options] verify [mode] backup...           # verify specified backups
    ctl_backups [options] reindex [mode] backup...          # reindex specified backups
    ctl_backups [options] compact [mode] backup...          # compact specified backups
    ctl_backups [options] lock [lock_opts] [mode] backup    # lock specified backup

options:
    -C alt_config       # alternate config file
    -F                  # force (run command even if not needed)
    -S                  # stop on error
    -v                  # verbose
    -w                  # wait for locks (i.e. don't skip locked backups)

mode:
    -A                  # all known backups (not valid for single backup commands)
    -D                  # specified backups interpreted as domains (nvfsbc)
    -P                  # specified backups interpreted as userid prefixes (nvfsbc)
    -f                  # specified backups interpreted as filenames
    -m                  # specified backups interpreted as mboxnames
    -u                  # specified backups interpreted as userids (default)

lock_opts:
    -c                  # exclusively create backup
    -s                  # lock backup and open index in sqlite
    -x cmd              # lock backup and execute cmd
    -p                  # lock backup and wait for eof on stdin (default)

list_opts:
    -t [hours]          # "stale" (no update in hours) backups only (default: 24)


cyr_backup
----------

sbin tool for inspecting backups

needs:
    * better name?
    * list stuff
    * show stuff
    * dump stuff
    * restore?

* should lock/move/delete (single backup commands) from ctl_backups be moved here?

usage:
    cyr_backup [options] [mode] backup list [all | chunks | mailboxes | messages]...
    cyr_backup [options] [mode] backup show chunks [id...]
    cyr_backup [options] [mode] backup show messages [guid...]
    cyr_backup [options] [mode] backup show mailboxes [mboxname | uniqueid]...
    cyr_backup [options] [mode] backup dump [dump_opts] chunk id
    cyr_backup [options] [mode] backup dump [dump_opts] message guid
    cyr_backup [options] [mode] backup json [chunks | mailboxes | messages]...

options:
    -C alt_config       # alternate config file
    -v                  # verbose

mode:
    -f                  # backup interpreted as filename
    -m                  # backup interpreted as mboxname
    -u                  # backup interpreted as userid (default)

commands:
    list: table of contents, one per line
    show: indexed details of listed items, one per paragraph, detail per line
    dump: relevant contents from backup stream
    json: indexed details of listed items in json format

dump options:
    -o filename         # dump to named file instead of stdout


partitions
----------

not enough information in sync protocol to handle partitions easily?

we know what the partition is when we do an APPLY operation (mailbox, message,
etc), but the initial GET operations don't include it.  so we need to already
know where the appropriate backup is partitioned in order to find the backup
file in order to look inside it to respond to the GET request

if we have a mailboxes database (indexed by mboxname, uniqueid and userid) then
maybe that would make it feasible?  if it's not in the mailboxes database then
we don't have a backup for it yet, so we respond accordingly, and get sent
enough information to create it.

does that mean the backup api needs to take an mbname on open, and it handles
the job of looking it up in the mailboxes database to find the appropriate
thing to open?

can we use sqlite for such a database, or is the load on it going to be too
heavy?  locking?  we have lots of database formats up our sleeves here, so
even though we use sqlite for the backup index there isn't any particular
reason we're beholden to it for the mailboxes db too

if we have a mailboxes db then we need a reconstruct tool for that, too

what if we support multiple backup partitions, but don't expect these
to necessarily correspond with mailbox partitions.  they're just for spreading
disk usage around.

* when creating a backup for a previously-unseen user we'd pick a random
  partition to put them on
* ctl_backups would need a command to move an existing backup to a
  given partition
* ctl_backups would need a command to pre-create a user backup on a
  given partition for initial distribution
* instead of "backup_data_path" setting, have one-or-more
  "backuppartition-<name>" settings, ala partition- and friends

see imap/partlist.[ch] for partition list management stuff.  it's complicated
and doesn't have a test suite, so maybe save this implementation until needed.

but... maybe rename backup_data_path to backuppartition-default in the meantime,
so that when we do add this it's not a complicated reconfig to update?

partlist_local_select (and lazy-loaded partlist_local_init) are where the
mailbox partitions come from (see also mboxlist_create_partition), do something
similar for backup partitions


data corruption
---------------

backups.db:
    * can be reconstructed from on disk files at any time
    * how to detect corruption? does cyrus_db detect/repair on its own?

backup indexes:
    * can be reindexed at any time from backup data
    * how to detect corruption? assume sqlite will notice, complain?

backup data:
    * what's zlib's failure mode? do we lose the entire chunk or just the corrupt bit?
    * verify will notice sha1sum mismatches
    * dlist format will reject some kinds of corruption (but not all)
    * reindex: should skip unparseable dlist lines
    * message data has its own checksums (guid)
    * reindex: should skip messages that don't match their own checksums
    * compact: "full" compact will only keep useful data according to index
    * backupd: will sync anything that's in user mailbox but not in backup index

i think this means that if a message or mailbox state becomes corrupted in
the backup data file, and it still exists in the user's real mailbox, you
recover from the corruption by reindexing and then letting the sync process
copy the missing data back in again.  and you can tidy up the data file by
running a compact over it.

you detect data corruption in most recent chunk reactively as soon as the
backup system needs to open it again (quick verify on open)

you detect data corruption in older chunks reactively by trying to restore from
it.  may be too late: if a message needs restoring it's because user mailbox no
longer has it

you detect data corruption preemptively by running the verify tool over it.
recommend scheduling this in EVENTS/cron?

if data corruption occurs in message that's no longer in user's mailbox, that
message is lost.  it was going to be deleted from the backup after $retention
period anyway (by compact), but if it needs restoring in the meantime, sorry


installation instructions
-------------------------

(obviously, most of this won't work at this point, because the code doesn't
exist.  but this is, approximately, where things are heading.)

on your backup server:
    * compile with --enable-backup configure option and install
    * imapd.conf:
        backuppartition-default: /var/spool/backup  # FIXME better example
        backup_db: twoskip
        backup_db_path: /var/imap/backups.db
        backup_staging_path: /var/spool/backup
        backup_retention_days: 7
    * cyrus.conf SERVICES:
        backupd cmd="backupd" listen="csync" prefork=0
        (remove other services, most likely)
        (should i create a master/conf/backup.conf example file?)
    * cyrus.conf EVENTS:
        compact cmd="ctl_backups compact -A" at=0400
    * start server as usual
    * do i want a special port for backupd?

on your imap server:
    * imapd.conf:
        sync_log_channels: backup
        sync_log: 1
        backup_sync_host: backup-server.example.com
        backup_sync_port: csync
        backup_sync_authname: ...
        backup_sync_password: ...
        backup_sync_repeat_interval: ... # seconds, smaller value = livelier backups but more i/o
        backup_sync_shutdown_file: ....
    * cyrus.conf STARTUP:
        backup_sync cmd="sync_client -r -n backup"
    * cyrus.conf SERVICES:
        restored cmd="restored" [...]
    * start/restart master

files and such:
    {configdirectory}/backups.db                        - database mapping userids to backup locations
    {backuppartition-name}/<hash>/<userid>_XXXXXX       - backup data stream for userid
    {backuppartition-name}/<hash>/<userid>_XXXXXX.index - index into userid's backup data stream

do i want rhost in the path?
    * protects from issue if multiple servers are trying to back up their own version of same user
      (though this is its own problem that the backup system shouldn't have to compensate for)
    * but makes location of undifferentiated user unpredictable
    * so probably not, actually


chatting about implementation 20/10
-----------------------------------

::

    09:54 @elliefm
    here's a fun sync question
    APPLY MESSAGE provides a list of messages
    can a single APPLY MESSAGE contain messages for multiple mailboxes and/or users?
    my first hunch is that it doesn't cross users, since the broadest granularity for a single sync run is USER
    10:06 kmurchison
    We'd have to check with Bron, but I *think* messages can cross mailboxes for a single user
    10:06 @brong
    yes
    APPLY MESSAGE just adds it to the reserve list
    10:07 @elliefm
    nah apply message uploads the message, APPLY RESERVE adds it to the reserve list :P
    10:07 @brong
    same same
    APPLY RESERVE copies it from a local mailbox
    APPLY MESSAGE uploads it
    10:07 @elliefm
    yep
    10:07 @brong
    they both wind up in the reserve list
    10:07 @elliefm
    ahh i see what you mean, gotcha
    10:07 @brong
    until you send a RESTART
    ideally you want it reserve in the same partition, but it will copy the message over if it's not on the same partition
    there's no restriction on which mailbox it came from/went to
    good for user renames, and good for an append to a bunch of mailboxes in different users / shared space all at once
    (which LMTP can do)
    10:10 @elliefm
    i can handle the case where a single APPLY MESSAGE contains messages for multiple mailboxes belonging to the same user
    but i'm in trouble if a single APPLY MESSAGE can contain messages belonging to different users
    10:14 @brong
    @elliefm: why?
    10:14 @brong
    you don't have to keep them if they aren't used
    10:15 @elliefm
    for backups - when i see the apply, i need to know which user's backup to add it to.  that's easy enough if it doesn't cross users but gets mega fiddly if it does
    i'm poking around in sync client to see if it's likely to be an issue or not
    11:00 @brong_
    @elliefm: I would stage it, and add it to users as it gets refcounted in by an index file
    11:07 @elliefm
    that's pretty much what we do for ordinary sync and delivery stuff yeah?
    11:08 @brong_
    yep
    and it's what the backup thing does
    11:09 @elliefm
    i'm pretty sure that APPLY RESERVE and APPLY MESSAGE don't give a damn about users, they're just "here's every message you might not have already had since last time we spoke" and it lets the APPLY MAILBOX work out where to attach them later
    11:09 @brong_
    yep
    11:09 @elliefm
    so yeah, i'll need to do something here
    i've been working so far on the idea that a single user's backup consists of 1) an append-only gzip stream of the sync protocol chat that built it, and 2) an index that tracks current state of mailboxes, and offsets within (1) of message data
    that gets us good compression (file per user, not file per message), and if the index gets corrupted or lost, it's rebuildable purely from (1), it doesn't need a live copy of the original mailbox
    11:12 @brong
    yep, that all works
    11:12 @elliefm
    (so if you lose your imap server, you're not unable to rebuild a broken index on the backup)
    11:13 @brong
    it's easy enough to require the sync protocol stream to only contain messages per user
    though "apply reserve" is messy
    because you need to return "yes, I have that message"
    11:13 @elliefm
    with that implementation i can't (easily) keep user.a's messages from not existing in user.b's data stream (though they won't be indexed)
    11:14 @brong
    I'm not too adverse to the idea of just unpacking each message as it comes off the wire into a temporary directory
    11:14 @elliefm
    (because at the time i'm receiving the sync data i don't know which it needs to go in, so if they come in in the same reserve i'd need to append them to both data streams)
    which isn't a huge problem, just… irks me a bit
    11:14 @brong
    and then reading the indexes as they come in, checking against the state DB to see if we already have them, and streaming them into the gzip if they aren't there yet
    what we can do is something like the current format, where files go into a tar
    11:16 @elliefm
    i guess the fiddly bit there is that there's one more moving part to keep synchronised across failure states
    a backup for a single user becomes 1) data stream + 2) any messages that were uploaded but not yet added to a mailbox + 3) index (which doesn't know what to do with (2))
    which in the general case is fine, the next sync will update the mailboxes, which will push (2) into (1) and index it nicely, and on we go
    but it's just a little bit more mess if there's a failure that you need to recover from between those states — it's no longer a simple case of "it's in the backup and we know everything about it" or "it doesn't exist", there's a third case of "well we might have the data but don't really know what to do with it"
    the other fiddly bit is that the process of appending to the data stream is suddenly in the business of crafting output rather than simply dumping what it gets, which isn't really burdensome, but it is one more little crack for bugs to crawl into
    i guess in terms of sync protocol, one thing i could do on my end is identify apply operations that seem to contain multiple users' data, and just return an error on those.  the sync client on the other end will promote them until they're eventually user syncs, which i think are always user granularity
    11:50 @elliefm
    i think for now, first stage implementation will be to stream the reserve/message commands in full to every user backup they might apply to.  and optimising that down so that each stream only contains messages belonging to that user can be a future optimisation


todo list
---------

* clean up error handling
* perl tool to anonymise sync proto talk
* verification step to check entire data stream for errors (even chunks that aren't indexed)
* prot_fill_cb: extra argument to pass back an error string to prot_fill
* ctl_backups verify: set level
* backupd: don't block on locked backups, return mailbox locked -- but sync_client doesn't handle this
* test multiple backup partitions
* configure: error if backups requested and we don't have zlib
* valgrind
* finish reconstruct
* compact: split before append?

compact implementation steps:
    1 remove unused chunks, keep everything else as is
    2 join adjacent chunks if small enough, split large chunks
    3 parse/rebuild message lines
    4 discard unused mailbox lines
