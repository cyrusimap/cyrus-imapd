/* emailid_flags.h - keep flags in step across copies of an email */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file
 * Every flag except \\Recent and \\Deleted is the same on all copies of an
 * email (draft-ietf-mailmaint-imap-objectid-bis).
 *
 * Writes to a copy queue their flag changes in the conversations state with
 * conversations_queue_flagchange().  emailid_flags_drain() applies the queue
 * to the email's other copies before the conversations db commits.  The
 * drain's own writes queue nothing.
 *
 * The drain changes only the copies the acting user, set with
 * emailid_flags_set_actor(), may change.
 */

#ifndef INCLUDED_EMAILID_FLAGS_H
#define INCLUDED_EMAILID_FLAGS_H

#include <stdbool.h>

struct auth_state;
struct conversations_state;

/**
 * Set the user whose changes later drains apply.
 *
 * The drain skips copies in mailboxes where this user lacks the read right,
 * drops every flag but \\Seen where they lack the write right, and drops
 * \\Seen where they lack the seen right.  An admin, or a NULL @p authstate
 * (the default), may change every copy.
 *
 * Processes that never set an actor, such as lmtpd and the command-line
 * tools, act with every right, as the owner or an admin would: they change
 * every copy, and change \\Seen on the record rather than in a seen.db.
 *
 * @param userid    the acting user, for logging; copied
 * @param authstate the acting user's auth state; the caller keeps it valid
 *                  until the next call
 * @param isadmin   whether the acting user is a server admin
 */
void emailid_flags_set_actor(const char *userid,
                             const struct auth_state *authstate,
                             bool isadmin);

/**
 * Stop queuing flag changes for the rest of the process.
 *
 * Replication applies carry the master's sibling writes, so a process that
 * only applies replication calls this at startup.
 */
void emailid_flags_disable(void);

/**
 * Stop queuing flag changes until emailid_flags_resume().
 *
 * For a process that also serves other clients, around a replication apply.
 *
 * @return the previous state, to pass to emailid_flags_resume()
 */
bool emailid_flags_suspend(void);

/**
 * Restore the state returned by emailid_flags_suspend().
 */
void emailid_flags_resume(bool was);

/**
 * Apply the queued flag changes to every other copy of each email, then empty
 * the queue.
 *
 * Copies that are \\Deleted or expunged, copies in folders that aren't mail
 * folders, and the copies a change came from are left alone.  Each mailbox
 * is opened once.
 *
 * Then each new copy merges with the other copies the acting user can read:
 * every copy gets the union of their flags other than \\Seen, and loses
 * \\Seen unless every one of them is seen.  This opens the mailboxes holding
 * those copies twice more, once to read and once to write.
 *
 * Where \\Seen isn't the record's flag for the acting user (see
 * mailbox_internal_seen()), it is changed in their seen.db instead, and the
 * record's own \\Seen is left alone.
 *
 * The caller holds the user's namespace lock, and calls this before
 * committing the conversations db.  On error, mailboxes already rewritten
 * have committed their index, so the caller still commits the conversations
 * db.
 *
 * @return 0, or an IMAP error
 */
int emailid_flags_drain(struct conversations_state *cstate);

#endif /* INCLUDED_EMAILID_FLAGS_H */
