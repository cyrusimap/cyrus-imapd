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
 */

#ifndef INCLUDED_EMAILID_FLAGS_H
#define INCLUDED_EMAILID_FLAGS_H

struct conversations_state;

/**
 * Apply the queued flag changes to every other copy of each email, then empty
 * the queue.
 *
 * Copies that are \\Deleted or expunged, copies in folders that aren't mail
 * folders, and the copies a change came from are left alone.  Each mailbox
 * is opened once.  The caller holds the user's namespace lock, and calls this
 * before committing the conversations db.
 *
 * @return 0, or an IMAP error, which must abort the commit.
 */
int emailid_flags_drain(struct conversations_state *cstate);

#endif /* INCLUDED_EMAILID_FLAGS_H */
