/* mboxlist.h -- Mailbox list manipulation routines
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: mboxlist.h,v 1.48 2010/01/06 17:01:37 murch Exp $
 */

#ifndef INCLUDED_MBOXLIST_H
#define INCLUDED_MBOXLIST_H

#include "config.h"
#include "cyrusdb.h"
#include "dlist.h"
#include "mailbox.h"
#include "auth.h"
#include "mboxevent.h"
#include "mboxname.h"

extern struct db *mbdb;

/*
 * Maximum length of partition name. [config.c has a limit of 70]
 */
#define MAX_PARTITION_LEN 64
#define MAILBOX_UNIQUEID_LEN 32

/* flags for types of mailboxes */
#define MBTYPE_REMOTE (1<<0) /* Not on this server (part is remote host) */
#define MBTYPE_RESERVE (1<<1) /* Reserved [mupdate/imapd] /
			       Rename Target [imapd] (part is normal, but
			       you are not allowed to create this mailbox,
			       even though it doesn't actually exist */
#define MBTYPE_NETNEWS (1<<2) /* Netnews Mailbox - NO LONGER USED */
#define MBTYPE_MOVING (1<<3) /* Mailbox in mid-transfer (part is remotehost!localpart) */
#define MBTYPE_DELETED (1<<4) /* Mailbox has been deleted, but not yet cleaned up */

/* master name of the mailboxes file */
#define FNAME_MBOXLIST "/mailboxes.db"

#define HOSTNAME_SIZE 512

/* each mailbox has the following data */
struct mboxlist_entry {
    const char *name;
    char * _alloc;
    int mbtype;
    const char *partition;
    const char *server; /* holds remote machine for REMOTE mailboxes */
    const char *acl;
    /* extra fields */
    const char *specialuse;
    const char *uniqueid;
};

struct mboxlist_entry *mboxlist_entry_create();

void mboxlist_entry_free(struct mboxlist_entry **mbentryptr);

/* formats a cstring from a mboxlist_entry.  Caller must free
 * after use */
char *mboxlist_entry_cstring(struct mboxlist_entry *mbentry);

/* Lookup 'name' in the mailbox list. */
int mboxlist_lookup(const char *name, struct mboxlist_entry **mbentryptr,
		    struct txn **tid);
int mboxlist_lookup_allow_reserved(const char *name,
				   struct mboxlist_entry **mbentryptr,
				   struct txn **tid);

/* insert/delete stub entries */
int mboxlist_insertremote(struct mboxlist_entry *mbentry, struct txn **rettid);
int mboxlist_deleteremote(const char *name, struct txn **in_tid);

/* Update a mailbox's entry */
int mboxlist_update(struct mboxlist_entry *mbentry, int localonly);

/* check user's ability to create mailbox */
int mboxlist_createmailboxcheck(const char *name, int mbtype,
				const char *partition,
				int isadmin, const char *userid, 
				struct auth_state *auth_state, 
				char **newacl, char **newpartition,
				int forceuser);

/* create mailbox */
/* localonly creates the local mailbox without touching mupdate */
/* forceuser allows the creation of user.x.<name> without a user.x */
/* dbonly skips filesystem operations (e.g. reconstruct) */
/* notify sends a MailboxCreate event notification */
int mboxlist_createmailbox(const char *name, int mbtype,
			   const char *partition,
			   int isadmin, const char *userid, 
			   struct auth_state *auth_state,
			   int localonly, int forceuser, int dbonly,
			   struct dlist *extargs, int notify);

/* create mailbox from sync */
int mboxlist_createsync(const char *name, int mbtype,
			const char *partition, 
			const char *userid, struct auth_state *auth_state,
			int options, unsigned uidvalidity, const char *acl,
			const char *uniqueid, struct mailbox **mboxptr);

/* delated delete */
/* Translate delete into rename */
/* prepare MailboxDelete notification if mboxevent is not NULL */
int
mboxlist_delayed_deletemailbox(const char *name, int isadmin, const char *userid, 
                               struct auth_state *auth_state,
                               struct mboxevent *mboxevent,
			       int checkacl,
                               int force);
/* Delete a mailbox. */
/* setting local_only disables any communication with the mupdate server
 * and deletes the mailbox from the filesystem regardless of if it is
 * MBTYPE_REMOTE or not */
/* force ignores errors and just tries to wipe the mailbox off the face of
 * the planet */
/* prepare MailboxDelete notification if mboxevent is not NULL */
int mboxlist_deletemailbox(const char *name, int isadmin, const char *userid, 
			   struct auth_state *auth_state,
			   struct mboxevent *mboxevent,
			   int checkacl,
			   int local_only, int force);

/* Rename/move a mailbox (hierarchical) */
/* prepare MailboxRename notification if mboxevent is not NULL */
int mboxlist_renamemailbox(const char *oldname, const char *newname,
			   const char *partition, unsigned uidvalidity,
			   int isadmin, const char *userid,
			   struct auth_state *auth_state,
			   struct mboxevent *mboxevent,
			   int forceuser, int ignorequota);

/* change ACL */
int mboxlist_setacl(struct namespace *namespace, const char *name,
		    const char *identifier, const char *rights, int isadmin,
		    const char *userid, struct auth_state *auth_state);

/* Change all ACLs on mailbox */
int mboxlist_sync_setacls(const char *name, const char *acl);

/* Set specialuse on a mailbox */
/* TODO: this takes a mailbox* so it doesn't really belong here */
int mboxlist_setspecialuse(struct mailbox *, const char *specialuse);

/* Find all mailboxes that match 'pattern'. */
int mboxlist_findall(struct namespace *namespace,
		     const char *pattern, int isadmin, const char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock);
int mboxlist_findall_alt(struct namespace *namespace,
			 const char *pattern, int isadmin, const char *userid, 
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock);

/* direct access to subs DB */
int mboxlist_allsubs(const char *userid, foreach_cb *proc, void *rock);
int mboxlist_allmbox(const char *prefix, foreach_cb *proc, void *rock);

/* Find subscribed mailboxes that match 'pattern'. */
int mboxlist_findsub(struct namespace *namespace,
		     const char *pattern, int isadmin, const char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock,
		     int force);
int mboxlist_findsub_alt(struct namespace *namespace,
			 const char *pattern, int isadmin, char const *userid, 
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock, int force);

/* given a mailbox 'name', where should we stage messages for it? 
   'stagedir' should be MAX_MAILBOX_PATH. */
int mboxlist_findstage(const char *name, char *stagedir, size_t sd_len);

/* Check 'user's subscription status for mailbox 'name' */
int mboxlist_checksub(const char *name, const char *userid);

/* Change 'user's subscription status for mailbox 'name'. */
int mboxlist_changesub(const char *name, const char *userid, 
		       struct auth_state *auth_state,
		       int add, int force, int notify);

/* set or create quota root */
int mboxlist_setquotas(const char *root,
		       int newquotas[QUOTA_NUMRESOURCES], int force);
int mboxlist_unsetquota(const char *root);

/* open the mailboxes db */
void mboxlist_open(const char *name);

/* close the database */
void mboxlist_close(void);

/* initialize database structures */
#define MBOXLIST_SYNC 0x02
void mboxlist_init(int flags);

/* done with database stuff */
void mboxlist_done(void);

/* for transactions */
int mboxlist_commit(struct txn *tid);
int mboxlist_abort(struct txn *tid);

int mboxlist_delayed_delete_isenabled(void);

#endif
