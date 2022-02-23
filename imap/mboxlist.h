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

/*
 * Maximum length of partition name. [config.c has a limit of 70]
 */
#define MAX_PARTITION_LEN 64

/* mailbox types and flags:
 *
 * the 4 lowest order bits are used for the mailbox type itself
 * higher order bits are used for flags on the mailbox
 */
#define MBTYPE_EMAIL        0x0    /* Default mbtype is zero */
#define MBTYPE_NETNEWS      0x1    /* Netnews Mailbox - NO LONGER USED */
#define MBTYPE_JMAPSUBMIT   0x2    /* JMAP Mail Submission Mailbox */
#define MBTYPE_JMAPPUSHSUB  0x3    /* JMAP Push Subscriptions */
#define MBTYPE_JMAPNOTIFY   0x4    /* JMAP Notifications */
#define MBTYPE_SIEVE        0x5    /* Sieve Script Mailbox */

#define MBTYPE_COLLECTION   0x8    /* WebDAV Collection Mailbox */
#define MBTYPE_CALENDAR     0x9    /* CalDAV Calendar Mailbox */
#define MBTYPE_ADDRESSBOOK  0xa    /* CardDAV Addressbook Mailbox */

#define MBTYPE_UNKNOWN      0xf    /* unknown type for error handling */

/* mailbox flags */
#define MBTYPE_REMOTE       (1<<4) /* Not on this server (part is remote host) */
#define MBTYPE_RESERVE      (1<<5) /* Reserved [mupdate/imapd] /
                                      Rename Target [imapd] (part is normal, but
                                      you are not allowed to create this mailbox,
                                      even though it doesn't actually exist */
#define MBTYPE_MOVING       (1<<6) /* Mailbox in mid-transfer
                                      (part is remotehost!localpart) */
#define MBTYPE_DELETED      (1<<7) /* Mailbox has been deleted,
                                      but not yet cleaned up */
#define MBTYPE_INTERMEDIATE (1<<8) /* Place holder
                                      for non-existent ancestor mailboxes */
#define MBTYPE_LEGACY_DIRS  (1<<9) /* Mailbox path uses legacy (by name) dirs */
/* NOTE: don't forget to also update the mappings for these in mboxlist.c:
 * mboxlist_string_to_mbtype()
 * mboxlist_mbtype_to_string()
 */

#define mbtype_isa(mbtype)          ((mbtype) & 0xf)
#define mbtypes_dav(mbtype)         ((mbtype) & 0x8)
#define mbtypes_unavailable(mbtype) \
  ((mbtype) & (MBTYPE_REMOTE | MBTYPE_RESERVE | MBTYPE_MOVING))
#define mbtypes_sync(mbtype)        ((mbtype) & ~MBTYPE_LEGACY_DIRS)

/* master name of the mailboxes file */
#define FNAME_MBOXLIST "/mailboxes.db"

#define HOSTNAME_SIZE 512

/* Each mailbox has the following data.
 * If you change or extend this struct, you MUST also update the
 * dump and undump implementations in ctl_mboxlist.c!
 */
struct mboxlist_entry {
    char *name;
    char *ext_name;
    time_t mtime;
    uint32_t uidvalidity;
    modseq_t createdmodseq;
    modseq_t foldermodseq;
    uint32_t mbtype;
    char *partition;
    char *server; /* holds remote machine for REMOTE mailboxes */
    char *acl;
    /* extra fields */
    char *uniqueid;
    /* legacy upgrade support */
    char *legacy_specialuse;
    /* replication support */
    ptrarray_t name_history;
};

#define MBENTRY_INITIALIZER  { NULL, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, \
                               NULL, NULL, PTRARRAY_INITIALIZER }

typedef struct mboxlist_entry mbentry_t;

typedef struct {
    char *name;
    time_t mtime;
    uint32_t uidvalidity;
    modseq_t createdmodseq;
    modseq_t foldermodseq;
    uint32_t mbtype;
    char *partition;
} former_name_t;

mbentry_t *mboxlist_entry_create();

char *mbentry_metapath(const struct mboxlist_entry *mbentry, int metatype, int isnew);
char *mbentry_datapath(const struct mboxlist_entry *mbentry, uint32_t);
char *mbentry_archivepath(const struct mboxlist_entry *mbentry, uint32_t);

mbentry_t *mboxlist_entry_copy(const mbentry_t *src);

void mboxlist_entry_free(mbentry_t **mbentryptr);

const char *mboxlist_mbtype_to_string(uint32_t mbtype);
uint32_t mboxlist_string_to_mbtype(const char *string);

int mboxlist_delete(const mbentry_t *mbentry);
int mboxlist_deletelock(const mbentry_t *mbentry);
/* Lookup 'name' in the mailbox list. */
int mboxlist_lookup(const char *name, mbentry_t **mbentryptr,
                    struct txn **tid);
int mboxlist_lookup_allow_all(const char *name,
                                   mbentry_t **mbentryptr,
                                   struct txn **tid);
int mboxlist_lookup_by_uniqueid(const char *uniqueid,
                                mbentry_t **entryptr, struct txn **tid);

char *mboxlist_find_specialuse(const char *use, const char *userid);
char *mboxlist_find_uniqueid(const char *uniqueid, const char *userid,
                             const struct auth_state *auth_state);


/* insert/delete stub entries */
int mboxlist_insertremote(mbentry_t *mbentry, struct txn **rettid);
int mboxlist_deleteremote(const char *name, struct txn **in_tid);

/* Update a mailbox's entry */
int mboxlist_update(const mbentry_t *mbentry, int localonly);
/* Update but take the usernamespace lock first */
int mboxlist_updatelock(const mbentry_t *mbentry, int localonly);

/* check user's ability to create mailbox */
int mboxlist_createmailboxcheck(const char *name, int mbtype,
                                const char *partition,
                                int isadmin, const char *userid,
                                const struct auth_state *auth_state,
                                char **newacl, char **newpartition,
                                int forceuser);

/* create the local mailbox without touching mupdate */
#define MBOXLIST_CREATE_LOCALONLY           (1<<0)
/* allow the creation of user.x.<name> without a user.x */
#define MBOXLIST_CREATE_FORCEUSER           (1<<1)
/* skip filesystem operations (e.g. reconstruct) */
#define MBOXLIST_CREATE_DBONLY              (1<<2)
/* send a MailboxCreate event notification */
#define MBOXLIST_CREATE_NOTIFY              (1<<3)
/* create mailbox from sync */
#define MBOXLIST_CREATE_SYNC                (1<<4)
/* don't promote intermediary into a real mailbox */
#define MBOXLIST_CREATE_KEEP_INTERMEDIARIES (1<<5)
/* create mailbox as read only by everyone */
#define MBOXLIST_CREATE_SETFLAGS_ONLY       (1<<6)

/* create mailbox */
/* if given a mailbox pointer, return the still-locked mailbox
 * for further manipulation */
int mboxlist_createmailbox(const mbentry_t *mbentry,
                           unsigned mboxopts, modseq_t highestmodseq,
                           unsigned isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           unsigned flags, struct mailbox **mboxptr);

/* create mailbox with wrapping namespacelock */
int mboxlist_createmailboxlock(const mbentry_t *mbentry,
                               unsigned mboxopts, modseq_t highestmodseq,
                               unsigned isadmin, const char *userid,
                               const struct auth_state *auth_state,
                               unsigned flags, struct mailbox **mboxptr);

#define MBOXLIST_DELETE_CHECKACL            (1<<0)
/* setting local_only disables any communication with the mupdate server
 * and deletes the mailbox from the filesystem regardless of if it is
 * MBTYPE_REMOTE or not */
#define MBOXLIST_DELETE_LOCALONLY           (1<<1)
/* force ignores errors and just tries to wipe the mailbox off the face of
 * the planet */
#define MBOXLIST_DELETE_FORCE               (1<<2)
#define MBOXLIST_DELETE_KEEP_INTERMEDIARIES (1<<3)
/* silently delete, do not bump modseq */
#define MBOXLIST_DELETE_SILENT              (1<<4)
/* unprotect_specialuse ignores the specialuse_protect config */
#define MBOXLIST_DELETE_UNPROTECT_SPECIALUSE (1<<5)
/* delayed delete */
/* Translate delete into rename */
/* prepare MailboxDelete notification if mboxevent is not NULL */
int
mboxlist_delayed_deletemailbox(const char *name, int isadmin, const char *userid,
                               const struct auth_state *auth_state,
                               struct mboxevent *mboxevent, int flags);
/* Delete a mailbox. */
/* prepare MailboxDelete notification if mboxevent is not NULL */
int mboxlist_deletemailbox(const char *name, int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           struct mboxevent *mboxevent, int flags);
/* same but wrap with a namespacelock */
int mboxlist_deletemailboxlock(const char *name, int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           struct mboxevent *mboxevent, int flags);

/* rename a tree of mailboxes - renames mailbox plus any children */
int mboxlist_renametree(const char *oldname, const char *newname,
                        const char *partition, unsigned uidvalidity,
                        int isadmin, const char *userid,
                        const struct auth_state *auth_state,
                        struct mboxevent *mboxevent,
                        int local_only, int forceuser, int ignorequota,
                        int keep_intermediaries, int move_subscription);
/* Rename/move a mailbox (hierarchical) */
/* prepare MailboxRename notification if mboxevent is not NULL */
int mboxlist_renamemailbox(const mbentry_t *mbentry, const char *newname,
                           const char *partition, unsigned uidvalidity,
                           int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           struct mboxevent *mboxevent,
                           int local_only, int forceuser, int ignorequota,
                           int keep_intermediaries, int move_subscription,
                           int silent);

/* change ACL */
int mboxlist_setacl(const struct namespace *namespace, const char *name,
                    const char *identifier, const char *rights, int isadmin,
                    const char *userid, const struct auth_state *auth_state);

/* Change all ACLs on mailbox */
int mboxlist_updateacl_raw(const char *name, const char *acl);
int mboxlist_sync_setacls(const char *name, const char *acl, modseq_t foldermodseq);
int mboxlist_update_foldermodseq(const char *name, modseq_t foldermodseq);

int mboxlist_set_racls(int enabled);

int mboxlist_cleanup_deletedentries(const mbentry_t *mbentry, time_t mark);

struct findall_data {
    const char *extname;
    int mb_category;
    const mbentry_t *mbentry;
    const mbname_t *mbname;
    int is_exactmatch;
};

typedef int findall_p(struct findall_data *data, void *rock);
typedef int findall_cb(struct findall_data *data, void *rock);

/* Find all mailboxes that match 'pattern'. */
int mboxlist_findall(struct namespace *namespace,
                     const char *pattern, int isadmin,
                     const char *userid, const struct auth_state *auth_state,
                     findall_cb *proc, void *rock);
int mboxlist_findallmulti(struct namespace *namespace,
                          const strarray_t *patterns, int isadmin,
                          const char *userid, const struct auth_state *auth_state,
                          findall_cb *proc, void *rock);
int mboxlist_findone(struct namespace *namespace,
                     const char *intname, int isadmin,
                     const char *userid, const struct auth_state *auth_state,
                     findall_cb *proc, void *rock);

int mboxlist_findall_withp(struct namespace *namespace,
                     const char *pattern, int isadmin,
                     const char *userid, const struct auth_state *auth_state,
                     findall_p *p, findall_cb *cb, void *rock);
int mboxlist_findallmulti_withp(struct namespace *namespace,
                          const strarray_t *patterns, int isadmin,
                          const char *userid, const struct auth_state *auth_state,
                          findall_p *p, findall_cb *cb, void *rock);
int mboxlist_findone_withp(struct namespace *namespace,
                     const char *intname, int isadmin,
                     const char *userid, const struct auth_state *auth_state,
                     findall_p *p, findall_cb *cb, void *rock);

/* Find a mailbox's parent (if any) */
int mboxlist_findparent(const char *mboxname,
                        mbentry_t **mbentryp);

int mboxlist_findparent_allow_all(const char *mboxname,
                                  mbentry_t **mbentryp);

/* direct access to subs DB */
typedef int user_cb(const char *userid, void *rock);
int mboxlist_alluser(user_cb *proc, void *rock);

typedef int mboxlist_cb(const mbentry_t *mbentry, void *rock);

#define MBOXTREE_TOMBSTONES (1<<0)
#define MBOXTREE_DELETED (1<<1)
#define MBOXTREE_SKIP_ROOT (1<<2)
#define MBOXTREE_SKIP_CHILDREN (1<<3)
#define MBOXTREE_SKIP_PERSONAL (1<<4)
#define MBOXTREE_PLUS_RACL (1<<5)
#define MBOXTREE_INTERMEDIATES (1<<6)
int mboxlist_allmbox(const char *prefix, mboxlist_cb *proc, void *rock, int flags);
int mboxlist_mboxtree(const char *mboxname, mboxlist_cb *proc, void *rock, int flags);
int mboxlist_usermboxtree(const char *userid, const struct auth_state *auth_state,
                          mboxlist_cb *proc, void *rock, int flags);
int mboxlist_usersubs(const char *userid, mboxlist_cb *proc, void *rock, int flags);

strarray_t *mboxlist_sublist(const char *userid);

/* Find subscribed mailboxes that match 'pattern'. */
int mboxlist_findsub(struct namespace *namespace,
                     const char *pattern, int isadmin,
                     const char *userid, const struct auth_state *auth_state,
                     findall_cb *proc, void *rock,
                     int force);
int mboxlist_findsubmulti(struct namespace *namespace,
                          const strarray_t *patterns, int isadmin,
                          const char *userid, const struct auth_state *auth_state,
                          findall_cb *proc, void *rock,
                          int force);

int mboxlist_findsub_withp(struct namespace *namespace,
                     const char *pattern, int isadmin,
                     const char *userid, const struct auth_state *auth_state,
                     findall_p *p, findall_cb *cb, void *rock,
                     int force);
int mboxlist_findsubmulti_withp(struct namespace *namespace,
                          const strarray_t *patterns, int isadmin,
                          const char *userid, const struct auth_state *auth_state,
                          findall_p *p, findall_cb *cb, void *rock,
                          int force);

/* given a mailbox 'name', where should we stage messages for it?
   'stagedir' should be MAX_MAILBOX_PATH. */
int mboxlist_findstage(const char *name, char *stagedir, size_t sd_len);

/* Check 'user's subscription status for mailbox 'name' */
int mboxlist_checksub(const char *name, const char *userid);

/* Change 'user's subscription status for mailbox 'name'. */
int mboxlist_changesub(const char *name, const char *userid,
                       const struct auth_state *auth_state,
                       int add, int force, int notify);

/* set or create quota root */
int mboxlist_setquotas(const char *root,
                       quota_t newquotas[QUOTA_NUMRESOURCES],
                       modseq_t modseq, int force);
int mboxlist_unsetquota(const char *root);

/* handle interemediates */
int mboxlist_update_intermediaries(const char *mboxname, int mbtype, modseq_t modseq);
int mboxlist_haschildren(const char *mboxname);

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

/* Promote an intermediary mailbox to a real mailbox. */
int mboxlist_promote_intermediary(const char *mboxname);

int mboxlist_upgrade(int *upgraded);

#endif
