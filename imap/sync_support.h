/* sync_support.h -- Cyrus synchronization support functions
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
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#ifndef INCLUDED_SYNC_SUPPORT_H
#define INCLUDED_SYNC_SUPPORT_H

#include "backend.h"
#include "dlist.h"
#include "prot.h"
#include "seen.h"
#include "mailbox.h"
#include "sync_log.h"

extern struct protocol_t imap_csync_protocol;
extern struct protocol_t csync_protocol;

#define SYNC_MSGID_LIST_HASH_SIZE        (65536)
#define SYNC_MESSAGE_LIST_HASH_SIZE      (65536)
#define SYNC_MESSAGE_LIST_MAX_OPEN_FILES (64)

const char *sync_get_config(const char *channel, const char *val);
int sync_get_durationconfig(const char *channel, const char *val, int defunit);
int sync_get_switchconfig(const char *channel, const char *val);

/* ====================================================================== */

int sync_parse_response(const char *name, struct protstream *in,
                        struct dlist **klp);

#define SYNC_PARSE_EAT_OKLINE   (1)
#define SYNC_PARSE_NOEAT_OKLINE (0)

/* ====================================================================== */

struct sync_msgid {
    struct sync_msgid *next;
    struct sync_msgid *hash_next;
    struct message_guid guid;
    struct body *body;
    size_t size;
    char *fname;
    unsigned int need_upload:1;
    unsigned int is_archive:1;
};

struct sync_msgid_list {
    struct sync_msgid *head;
    struct sync_msgid *tail;
    struct sync_msgid **hash;
    int hash_size;
    int count;      /* Total number of messages in list    */
    int toupload;   /* Number of messages needing upload in list */
};

struct sync_msgid_list *sync_msgid_list_create(int hash_size);

struct sync_msgid *sync_msgid_insert(struct sync_msgid_list *list,
                                     const struct message_guid *guid);

void sync_msgid_remove(struct sync_msgid_list *l,
                       const struct message_guid *guid);

struct sync_msgid *sync_msgid_lookup(const struct sync_msgid_list *list,
                                     const struct message_guid *guid);

void sync_msgid_list_free(struct sync_msgid_list **list);

struct sync_reserve {
    struct sync_reserve *next;
    char *part;
    struct sync_msgid_list *list;
};

struct sync_reserve_list {
    struct sync_reserve *head;
    struct sync_reserve *tail;
    int hash_size;
};

struct sync_reserve_list *sync_reserve_list_create(int hash_size);

struct sync_msgid_list *sync_reserve_partlist(struct sync_reserve_list *list,
                                              const char *part);

void sync_reserve_list_free(struct sync_reserve_list **list);

/* ====================================================================== */

struct sync_folder {
    struct sync_folder *next;
    struct mailbox *mailbox;
    char *uniqueid;
    char *name;
    uint32_t mbtype;
    char *part;
    char *acl;
    uint32_t last_uid;
    modseq_t highestmodseq;
    uint32_t options;
    uint32_t uidvalidity;
    struct synccrcs synccrcs;
    uint32_t recentuid;
    time_t recenttime;
    time_t pop3_last_login;
    time_t pop3_show_after;
    struct sync_annot_list *annots;
    modseq_t xconvmodseq;
    modseq_t raclmodseq;
    modseq_t foldermodseq;
    int ispartial;
    struct quota quota;
    int   mark;
    int   reserve;  /* Folder has been processed by reserve operation */
};

struct sync_folder_list {
    struct sync_folder *head, *tail;
    unsigned long count;
};

struct sync_folder_list *sync_folder_list_create(void);

struct sync_folder *sync_folder_list_add(struct sync_folder_list *l,
                                         const char *uniqueid, const char *name,
                                         uint32_t mbtype,
                                         const char *part, const char *acl,
                                         uint32_t options,
                                         uint32_t uidvalidity,
                                         uint32_t last_uid,
                                         modseq_t highestmodseq,
                                         struct synccrcs synccrcs,
                                         uint32_t recentuid,
                                         time_t recenttime,
                                         time_t pop3_last_login,
                                         time_t pop3_show_after,
                                         struct sync_annot_list *annot,
                                         modseq_t xconvmodseq,
                                         modseq_t raclmodseq,
                                         modseq_t foldermodseq,
                                         int ispartial);

struct sync_folder *sync_folder_lookup(struct sync_folder_list *l,
                                       const char *uniqueid);

void sync_folder_list_free(struct sync_folder_list **lp);

/* ====================================================================== */

struct sync_rename {
    struct sync_rename *next;
    char *uniqueid;
    char *oldname;
    char *newname;
    char *part;
    unsigned uidvalidity;
    int   done;
};

struct sync_rename_list {
    struct sync_rename *head, *tail;
    unsigned long count;
    unsigned long done;
};

struct sync_rename_list *sync_rename_list_create(void);


struct sync_rename *sync_rename_list_add(struct sync_rename_list *l,
                                         const char *id, const char *oldname,
                                         const char *newname, const char *partition,
                                         unsigned uidvalidity);

struct sync_rename *sync_rename_lookup(struct sync_rename_list *l,
                                            const char *oldname);

void sync_rename_list_free(struct sync_rename_list **lp);

/* ====================================================================== */

struct sync_quota {
    struct sync_quota *next;
    char *root;
    quota_t limits[QUOTA_NUMRESOURCES];
    int done;
};

struct sync_quota_list {
    struct sync_quota *head, *tail;
    unsigned long count;
    unsigned long done;
};

struct sync_quota_list *sync_quota_list_create(void);

struct sync_quota *sync_quota_list_add(struct sync_quota_list *l,
                                       const char *root);

struct sync_quota *sync_quota_lookup(struct sync_quota_list *l,
                                          const char *name);

void sync_quota_list_free(struct sync_quota_list **lp);

void sync_encode_quota_limits(struct dlist *kl, const quota_t limits[QUOTA_NUMRESOURCES]);
void sync_decode_quota_limits(/*const*/ struct dlist *kl, quota_t limits[QUOTA_NUMRESOURCES]);

/* ====================================================================== */

struct sync_name {
    struct sync_name *next;
    char *name;
    int mark;
};

struct sync_name_list {
    struct sync_name *head, *tail;
    unsigned long count;
    unsigned long marked;
};

struct sync_name_list *sync_name_list_create(void);

struct sync_name *sync_name_list_add(struct sync_name_list *l,
                                     const char *name);

struct sync_name *sync_name_lookup(struct sync_name_list *l,
                                        const char *name);

void sync_name_list_free(struct sync_name_list **lp);

/* ====================================================================== */

struct sync_seen {
    struct sync_seen *next;
    char *userid;
    char *uniqueid;
    struct seendata sd;
    int mark;
};

struct sync_seen_list {
    struct sync_seen *head, *tail;
    unsigned long count;
};

struct sync_seen_list *sync_seen_list_create(void);

struct sync_seen *sync_seen_list_add(struct sync_seen_list *l,
                                     const char *uniqueid,
                                     time_t lastread, unsigned lastuid,
                                     time_t lastchange, const char *seenuids);

struct sync_seen *sync_seen_list_lookup(struct sync_seen_list *l,
                                        const char *uniqueid);

void sync_seen_list_free(struct sync_seen_list **lp);

/* ====================================================================== */

struct sync_sieve {
    struct sync_sieve *next;
    char *user;
    char *name;
    time_t last_update;
    struct message_guid guid;
    int active;
    int mark;
};

struct sync_sieve_list {
    struct sync_sieve *head;
    struct sync_sieve *tail;
    unsigned long count;
};

struct sync_sieve_list *sync_sieve_list_create(void);

struct sync_sieve *sync_sieve_lookup(struct sync_sieve_list *l,
                                     const char *name);

void sync_sieve_list_free(struct sync_sieve_list **lp);

struct sync_sieve_list *sync_sieve_list_generate(const char *userid);

char *sync_sieve_read(const char *userid, const char *name, uint32_t *sizep);

int sync_sieve_upload(const char *userid, const char *name,
                      time_t last_update, const char *content, size_t len);

int sync_sieve_activate(const char *userid, const char *bcname);

int sync_sieve_deactivate(const char *userid);

int sync_sieve_delete(const char *userid, const char *script);

/* ====================================================================== */

struct sync_annot {
    struct sync_annot *next;
    char *entry;
    char *userid;
    struct buf value;
    int mark;
    modseq_t modseq;
};

struct sync_annot_list {
    struct sync_annot *head;
    struct sync_annot *tail;
    unsigned long count;
};

struct sync_annot_list *sync_annot_list_create(void);

void sync_annot_list_add(struct sync_annot_list *l,
                         const char *entry, const char *userid,
                         const struct buf *value,
                         modseq_t modseq);

void sync_annot_list_free(struct sync_annot_list **lp);

/* ====================================================================== */

struct sync_action {
    struct sync_action *next;
    int active;
    char *name;
    char *user;
};

struct sync_action_list {
    struct sync_action *head, *tail;
    unsigned long count;
};

struct sync_action_list *sync_action_list_create(void);

void sync_action_list_add(struct sync_action_list *l,
                          const char *name, const char *user);

void sync_action_list_free(struct sync_action_list **lp);

/* ====================================================================== */

void sync_send_response(struct dlist *kl, struct protstream *out);
void sync_send_apply(struct dlist *kl, struct protstream *out);
void sync_send_lookup(struct dlist *kl, struct protstream *out);
void sync_send_restart(struct protstream *out);
void sync_send_restore(struct dlist *kl, struct protstream *out);

struct dlist *sync_parseline(struct protstream *in);

/* ====================================================================== */

int addmbox_cb(const mbentry_t *mbentry, void *rock);

int parse_upload(struct dlist *kr, struct mailbox *mailbox,
                 struct index_record *record,
                 struct sync_annot_list **annotsp);
int sync_append_copyfile(struct mailbox *mailbox,
                         struct index_record *record,
                         const struct sync_annot_list *sal,
                         const struct sync_msgid_list *part_list);

/* ====================================================================== */

int read_annotations(const struct mailbox *,
                     const struct index_record *,
                     struct sync_annot_list **,
                     modseq_t since_modseq,
                     int flags);

/* ====================================================================== */

int sync_mailbox_version_check(struct mailbox **mailboxp);

/* =====================  client-side sync  ============================= */

struct sync_client_state {
    struct backend *backend;
    struct protstream *clientin;
    const char *servername;
    const char *channel;
    struct db *cachedb;
    struct buf tagbuf;
    int flags;
};
#define SYNC_CLIENT_STATE_INITIALIZER { NULL, NULL, NULL, NULL, NULL, BUF_INITIALIZER, 0 }

/* =====================  server-side sync  ============================= */

struct sync_state {
    char *userid;
    int userisadmin;
    struct auth_state *authstate;
    struct namespace *namespace;
    struct protstream *pout;
    int local_only;
};

int sync_get_message(struct dlist *kin, struct sync_state *sstate);
int sync_get_sieve(struct dlist *kin, struct sync_state *sstate);
int sync_get_annotation(struct dlist *kin, struct sync_state *sstate);
int sync_get_quota(struct dlist *kin, struct sync_state *sstate);
int sync_get_fullmailbox(struct dlist *kin, struct sync_state *sstate);
int sync_get_mailboxes(struct dlist *kin, struct sync_state *sstate);
int sync_get_meta(struct dlist *kin, struct sync_state *sstate);
int sync_get_user(struct dlist *kin, struct sync_state *sstate);

int sync_apply_reserve(struct dlist *kl,
                       struct sync_reserve_list *reserve_list,
                       struct sync_state *sstate);
int sync_apply_unquota(struct dlist *kin, struct sync_state *sstate);
int sync_apply_quota(struct dlist *kin, struct sync_state *sstate);
int sync_apply_mailbox(struct dlist *kin,
                       struct sync_reserve_list *reserve_list,
                       struct sync_state *sstate);
int sync_apply_unmailbox(struct dlist *kin, struct sync_state *sstate);
int sync_apply_rename(struct dlist *kin, struct sync_state *sstate);
int sync_apply_changesub(struct dlist *kin, struct sync_state *sstate);
int sync_apply_annotation(struct dlist *kin, struct sync_state *sstate);
int sync_apply_unannotation(struct dlist *kin, struct sync_state *sstate);
int sync_apply_sieve(struct dlist *kin, struct sync_state *sstate);
int sync_apply_unsieve(struct dlist *kin, struct sync_state *sstate);
int sync_apply_activate_sieve(struct dlist *kin, struct sync_state *sstate);
int sync_apply_unactivate_sieve(struct dlist *kin, struct sync_state *sstate);
int sync_apply_seen(struct dlist *kin, struct sync_state *sstate);
int sync_apply_unuser(struct dlist *kin, struct sync_state *sstate);
int sync_apply_expunge(struct dlist *kin, struct sync_state *sstate);
int sync_apply_message(struct dlist *kin,
                       struct sync_reserve_list *reserve_list,
                       struct sync_state *sstate);

const char *sync_apply(struct dlist *kin, struct sync_reserve_list *reserve_list, struct sync_state *state);
const char *sync_get(struct dlist *kin, struct sync_state *state);
const char *sync_restore(struct dlist *kin,
                         struct sync_reserve_list *reserve_list,
                         struct sync_state *state);

/* =====================  client-side sync  ============================= */

#define SYNC_FLAG_VERBOSE   (1<<0)
#define SYNC_FLAG_LOGGING   (1<<1)
#define SYNC_FLAG_LOCALONLY (1<<2)
#define SYNC_FLAG_DELETE_REMOTE (1<<3)
#define SYNC_FLAG_NO_COPYBACK (1<<4)
#define SYNC_FLAG_BATCH (1<<5)

int sync_do_seen(struct sync_client_state *sync_cs, const char *userid, char *uniqueid);
int sync_do_quota(struct sync_client_state *sync_cs, const char *root);
int sync_do_annotation(struct sync_client_state *sync_cs, const char *mboxname);
int sync_do_mailboxes(struct sync_client_state *sync_cs,
                      struct sync_name_list *mboxname_list,
                      const char *topart, int flags);
int sync_do_user(struct sync_client_state *sync_cs,
                 const char *userid, const char *topart);
int sync_do_meta(struct sync_client_state *sync_cs, const char *userid);
int sync_do_sub(struct sync_client_state *sync_cs,
                const char *userid, const char *mboxname, int add);

int sync_response_parse(struct sync_client_state *sync_cs, const char *cmd,
                        struct sync_folder_list *folder_list,
                        struct sync_name_list *sub_list,
                        struct sync_sieve_list *sieve_list,
                        struct sync_seen_list *seen_list,
                        struct sync_quota_list *quota_list);
int sync_find_reserve_messages(struct mailbox *mailbox,
                               uint32_t fromuid, uint32_t touid,
                               struct sync_msgid_list *part_list);
int sync_reserve_partition(struct sync_client_state *sync_cs, char *partition,
                           struct sync_folder_list *replica_folders,
                           struct sync_msgid_list *part_list);

int sync_do_update_mailbox(struct sync_client_state *sync_cs,
                           struct sync_folder *local,
                           struct sync_folder *remote,
                           const char *topart,
                           struct sync_reserve_list *reserve_guids);

int sync_do_folder_delete(struct sync_client_state *sync_cs,
                          const char *mboxname);
int sync_do_user_quota(struct sync_client_state *sync_cs,
                       struct sync_name_list *master_quotaroots,
                       struct sync_quota_list *replica_quota);
int sync_do_user_sub(struct sync_client_state *sync_cs, const char *userid,
                     struct sync_name_list *replica_subs);
int sync_do_user_seen(struct sync_client_state *sync_cs, const char *userid,
                      struct sync_seen_list *replica_seen);
int sync_do_user_sieve(struct sync_client_state *sync_cs, const char *userid,
                       struct sync_sieve_list *replica_sieve);

int sync_do_restart(struct sync_client_state *sync_cs);

int sync_do_reader(struct sync_client_state *sync_cs, sync_log_reader_t *slr);

int sync_connect(struct sync_client_state *sync_cs);
void sync_disconnect(struct sync_client_state *sync_cs);

int sync_checkpoint(struct protstream *clientin);


/* ====================================================================== */

#endif /* INCLUDED_SYNC_SUPPORT_H */
