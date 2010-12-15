/* sync_support.h -- Cyrus synchonization support functions
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
 * $Id: sync_support.h,v 1.12 2010/01/06 17:01:42 murch Exp $
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#ifndef INCLUDED_SYNC_SUPPORT_H
#define INCLUDED_SYNC_SUPPORT_H

#include "dlist.h"
#include "prot.h"
#include "mailbox.h"

#define SYNC_MSGID_LIST_HASH_SIZE        (65536)
#define SYNC_MESSAGE_LIST_HASH_SIZE      (65536)
#define SYNC_MESSAGE_LIST_MAX_OPEN_FILES (64)

int sync_eatlines_unsolicited(struct protstream *pin, int c);

void sync_printdate(struct protstream *out, time_t time);
time_t sync_parsedate(const char *s);
int sync_getflags(struct dlist *kl,
		  struct mailbox *mailbox,
		  struct index_record *record);
unsigned sync_mailbox_finduid(struct mailbox *mailbox, unsigned uid);

void sync_print_flags(struct dlist *kl,
		      struct mailbox *mailbox,
		      struct index_record *record);

char *sync_encode_options(int options);
int sync_parse_options(const char *source);

char *sync_encode_type(int type);
int sync_parse_type(const char *source);

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
    int mark;
};

struct sync_msgid_list {
    struct sync_msgid *head;
    struct sync_msgid *tail;
    struct sync_msgid **hash;
    int hash_size;
    int count;      /* Total number of messages in list    */
    int marked;     /* Number of reserved messages in list */
};

struct sync_msgid_list *sync_msgid_list_create(int hash_size);

struct sync_msgid *sync_msgid_add(struct sync_msgid_list *list,
				  struct message_guid *guid);

void sync_msgid_remove(struct sync_msgid_list *l,
		       struct message_guid *guid);

struct sync_msgid *sync_msgid_lookup(struct sync_msgid_list *list,
				     struct message_guid *guid);

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
    char *uniqueid;
    char *name;
    char *part;
    char *acl;
    char *specialuse;
    unsigned last_uid;
    modseq_t highestmodseq;
    unsigned options;
    unsigned long uidvalidity;
    char *sync_crc;
    unsigned long recentuid;
    time_t recenttime;
    time_t pop3_last_login;
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
					 const char *part, const char *acl, 
					 uint32_t options,
					 uint32_t uidvalidity, 
					 uint32_t last_uid,
					 modseq_t highestmodseq,
					 const char *crc,
					 uint32_t recentuid,
					 time_t recenttime,
					 time_t pop3_last_login,
					 const char *specialuse);

struct sync_folder *sync_folder_lookup(struct sync_folder_list *l,
				       const char *uniqueid);

struct sync_folder *sync_folder_lookup_byname(struct sync_folder_list *l,
					      const char *name);

int sync_folder_mark(struct sync_folder_list *l, const char *uniqueid);

void sync_folder_list_free(struct sync_folder_list **lp);

/* ====================================================================== */

struct sync_rename {
    struct sync_rename *next;
    char *uniqueid;
    char *oldname;
    char *newname;
    char *part;
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
					      const char *newname, const char *partition);

struct sync_rename *sync_rename_lookup(struct sync_rename_list *l,
					    const char *oldname);

void sync_rename_list_free(struct sync_rename_list **lp);

/* ====================================================================== */

struct sync_quota {
    struct sync_quota *next;
    char *root;
    int limit;
    int done;
};

struct sync_quota_list {
    struct sync_quota *head, *tail;
    unsigned long count;
    unsigned long done;
};

struct sync_quota_list *sync_quota_list_create(void);

struct sync_quota *sync_quota_list_add(struct sync_quota_list *l,
					    const char *root, int limit);

struct sync_quota *sync_quota_lookup(struct sync_quota_list *l,
					  const char *name);

void sync_quota_list_free(struct sync_quota_list **lp);

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

void sync_sieve_list_add(struct sync_sieve_list *l,
			 const char *name, time_t last_update, 
			 struct message_guid *guidp, int active);

struct sync_sieve *sync_sieve_lookup(struct sync_sieve_list *l,
				     const char *name);

void sync_sieve_list_set_active(struct sync_sieve_list *l, const char *name);

void sync_sieve_list_free(struct sync_sieve_list **lp);

struct sync_sieve_list *sync_sieve_list_generate(const char *userid);

char *sync_sieve_read(const char *userid, const char *name, uint32_t *sizep);

int sync_sieve_upload(const char *userid, const char *name,
		      time_t last_update, const char *content, size_t len);

int sync_sieve_activate(const char *userid, const char *name);

int sync_sieve_deactivate(const char *userid);

int sync_sieve_delete(const char *userid, const char *name);

/* ====================================================================== */

struct sync_annot {
    struct sync_annot *next;
    char *entry;
    char *userid;
    char *value;
    int mark;
};

struct sync_annot_list {
    struct sync_annot *head;
    struct sync_annot *tail;
    unsigned long count;
};

struct sync_annot_list *sync_annot_list_create(void);

void sync_annot_list_add(struct sync_annot_list *l,
			 const char *entry, const char *userid,
			 const char *value);

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

struct dlist *sync_parseline(struct protstream *in);

/* ====================================================================== */

int addmbox(char *name, int matchlen, int maycreate, void *rock);
int addmbox_sub(void *rockp, const char *key, int keylen,
		const char *data __attribute__((unused)),
		int datalen __attribute__((unused)));

int sync_mailbox(struct mailbox *mailbox,
		 struct sync_folder *remote,
		 struct sync_msgid_list *part_list,
		 struct dlist *kl, struct dlist *kupload,
		 int printrecords);

int parse_upload(struct dlist *kr, struct mailbox *mailbox,
		 struct index_record *record);
int sync_append_copyfile(struct mailbox *mailbox,
			 struct index_record *record);

/* ====================================================================== */

const char *sync_crc_get_algorithm(void);
const char *sync_crc_list_algorithms(void);
const char *sync_crc_get_covers(void);
const char *sync_crc_list_covers(void);
int sync_crc_setup(const char *, const char *, int);
int sync_crc_calc(struct mailbox *, char *, int);

/* ====================================================================== */

#endif /* INCLUDED_SYNC_SUPPORT_H */
