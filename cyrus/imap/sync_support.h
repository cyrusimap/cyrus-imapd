/* sync_support.h -- Cyrus synchonization support functions
 *
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 * $Id: sync_support.h,v 1.1.2.5 2005/03/15 18:24:24 ken3 Exp $
 */

#ifndef INCLUDED_SYNC_SUPPORT_H
#define INCLUDED_SYNC_SUPPORT_H

#include "prot.h"

#define SYNC_MSGID_LIST_HASH_SIZE        (65536)
#define SYNC_MESSAGE_LIST_HASH_SIZE      (65536)
#define SYNC_MESSAGE_LIST_MAX_OPEN_FILES (64)

#define sync_atoul(s) strtoul(s, NULL, 10)

int sync_eatlines_unsolicited(struct protstream *pin, int c);

void sync_printstring(struct protstream *out, const char *s);

void sync_printastring(struct protstream *out, const char *s);

void sync_flag_print(struct protstream *output, int *have_onep, char *value);

/* ====================================================================== */

int sync_parse_code(char *cmd, struct protstream *in, int eat,
		    int *unsolicitedp);

#define SYNC_PARSE_EAT_OKLINE   (1)
#define SYNC_PARSE_NOEAT_OKLINE (0)

/* ====================================================================== */

struct sync_flags {
    bit32  system_flags;
    bit32  user_flags[MAX_USER_FLAGS/32];
};

struct sync_flags_meta {
    char  *flagname[MAX_USER_FLAGS];
    int    newflags;
};

void sync_flags_clear(struct sync_flags *flags);

void sync_flags_meta_clear(struct sync_flags_meta *meta);

void sync_flags_meta_free(struct sync_flags_meta *meta);

int sync_getflags(struct protstream *input,
		  struct sync_flags *flags, struct sync_flags_meta *meta);

void sync_flags_meta_to_list(struct sync_flags_meta *meta, char **flagname);

/* ====================================================================== */

/* sync_msg_list records message lists in client */

struct sync_msg {
    struct sync_msg *next;
    struct message_uuid uuid;
    unsigned long uid;
    struct sync_flags flags;
};

struct sync_msg_list {
    struct sync_msg *head, *tail;
    unsigned long count;
    unsigned long last_uid;
    struct sync_flags_meta meta;
};

struct sync_msg_list *sync_msg_list_create(char **flagname,
					   unsigned long last_uid);

struct sync_msg *sync_msg_list_add(struct sync_msg_list *l);

void sync_msg_list_free(struct sync_msg_list **lp);

/* ====================================================================== */

struct sync_msgid {
    struct sync_msgid *next;
    struct sync_msgid *hash_next;
    struct message_uuid uuid;
    int count;
    int reserved;
};

struct sync_msgid_list {
    struct sync_msgid *head;
    struct sync_msgid *tail;
    struct sync_msgid **hash;
    int hash_size;
    int count;      /* Total number of messages in list    */
    int reserved;   /* Number of reserved messages in list */
};

struct sync_msgid_list *sync_msgid_list_create(int hash_size);

struct sync_msgid *sync_msgid_add(struct sync_msgid_list *list,
				  struct message_uuid *uuid);

struct sync_msgid *sync_msgid_lookup(struct sync_msgid_list *list,
				     struct message_uuid *uuid);

void sync_msgid_list_free(struct sync_msgid_list **list);

/* ====================================================================== */

struct sync_folder {
    struct sync_folder *next;
    struct sync_msg_list *msglist;
    char *id;
    char *name;
    char *acl;
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
					 char *id, char *name, char *acl,
					 struct quota *quota);

struct sync_folder *sync_folder_lookup(struct sync_folder_list *l, char *id);

struct sync_folder *sync_folder_lookup_byname(struct sync_folder_list *l,
					      char *name);

int sync_folder_mark(struct sync_folder_list *l, char *id);

void sync_folder_list_free(struct sync_folder_list **lp);

/* ====================================================================== */

struct sync_rename_item {
    struct sync_rename_item *next;
    char *id;
    char *oldname;
    char *newname;
    int   done;
};

struct sync_rename_list {
    struct sync_rename_item *head, *tail;
    unsigned long count;
    unsigned long done;
};

struct sync_rename_list *sync_rename_list_create(void);


struct sync_rename_item *sync_rename_list_add(struct sync_rename_list *l,
					      char *id, char *name, char *acl);

struct sync_rename_item *sync_rename_lookup(struct sync_rename_list *l,
					    char *oldname);

void sync_rename_list_free(struct sync_rename_list **lp);

/* ====================================================================== */

struct sync_user {
    struct sync_user *next;
    struct sync_folder_list *folder_list;
    char *userid;
};

struct sync_user_list {
    struct sync_user *head, *tail;
    unsigned long count;
};

struct sync_user_list *sync_user_list_create(void);

struct sync_user *sync_user_list_add(struct sync_user_list *l, char *userid);

struct sync_user *sync_user_list_lookup(struct sync_user_list *l, char *userid);

void sync_user_list_free(struct sync_user_list **lp);

/* ====================================================================== */

#define SYNC_MESSAGE_INIT_CACHE (16384)

/* Reset sync_message_list after 512 MBytes to avoid problems with large
 * mmaped files on 32 bit platform */
#define SYNC_MESSAGE_LIST_MAX_CACHE (512*1024*1024)

struct sync_message {
    struct sync_message *next;
    struct sync_message *hash_next;
    unsigned  long  hdr_size;
    unsigned  long  cache_offset;
    unsigned  long  cache_size;
    unsigned  long  content_lines;
    unsigned  long  cache_version;
    struct message_uuid uuid;
    char           *msg_path;
    unsigned long   msg_size;
};

struct sync_message_list {
    struct sync_message *head, *tail;
    struct sync_message **hash;
    int hash_size;
    unsigned long  count;
    char *stage_dir;
    int   stage_dir_len;
    FILE **file;
    int file_count;
    int file_max;

    /* Cache structure associated with messages */
    char *cache_name;
    int   cache_fd;
    const char *cache_base;
    unsigned long cache_len;
    void *cache_buffer;
    unsigned long cache_buffer_alloc;
    unsigned long cache_buffer_size;
};

struct sync_message_list *sync_message_list_create(int hash_size, int file_max);

void sync_message_list_cache(struct sync_message_list *l,
			     char *entry, int size);

int sync_message_list_cache_flush(struct sync_message_list *l);

unsigned long sync_message_list_cache_offset(struct sync_message_list *l);


struct sync_message *sync_message_add(struct sync_message_list *l,
				      struct message_uuid *uuid);

char *sync_message_next_path(struct sync_message_list *l);

void sync_message_list_free(struct sync_message_list **lp);

int sync_message_list_need_restart(struct sync_message_list *l);

struct sync_message *sync_message_find(struct sync_message_list *l,
				       struct message_uuid *uuid);

void sync_message_fsync(struct sync_message_list *l);

FILE *sync_message_open(struct sync_message_list *l,
			struct sync_message *message);

/* ====================================================================== */

struct sync_upload_item {
    struct sync_upload_item *next;   /* Simple linked list should suffice */
    bit32  uid;         
    time_t internaldate;
    time_t sentdate;    
    time_t last_updated;
    struct sync_flags    flags;
    struct message_uuid  uuid;
    struct sync_message *message;
};

struct sync_upload_list {
    struct sync_upload_item *head;
    struct sync_upload_item *tail;
    unsigned long count;
    struct sync_flags_meta meta;
    unsigned long new_last_uid;
};

struct sync_upload_list *sync_upload_list_create(unsigned long new_last_uid,
						 char **flagname);

struct sync_upload_item *sync_upload_list_add(struct sync_upload_list *l);

void sync_upload_list_free(struct sync_upload_list **lp);

/* ====================================================================== */

int sync_getcache(struct protstream *input, struct protstream *output,
		  struct sync_message_list *list,
		  struct sync_message *message);


int sync_getmessage(struct protstream *input, struct protstream *output,
		    struct sync_message_list *list,
		    struct sync_message *message);

int sync_getsimple(struct protstream *input, struct protstream *output,
		   struct sync_message_list *list,
		   struct sync_message *message);

/* ====================================================================== */

struct sync_flag_item {
    struct sync_flag_item *next;
    unsigned long          uid;
    struct sync_flags      flags;
};

struct sync_flag_list {
    struct sync_flag_item *head;
    struct sync_flag_item *tail;
    struct sync_flags_meta meta;
    unsigned long count;
};

struct sync_flag_list *sync_flag_list_create(char **flagname);

struct sync_flag_item *sync_flag_list_add(struct sync_flag_list *l);

void sync_flag_list_free(struct sync_flag_list **lp);

/* ====================================================================== */

struct sync_sieve_item {
    struct sync_sieve_item *next;
    char *name;
    time_t last_update;
    int active;
    int mark;
};

struct sync_sieve_list {
    struct sync_sieve_item *head;
    struct sync_sieve_item *tail;
    unsigned long count;
};

struct sync_sieve_list *sync_sieve_list_create(void);

void sync_sieve_list_add(struct sync_sieve_list *l,
			 char *name, time_t last_update, int active);

struct sync_sieve_item *sync_sieve_lookup(struct sync_sieve_list *l,
					  char *name);

void sync_sieve_list_set_active(struct sync_sieve_list *l, char *name);

void sync_sieve_list_free(struct sync_sieve_list **lp);

struct sync_sieve_list *sync_sieve_list_generate(char *userid);

char *sync_sieve_read(char *userid, char *name, unsigned long *sizep);

int sync_sieve_upload(struct protstream *input, struct protstream *output,
		      char *userid, char *name, unsigned long last_update);

int sync_sieve_activate(char *userid, char *name);

int sync_sieve_deactivate(char *userid);

int sync_sieve_delete(char *userid, char *name);

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

void sync_action_list_add(struct sync_action_list *l, char *name,
			  char *user);

void sync_action_list_free(struct sync_action_list **lp);

/* ====================================================================== */

struct sync_lock {
    int fd;
    int count;
};

void sync_lock_reset(struct sync_lock *sync_lock);

int sync_lock(struct sync_lock *lock);

int sync_user_unlock(struct sync_lock *lock);

#endif /* INCLUDED_SYNC_SUPPORT_H */
