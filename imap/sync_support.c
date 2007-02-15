/* sync_support.c -- Cyrus synchonization support functions
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
 * $Id: sync_support.c,v 1.3 2007/02/15 14:57:01 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <utime.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "message.h"
#include "util.h"
#include "retry.h"
#include "lock.h"
#include "prot.h"
#include "sync_support.h"
#include "sync_commit.h"

/* Parse routines */

enum {
    MAXQUOTED = 8192,
    MAXWORD = 8192,
    MAXLITERAL = INT_MAX / 20
};

/* Get a simple line (typically error text) */
#define BUFGROWSIZE 100
int sync_getline(struct protstream *in, struct buf *buf)
{
    int len = 0;
    int c;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c = prot_getc(in);

	if (c == EOF || (c == '\r') || (c == '\n')) {
            /* Munch optional LF after CR */
            if (c == '\r' && ((c = prot_getc(in)) != EOF && c != '\n')) {
                prot_ungetc(c, in);
                c = '\r';
            }
	    buf->s[len] = '\0';
	    buf->len = len;
	    return c;
	}
	if (len == buf->alloc) {
	    buf->alloc += BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
            if (len > MAXWORD) {
                fatal("word too long", EC_IOERR);
            }
	}
	buf->s[len++] = c;
    }
    return(c);
}

/*
 * Eat lines up to next OK/NO/BAD response line
 *
 */

int sync_eatlines_unsolicited(struct protstream *in, int c)
{
    static struct buf response;   /* BSS */
    static struct buf line;       /* BSS */

    if (c != '\n') {
        sync_getline(in, &line);   /* Partial line */
        syslog(LOG_ERR, "Discarding: %s", line.s);
    }

    do {
        if ((c = getword(in, &response)) == EOF)
            return(IMAP_PROTOCOL_ERROR);

        sync_getline(in, &line);
        syslog(LOG_ERR, "Discarding: %s", line.s);
    } while (response.s[0] == '*');

    if (!strcmp(response.s, "OK") ||
        !strcmp(response.s, "NO") ||
        !strcmp(response.s, "BAD")) {
        syslog(LOG_ERR, "sync_eatlines_unsolicited(): resynchronised okay");
        return(0);
    }

    syslog(LOG_ERR, "sync_eatlines_unsolicited(): failed to resynchronise!");
    return(IMAP_PROTOCOL_ERROR);
}

/* ====================================================================== */

/*
 * Print 's' as a quoted-string or literal (but not an atom)
 */
void sync_printstring(struct protstream *out, const char *s)
{
    const char *p;
    int len = 0;

    /* Look for any non-QCHAR characters */
    for (p = s; *p && len < 1024; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    /* if it's too long, literal it */
    if (*p || len >= 1024) {
	prot_printf(out, "{%lu+}\r\n%s", strlen(s), s);
    } else {
	prot_printf(out, "\"%s\"", s);
    }
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
void sync_printastring(struct protstream *out, const char *s)
{
    const char *p;
    int len = 0;

    if (!s || !*s) {
	prot_printf(out, "\"\"");
	return;
    }

    if (imparse_isatom(s)) {
	prot_printf(out, "%s", s);
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p && len < 1024; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    /* if it's too long, literal it */
    if (*p || len >= 1024) {
	prot_printf(out, "{%lu+}\r\n%s", strlen(s), s);
    } else {
	prot_printf(out, "\"%s\"", s);
    }
}

void sync_flag_print(struct protstream *output, int *have_onep, char *value)
{
    if (*have_onep)
        prot_putc(' ', output);

    prot_printf(output, "%s", value);
    *have_onep = 1;
}

/* ====================================================================== */

int sync_parse_code(char *cmd, struct protstream *in, int eat,
		    int *unsolicitedp)
{
    static struct buf response;   /* BSS */
    static struct buf errmsg;
    int c;
    char *s;

    if (unsolicitedp) *unsolicitedp = 0;

    if ((c = getword(in, &response)) == EOF)
        return(IMAP_PROTOCOL_ERROR);

    if (c != ' ') goto parse_err;

    if (!strcmp(response.s, "OK")) {
        if (eat == SYNC_PARSE_EAT_OKLINE) eatline(in, c);
        return(0);
    } else if (!strcmp(response.s, "NO")) {
        sync_getline(in, &errmsg);
        syslog(LOG_ERR, "%s received NO response: %s", cmd, errmsg.s);

        /* Slight hack to transform certain error strings into equivalent
         * imap_err value so that caller has some idea of cause */
        if (!strncmp(errmsg.s, "IMAP_INVALID_USER ",
                     strlen("IMAP_INVALID_USER ")))
            return(IMAP_INVALID_USER);
        else if (!strncmp(errmsg.s, "IMAP_MAILBOX_NONEXISTENT ",
                          strlen("IMAP_MAILBOX_NONEXISTENT ")))
            return(IMAP_MAILBOX_NONEXISTENT);
        else
            return(IMAP_REMOTE_DENIED);
    } else if (response.s[0] != '*')
        goto parse_err;

    /* Unsolicited response */
    if (!unsolicitedp) goto parse_err;

    for (s = response.s; *s ; s++)
        if (*s != '*') goto parse_err;

    *unsolicitedp = s - response.s;
    return(0);

 parse_err:
    sync_getline(in, &errmsg);
    syslog(LOG_ERR, "%s received %s response: %s",
           cmd, response.s, errmsg.s);
    return(IMAP_PROTOCOL_ERROR);
}

/* ====================================================================== */

void sync_flags_clear(struct sync_flags *flags)
{
    memset(flags, 0, sizeof(struct sync_flags));
}

void sync_flags_meta_clear(struct sync_flags_meta *meta)
{
    memset(meta, 0, sizeof(struct sync_flags_meta));
}

void sync_flags_meta_free(struct sync_flags_meta *meta)
{
    int n;

    for (n = 0; n < MAX_USER_FLAGS; n++) {
        if (meta->flagname[n])
            free(meta->flagname[n]);
    }
}

static void sync_flags_meta_from_list(struct sync_flags_meta *meta,
				      char **flagname)
{
    int n;

    for (n = 0; n < MAX_USER_FLAGS; n++) {
        if (flagname[n])
            meta->flagname[n] = xstrdup(flagname[n]);
        else
            meta->flagname[n] = NULL;
    }

    meta->newflags = 0;
}

void sync_flags_meta_to_list(struct sync_flags_meta *meta, char **flagname)
{
    int n;

    for (n = 0; n < MAX_USER_FLAGS; n++) {
        if (flagname[n] && meta->flagname[n] &&
            !strcmp(flagname[n], meta->flagname[n]))
            continue;
        
        if (meta->flagname[n])
            flagname[n] = xstrdup(meta->flagname[n]);
        else
            flagname[n] = NULL;
    }

    meta->newflags = 0;
}

int sync_getflags(struct protstream *input,
		  struct sync_flags *flags, struct sync_flags_meta *meta)
{
    static struct buf flagtoken;            /* Relies on zeroed BSS */
    int inlist = 0;
    int flag  = -1;
    int empty = -1;
    int c, i;
    char *s;

    sync_flags_clear(flags);

    for (;;) {
	if ((c = getword(input, &flagtoken)) == EOF)
            return(EOF);

        s = flagtoken.s;

	if (c == '(' && !s[0] && !inlist) {
	    inlist = 1;
	    continue;
	}
	if (!s[0]) break;

	if (s[0] == '\\') {
            /* System flags */
	    lcase(s);
	    if (!strcmp(s, "\\seen")) {
		/* flags->seen = 1; */
	    } else if (!strcasecmp(s, "\\answered")) {
		flags->system_flags |= FLAG_ANSWERED;
	    } else if (!strcasecmp(s, "\\flagged")) {
		flags->system_flags |= FLAG_FLAGGED;
	    } else if (!strcasecmp(s, "\\deleted")) {
		flags->system_flags |= FLAG_DELETED;
	    } else if (!strcasecmp(s, "\\draft")) {
		flags->system_flags |= FLAG_DRAFT;
	    } else {
                syslog(LOG_ERR, "Unknown system flag: %s", s);
            }
	} else if (imparse_isatom(s)) {
            flag = empty = (-1);
            for (i = 0 ; i < MAX_USER_FLAGS ; i++) {
                if (meta->flagname[i] && !strcmp(meta->flagname[i], s)) {
                    flag = i;
                    break;
                }
                if ((empty < 0) && (meta->flagname[i] == NULL))
                    empty = i;
            }
            if ((flag < 0) && (empty >= 0)) {
                flag = empty;
                meta->flagname[flag] = xstrdup(s);
                meta->newflags = 1;  /* Have new user flag */
            }
            if (flag >= 0) {
                flags->user_flags[flag/32] |= 1<<(flag&31);
            } else {
                syslog(LOG_ERR, "Unable to record user flag: %s", s);
            }
        } else
            return('-');  /* Force parse error */

	if (c != ' ') break;
    }

    if (!inlist || (c != ')'))
        return('-');  /* Force parse error */

    return(prot_getc(input));
}

/* ====================================================================== */

/* sync_msg stuff */

struct sync_msg_list *sync_msg_list_create(char **flagname,
					   unsigned long last_uid)
{
    struct sync_msg_list *l = xzmalloc(sizeof (struct sync_msg_list));

    l->head     = NULL;
    l->tail     = NULL;
    l->count    = 0;
    l->last_uid = last_uid;
    sync_flags_meta_clear(&l->meta);

    if (flagname)
        sync_flags_meta_from_list(&l->meta, flagname);

    return(l);
}

struct sync_msg *sync_msg_list_add(struct sync_msg_list *l)
{
    struct sync_msg *result = xzmalloc(sizeof(struct sync_msg));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    return(result);
}

void sync_msg_list_free(struct sync_msg_list **lp)
{
    struct sync_msg_list *l = *lp;
    struct sync_msg *current, *next;

    current = l->head;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    sync_flags_meta_free(&l->meta);
    free(l);

    *lp = NULL;
}


/* ====================================================================== */

struct sync_msgid_list *sync_msgid_list_create(int hash_size)
{
    struct sync_msgid_list *l = xzmalloc(sizeof (struct sync_msgid_list));

    /* Pick a sensible default if no size given */
    if (hash_size == 0)
        hash_size = 256;

    l->head      = NULL;
    l->tail      = NULL;
    l->hash_size = hash_size;
    l->hash      = xzmalloc(hash_size * sizeof(struct sync_msgid *));
    l->count     = 0;
    l->reserved  = 0;

    return(l);
}

struct sync_msgid *sync_msgid_add(struct sync_msgid_list *l,
				  struct message_uuid *uuid)
{
    struct sync_msgid *result;
    int offset;

    if (message_uuid_isnull(uuid))
        return(NULL);

    result = xzmalloc(sizeof(struct sync_msgid));
    offset = message_uuid_hash(uuid, l->hash_size);

    message_uuid_copy(&result->uuid, uuid);

    l->count++;
    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    /* Insert at start of list */
    result->hash_next = l->hash[offset];
    l->hash[offset]   = result;

    return(result);
}

void sync_msgid_list_free(struct sync_msgid_list **lp)
{
    struct sync_msgid_list *l = *lp;
    struct sync_msgid *current, *next;

    current = l->head;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    free(l->hash);
    free(l);

    *lp = NULL;
}

struct sync_msgid *sync_msgid_lookup(struct sync_msgid_list *l,
				     struct message_uuid *uuid)
{
    int offset = message_uuid_hash(uuid, l->hash_size);
    struct sync_msgid *msgid;

    if (message_uuid_isnull(uuid))
        return(NULL);

    for (msgid = l->hash[offset] ; msgid ; msgid = msgid->hash_next) {
        if (message_uuid_compare(&msgid->uuid, uuid))
            return(msgid);
    }
    return(NULL);
}

/* ====================================================================== */

struct sync_folder_list *sync_folder_list_create(void)
{
    struct sync_folder_list *l = xzmalloc(sizeof (struct sync_folder_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;

    return(l);
}

struct sync_folder *sync_folder_list_add(struct sync_folder_list *l,
					 char *id, char *name, char *acl,
					 unsigned long options,
					 struct quota *quota)
{
    struct sync_folder *result = xzmalloc(sizeof(struct sync_folder));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next    = NULL;
    result->msglist = NULL;
    result->id      = (id)   ? xstrdup(id)   : NULL;
    result->name    = (name) ? xstrdup(name) : NULL;
    result->acl     = (acl)  ? xstrdup(acl)  : NULL;
    result->options = options;
    if (quota) {
	result->quota.root = result->name;
	result->quota.limit = quota->limit;
    }
    result->mark    = 0;
    result->reserve = 0;

    return(result);
}

struct sync_folder *sync_folder_lookup(struct sync_folder_list *l, char *id)
{
    struct sync_folder *p;

    for (p = l->head ; p ; p = p->next) {
        if (!strcmp(p->id, id))
            return(p);
    }
    return(NULL);
}

struct sync_folder *sync_folder_lookup_byname(struct sync_folder_list *l,
					      char *name)
{
    struct sync_folder *p;

    for (p = l->head ; p ; p = p->next) {
        if (!strcmp(p->name, name))
            return(p);
    }
    return(NULL);
}

int sync_folder_mark(struct sync_folder_list *l, char *id)
{
    struct sync_folder *p;

    for (p = l->head ; p ; p = p->next) {
        if (!strcmp(p->id, id)) {
            p->mark = 1;
            return(1);
        }
    }
    return(0);
}

void sync_folder_list_free(struct sync_folder_list **lp)
{
    struct sync_folder_list *l = *lp;
    struct sync_folder *current, *next;

    if (!l) return;

    current = l->head;
    while (current) {
        next = current->next;

        if (current->id)      free(current->id);
        if (current->name)    free(current->name);
        if (current->acl)     free(current->acl);
        if (current->msglist) sync_msg_list_free(&current->msglist);

        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_rename_list *sync_rename_list_create(void)
{
    struct sync_rename_list *l = xzmalloc(sizeof (struct sync_rename_list));

    l->head  = NULL;
    l->tail  = NULL;
    l->count = 0;
    l->done  = 0;

    return(l);
}

struct sync_rename_item *sync_rename_list_add(struct sync_rename_list *l,
					      char *id, char *oldname,
					      char *newname)
{
    struct sync_rename_item *result
        = xzmalloc(sizeof(struct sync_rename_item));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next    = NULL;
    result->id      = xstrdup(id);
    result->oldname = xstrdup(oldname);
    result->newname = xstrdup(newname);
    result->done    = 0;

    return(result);
}

struct sync_rename_item *sync_rename_lookup(struct sync_rename_list *l,
					    char *oldname)
{
    struct sync_rename_item *p;

    for (p = l->head ; p ; p = p->next) {
        if (!strcmp(p->oldname, oldname))
            return(p);
    }
    return(NULL);
}

void sync_rename_list_free(struct sync_rename_list **lp)
{
    struct sync_rename_list *l = *lp;
    struct sync_rename_item *current, *next;

    if (!l) return;

    current = l->head;
    while (current) {
        next = current->next;

        free(current->id);
        free(current->oldname);
        free(current->newname);
        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_user_list *sync_user_list_create(void)
{
    struct sync_user_list *l = xzmalloc(sizeof (struct sync_user_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;

    return(l);
}

struct sync_user *sync_user_list_add(struct sync_user_list *l, char *userid)
{
    struct sync_user *result = xzmalloc(sizeof(struct sync_user));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next        = NULL;
    result->userid      = xstrdup(userid);
    result->folder_list = sync_folder_list_create();

    return(result);
}

struct sync_user *sync_user_list_lookup(struct sync_user_list *l, char *userid)
{
    struct sync_user *p;

    for (p = l->head ; p ; p = p->next) {
        if (!strcmp(p->userid, userid))
            return(p);
    }
    return(NULL);
}


void sync_user_list_free(struct sync_user_list **lp)
{
    struct sync_user_list *l = *lp;
    struct sync_user *current, *next;

    if (!l) return;

    current = l->head;
    while (current) {
        next = current->next;

        free(current->userid);
        sync_folder_list_free(&current->folder_list);

        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_message_list *sync_message_list_create(int hash_size, int file_max)
{
    struct sync_message_list *l = xzmalloc(sizeof (struct sync_message_list));
    const char *root;

    /* Pick a sensible default if no size given */
    if (hash_size == 0)
        hash_size = 256;

    l->head  = NULL;
    l->tail  = NULL;
    l->hash  = xzmalloc(hash_size * sizeof(struct sync_msgid *));
    l->hash_size = hash_size;
    l->count = 0;

    l->file       = xzmalloc(file_max * sizeof(FILE *));
    l->file_count = 0;
    l->file_max   = file_max;  

    /* Set up cache file */
    root = config_partitiondir(config_defpartition);

    snprintf(l->cache_name, sizeof(l->cache_name), "%s/sync./%lu.cache",
	     root, (unsigned long) getpid());

    l->cache_fd = open(l->cache_name, O_RDWR|O_CREAT|O_TRUNC, 0666);
    if (l->cache_fd < 0 && errno == ENOENT) {
	if (!cyrus_mkdir(l->cache_name, 0755)) {
	    l->cache_fd = open(l->cache_name, O_RDWR|O_CREAT|O_TRUNC, 0666);
	}
    }
    if (l->cache_fd < 0) {
        syslog(LOG_ERR, "Failed to open %s: %m", l->cache_name);
        return(NULL);
    }
    l->cache_base = 0;
    l->cache_len  = 0;

    l->cache_buffer_size  = 0;
    l->cache_buffer_alloc = SYNC_MESSAGE_INIT_CACHE;
    l->cache_buffer       = xmalloc(l->cache_buffer_alloc);
    return(l);
}

int sync_message_list_newstage(struct sync_message_list *l, char *mboxname)
{
    int r;
    const char *root;
    char *partition;
 
    /* Find mailbox partition */
    r = mboxlist_detail(mboxname, NULL, NULL, NULL, &partition, NULL, NULL);
    if (!r) {
	root = config_partitiondir(partition);
	if (!root) r = IMAP_PARTITION_UNKNOWN;
    }
    if (r) {
	syslog(LOG_ERR, "couldn't find sync stage directory for mbox: '%s': %s",
	       mboxname, error_message(r));
	return r;
    }

    snprintf(l->stage_dir, sizeof(l->stage_dir), "%s/sync./%lu",
	     root, (unsigned long) getpid());

    if (cyrus_mkdir(l->stage_dir, 0755) == -1) return IMAP_IOERROR;
    if (mkdir(l->stage_dir, 0755) == -1 && errno != EEXIST) {
	syslog(LOG_ERR, "Failed to create %s:%m", l->stage_dir);
	return IMAP_IOERROR;
    }

    return 0;
}

void sync_message_list_cache(struct sync_message_list *l, char *entry, int size)
{
    if ((l->cache_buffer_size + size) > l->cache_buffer_alloc) {
        if (size > l->cache_buffer_alloc)
            l->cache_buffer_alloc  = 2 * size;  /* _Big_ cache entry! */ 
        else
            l->cache_buffer_alloc *= 2;

        l->cache_buffer = xrealloc(l->cache_buffer, l->cache_buffer_alloc);
    }
    memcpy(l->cache_buffer+l->cache_buffer_size, entry, size);
    l->cache_buffer_size += size;
}

int sync_message_list_cache_flush(struct sync_message_list *l)
{
    int n;

    if (l->cache_buffer_size == 0)
        return(0);

    n = retry_write(l->cache_fd, l->cache_buffer, l->cache_buffer_size);

    if (n < l->cache_buffer_size) {
        syslog(LOG_ERR,
               "sync_message_flush_cache(): failed to write %lu bytes: %m",
               l->cache_buffer_size);

        return(IMAP_IOERROR);
    }

    l->cache_buffer_size = 0;
    return(0);
}

unsigned long sync_message_list_cache_offset(struct sync_message_list *l)
{
    return(lseek(l->cache_fd, 0, SEEK_CUR) + l->cache_buffer_size);
}

char *sync_message_next_path(struct sync_message_list *l)
{
    static char result[MAX_MAILBOX_PATH+1];

    snprintf(result, sizeof(result), "%s/%lu.", l->stage_dir, l->count);

    return(result);
}

struct sync_message *sync_message_add(struct sync_message_list *l,
				      struct message_uuid *uuid)
{
    struct sync_message *result;
    int offset;

    result = xzmalloc(sizeof(struct sync_message));
    message_uuid_set_null(&result->uuid);
    
    result->msg_path = xzmalloc(5 * (MAX_MAILBOX_PATH+1) * sizeof(char));
    result->msg_path_end = result->msg_path +
	5 * (MAX_MAILBOX_PATH+1) * sizeof(char);

    snprintf(result->stagename, sizeof(result->stagename), "%lu.", l->count);

    snprintf(result->msg_path, MAX_MAILBOX_PATH,
	     "%s/%s", l->stage_dir, result->stagename);
    /* make sure there's a NUL NUL at the end */
    result->msg_path[strlen(result->msg_path) + 1] = '\0';

    l->count++;
    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    if (uuid && !message_uuid_isnull(uuid)) {
        /* Messages with UUIDs get fast hash lookup for duplicate copies */
        message_uuid_copy(&result->uuid, uuid);
        offset = message_uuid_hash(uuid, l->hash_size);

        /* Insert at start of list */
        result->hash_next = l->hash[offset];
        l->hash[offset]   = result;
    }
    return(result);
}

void sync_message_fsync(struct sync_message_list *l)
{
    int i;

    if (l->file_count == 0)
        return;

    /* fsync() files in reverse order: ReiserFS FAQ indicates that this
     * gives best potential for optimisation */
    for (i = (l->file_count-1) ; i >= 0 ; i--) {
        fsync(fileno(l->file[i]));
        fclose(l->file[i]);
        l->file[i] = NULL;
    }
    l->file_count = 0;
}

FILE *sync_message_open(struct sync_message_list *l,
			struct sync_message *message)
{
    FILE *file;

    if (l->file_count == l->file_max)
        sync_message_fsync(l);

    /* unlink just in case a previous crash left a file 
     * hard linked into someone else's mailbox! */
    if (unlink(message->msg_path) == -1 && errno != ENOENT) {
	syslog(LOG_ERR,
	       "sync_message_open(): failed to unlink stale file %s: %m",
	       message->msg_path);
	return(NULL);
    }

    /* Open read/write so file can later be mmap()ed if needed */
    if ((file=fopen(message->msg_path, "w+")) == NULL) {
        syslog(LOG_ERR, "sync_message_open(): Unable to open %s: %m",
               message->msg_path);
        return(NULL);
    }

    l->file[l->file_count++] = file;

    return(file);
}

int sync_message_copy_fromstage(struct sync_message *message,
				struct mailbox *mailbox,
				unsigned long uid)
{
    int r;
    const char *root;
    char *partition, stagefile[MAX_MAILBOX_PATH+1], *p;
    size_t sflen;
    char  target[MAX_MAILBOX_PATH+1];
 
    /* Find mailbox partition */
    r = mboxlist_detail(mailbox->name, NULL, NULL, NULL, &partition, NULL, NULL);
    if (!r) {
	root = config_partitiondir(partition);
	if (!root) r = IMAP_PARTITION_UNKNOWN;
    }
    if (r) {
	syslog(LOG_ERR, "couldn't find sync stage directory for mbox: '%s': %s",
	       mailbox->name, error_message(r));
	return r;
    }

    snprintf(stagefile, sizeof(stagefile), "%s/sync./%lu/%s",
	     root, (unsigned long) getpid(), message->stagename);
    sflen = strlen(stagefile);

    p = message->msg_path;
    while (p < message->msg_path_end) {
	int sl = strlen(p);

	if (sl == 0) {
	    /* our partition isn't here */
	    break;
	}
	if (!strcmp(stagefile, p)) {
	    /* aha, this is us */
	    break;
	}
	
	p += sl + 1;
    }

    if (*p == '\0') {
	/* ok, create this file, and copy the name of it into 'p'.
	   make sure not to overwrite message->msg_path_end */

	/* create the new staging file from the first stage part */
	r = mailbox_copyfile(message->msg_path, stagefile, 0);
	if (r) {
	    /* maybe the directory doesn't exist? */
	    if (cyrus_mkdir(stagefile, 0755) == -1) {
		syslog(LOG_ERR, "couldn't create sync stage directory for : %s: %m",
		       stagefile);
	    } else {
		syslog(LOG_NOTICE, "created sync stage directory for %s",
		       stagefile);
		r = mailbox_copyfile(message->msg_path, stagefile, 0);
	    }
	}
	if (r) {
	    /* oh well, we tried */

	    syslog(LOG_ERR, "IOERROR: creating message file %s: %m", 
		   stagefile);
	    unlink(stagefile);
	    return r;
	}
	
	if (p + sflen > message->msg_path_end - 5) {
	    int cursize = message->msg_path_end - message->msg_path;
	    int curp = p - message->msg_path;

	    /* need more room; double the buffer */
	    message->msg_path = xrealloc(message->msg_path, 2 * cursize);
	    message->msg_path_end = message->msg_path + 2 * cursize;
	    p = message->msg_path + curp;
	}
	strcpy(p, stagefile);
	/* make sure there's a NUL NUL at the end */
	p[sflen + 1] = '\0';
    }

    /* 'p' contains the message and is on the same partition
       as the mailbox we're looking at */

    snprintf(target, MAX_MAILBOX_PATH, "%s/%lu.", mailbox->path, uid);

    return mailbox_copyfile(p, target, 0);
}

void sync_message_list_free(struct sync_message_list **lp)
{
    struct sync_message_list *l = *lp;
    struct sync_message *current, *next;

    for (current = l->head; current ; current = next) {
        next = current->next;

        if (current->msg_path) {
	    char *p = current->msg_path;
	    while (*p != '\0' && p < current->msg_path_end) {
		if (unlink(p) != 0) {
		    syslog(LOG_ERR, "IOERROR, error unlinking file %s: %m", p);
		}
		p += strlen(p) + 1;
	    }
            free(current->msg_path);
        }
        free(current);
    }
    if (l->cache_base && (l->cache_len > 0))
        map_free(&l->cache_base, &l->cache_len);
    if (l->cache_fd) {
        close(l->cache_fd);
        unlink(l->cache_name);
    }
    rmdir(l->stage_dir);
    free(l->cache_buffer);
    free(l->hash);
    free(l->file);
    free(l);
    *lp = NULL;
}

struct sync_message *sync_message_find(struct sync_message_list *l,
				       struct message_uuid *uuid)
{
    struct sync_message *current;
    int offset = message_uuid_hash(uuid, l->hash_size);

    if (message_uuid_isnull(uuid))
        return(NULL);

    for (current = l->hash[offset] ; current ; current = current->hash_next) {
        if (message_uuid_compare(&current->uuid, uuid))
            return(current);
    }
    return(NULL);
}

int sync_message_list_need_restart(struct sync_message_list *l)
{
    return((l->count > 1000) ||
	   lseek(l->cache_fd, 0, SEEK_CUR) >= SYNC_MESSAGE_LIST_MAX_CACHE);
}

/* ====================================================================== */

static int sync_getliteral_size(struct protstream *input,
				struct protstream *output,
				unsigned long *sizep)
{
    static struct buf arg;            /* Relies on zeroed BSS */
    unsigned long   size     = 0;
    int   sawdigit = 0;
    int   isnowait = 0;
    int   c        = getword(input, &arg);
    char *p        = arg.s;

    if (c == EOF) return(IMAP_IOERROR);

    if ((p == NULL) || (*p != '{'))
        return(IMAP_PROTOCOL_ERROR);

    /* Read size from literal */
    for (p = p + 1; *p && isdigit((int) *p); p++) {
        sawdigit++;
        size = (size*10) + *p - '0';
    }
    if (*p == '+') {
        isnowait++;
        p++;
    }

    if (c == '\r') c = prot_getc(input);
	
    if (*p != '}' || p[1] || c != '\n' || !sawdigit)
        return(IMAP_PROTOCOL_ERROR);

    if (!isnowait) {
        /* Tell client to send the message */
        prot_printf(output, "+ go ahead\r\n");
        prot_flush(output);
    }
    *sizep = size;
    return(0);
}

int sync_getcache(struct protstream *input, struct protstream *output,
		  struct sync_message_list *list, struct sync_message *message)
{
    static char          *cache_entry = NULL;
    static unsigned long  max_cache_size  = 0;
    unsigned long cache_size, size;
    int c, r = 0;
    static struct buf version;
    char *p;
    int n;

    /* Parse Cache version number */
    if ((c = getastring(input, output, &version)) != ' ')
        return(IMAP_IOERROR);
    message->cache_version = sync_atoul(version.s);

    if ((r = sync_getliteral_size(input, output, &cache_size)))
        return(r);

    if (cache_size > max_cache_size) {
	cache_entry = xrealloc(cache_entry, cache_size);
        max_cache_size = cache_size;
    }

    p = cache_entry;
    size = cache_size;
    while (size) {
	n = prot_read(input, p, size);
	if (!n) {
	    syslog(LOG_ERR,
		   "IOERROR: reading cache entry: unexpected end of file");
	    return(IMAP_IOERROR);
	}

	p += n;
	size -=n;
    }
    message->cache_offset = sync_message_list_cache_offset(list);
    message->cache_size   = cache_size;

    sync_message_list_cache(list, cache_entry, cache_size);
    return(0);
}

int sync_getmessage(struct protstream *input, struct protstream *output,
		    struct sync_message_list *list,
		    struct sync_message *message)
{
    FILE *file;
    int   r = 0;
    unsigned long size;
    char buf[8192+1];
    int n;

    if ((r = sync_getliteral_size(input, output, &message->msg_size)))
        return(r);

    if ((file=sync_message_open(list, message)) == NULL)
        return(IMAP_IOERROR);

    size = message->msg_size;
    while (size) {
	n = prot_read(input, buf, size > 8192 ? 8192 : size);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading message: unexpected end of file");
	    r = IMAP_IOERROR;
	    break;
	}

	size -= n;
	fwrite(buf, 1, n, file);
    }

    /* fsync()/fclose() batched later */
    return(r);
}

int sync_getsimple(struct protstream *input, struct protstream *output,
		   struct sync_message_list *list,
		   struct sync_message *message)
{
    FILE         *file;
    int           r = 0;
    unsigned long size;
    const char *msg_base = 0;
    unsigned long msg_len = 0;
    struct index_record record;
    char buf[8192+1];
    int n;

    /* If switching from PARSED to SIMPLE, need to flush cache.  This is
     * redundant as it duplicates code in cmd_upload() (which is the
     * logical place for the code to go), but better safe than sorry. */
    if (list->cache_buffer_size > 0)
        sync_message_list_cache_flush(list);

    if ((r = sync_getliteral_size(input, output, &message->msg_size)))
        return(r);

    /* Open read/write so file can later be mmap()ed */
    if ((file=fopen(message->msg_path, "w+")) == NULL) {
        syslog(LOG_ERR, "sync_getsimple(): Unable to open %s: %m",
               message->msg_path);

        r = IMAP_IOERROR;
    }

    size = message->msg_size;
    while (size) {
	n = prot_read(input, buf, size > 8192 ? 8192 : size);
	if (!n) {
	    syslog(LOG_ERR,
		   "IOERROR: reading message: unexpected end of file");
	    r = IMAP_IOERROR;
	    break;
	}

	size -= n;
	fwrite(buf, 1, n, file);
    }

    if (r) {
        fclose(file);
        return(IMAP_IOERROR);
    }

    /* Make sure that message flushed to disk just incase mmap has problems */
    fflush(file);
    if (ferror(file)) {
        fclose(file);
        return(IMAP_IOERROR);
    }

    if (fsync(fileno(file)) < 0) {
        fclose(file);
        return(IMAP_IOERROR);
    }

    map_refresh(fileno(file), 1, &msg_base, &msg_len, message->msg_size,
		"new message", "unknown");

    r = message_parse_mapped_async(msg_base, msg_len,
                                   MAILBOX_FORMAT_NORMAL,
                                   list->cache_fd, &record);
    map_free(&msg_base, &msg_len);

    message->hdr_size     = record.header_size;
    message->cache_offset = record.cache_offset;
    message->cache_size 
        = lseek(list->cache_fd, 0, SEEK_CUR) - record.cache_offset;

    fclose(file);
    return(r);
}

/* ====================================================================== */

struct sync_upload_list *sync_upload_list_create(unsigned long new_last_uid,
						 char **flagname)
{
    struct sync_upload_list *l = xzmalloc(sizeof (struct sync_upload_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;
    l->new_last_uid = new_last_uid;

    sync_flags_meta_clear(&l->meta);
    sync_flags_meta_from_list(&l->meta, flagname);

    return(l);
}

struct sync_upload_item *sync_upload_list_add(struct sync_upload_list *l)
{
    struct sync_upload_item *result
        = xzmalloc(sizeof(struct sync_upload_item));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    return(result);
}

void sync_upload_list_free(struct sync_upload_list **lp)
{
    struct sync_upload_list *l = *lp;
    struct sync_upload_item *current, *next;

    current = l->head;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    sync_flags_meta_free(&l->meta);
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_flag_list *sync_flag_list_create(char **flagname)
{
    struct sync_flag_list *l = xzmalloc(sizeof (struct sync_flag_list));

    sync_flags_meta_clear(&l->meta);
    sync_flags_meta_from_list(&l->meta, flagname);

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;
    return(l);
}

struct sync_flag_item *sync_flag_list_add(struct sync_flag_list *l)
{
    struct sync_flag_item *result = xzmalloc(sizeof(struct sync_flag_item));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;
    return(result);
}

void sync_flag_list_free(struct sync_flag_list **lp)
{
    struct sync_flag_list *l = *lp;
    struct sync_flag_item *current, *next;

    current = l->head;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    sync_flags_meta_free(&l->meta);
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

char *sync_sieve_get_path(char *userid, char *sieve_path, size_t psize)
{
    char *domain;

    if (config_getenum(IMAPOPT_VIRTDOMAINS) && (domain = strchr(userid, '@'))) {
	char d = (char) dir_hash_c(domain+1);
	*domain = '\0';  /* split user@domain */
	snprintf(sieve_path, psize, "%s%s%c/%s/%c/%s",
		 config_getstring(IMAPOPT_SIEVEDIR),
		 FNAME_DOMAINDIR, d, domain+1, dir_hash_c(userid), userid);
	*domain = '@';  /* reassemble user@domain */
    }
    else {
	snprintf(sieve_path, psize, "%s/%c/%s",
		 config_getstring(IMAPOPT_SIEVEDIR), dir_hash_c(userid), userid);
    }

    return sieve_path;
}


struct sync_sieve_list *sync_sieve_list_create()
{
    struct sync_sieve_list *l = xzmalloc(sizeof (struct sync_sieve_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;
    return(l);
}

void sync_sieve_list_add(struct sync_sieve_list *l,
			 char *name, time_t last_update, int active)
{
    struct sync_sieve_item *item = xzmalloc(sizeof(struct sync_sieve_item));

    item->name = xstrdup(name);
    item->last_update = last_update;
    item->active = active;
    item->mark = 0;

    if (l->tail)
        l->tail = l->tail->next = item;
    else
        l->head = l->tail = item;

    l->count++;
}

struct sync_sieve_item *sync_sieve_lookup(struct sync_sieve_list *l, char *name)
{
    struct sync_sieve_item *p;

    for (p = l->head ; p ; p = p->next) {
        if (!strcmp(p->name, name))
            return(p);
    }
    return(NULL);
}

void sync_sieve_list_set_active(struct sync_sieve_list *l, char *name)
{
    struct sync_sieve_item *item;

    for (item = l->head ; item ; item = item->next) {
        if (!strcmp(item->name, name)) {
            item->active = 1;
            break;
        }
    }
}

void sync_sieve_list_free(struct sync_sieve_list **lp)
{
    struct sync_sieve_list *l = *lp;
    struct sync_sieve_item *current, *next;

    current = l->head;
    while (current) {
        next = current->next;
        if (current->name)
            free(current->name);
        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

struct sync_sieve_list *sync_sieve_list_generate(char *userid)
{
    struct sync_sieve_list *list = sync_sieve_list_create();
    char sieve_path[2048];   /* Follows existing code... */
    char filename[2048];
    char active[2048];
    DIR *mbdir;
    struct dirent *next = NULL;
    struct stat sbuf;
    int count;

    list = sync_sieve_list_create();

    sync_sieve_get_path(userid, sieve_path, sizeof(sieve_path));

    if (!(mbdir = opendir(sieve_path)))
        return(list);

    active[0] = '\0';
    while((next = readdir(mbdir)) != NULL) {
        if(!strcmp(next->d_name, ".") || !strcmp(next->d_name, ".."))
            continue;

        snprintf(filename, sizeof(filename), "%s/%s",
                 sieve_path, next->d_name);

        if (stat(filename, &sbuf) < 0)
            continue;

        if (!strcmp(next->d_name, "defaultbc")) {
            if (sbuf.st_mode & S_IFLNK) {
                count = readlink(filename, active, 2047);

                if (count >= 0) {
                    active[count] = '\0';
                } else {
                    /* XXX Report problem? */
                }
            }
            continue;
        }
        sync_sieve_list_add(list, next->d_name, sbuf.st_mtime, 0);
    }
    closedir(mbdir);

    if (active[0])
        sync_sieve_list_set_active(list, active);

    return(list);
}

char *sync_sieve_read(char *userid, char *name, unsigned long *sizep)
{
    char sieve_path[2048];
    char filename[2048];
    FILE *file;
    struct stat sbuf;
    char *result, *s;
    unsigned long count;
    int c;

    if (sizep)
        *sizep = 0;

    sync_sieve_get_path(userid, sieve_path, sizeof(sieve_path));
    
    snprintf(filename, sizeof(filename), "%s/%s", sieve_path, name);

    file=fopen(filename, "r");

    if ((file == NULL) || (fstat(fileno(file), &sbuf) < 0))
        return(NULL);

    count = sbuf.st_size;
    s = result = xmalloc(count+1);

    if (sizep)
        *sizep = count;

    while (count > 0) {
        if ((c=fgetc(file)) == EOF)
            break;
        *s++ = c;
        count--;
    }
    fclose(file);
    *s = '\0';

    return(result);
}

int sync_sieve_upload(struct protstream *input, struct protstream *output,
		      char *userid, char *name, unsigned long last_update)
{
    char sieve_path[2048];
    char tmpname[2048];
    char newname[2048];
    FILE *file;
    int   r = 0;
    unsigned long size;
    struct stat sbuf;
    struct utimbuf utimbuf;
    char buf[8192+1];
    int n;

    sync_sieve_get_path(userid, sieve_path, sizeof(sieve_path));

    if (stat(sieve_path, &sbuf) == -1 && errno == ENOENT) {
	if (cyrus_mkdir(sieve_path, 0755) == -1) return IMAP_IOERROR;
	if (mkdir(sieve_path, 0755) == -1 && errno != EEXIST) {
	    syslog(LOG_ERR, "Failed to create %s:%m", sieve_path);
	    return IMAP_IOERROR;
	}
    }

    snprintf(tmpname, sizeof(tmpname), "%s/sync_tmp-%lu",
             sieve_path, (unsigned long)getpid());
    snprintf(newname, sizeof(newname), "%s/%s", sieve_path, name);

    if ((r = sync_getliteral_size(input, output, &size)))
        return(r);

    if ((file=fopen(tmpname, "w")) == NULL) {
        return(IMAP_IOERROR);
    }

    while (size) {
	n = prot_read(input, buf, size > 8192 ? 8192 : size);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading message: unexpected end of file");
	    r = IMAP_IOERROR;
	    break;
	}

	size -= n;
	fwrite(buf, 1, n, file);
    }

    if ((fflush(file) != 0) || (fsync(fileno(file)) < 0))
        r = IMAP_IOERROR;

    fclose(file);

    utimbuf.actime  = time(NULL);
    utimbuf.modtime = last_update;

    if (!r && (utime(tmpname, &utimbuf) < 0))
        r = IMAP_IOERROR;

    if (!r && (rename(tmpname, newname) < 0))
        r = IMAP_IOERROR;

    return(r);
}


int sync_sieve_activate(char *userid, char *name)
{
    char sieve_path[2048];
    char target[2048];
    char active[2048];

    sync_sieve_get_path(userid, sieve_path, sizeof(sieve_path));

    snprintf(target, sizeof(target), "%s", name);
    snprintf(active, sizeof(active), "%s/%s", sieve_path, "defaultbc");
    unlink(active);
    
    if (symlink(target, active) < 0)
        return(IMAP_IOERROR);

    return(0);
}

int sync_sieve_deactivate(char *userid)
{
    char sieve_path[2048];
    char active[2048];

    sync_sieve_get_path(userid, sieve_path, sizeof(sieve_path));

    snprintf(active, sizeof(active), "%s/%s", sieve_path, "defaultbc");
    unlink(active);
    
    return(0);
}

int sync_sieve_delete(char *userid, char *name)
{
    char sieve_path[2048];
    char filename[2048];
    char active[2048];
    DIR *mbdir;
    struct dirent *next = NULL;
    struct stat sbuf;
    int is_default = 0;
    int count;

    sync_sieve_get_path(userid, sieve_path, sizeof(sieve_path));

    if (!(mbdir = opendir(sieve_path)))
        return(IMAP_IOERROR);

    while((next = readdir(mbdir)) != NULL) {
        if(!strcmp(next->d_name, ".") || !strcmp(next->d_name, ".."))
            continue;

        snprintf(filename, sizeof(filename), "%s/%s",
                 sieve_path, next->d_name);

        if (stat(filename, &sbuf) < 0)
            continue;

        if (!strcmp(next->d_name, "defaultbc")) {
            if (sbuf.st_mode & S_IFLNK) {
                count = readlink(filename, active, 2047);

                if (count >= 0) {
                    active[count] = '\0';
                    if (!strcmp(active, name))
                        is_default = 1;
                }
            }
            continue;
        }
    }
    closedir(mbdir);

    if (is_default) {
        snprintf(filename, sizeof(filename), "%s/defaultbc", sieve_path);
        unlink(filename);
    }

    snprintf(filename, sizeof(filename), "%s/%s", sieve_path, name);
    unlink(filename);

    return(0);
}

/* ====================================================================== */

struct sync_annot_list *sync_annot_list_create()
{
    struct sync_annot_list *l = xzmalloc(sizeof (struct sync_annot_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;
    return(l);
}

void sync_annot_list_add(struct sync_annot_list *l,
			 const char *entry, const char *userid,
			 const char *value)
{
    struct sync_annot_item *item = xzmalloc(sizeof(struct sync_annot_item));

    item->entry = xstrdup(entry);
    item->userid = xstrdup(userid);
    item->value = xstrdup(value);
    item->mark = 0;

    if (l->tail)
        l->tail = l->tail->next = item;
    else
        l->head = l->tail = item;

    l->count++;
}

void sync_annot_list_free(struct sync_annot_list **lp)
{
    struct sync_annot_list *l = *lp;
    struct sync_annot_item *current, *next;

    current = l->head;
    while (current) {
        next = current->next;
        if (current->entry) free(current->entry);
        if (current->userid) free(current->userid);
        if (current->value) free(current->value);
        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_action_list *sync_action_list_create(void)
{
    struct sync_action_list *l = xzmalloc(sizeof (struct sync_action_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;

    return(l);
}

void sync_action_list_add(struct sync_action_list *l, char *name, char *user)
{
    struct sync_action *current;

    if (!name && !user) return;

    for (current = l->head ; current ; current = current->next) {
        if ((!name || (current->name && !strcmp(current->name, name))) &&
	    (!user || (current->user && !strcmp(current->user, user)))) {
	    current->active = 1;  /* Make sure active */
	    return;
	} else {
	    /* name and/or user don't match current: no match possible */
	}
    }

    current           = xzmalloc(sizeof(struct sync_action));
    current->next     = NULL;
    current->name     = (name)  ? xstrdup(name)  : NULL;
    current->user     = (user)  ? xstrdup(user)  : NULL;
    current->active   = 1;

    if (l->tail)
        l->tail = l->tail->next = current;
    else
        l->head = l->tail = current;

    l->count++;

}

void sync_action_list_free(struct sync_action_list **lp)
{
    struct sync_action_list *l = *lp;
    struct sync_action *current, *next;

    current = l->head;
    while (current) {
        next = current->next;

        if (current->name) free(current->name);
        if (current->user) free(current->user);

        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

void sync_lock_reset(struct sync_lock *lock)
{
    lock->fd = -1;
    lock->count = 0;
}

int sync_unlock(struct sync_lock *lock)
{
    assert(lock->fd >= 0);
    assert(lock->count != 0);

    if (--lock->count == 0) {
	lock_unlock(lock->fd);
	close(lock->fd);
	lock->fd = -1;
    }

    return(0);
}

int sync_lock(struct sync_lock *lock)
{
    static char lockfile[MAX_MAILBOX_PATH] = "";
    int r = 0;

    if (lock->count++) return 0;

    if (!*lockfile) {
	strlcpy(lockfile, config_dir, sizeof(lockfile));
	strlcat(lockfile, "/sync/lock", sizeof(lockfile));
    }

    lock->fd = open(lockfile, O_WRONLY|O_CREAT, 0640);
    if (lock->fd < 0 && errno == ENOENT) {
	if (!cyrus_mkdir(lockfile, 0755)) {
	    lock->fd = open(lockfile, O_WRONLY|O_CREAT, 0640);
	}
    }
    if (lock->fd < 0) {
        syslog(LOG_ERR, "Unable to create file %s: %s",
	       lockfile, strerror(errno));
        return(IMAP_IOERROR);
    }

    r = lock_blocking(lock->fd);
    if (r) {
	lock->count--;
	syslog(LOG_ERR, "Unable to lock %s: %s", lockfile, strerror(errno));
    }

    return(r);
}
