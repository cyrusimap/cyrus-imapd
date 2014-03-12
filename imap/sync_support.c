/* sync_support.c -- Cyrus synchronization support functions
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
 * $Id: sync_support.c,v 1.25 2010/01/06 17:01:41 murch Exp $
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
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "message.h"
#include "util.h"
#include "user.h"
#include "retry.h"
#include "cyr_lock.h"
#include "prot.h"
#include "dlist.h"

#include "message_guid.h"
#include "sync_support.h"
#include "sync_log.h"

/* Parse routines */

char *sync_encode_options(int options)
{
    static char buf[4];
    int i = 0;

    if (options & OPT_POP3_NEW_UIDL)
	buf[i++] = 'P';
    if (options & OPT_IMAP_SHAREDSEEN)
	buf[i++] = 'S';
    if (options & OPT_IMAP_DUPDELIVER)
	buf[i++] = 'D';
    buf[i] = '\0';

    return buf;
}

int sync_parse_options(const char *options)
{
    int res = 0;
    const char *p = options;

    if (!options) return 0;

    while (*p) {
	switch(*p) {
	case 'P':
	    res |= OPT_POP3_NEW_UIDL;
	    break;
	case 'S':
	    res |= OPT_IMAP_SHAREDSEEN;
	    break;
	case 'D':
	    res |= OPT_IMAP_DUPDELIVER;
	    break;
	}
	p++;
    }

    return res;
}

/* Get a simple line (typically error text) */
#define BUFGROWSIZE 100
int sync_getline(struct protstream *in, struct buf *buf)
{
    unsigned len = 0;
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
	    if (len > config_maxword) {
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

void sync_print_flags(struct dlist *kl,
		      struct mailbox *mailbox, 
		      struct index_record *record)
{
    int flag;
    struct dlist *fl = dlist_list(kl, "FLAGS");

    if (record->system_flags & FLAG_DELETED)
	dlist_flag(fl, "FLAG", "\\Deleted");
    if (record->system_flags & FLAG_ANSWERED)
	dlist_flag(fl, "FLAG", "\\Answered");
    if (record->system_flags & FLAG_FLAGGED)
	dlist_flag(fl, "FLAG", "\\Flagged");
    if (record->system_flags & FLAG_DRAFT)
	dlist_flag(fl, "FLAG", "\\Draft");
    if (record->system_flags & FLAG_EXPUNGED)
	dlist_flag(fl, "FLAG", "\\Expunged");
    if (record->system_flags & FLAG_SEEN)
	dlist_flag(fl, "FLAG", "\\Seen");
        
    /* print user flags in mailbox order */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(record->user_flags[flag/32] & (1<<(flag&31))))
	    continue;
	dlist_flag(fl, "FLAG", mailbox->flagname[flag]);
    }
}

int sync_getflags(struct dlist *kl,
		  struct mailbox *mailbox,
		  struct index_record *record)
{
    struct dlist *ki;
    int userflag;

    for (ki = kl->head; ki; ki = ki->next) {
	char *s = xstrdup(ki->sval);

	if (s[0] == '\\') {
	    /* System flags */
	    lcase(s);
	    if (!strcmp(s, "\\seen")) {
		record->system_flags |= FLAG_SEEN;
	    } else if (!strcmp(s, "\\expunged")) {
		record->system_flags |= FLAG_EXPUNGED;
	    } else if (!strcmp(s, "\\answered")) {
		record->system_flags |= FLAG_ANSWERED;
	    } else if (!strcmp(s, "\\flagged")) {
		record->system_flags |= FLAG_FLAGGED;
	    } else if (!strcmp(s, "\\deleted")) {
		record->system_flags |= FLAG_DELETED;
	    } else if (!strcmp(s, "\\draft")) {
		record->system_flags |= FLAG_DRAFT;
	    } else {
		syslog(LOG_ERR, "Unknown system flag: %s", s);
	    }
	}
	else {
	    if (mailbox_user_flag(mailbox, s, &userflag)) {
		syslog(LOG_ERR, "Unable to record user flag: %s", s);
		return IMAP_IOERROR;
	    }
	    record->user_flags[userflag/32] |= 1<<(userflag&31);
	}

	free(s);
    }

    return 0;
}

int parse_upload(struct dlist *kr, struct mailbox *mailbox,
			struct index_record *record)
{
    struct dlist *fl;
    const char *guid;
    int r;

    memset(record, 0, sizeof(struct index_record));

    if (!dlist_getnum(kr, "UID", &record->uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getmodseq(kr, "MODSEQ", &record->modseq))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kr, "LAST_UPDATED", &record->last_updated))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kr, "FLAGS", &fl))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kr, "INTERNALDATE", &record->internaldate))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kr, "SIZE", &record->size))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kr, "GUID", &guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* parse the flags */
    r = sync_getflags(fl, mailbox, record);
    if (r) return r;

    /* check the GUID format */
    if (!message_guid_decode(&record->guid, guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return 0;
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
    l->marked    = 0;

    return(l);
}

struct sync_msgid *sync_msgid_add(struct sync_msgid_list *l,
				  struct message_guid *guid)
{
    struct sync_msgid *result;
    int offset;

    if (message_guid_isnull(guid))
        return(NULL);

    result = xzmalloc(sizeof(struct sync_msgid));
    offset = message_guid_hash(guid, l->hash_size);

    message_guid_copy(&result->guid, guid);

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

void sync_msgid_remove(struct sync_msgid_list *l,
		       struct message_guid *guid)
{
    int offset = message_guid_hash(guid, l->hash_size);
    struct sync_msgid *msgid;

    if (message_guid_isnull(guid)) return;

    for (msgid = l->hash[offset] ; msgid ; msgid = msgid->hash_next) {
	if (message_guid_equal(&msgid->guid, guid)) {
	    message_guid_set_null(&msgid->guid);
	    return;
	}
    }
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
				     struct message_guid *guid)
{
    int offset = message_guid_hash(guid, l->hash_size);
    struct sync_msgid *msgid;

    if (message_guid_isnull(guid))
        return(NULL);

    for (msgid = l->hash[offset] ; msgid ; msgid = msgid->hash_next) {
        if (message_guid_equal(&msgid->guid, guid))
            return(msgid);
    }
    return(NULL);
}

struct sync_reserve_list *sync_reserve_list_create(int hash_size)
{
    struct sync_reserve_list *l = xmalloc(sizeof(struct sync_reserve_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->hash_size = hash_size;

    return l;
}

struct sync_msgid_list *sync_reserve_partlist(struct sync_reserve_list *l,
					      const char *part)
{
    struct sync_reserve *item;

    for (item = l->head; item; item = item->next) {
	if (!strcmp(item->part, part))
	    return item->list;
    }

    /* not found, create it */
    item = xmalloc(sizeof(struct sync_reserve));
    item->part = xstrdup(part);
    item->next = NULL;
    item->list = sync_msgid_list_create(l->hash_size);

    if (l->tail)
	l->tail = l->tail->next = item;
    else
	l->tail = l->head = item;

    return item->list;
}

void sync_reserve_list_free(struct sync_reserve_list **lp)
{
    struct sync_reserve_list *l = *lp;
    struct sync_reserve *current, *next;

    current = l->head;
    while (current) {
	next = current->next;
	sync_msgid_list_free(&current->list);
	free(current->part);
	free(current);
	current = next;
    }
    free(l);

    *lp = NULL;
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
					 const char *uniqueid, const char *name,
					 uint32_t mbtype,
					 const char *part, const char *acl,
					 uint32_t options,
					 uint32_t uidvalidity, 
					 uint32_t last_uid,
					 modseq_t highestmodseq,
					 uint32_t crc,
					 uint32_t recentuid,
					 time_t recenttime,
					 time_t pop3_last_login)
{
    struct sync_folder *result = xzmalloc(sizeof(struct sync_folder));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next = NULL;
    result->mailbox = NULL;

    result->uniqueid = (uniqueid) ? xstrdup(uniqueid) : NULL;
    result->name = (name) ? xstrdup(name) : NULL;
    result->mbtype = mbtype;
    result->part = (part) ? xstrdup(part) : NULL;
    result->acl = (acl) ? xstrdup(acl)  : NULL;
    result->uidvalidity = uidvalidity;
    result->last_uid = last_uid;
    result->highestmodseq = highestmodseq;
    result->options = options;
    result->sync_crc = crc;
    result->recentuid = recentuid;
    result->recenttime = recenttime;
    result->pop3_last_login = pop3_last_login;

    result->mark     = 0;
    result->reserve  = 0;

    return(result);
}

struct sync_folder *sync_folder_lookup(struct sync_folder_list *l,
				       const char *uniqueid)
{
    struct sync_folder *p;

    for (p = l->head; p; p = p->next) {
        if (!strcmp(p->uniqueid, uniqueid))
            return p;
    }
    return NULL;
}

struct sync_folder *sync_folder_lookup_byname(struct sync_folder_list *l,
					      const char *name)
{
    struct sync_folder *p;

    for (p = l->head; p; p = p->next) {
        if (!strcmp(p->name, name))
            return p;
    }
    return NULL;
}

int sync_folder_mark(struct sync_folder_list *l, const char *uniqueid)
{
    struct sync_folder *p = sync_folder_lookup(l, uniqueid);

    if (p) {
	p->mark = 1;
	return 1;
    }

    return 0;
}

void sync_folder_list_free(struct sync_folder_list **lp)
{
    struct sync_folder_list *l = *lp;
    struct sync_folder *current, *next;

    if (!l) return;

    current = l->head;
    while (current) {
        next = current->next;
        free(current->uniqueid);
        free(current->name);
        free(current->part);
        free(current->acl);
        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_rename_list *sync_rename_list_create(void)
{
    struct sync_rename_list *l = xzmalloc(sizeof(struct sync_rename_list));

    l->head  = NULL;
    l->tail  = NULL;
    l->count = 0;
    l->done  = 0;

    return(l);
}

struct sync_rename *sync_rename_list_add(struct sync_rename_list *l,
					      const char *uniqueid, const char *oldname,
					      const char *newname, const char *partition)
{
    struct sync_rename *result
        = xzmalloc(sizeof(struct sync_rename));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next = NULL;
    result->uniqueid = xstrdup(uniqueid);
    result->oldname = xstrdup(oldname);
    result->newname = xstrdup(newname);
    result->part = xstrdup(partition);
    result->done = 0;

    return result;
}

struct sync_rename *sync_rename_lookup(struct sync_rename_list *l,
					    const char *oldname)
{
    struct sync_rename *p;

    for (p = l->head; p; p = p->next) {
        if (!strcmp(p->oldname, oldname))
            return p;
    }

    return NULL;
}

void sync_rename_list_free(struct sync_rename_list **lp)
{
    struct sync_rename_list *l = *lp;
    struct sync_rename *current, *next;

    if (!l) return;

    current = l->head;
    while (current) {
        next = current->next;
        free(current->uniqueid);
        free(current->oldname);
        free(current->newname);
        free(current->part);
        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_quota_list *sync_quota_list_create(void)
{
    struct sync_quota_list *l = xzmalloc(sizeof(struct sync_quota_list));

    l->head  = NULL;
    l->tail  = NULL;
    l->count = 0;
    l->done  = 0;

    return(l);
}

struct sync_quota *sync_quota_list_add(struct sync_quota_list *l,
					    const char *root, int limit)
{
    struct sync_quota *result
        = xzmalloc(sizeof(struct sync_quota));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next = NULL;
    result->root = xstrdup(root);
    result->limit = limit;
    result->done = 0;

    return result;
}

struct sync_quota *sync_quota_lookup(struct sync_quota_list *l,
					  const char *name)
{
    struct sync_quota *p;

    for (p = l->head; p; p = p->next) {
        if (!strcmp(p->root, name))
            return p;
    }

    return NULL;
}

void sync_quota_list_free(struct sync_quota_list **lp)
{
    struct sync_quota_list *l = *lp;
    struct sync_quota *current, *next;

    if (!l) return;

    current = l->head;
    while (current) {
        next = current->next;
        free(current->root);
        free(current);
        current = next;
    }
    free(l);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_sieve_list *sync_sieve_list_create()
{
    struct sync_sieve_list *l = xzmalloc(sizeof (struct sync_sieve_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;

    return l;
}

void sync_sieve_list_add(struct sync_sieve_list *l, const char *name,
			 time_t last_update, int active)
{
    struct sync_sieve *item = xzmalloc(sizeof(struct sync_sieve));

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

struct sync_sieve *sync_sieve_lookup(struct sync_sieve_list *l, char *name)
{
    struct sync_sieve *p;

    for (p = l->head; p; p = p->next) {
        if (!strcmp(p->name, name))
            return p;
    }

    return NULL;
}

void sync_sieve_list_set_active(struct sync_sieve_list *l, char *name)
{
    struct sync_sieve *item;

    for (item = l->head; item; item = item->next) {
        if (!strcmp(item->name, name)) {
            item->active = 1;
            break;
        }
    }
}

void sync_sieve_list_free(struct sync_sieve_list **lp)
{
    struct sync_sieve_list *l = *lp;
    struct sync_sieve *current, *next;

    current = l->head;
    while (current) {
	next = current->next;
	free(current->name);
	free(current);
	current = next;
    }
    free(l);
    *lp = NULL;
}

struct sync_sieve_list *sync_sieve_list_generate(const char *userid)
{
    struct sync_sieve_list *list = sync_sieve_list_create();
    const char *sieve_path = user_sieve_path(userid);
    char filename[2048];
    char active[2048];
    DIR *mbdir;
    struct dirent *next = NULL;
    struct stat sbuf;
    int count;


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

    return list;
}

char *sync_sieve_read(const char *userid, const char *name, uint32_t *sizep)
{
    const char *sieve_path = user_sieve_path(userid);
    char filename[2048];
    FILE *file;
    struct stat sbuf;
    char *result, *s;
    uint32_t count;
    int c;

    if (sizep)
        *sizep = 0;

    snprintf(filename, sizeof(filename), "%s/%s", sieve_path, name);

    file = fopen(filename, "r");
    if (!file) return NULL;

    if (fstat(fileno(file), &sbuf) < 0) {
	fclose(file);
	return(NULL);
    }

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

int sync_sieve_upload(const char *userid, const char *name,
		      time_t last_update, const char *content,
		      size_t len)
{
    const char *sieve_path = user_sieve_path(userid);
    char tmpname[2048];
    char newname[2048];
    FILE *file;
    int   r = 0;
    struct stat sbuf;
    struct utimbuf utimbuf;

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

    if ((file=fopen(tmpname, "w")) == NULL) {
        return(IMAP_IOERROR);
    }

    /* XXX - error handling */
    fwrite(content, 1, len, file);

    if ((fflush(file) != 0) || (fsync(fileno(file)) < 0))
        r = IMAP_IOERROR;

    fclose(file);

    utimbuf.actime  = time(NULL);
    utimbuf.modtime = last_update;

    if (!r && (utime(tmpname, &utimbuf) < 0))
        r = IMAP_IOERROR;

    if (!r && (rename(tmpname, newname) < 0))
        r = IMAP_IOERROR;

    sync_log_sieve(userid);

    return r;
}

int sync_sieve_activate(const char *userid, const char *name)
{
    const char *sieve_path = user_sieve_path(userid);
    char target[2048];
    char active[2048];

    snprintf(target, sizeof(target), "%s", name);
    snprintf(active, sizeof(active), "%s/%s", sieve_path, "defaultbc");
    unlink(active);
    
    if (symlink(target, active) < 0)
        return(IMAP_IOERROR);

    sync_log_sieve(userid);

    return(0);
}

int sync_sieve_deactivate(const char *userid)
{
    const char *sieve_path = user_sieve_path(userid);
    char active[2048];

    snprintf(active, sizeof(active), "%s/%s", sieve_path, "defaultbc");
    unlink(active);

    sync_log_sieve(userid);
    
    return(0);
}

int sync_sieve_delete(const char *userid, const char *name)
{
    const char *sieve_path = user_sieve_path(userid);
    char filename[2048];
    char active[2048];
    DIR *mbdir;
    struct dirent *next = NULL;
    struct stat sbuf;
    int is_default = 0;
    int count;

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

    sync_log_sieve(userid);

    return(0);
}

/* ====================================================================== */

struct sync_name_list *sync_name_list_create()
{
    struct sync_name_list *l = xzmalloc(sizeof (struct sync_name_list));
    l->head = NULL;
    l->tail = NULL;
    l->count = 0;
    l->marked = 0;
    return l;
}

struct sync_name *sync_name_list_add(struct sync_name_list *l,
				     const char *name)
{
    struct sync_name *item = xzmalloc(sizeof(struct sync_name));

    if (l->tail)
        l->tail = l->tail->next = item;
    else
        l->head = l->tail = item;

    l->count++;

    item->next = NULL;
    item->name = xstrdup(name);
    item->mark = 0;

    return item;
}

struct sync_name *sync_name_lookup(struct sync_name_list *l,
					const char *name)
{
    struct sync_name *p;

    for (p = l->head; p; p = p->next)
	if (!strcmp(p->name, name))
	    return p;

    return NULL;
}

void sync_name_list_free(struct sync_name_list **lp)
{
    struct sync_name *current, *next;

    current = (*lp)->head;
    while (current) {
        next = current->next;
        free(current->name);
        free(current);
        current = next;
    }
    free(*lp);
    *lp = NULL;
}

/* ====================================================================== */

struct sync_seen_list *sync_seen_list_create()
{
    struct sync_seen_list *l = xzmalloc(sizeof (struct sync_seen_list));
    l->head = NULL;
    l->tail = NULL;
    l->count = 0;
    return l;
}

struct sync_seen *sync_seen_list_add(struct sync_seen_list *l,
				     const char *uniqueid, time_t lastread,
				     unsigned lastuid, time_t lastchange,
				     const char *seenuids)
{
    struct sync_seen *item = xzmalloc(sizeof(struct sync_seen));

    if (l->tail)
        l->tail = l->tail->next = item;
    else
        l->head = l->tail = item;

    l->count++;

    item->next = NULL;
    item->uniqueid = xstrdup(uniqueid);
    item->sd.lastread = lastread;
    item->sd.lastuid = lastuid;
    item->sd.lastchange = lastchange;
    item->sd.seenuids = xstrdup(seenuids);
    item->mark = 0;

    return item;
}

struct sync_seen *sync_seen_list_lookup(struct sync_seen_list *l,
					const char *uniqueid)
{
    struct sync_seen *p;

    for (p = l->head; p; p = p->next)
	if (!strcmp(p->uniqueid, uniqueid))
	    return p;

    return NULL;
}

void sync_seen_list_free(struct sync_seen_list **lp)
{
    struct sync_seen *current, *next;

    current = (*lp)->head;
    while (current) {
	next = current->next;
	free(current->uniqueid);
	seen_freedata(&current->sd);
	free(current);
	current = next;
    }
    free(*lp);
    *lp = NULL;
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
    struct sync_annot *item = xzmalloc(sizeof(struct sync_annot));

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
    struct sync_annot *current, *next;

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

/* simple binary search */
unsigned sync_mailbox_finduid(struct mailbox *mailbox, unsigned uid)
{
    unsigned low=1, high=mailbox->i.num_records, mid;
    struct index_record record;

    while (low <= high) {
        mid = (high - low)/2 + low;
	if (mailbox_read_index_record(mailbox, mid, &record))
	    return 0;

        if (record.uid == uid)
            return mid;
        else if (record.uid > uid)
            high = mid - 1;
        else
            low = mid + 1;
    }
    return 0;
}

int addmbox(char *name,
	    int matchlen __attribute__((unused)),
	    int maycreate __attribute__((unused)),
	    void *rock)
{
    struct sync_name_list *list = (struct sync_name_list *) rock;
    struct mboxlist_entry mbentry;

    if (mboxlist_lookup(name, &mbentry, NULL))
	return 0;

    /* only want normal mailboxes... */
    if (!(mbentry.mbtype & (MBTYPE_RESERVE | MBTYPE_MOVING | MBTYPE_REMOTE))) 
	sync_name_list_add(list, name);

    return 0;
}

int addmbox_sub(void *rock, const char *key, int keylen,
		const char *data __attribute__((unused)),
		int datalen __attribute__((unused)))
{
    struct sync_name_list *list = (struct sync_name_list *) rock;

    /* XXX - double malloc because of list_add, clean up later */
    char *name = xstrndup(key, keylen);
    sync_name_list_add(list, name);
    free(name);

    return 0;
}

/* NOTE - we don't prot_flush here, as we always send an OK at the
 * end of a response anyway */
void sync_send_response(struct dlist *kl, struct protstream *out)
{
    prot_printf(out, "* ");
    dlist_print(kl, 1, out);
    prot_printf(out, "\r\n");
}

static const char *sync_gentag(struct buf *tag)
{
    static unsigned cmdcnt = 0;

    buf_reset(tag);
    buf_printf(tag, "S%d", cmdcnt++);
    return buf_cstring(tag);
}

/* these are one-shot commands for get and apply, so flush the stream
 * after sending */
void sync_send_apply(struct dlist *kl, struct protstream *out)
{
    if (out->userdata) {
	/* IMAP flavor (w/ tag) */
	prot_printf(out, "%s SYNC", sync_gentag((struct buf *) out->userdata));
    }
    prot_printf(out, "APPLY ");
    dlist_print(kl, 1, out);
    prot_printf(out, "\r\n");
    prot_flush(out);
}

void sync_send_lookup(struct dlist *kl, struct protstream *out)
{
    if (out->userdata) {
	/* IMAP flavor (w/ tag) */
	prot_printf(out, "%s SYNC", sync_gentag((struct buf *) out->userdata));
    }
    prot_printf(out, "GET ");
    dlist_print(kl, 1, out);
    prot_printf(out, "\r\n");
    prot_flush(out);
}

struct dlist *sync_parseline(struct protstream *in)
{
    struct dlist *dl = NULL;
    char c;

    c = dlist_parse(&dl, 1, in);

    /* end line - or fail */
    if (c == '\r') c = prot_getc(in);
    if (c == '\n') return dl;

    dlist_free(&dl);
    eatline(in, c);
    return NULL;
}

static int sync_send_file(struct mailbox *mailbox,
			  const char *topart,
			  struct index_record *record,
			  struct sync_msgid_list *part_list,
			  struct dlist *kupload)
{
    struct sync_msgid *msgid;
    const char *fname;

    /* is it already reserved? */
    msgid = sync_msgid_lookup(part_list, &record->guid);
    if (msgid && msgid->mark) 
	return 0;

    /* we'll trust that it exists - if not, we'll bail later,
     * but right now we're under locks, so be fast */
    fname = mailbox_message_fname(mailbox, record->uid);
    if (!fname) return IMAP_MAILBOX_BADNAME;

    dlist_file(kupload, "MESSAGE", topart, &record->guid, record->size, fname);

    return 0;
}

static int sync_mailbox(struct mailbox *mailbox,
			struct sync_folder *remote,
			const char *topart,
			struct sync_msgid_list *part_list,
			struct dlist *kl, struct dlist *kupload,
			int printrecords)
{
    if (!topart) topart = mailbox->part;

    dlist_atom(kl, "UNIQUEID", mailbox->uniqueid);
    dlist_atom(kl, "MBOXNAME", mailbox->name);
    if (mailbox->mbtype)
	dlist_atom(kl, "MBOXTYPE", mboxlist_mbtype_to_string(mailbox->mbtype));
    dlist_num(kl, "LAST_UID", mailbox->i.last_uid);
    dlist_modseq(kl, "HIGHESTMODSEQ", mailbox->i.highestmodseq);
    dlist_num(kl, "RECENTUID", mailbox->i.recentuid);
    dlist_date(kl, "RECENTTIME", mailbox->i.recenttime);
    dlist_date(kl, "LAST_APPENDDATE", mailbox->i.last_appenddate);
    dlist_date(kl, "POP3_LAST_LOGIN", mailbox->i.pop3_last_login);
    dlist_num(kl, "UIDVALIDITY", mailbox->i.uidvalidity);
    dlist_atom(kl, "PARTITION", topart);
    dlist_atom(kl, "ACL", mailbox->acl);
    dlist_atom(kl, "OPTIONS", sync_encode_options(mailbox->i.options));
    dlist_num(kl, "SYNC_CRC", mailbox->i.sync_crc);
    if (mailbox->quotaroot) 
	dlist_atom(kl, "QUOTAROOT", mailbox->quotaroot);

    if (printrecords) {
	struct index_record record;
	struct dlist *il;
	struct dlist *rl = dlist_list(kl, "RECORD");
	uint32_t recno;
	int send_file;
	uint32_t prevuid = 0;

	for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	    /* we can't send bogus records */
	    if (mailbox_read_index_record(mailbox, recno, &record)) {
		syslog(LOG_ERR, "SYNCERROR: corrupt mailbox %s %u, IOERROR",
		       mailbox->name, recno);
		return IMAP_IOERROR;
	    }

	    if  (record.uid <= prevuid) {
		syslog(LOG_ERR, "SYNCERROR: corrupt mailbox %s %u, ordering",
		       mailbox->name, recno);
		return IMAP_IOERROR;
	    }
	    prevuid = record.uid;

	    /* start off thinking we're sending the file too */
	    send_file = 1;

	    /* seen it already! SKIP */
	    if (remote && record.modseq <= remote->highestmodseq)
		continue;

	    /* does it exist at the other end?  Don't send it */
	    if (remote && record.uid <= remote->last_uid)
		send_file = 0;

	    /* if we're not uploading messages... don't send file */
	    if (!part_list || !kupload)
		send_file = 0;

	    /* if we don't HAVE the file we can't send it */
	    if (record.system_flags & FLAG_UNLINKED)
		send_file = 0;

	    if (send_file) {
		int r = sync_send_file(mailbox, topart,
				       &record, part_list, kupload);
		if (r) return r;
	    }

	    il = dlist_kvlist(rl, "RECORD");
	    dlist_num(il, "UID", record.uid);
	    dlist_modseq(il, "MODSEQ", record.modseq);
	    dlist_date(il, "LAST_UPDATED", record.last_updated);
	    sync_print_flags(il, mailbox, &record);
	    dlist_date(il, "INTERNALDATE", record.internaldate);
	    dlist_num(il, "SIZE", record.size);
	    dlist_atom(il, "GUID", message_guid_encode(&record.guid));
	}
    }

    return 0;
}

int sync_parse_response(const char *cmd, struct protstream *in,
			struct dlist **klp)
{
    static struct buf response;   /* BSS */
    static struct buf errmsg;
    struct dlist *kl = NULL;
    int c;

    if ((c = getword(in, &response)) == EOF) {
	syslog(LOG_ERR, "IOERROR: zero length response to %s (%s)",
	       cmd, prot_error(in));
	return IMAP_PROTOCOL_ERROR;
    }

    if (c != ' ') goto parse_err;

    kl = dlist_new(cmd);
    while (!strcmp(response.s, "*")) {
	struct dlist *item = sync_parseline(in);
	if (!item) goto parse_err;
	dlist_stitch(kl, item);
	if ((c = getword(in, &response)) == EOF)
	    goto parse_err;
    }

    if (in->userdata) {
	/* check IMAP response tag */
	if (strcmp(response.s, buf_cstring((struct buf *) in->userdata)))
	    goto parse_err;

	/* first word was IMAP response tag - get response token */
	if ((c = getword(in, &response)) == EOF)
	    return IMAP_PROTOCOL_ERROR;

	if (c != ' ') goto parse_err;
    }

    if (!strcmp(response.s, "OK")) {
	if (klp) *klp = kl;
	else dlist_free(&kl);
        eatline(in, c);
        return 0;
    }
    if (!strcmp(response.s, "NO")) {
	dlist_free(&kl);
        sync_getline(in, &errmsg);
        syslog(LOG_ERR, "%s received NO response: %s", cmd, errmsg.s);

        /* Slight hack to transform certain error strings into equivalent
         * imap_err value so that caller has some idea of cause.  Match
	 * this to the logic at sync_print_response() */
        if (!strncmp(errmsg.s, "[IMAP_INVALID_USER] ",
                     strlen("[IMAP_INVALID_USER] ")))
            return IMAP_INVALID_USER;
        else if (!strncmp(errmsg.s, "[IMAP_MAILBOX_NONEXISTENT] ",
                          strlen("[IMAP_MAILBOX_NONEXISTENT] ")))
            return IMAP_MAILBOX_NONEXISTENT;
        else if (!strncmp(errmsg.s, "[IMAP_MAILBOX_CRC] ",
                          strlen("[IMAP_MAILBOX_CRC] ")))
            return IMAP_MAILBOX_CRC;
        else if (!strncmp(errmsg.s, "[IMAP_PROTOCOL_ERROR] ",
                          strlen("[IMAP_PROTOCOL_ERROR] ")))
            return IMAP_PROTOCOL_ERROR;
        else if (!strncmp(errmsg.s, "[IMAP_PROTOCOL_BAD_PARAMETERS] ",
                          strlen("[IMAP_PROTOCOL_BAD_PARAMETERS] ")))
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        else
            return IMAP_REMOTE_DENIED;
    }

 parse_err:
    dlist_free(&kl);
    sync_getline(in, &errmsg);
    syslog(LOG_ERR, "IOERROR: %s received %s response: %s",
	   cmd, response.s, errmsg.s);
    return IMAP_PROTOCOL_ERROR;
}

int sync_append_copyfile(struct mailbox *mailbox,
			 struct index_record *record)
{
    const char *fname, *destname;
    struct message_guid tmp_guid;
    int r;

    message_guid_copy(&tmp_guid, &record->guid);

    fname = dlist_reserve_path(mailbox->part, &tmp_guid);
    if (!fname) {
	r = IMAP_IOERROR;
	syslog(LOG_ERR, "IOERROR: Failed to reserve file %s",
	       message_guid_encode(&tmp_guid));
	return r;
    }

    r = message_parse(fname, record);
    if (r) {
	/* deal with unlinked master records */
	if (record->system_flags & FLAG_EXPUNGED) {
	    record->system_flags |= FLAG_UNLINKED;
	    goto just_write;
	}
	syslog(LOG_ERR, "IOERROR: failed to parse %s", fname);
	return r;
    }

    if (!message_guid_equal(&tmp_guid, &record->guid)) {
	syslog(LOG_ERR, "IOERROR: guid mismatch on parse %s", fname);
	return IMAP_MAILBOX_CRC;
    }

    destname = mailbox_message_fname(mailbox, record->uid);
    cyrus_mkdir(destname, 0755);
    r = mailbox_copyfile(fname, destname, 0);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Failed to copy %s to %s",
	       fname, destname);
	return r;
    }

 just_write:
    return mailbox_append_index_record(mailbox, record);
}


/* =======================  server-side sync  =========================== */


static void reserve_folder(const char *part, const char *mboxname,
			   struct sync_msgid_list *part_list)
{
    struct mailbox *mailbox = NULL;
    struct index_record record;
    struct index_record record2;
    int r;
    struct sync_msgid *item;
    const char *mailbox_msg_path, *stage_msg_path;
    uint32_t recno;

    /* Open and lock mailbox */
    r = mailbox_open_irl(mboxname, &mailbox);
    
    if (r) return;

    for (recno = 1; 
	 part_list->marked < part_list->count && recno <= mailbox->i.num_records;
	 recno++) {
	if (mailbox_read_index_record(mailbox, recno, &record))
	    continue;

	if (record.system_flags & FLAG_UNLINKED)
	    continue;

	item = sync_msgid_lookup(part_list, &record.guid);
	if (!item || item->mark)
	    continue;

	/* Attempt to reserve this message */
	mailbox_msg_path = mailbox_message_fname(mailbox, record.uid);
	stage_msg_path = dlist_reserve_path(part, &record.guid);

	/* check that the sha1 of the file on disk is correct */
	memset(&record2, 0, sizeof(struct index_record));
	r = message_parse(mailbox_msg_path, &record2);
	if (r) {
	    syslog(LOG_ERR, "IOERROR: Unable to parse %s",
		   mailbox_msg_path);
	    continue;
	}
	if (!message_guid_equal(&record.guid, &record2.guid)) {
	    syslog(LOG_ERR, "IOERROR: GUID mismatch on parse for %s",
		   mailbox_msg_path);
	    continue;
	}

	if (mailbox_copyfile(mailbox_msg_path, stage_msg_path, 0) != 0) {
	    syslog(LOG_ERR, "IOERROR: Unable to link %s -> %s: %m",
		   mailbox_msg_path, stage_msg_path);
	    continue;
	}

	item->mark = 1;
	part_list->marked++;
    }

    mailbox_close(&mailbox);
}

int sync_apply_reserve(struct dlist *kl,
		       struct sync_reserve_list *reserve_list,
		       struct sync_state *sstate)
{
    struct message_guid tmp_guid;
    struct sync_name_list *missing = sync_name_list_create();
    struct sync_name_list *folder_names = sync_name_list_create();
    struct sync_msgid_list *part_list;
    struct sync_msgid *item;
    struct sync_name *folder;
    struct mboxlist_entry mbentry;
    const char *partition = NULL;
    struct dlist *ml;
    struct dlist *gl;
    struct dlist *i;
    struct dlist *kout;

    if (!dlist_getatom(kl, "PARTITION", &partition)) goto parse_err;
    if (!dlist_getlist(kl, "MBOXNAME", &ml)) goto parse_err;
    if (!dlist_getlist(kl, "GUID", &gl)) goto parse_err;

    part_list = sync_reserve_partlist(reserve_list, partition);
    for (i = gl->head; i; i = i->next) {
	if (!i->sval || !message_guid_decode(&tmp_guid, i->sval))
	    goto parse_err;
	sync_msgid_add(part_list, &tmp_guid);
    }

    /* need a list so we can mark items */
    for (i = ml->head; i; i = i->next) {
	sync_name_list_add(folder_names, i->sval);
    }

    for (folder = folder_names->head; 
	 part_list->marked < part_list->count && folder;
	 folder = folder->next) {
	if (mboxlist_lookup(folder->name, &mbentry, 0) ||
	    strcmp(mbentry.partition, partition))
	    continue; /* try folders on the same partition first! */
	reserve_folder(partition, folder->name, part_list);
	folder->mark = 1;
    }

    /* if we have other folders, check them now */
    for (folder = folder_names->head; 
	 part_list->marked < part_list->count && folder;
	 folder = folder->next) {
	if (folder->mark)
	    continue;
	reserve_folder(partition, folder->name, part_list);
    }

    /* check if we missed any */
    kout = dlist_list(NULL, "MISSING");
    for (i = gl->head; i; i = i->next) {
	if (!message_guid_decode(&tmp_guid, i->sval))
	    continue;
	item = sync_msgid_lookup(part_list, &tmp_guid);
	if (item && !item->mark)
	    dlist_atom(kout, "GUID", i->sval);
    }
    if (kout->head)
	sync_send_response(kout, sstate->pout);
    dlist_free(&kout);

    sync_name_list_free(&folder_names);
    sync_name_list_free(&missing);

    return 0;

 parse_err:
    sync_name_list_free(&folder_names);
    sync_name_list_free(&missing);

    return IMAP_PROTOCOL_BAD_PARAMETERS;
}

/* ====================================================================== */

int sync_apply_unquota(struct dlist *kin,
		       struct sync_state *sstate __attribute__((unused)))
{
    return mboxlist_unsetquota(kin->sval);
}

int sync_apply_quota(struct dlist *kin,
		     struct sync_state *sstate __attribute__((unused)))
{
    const char *root;
    uint32_t limit;

    if (!dlist_getatom(kin, "ROOT", &root))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "LIMIT", &limit))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return mboxlist_setquota(root, limit, 1);
}

/* ====================================================================== */

static int mailbox_compare_update(struct mailbox *mailbox,
				  struct dlist *kr, int doupdate)
{
    struct index_record mrecord;
    struct index_record rrecord;
    uint32_t recno = 1;
    struct dlist *ki;
    int r;
    int i;

    rrecord.uid = 0;
    for (ki = kr->head; ki; ki = ki->next) {
	r = parse_upload(ki, mailbox, &mrecord);
	if (r) {
	    syslog(LOG_ERR, "Failed to parse uploaded record"); 
	    return r;
	}

	while (rrecord.uid < mrecord.uid) {
	    /* hit the end?  Magic marker */
	    if (recno > mailbox->i.num_records) {
		rrecord.uid = UINT32_MAX;
		break;
	    }

	    /* read another record */
	    r = mailbox_read_index_record(mailbox, recno, &rrecord);
	    if (r) {
		syslog(LOG_ERR, "Failed to read record %s %d",
		       mailbox->name, recno);
		return r;
	    }
	    recno++;
	}

	/* found a match, check for updates */
	if (rrecord.uid == mrecord.uid) {
	    /* GUID mismatch on a non-expunged record is an error straight away */
	    if (!(mrecord.system_flags & FLAG_EXPUNGED)) {
		if (!message_guid_equal(&mrecord.guid, &rrecord.guid)) {
		    syslog(LOG_ERR, "SYNCERROR: guid mismatch %s %u",
			   mailbox->name, mrecord.uid);
		    return IMAP_MAILBOX_CRC;
		}
		if (rrecord.system_flags & FLAG_EXPUNGED) {
		    syslog(LOG_ERR, "SYNCERROR: expunged on replica %s %u",
			   mailbox->name, mrecord.uid);
		    return IMAP_MAILBOX_CRC;
		}
	    }
	    /* higher modseq on the replica is an error */
	    if (rrecord.modseq > mrecord.modseq) {
		syslog(LOG_ERR, "SYNCERROR: higher modseq on replica %s %u",
		       mailbox->name, mrecord.uid);
		return IMAP_MAILBOX_CRC;
	    }

	    /* skip out on the first pass */
	    if (!doupdate) continue;

	    rrecord.modseq = mrecord.modseq;
	    rrecord.last_updated = mrecord.last_updated;
	    rrecord.internaldate = mrecord.internaldate;
	    rrecord.system_flags = (mrecord.system_flags & ~FLAG_UNLINKED) |
				   (rrecord.system_flags & FLAG_UNLINKED);
	    for (i = 0; i < MAX_USER_FLAGS/32; i++)
		rrecord.user_flags[i] = mrecord.user_flags[i];
	    rrecord.silent = 1;
	    r = mailbox_rewrite_index_record(mailbox, &rrecord);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to rewrite record %s %d",
		       mailbox->name, recno);
		return r;
	    }
	}

	/* not found and less than LAST_UID, bogus */
	else if (mrecord.uid <= mailbox->i.last_uid) {
	    /* Expunged, just skip it */
	    if (!(mrecord.system_flags & FLAG_EXPUNGED))
		return IMAP_MAILBOX_CRC;
	}

	/* after LAST_UID, it's an append, that's OK */
	else {
	    /* skip out on the first pass */
	    if (!doupdate) continue;

	    mrecord.silent = 1;
	    r = sync_append_copyfile(mailbox, &mrecord);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to append file %s %d",
		       mailbox->name, recno);
		return r;
	    }
	}
    }

    return 0;
}

int sync_apply_mailbox(struct dlist *kin, struct sync_state *sstate)
{
    /* fields from the request */
    const char *uniqueid;
    const char *partition;
    const char *mboxname;
    const char *mboxtype = NULL; /* optional */
    uint32_t mbtype;
    uint32_t last_uid;
    modseq_t highestmodseq;
    uint32_t recentuid;
    time_t recenttime;
    time_t last_appenddate;
    time_t pop3_last_login;
    uint32_t uidvalidity;
    const char *acl;
    const char *options_str;
    uint32_t sync_crc;

    uint32_t options;

    struct mailbox *mailbox = NULL;
    uint32_t newcrc;
    struct dlist *kr;
    int r;

    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "LAST_UID", &last_uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getmodseq(kin, "HIGHESTMODSEQ", &highestmodseq))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "RECENTUID", &recentuid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "RECENTTIME", &recenttime))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LAST_APPENDDATE", &last_appenddate))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "POP3_LAST_LOGIN", &pop3_last_login))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "SYNC_CRC", &sync_crc))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "UIDVALIDITY", &uidvalidity))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ACL", &acl))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "OPTIONS", &options_str))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kin, "RECORD", &kr))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    /* optional */
    dlist_getatom(kin, "MBOXTYPE", &mboxtype);

    options = sync_parse_options(options_str);

    mbtype = mboxlist_string_to_mbtype(mboxtype);

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	r = mboxlist_createsync(mboxname, mbtype, partition,
				sstate->userid, sstate->authstate,
				options, uidvalidity, acl, uniqueid,
				sstate->local_only, &mailbox);
    }
    if (r) {
	syslog(LOG_ERR, "Failed to open mailbox %s to update", mboxname);
	return r;
    }

    if (mailbox->mbtype != (int) mbtype) {
	/* is this even possible ? */
	syslog(LOG_ERR, "Invalid Mailbox Type %s (%d %d)",
	       mailbox->name, mailbox->mbtype, mbtype);
	mailbox_close(&mailbox);
	return IMAP_MAILBOX_BADTYPE;
    }

    if (strcmp(mailbox->uniqueid, uniqueid)) {
	syslog(LOG_ERR, "Mailbox uniqueid changed %s - retry", mboxname);
	mailbox_close(&mailbox);
	return IMAP_MAILBOX_MOVED;
    }

    /* skip out now, it's going to mismatch for sure! */
    if (highestmodseq < mailbox->i.highestmodseq) {
	syslog(LOG_ERR, "higher modseq on replica %s - "
	       MODSEQ_FMT " < " MODSEQ_FMT,
	       mboxname, highestmodseq, mailbox->i.highestmodseq);
	mailbox_close(&mailbox);
	return IMAP_MAILBOX_CRC;
    }

    if (last_uid < mailbox->i.last_uid) {
	syslog(LOG_ERR, "higher last_uid on replica %s - %u < %u",
	       mboxname, last_uid, mailbox->i.last_uid);
	mailbox_close(&mailbox);
	return IMAP_MAILBOX_CRC;
    }

    if (strcmp(mailbox->acl, acl)) {
	mailbox_set_acl(mailbox, acl, 0);
	r = mboxlist_sync_setacls(mboxname, acl);
	if (r) {
	    mailbox_close(&mailbox);
	    return r;
	}
    }

    r = mailbox_compare_update(mailbox, kr, 0);
    if (r) {
	mailbox_close(&mailbox);
	return r;
    }

    /* now we're committed to writing something no matter what happens! */

    r = mailbox_compare_update(mailbox, kr, 1);
    if (r) {
	abort();
	return r;
    }

    mailbox_index_dirty(mailbox);
    assert(mailbox->i.last_uid <= last_uid);
    mailbox->i.last_uid = last_uid;
    mailbox->i.highestmodseq = highestmodseq;
    mailbox->i.recentuid = recentuid;
    mailbox->i.recenttime = recenttime;
    mailbox->i.last_appenddate = last_appenddate;
    mailbox->i.pop3_last_login = pop3_last_login;
    /* mailbox->i.options = options; ... not really, there's unsyncable stuff in here */

    if (mailbox->i.uidvalidity < uidvalidity) {
	syslog(LOG_ERR, "%s uidvalidity higher on master, updating %u => %u",
	       mailbox->name, mailbox->i.uidvalidity, uidvalidity);
	mailbox->i.uidvalidity = uidvalidity;
    }

    /* try re-calculating the CRC on mismatch... */
    if (mailbox->i.sync_crc != sync_crc) {
	mailbox_index_recalc(mailbox);
    }
    newcrc = mailbox->i.sync_crc;
    mailbox_close(&mailbox);

    /* check return value */
    if (r) return r;
    if (newcrc != sync_crc)
	return IMAP_MAILBOX_CRC;
    return 0;
}

/* ====================================================================== */

static int getannotation_cb(const char *mailbox,
			    const char *entry, const char *userid,
			    struct annotation_data *attrib,
			    void *rock)
{
    struct protstream *pout = (struct protstream *) rock;
    struct dlist *kl;

    kl = dlist_new("ANNOTATION");
    dlist_atom(kl, "MBOXNAME", mailbox);
    dlist_atom(kl, "ENTRY", entry);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "VALUE", attrib->value);
    sync_send_response(kl, pout);
    dlist_free(&kl);

    return 0;
}

int sync_get_annotation(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname = kin->sval;
    return annotatemore_findall(mboxname, "*", &getannotation_cb,
				(void *) sstate->pout, NULL);
}

static void print_quota(struct quota *q, struct protstream *pout)
{
    struct dlist *kl;

    kl = dlist_new("QUOTA");
    dlist_atom(kl, "ROOT", q->root);
    dlist_num(kl, "LIMIT", q->limit);
    sync_send_response(kl, pout);
    dlist_free(&kl);
}

static int quota_work(const char *root, struct protstream *pout)
{
    struct quota q;

    q.root = root;
    if (!quota_read(&q, NULL, 0)) print_quota(&q, pout);

    return 0;
}

int sync_get_quota(struct dlist *kin, struct sync_state *sstate)
{
    return quota_work(kin->sval, sstate->pout);
}

struct mbox_rock {
    struct protstream *pout;
    struct sync_name_list *qrl;
};

static int mailbox_cb(char *name,
		      int matchlen __attribute__((unused)),
		      int maycreate __attribute__((unused)),
		      void *rock)
{
    struct mbox_rock *mrock = (struct mbox_rock *) rock;
    struct sync_name_list *qrl = mrock->qrl;
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_kvlist(NULL, "MAILBOX");
    int r;

    r = mailbox_open_irl(name, &mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT) return 0;
    if (r == IMAP_MAILBOX_RESERVED) return 0;
    if (r) return r;

    if (qrl && mailbox->quotaroot &&
	 !sync_name_lookup(qrl, mailbox->quotaroot))
	sync_name_list_add(qrl, mailbox->quotaroot);

    r = sync_mailbox(mailbox, NULL, NULL, NULL, kl, NULL, 0);
    if (!r) sync_send_response(kl, mrock->pout);
    dlist_free(&kl);
    mailbox_close(&mailbox);

    return r;
}

int sync_get_fullmailbox(struct dlist *kin, struct sync_state *sstate)
{
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_kvlist(NULL, "MAILBOX");
    int r;

    r = mailbox_open_irl(kin->sval, &mailbox);
    if (r) return r;

    r = sync_mailbox(mailbox, NULL, NULL, NULL, kl, NULL, 1);
    if (!r) sync_send_response(kl, sstate->pout);
    dlist_free(&kl);
    mailbox_close(&mailbox);

    return r;
}

int sync_get_mailboxes(struct dlist *kin, struct sync_state *sstate)
{
    struct dlist *ki;
    struct mbox_rock mrock = { sstate->pout, NULL };

    for (ki = kin->head; ki; ki = ki->next)
	mailbox_cb(ki->sval, 0, 0, &mrock);

    return 0;
}

/* ====================================================================== */

static int print_seen(const char *uniqueid, struct seendata *sd, void *rock)
{
    struct dlist *kl;
    struct protstream *pout = (struct protstream *) rock;

    kl = dlist_new("SEEN");
    dlist_atom(kl, "UNIQUEID", uniqueid);
    dlist_date(kl, "LASTREAD", sd->lastread);
    dlist_num(kl, "LASTUID", sd->lastuid);
    dlist_date(kl, "LASTCHANGE", sd->lastchange);
    dlist_atom(kl, "SEENUIDS", sd->seenuids);
    sync_send_response(kl, pout);
    dlist_free(&kl);

    return 0;
}

static int user_getseen(const char *userid, struct protstream *pout)
{
    struct seen *seendb = NULL;

    /* no SEEN DB is OK, just return */
    if (seen_open(userid, SEEN_SILENT, &seendb))
	return 0;

    seen_foreach(seendb, print_seen, pout);
    seen_close(&seendb);

    return 0;
}


static int user_getsub(const char *userid, struct protstream *pout)
{
    struct sync_name_list *list = sync_name_list_create();
    struct sync_name *item;
    struct dlist *kl;

    mboxlist_allsubs(userid, addmbox_sub, list);

    kl = dlist_list(NULL, "LSUB");
    for (item = list->head; item; item = item->next) {
	dlist_atom(kl, "MBOXNAME", item->name);
    }
    if (kl->head)
	sync_send_response(kl, pout);

    dlist_free(&kl);
    sync_name_list_free(&list);

    return 0;
}

static int user_getsieve(const char *userid, struct protstream *pout)
{
    struct sync_sieve_list *sieve_list;
    struct sync_sieve *sieve;
    struct dlist *kl;

    sieve_list = sync_sieve_list_generate(userid);

    if (!sieve_list) return 0;

    for (sieve = sieve_list->head; sieve; sieve = sieve->next) {
	kl = dlist_new("SIEVE");
	dlist_atom(kl, "FILENAME", sieve->name);
	dlist_date(kl, "LAST_UPDATE", sieve->last_update);
	dlist_num(kl, "ISACTIVE", sieve->active ? 1 : 0);
	sync_send_response(kl, pout);
	dlist_free(&kl);
    }

    sync_sieve_list_free(&sieve_list);

    return 0;
}

static int user_meta(const char *userid, struct protstream *pout)
{
    user_getseen(userid, pout);
    user_getsub(userid, pout);
    user_getsieve(userid, pout);
    return 0;
}

int sync_get_meta(struct dlist *kin, struct sync_state *sstate)
{
    return user_meta(kin->sval, sstate->pout);
}

int sync_get_user(struct dlist *kin, struct sync_state *sstate)
{
    char buf[MAX_MAILBOX_PATH];
    int r;
    struct sync_name_list *quotaroots;
    struct sync_name *qr;
    const char *userid = kin->sval;
    struct mbox_rock mrock;

    quotaroots = sync_name_list_create();
    mrock.qrl = quotaroots;
    mrock.pout = sstate->pout;

    /* inbox */
    (*sstate->namespace->mboxname_tointernal)(sstate->namespace, "INBOX",
					      userid, buf);
    r = mailbox_cb(buf, 0, 0, &mrock);
    if (r) goto bail;

    /* deleted namespace items if enabled */
    if (mboxlist_delayed_delete_isenabled()) {
        char deletedname[MAX_MAILBOX_BUFFER];
        mboxname_todeleted(buf, deletedname, 0);
        strlcat(deletedname, ".*", sizeof(deletedname));
        r = (*sstate->namespace->mboxlist_findall)(sstate->namespace,
						   deletedname, 
						   sstate->userisadmin,
						   userid, sstate->authstate,
						   mailbox_cb, &mrock);
	if (r) goto bail;
    }

    /* And then all folders */
    strlcat(buf, ".*", sizeof(buf));
    r = (*sstate->namespace->mboxlist_findall)(sstate->namespace, buf,
					       sstate->userisadmin,
					       userid, sstate->authstate,
					       mailbox_cb, &mrock);
    if (r) goto bail;

    for (qr = quotaroots->head; qr; qr = qr->next) {
	r = quota_work(qr->name, sstate->pout);
	if (r) goto bail;
    }

    r = user_meta(userid, sstate->pout);
    if (r) goto bail;

    sync_log_user(userid);

bail:
    sync_name_list_free(&quotaroots);
    return r;
}

/* ====================================================================== */

int sync_apply_unmailbox(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname = kin->sval;

    /* Delete with admin priveleges */
    return mboxlist_deletemailbox(mboxname, sstate->userisadmin, sstate->userid,
				  sstate->authstate, 0, sstate->local_only, 1);
}

int sync_apply_rename(struct dlist *kin, struct sync_state *sstate)
{
    const char *oldmboxname;
    const char *newmboxname;
    const char *partition;

    if (!dlist_getatom(kin, "OLDMBOXNAME", &oldmboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "NEWMBOXNAME", &newmboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return mboxlist_renamemailbox(oldmboxname, newmboxname, partition,
                                  1, sstate->userid, sstate->authstate,
				  sstate->local_only, 1, 1);
}

int sync_apply_changesub(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname;
    const char *userid;
    int add;

    /* SUB or UNSUB */
    add = strcmp(kin->name, "SUB") ? 0 : 1;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return mboxlist_changesub(mboxname, userid, sstate->authstate, add, add);
}

/* ====================================================================== */

int sync_apply_annotation(struct dlist *kin, struct sync_state *sstate)
{
    struct entryattlist *entryatts = NULL;
    struct attvaluelist *attvalues = NULL;
    const char *mboxname = NULL;
    const char *entry = NULL;
    const char *value = NULL;
    const char *userid = NULL;
    char *name = NULL;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ENTRY", &entry))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "VALUE", &value))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* annotatemore_store() expects external mailbox names,
       so translate the separator character */
    name = xstrdup(mboxname);
    mboxname_hiersep_toexternal(sstate->namespace, name, 0);

    appendattvalue(&attvalues, *userid ? "value.priv" : "value.shared", value);
    appendentryatt(&entryatts, entry, attvalues);
    r = annotatemore_store(name, entryatts, sstate->namespace,
			   sstate->userisadmin, userid, sstate->authstate);

    freeentryatts(entryatts);
    free(name);

    return r;
}

int sync_apply_unannotation(struct dlist *kin, struct sync_state *sstate)
{
    struct entryattlist *entryatts = NULL;
    struct attvaluelist *attvalues = NULL;
    const char *mboxname = NULL;
    const char *entry = NULL;
    const char *userid = NULL;
    char *name = NULL;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ENTRY", &entry))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* annotatemore_store() expects external mailbox names,
       so translate the separator character */
    name = xstrdup(mboxname);
    mboxname_hiersep_toexternal(sstate->namespace, name, 0);

    appendattvalue(&attvalues, *userid ? "value.priv" : "value.shared", NULL);
    appendentryatt(&entryatts, entry, attvalues);
    r = annotatemore_store(name, entryatts, sstate->namespace,
			   sstate->userisadmin, userid, sstate->authstate);

    freeentryatts(entryatts);
    free(name);

    return r;
}

int sync_apply_sieve(struct dlist *kin,
		     struct sync_state *sstate __attribute__((unused)))
{
    const char *userid;
    const char *filename;
    time_t last_update;
    const char *content;
    size_t len;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LAST_UPDATE", &last_update))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getbuf(kin, "CONTENT", &content, &len))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_upload(userid, filename, last_update, content, len);
}

int sync_apply_unsieve(struct dlist *kin,
		       struct sync_state *sstate __attribute__((unused)))
{
    const char *userid;
    const char *filename;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_delete(userid, filename);
}

int sync_apply_activate_sieve(struct dlist *kin,
			      struct sync_state *sstate __attribute__((unused)))
{
    const char *userid;
    const char *filename;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_activate(userid, filename);
}

int sync_apply_unactivate_sieve(struct dlist *kin,
				struct sync_state *sstate __attribute__((unused)))
{
    const char *userid;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_deactivate(userid);
}

int sync_apply_seen(struct dlist *kin,
		    struct sync_state *sstate __attribute__((unused)))
{
    int r;
    struct seen *seendb = NULL;
    struct seendata sd = SEENDATA_INITIALIZER;
    const char *seenuids;
    const char *userid;
    const char *uniqueid;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LASTREAD", &sd.lastread))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "LASTUID", &sd.lastuid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LASTCHANGE", &sd.lastchange))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "SEENUIDS", &seenuids))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    sd.seenuids = xstrdup(seenuids);

    r = seen_open(userid, SEEN_CREATE, &seendb);
    if (r) return r;

    r = seen_write(seendb, uniqueid, &sd);
    seen_close(&seendb);

    seen_freedata(&sd);

    return r;
}

int sync_apply_unuser(struct dlist *kin, struct sync_state *sstate)
{
    struct sync_name_list *list = sync_name_list_create();
    struct sync_name *item;
    const char *userid = kin->sval;
    char buf[MAX_MAILBOX_NAME];
    int r = 0;

    /* Nuke subscriptions */
    mboxlist_allsubs(userid, addmbox_sub, list);

    /* ignore failures here - the subs file gets deleted soon anyway */
    for (item = list->head; item; item = item->next) {
        mboxlist_changesub(item->name, userid, sstate->authstate, 0, 0);
    }
    sync_name_list_free(&list);

    /* Nuke normal folders */
    list = sync_name_list_create();

    (*sstate->namespace->mboxname_tointernal)(sstate->namespace, "INBOX",
					      userid, buf);
    strlcat(buf, ".*", sizeof(buf));
    r = (*sstate->namespace->mboxlist_findall)(sstate->namespace, buf,
					       sstate->userisadmin,
					       sstate->userid,
					       sstate->authstate,
					       addmbox, (void *)list);
    if (r) goto fail;

    for (item = list->head; item; item = item->next) {
        r = mboxlist_deletemailbox(item->name, sstate->userisadmin,
				   sstate->userid, sstate->authstate,
				   0, sstate->local_only, 1);
        if (r) goto fail;
    }

    /* Nuke inbox (recursive nuke possible?) */
    (*sstate->namespace->mboxname_tointernal)(sstate->namespace, "INBOX",
					      userid, buf);
    r = mboxlist_deletemailbox(buf, sstate->userisadmin, sstate->userid,
			       sstate->authstate, 0, sstate->local_only, 1);
    if (r && (r != IMAP_MAILBOX_NONEXISTENT)) goto fail;

    r = user_deletedata((char *)userid, sstate->userid, sstate->authstate, 1);

 fail:
    sync_name_list_free(&list);

    return r;
}

/* ====================================================================== */

int sync_get_sieve(struct dlist *kin, struct sync_state *sstate)
{
    struct dlist *kl;
    const char *userid;
    const char *filename;
    uint32_t size;
    char *sieve;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    sieve = sync_sieve_read(userid, filename, &size);
    if (!sieve)
	return IMAP_MAILBOX_NONEXISTENT;

    kl = dlist_new("SIEVE");
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    dlist_buf(kl, "CONTENT", sieve, size);
    sync_send_response(kl, sstate->pout);
    dlist_free(&kl);

    return 0;
}

/* NOTE - can't lock a mailbox here, because it could deadlock,
 * so just pick the file out from under the hood */
int sync_get_message(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname;
    const char *partition;
    const char *guid;
    uint32_t uid;
    const char *fname;
    struct dlist *kl;
    struct message_guid tmp_guid;
    struct stat sbuf;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "GUID", &guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum(kin, "UID", &uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!message_guid_decode(&tmp_guid, guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    fname = mboxname_datapath(partition, mboxname, uid);
    if (stat(fname, &sbuf) == -1)
	return IMAP_MAILBOX_NONEXISTENT;

    kl = dlist_file(NULL, "MESSAGE", partition, &tmp_guid, sbuf.st_size, fname);
    sync_send_response(kl, sstate->pout);
    dlist_free(&kl);

    return 0;
}

int sync_apply_expunge(struct dlist *kin,
		       struct sync_state *sstate __attribute__((unused)))
{
    const char *mboxname;
    const char *uniqueid;
    struct dlist *ul;
    struct dlist *ui;
    struct mailbox *mailbox = NULL;
    struct index_record record;
    uint32_t recno;
    int r = 0;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kin, "UID", &ul))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) goto done;

    /* don't want to expunge the wrong mailbox! */
    if (strcmp(mailbox->uniqueid, uniqueid)) {
	r = IMAP_MAILBOX_MOVED;
	goto done;
    }

    ui = ul->head;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);
	if (r) goto done;
	if (record.system_flags & FLAG_EXPUNGED) continue;
	while (ui && ui->nval < record.uid) ui = ui->next;
	if (!ui) break; /* no point continuing */
	if (record.uid == ui->nval) {
	    record.system_flags |= FLAG_EXPUNGED;
	    record.silent = 1; /* so the next sync will succeed */
	    r = mailbox_rewrite_index_record(mailbox, &record);
	    if (r) goto done;
	}
    }

done:
    mailbox_close(&mailbox);
    return r;
}

int sync_apply_message(struct dlist *kin,
		       struct sync_reserve_list *reserve_list,
		       struct sync_state *sstate __attribute__((unused)))
{
    struct sync_msgid_list *part_list;
    struct dlist *ki;
    struct sync_msgid *msgid;

    for (ki = kin->head; ki; ki = ki->next) {
	if (ki->type != DL_FILE)
	    continue;

	part_list = sync_reserve_partlist(reserve_list, ki->part);
	msgid = sync_msgid_lookup(part_list, &ki->gval);
	if (!msgid) 
	    msgid = sync_msgid_add(part_list, &ki->gval);
	if (!msgid->mark) {
	    msgid->mark = 1;
	    part_list->marked++;
	}
    }

    return 0;
}

void sync_print_response(char *tag, int r, struct protstream *pout)
{
    const char *resp;

    switch (r) {
    case 0:
	resp = "OK";
	break;
    case IMAP_INVALID_USER:
	resp = "NO [IMAP_INVALID_USER]";
	break;
    case IMAP_MAILBOX_NONEXISTENT:
	resp = "NO [IMAP_MAILBOX_NONEXISTENT]";
	break;
    case IMAP_MAILBOX_CRC:
	resp = "NO [IMAP_MAILBOX_CRC]";
	break;
    case IMAP_PROTOCOL_ERROR:
	resp = "NO [IMAP_PROTOCOL_ERROR]";
	break;
    case IMAP_PROTOCOL_BAD_PARAMETERS:
	resp = "NO [IMAP_PROTOCOL_BAD_PARAMETERS]";
	break;
    default:
	resp = "NO";
    }

    prot_printf(pout, "%s %s %s\r\n", tag, resp, error_message(r));
}


/* =======================  client-side sync  =========================== */


/* Routines relevant to reserve operation */

/* Find the messages that we will want to upload from this mailbox,
 * flag messages that are already available at the server end */

int sync_find_reserve_messages(struct mailbox *mailbox,
			       unsigned last_uid,
			       struct sync_msgid_list *part_list)
{
    struct index_record record;
    uint32_t recno;
    int r;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);

	if (r) {
	    syslog(LOG_ERR,
		   "IOERROR: reading index entry for recno %u of %s: %m",
		   recno, mailbox->name);
	    return IMAP_IOERROR;
	}

	if (record.system_flags & FLAG_UNLINKED)
	    continue;

	/* skip over records already on replica */
	if (record.uid <= last_uid)
	    continue;

	sync_msgid_add(part_list, &record.guid);
    }
    
    return(0);
}

static int find_reserve_all(struct sync_name_list *mboxname_list,
			    const char *topart,
			    struct sync_folder_list *master_folders,
			    struct sync_folder_list *replica_folders,
			    struct sync_reserve_list *reserve_guids)
{
    struct sync_name *mbox;
    struct sync_folder *rfolder;
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox = NULL;
    int r = 0;

    /* Find messages we want to upload that are available on server */
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
	r = mailbox_open_irl(mbox->name, &mailbox);

	/* Quietly skip over folders which have been deleted since we
	   started working (but record fact in case caller cares) */
	if (r == IMAP_MAILBOX_NONEXISTENT) {  
	    r = 0;     
	    continue;
	}

	/* Quietly ignore objects that we don't have access to.
	 * Includes directory stubs, which have not underlying cyrus.*
	 * files in the filesystem */
	if (r == IMAP_PERMISSION_DENIED) {
	    r = 0;
	    continue;
	}

	if (r) {
	    syslog(LOG_ERR, "IOERROR: Failed to open %s: %s",
		   mbox->name, error_message(r));
	    goto bail;
	}

	/* mailbox is open from here, no exiting without closing it! */

	part_list = sync_reserve_partlist(reserve_guids,
					  topart ? topart : mailbox->part);

	sync_folder_list_add(master_folders, mailbox->uniqueid, mailbox->name,
			     mailbox->mbtype,
			     mailbox->part, mailbox->acl, mailbox->i.options,
			     mailbox->i.uidvalidity, mailbox->i.last_uid,
			     mailbox->i.highestmodseq, mailbox->i.sync_crc,
			     mailbox->i.recentuid, mailbox->i.recenttime,
			     mailbox->i.pop3_last_login);

	rfolder = sync_folder_lookup(replica_folders, mailbox->uniqueid);
	if (rfolder)
	    sync_find_reserve_messages(mailbox, rfolder->last_uid, part_list);
	else
	    sync_find_reserve_messages(mailbox, 0, part_list);

	mailbox_close(&mailbox);
    }

bail:
    return r;
}

static int mark_missing (struct dlist *kin,
			 struct sync_msgid_list *part_list)
{
    struct dlist *kl = kin->head;
    struct dlist *ki;
    struct message_guid tmp_guid;
    struct sync_msgid *msgid;

    /* no missing at all, good */
    if (!kl) return 0;

    if (strcmp(kl->name, "MISSING")) {
	syslog(LOG_ERR, "SYNCERROR: Illegal response to RESERVE: %s",
	       kl->name);
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    /* unmark each missing item */
    for (ki = kl->head; ki; ki = ki->next) {
	if (!message_guid_decode(&tmp_guid, ki->sval)) {
	    syslog(LOG_ERR, "SYNCERROR: reserve: failed to parse GUID %s",
		   ki->sval);
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
        }

	msgid = sync_msgid_lookup(part_list, &tmp_guid);
	if (!msgid) {
	    syslog(LOG_ERR, "SYNCERROR: reserve: Got unexpected GUID %s", ki->sval);
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	}

	msgid->mark = 0;
	part_list->marked--;
    }

    return 0;
}

int sync_reserve_partition(char *partition,
			   struct sync_folder_list *replica_folders,
			   struct sync_msgid_list *part_list,
			   struct backend *sync_be)
{
    const char *cmd = "RESERVE";
    struct sync_msgid *msgid;
    struct sync_folder *folder;
    struct dlist *kl;
    struct dlist *kin = NULL;
    struct dlist *ki;
    int r;

    if (!part_list->count)
	return 0; /* nothing to reserve */

    if (!replica_folders->head)
	return 0; /* nowhere to reserve */

    kl = dlist_new(cmd);
    dlist_atom(kl, "PARTITION", partition);

    ki = dlist_list(kl, "MBOXNAME");
    for (folder = replica_folders->head; folder; folder = folder->next)
	dlist_atom(ki, "MBOXNAME", folder->name);

    ki = dlist_list(kl, "GUID");
    for (msgid = part_list->head; msgid; msgid = msgid->next) {
	dlist_atom(ki, "GUID", message_guid_encode(&msgid->guid));
	msgid->mark = 1;
	part_list->marked++;
    }

    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_be->in, &kin);
    if (r) return r;

    r = mark_missing(kin, part_list);
    dlist_free(&kin);

    return r;
}

static int reserve_messages(struct sync_name_list *mboxname_list,
			    const char *topart,
			    struct sync_folder_list *master_folders,
			    struct sync_folder_list *replica_folders,
			    struct sync_reserve_list *reserve_guids,
			    struct backend *sync_be)
{
    struct sync_reserve *reserve;
    int r;

    r = find_reserve_all(mboxname_list, topart, master_folders, 
			 replica_folders, reserve_guids);
    if (r) return r;

    for (reserve = reserve_guids->head; reserve; reserve = reserve->next) {
	r = sync_reserve_partition(reserve->part, replica_folders,
				   reserve->list, sync_be);
	if (r) return r;
    }

    return 0;
}


int sync_response_parse(struct protstream *sync_in, const char *cmd,
			struct sync_folder_list *folder_list,
			struct sync_name_list *sub_list,
			struct sync_sieve_list *sieve_list,
			struct sync_seen_list *seen_list,
			struct sync_quota_list *quota_list)
{
    struct dlist *kin = NULL;
    struct dlist *kl;
    int r;

    r = sync_parse_response(cmd, sync_in, &kin);

    /* Unpleasant: translate remote access error into "please reset me" */
    if (r == IMAP_MAILBOX_NONEXISTENT)
        return 0;

    if (r) return r;

    for (kl = kin->head; kl; kl = kl->next) {
	if (!strcmp(kl->name, "SIEVE")) {
	    const char *filename = NULL;
	    time_t modtime = 0;
	    uint32_t active = 0;
	    if (!sieve_list) goto parse_err;
	    if (!dlist_getatom(kl, "FILENAME", &filename)) goto parse_err;
	    if (!dlist_getdate(kl, "LAST_UPDATE", &modtime)) goto parse_err;
	    dlist_getnum(kl, "ISACTIVE", &active); /* optional */
	    sync_sieve_list_add(sieve_list, filename, modtime, active);
	}

	else if (!strcmp(kl->name, "QUOTA")) {
	    const char *root = NULL;
	    uint32_t limit = 0;
	    if (!quota_list) goto parse_err;
	    if (!dlist_getatom(kl, "ROOT", &root)) goto parse_err;
	    if (!dlist_getnum(kl, "LIMIT", &limit)) goto parse_err;
	    sync_quota_list_add(quota_list, root, limit);
	}

	else if (!strcmp(kl->name, "LSUB")) {
	    struct dlist *i;
	    if (!sub_list) goto parse_err;
	    for (i = kl->head; i; i = i->next) {
		sync_name_list_add(sub_list, i->sval);
	    }
	}

	else if (!strcmp(kl->name, "SEEN")) {
	    const char *uniqueid = NULL;
	    time_t lastread = 0;
	    uint32_t lastuid = 0;
	    time_t lastchange = 0;
	    const char *seenuids = NULL;
	    if (!seen_list) goto parse_err;
	    if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) goto parse_err;
	    if (!dlist_getdate(kl, "LASTREAD", &lastread)) goto parse_err;
	    if (!dlist_getnum(kl, "LASTUID", &lastuid)) goto parse_err;
	    if (!dlist_getdate(kl, "LASTCHANGE", &lastchange)) goto parse_err;
	    if (!dlist_getatom(kl, "SEENUIDS", &seenuids)) goto parse_err;
	    sync_seen_list_add(seen_list, uniqueid, lastread,
			       lastuid, lastchange, seenuids);
	}

	else if (!strcmp(kl->name, "MAILBOX")) {
	    const char *uniqueid = NULL;
	    const char *mboxname = NULL;
	    const char *mboxtype = NULL;
	    const char *part = NULL;
	    const char *acl = NULL;
	    const char *options = NULL;
	    modseq_t highestmodseq = 0;
	    uint32_t uidvalidity = 0;
	    uint32_t last_uid = 0;
	    uint32_t sync_crc = 0;
	    uint32_t recentuid = 0;
	    time_t recenttime = 0;
	    time_t pop3_last_login = 0;
	    if (!folder_list) goto parse_err;
	    if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) goto parse_err;
	    if (!dlist_getatom(kl, "MBOXNAME", &mboxname)) goto parse_err;
	    if (!dlist_getatom(kl, "PARTITION", &part)) goto parse_err;
	    if (!dlist_getatom(kl, "ACL", &acl)) goto parse_err;
	    if (!dlist_getatom(kl, "OPTIONS", &options)) goto parse_err;
	    if (!dlist_getmodseq(kl, "HIGHESTMODSEQ", &highestmodseq)) goto parse_err;
	    if (!dlist_getnum(kl, "UIDVALIDITY", &uidvalidity)) goto parse_err;
	    if (!dlist_getnum(kl, "LAST_UID", &last_uid)) goto parse_err;
	    if (!dlist_getnum(kl, "SYNC_CRC", &sync_crc)) goto parse_err;
	    if (!dlist_getnum(kl, "RECENTUID", &recentuid)) goto parse_err;
	    if (!dlist_getdate(kl, "RECENTTIME", &recenttime)) goto parse_err;
	    if (!dlist_getdate(kl, "POP3_LAST_LOGIN", &pop3_last_login)) goto parse_err;
	    /* optional */
	    dlist_getatom(kl, "MBOXTYPE", &mboxtype);

	    sync_folder_list_add(folder_list, uniqueid, mboxname,
				 mboxlist_string_to_mbtype(mboxtype),
				 part, acl,
				 sync_parse_options(options),
				 uidvalidity, last_uid, 
				 highestmodseq, sync_crc,
				 recentuid, recenttime,
				 pop3_last_login);
	}
	else
	    goto parse_err;
    }
    dlist_free(&kin);

    return r;

 parse_err:
    dlist_free(&kin);
    syslog(LOG_ERR, "SYNCERROR: %s: Invalid response %s",
	   cmd, dlist_lastkey());
    return IMAP_PROTOCOL_BAD_PARAMETERS;
}

static int user_reset(char *userid, struct backend *sync_be)
{
    const char *cmd = "UNUSER";
    struct dlist *kl;

    kl = dlist_atom(NULL, cmd, userid);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int folder_rename(char *oldname, char *newname, char *partition,
			 struct backend *sync_be, unsigned flags)
{
    const char *cmd = (flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_RENAME" : "RENAME";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "OLDMBOXNAME", oldname);
    dlist_atom(kl, "NEWMBOXNAME", newname);
    dlist_atom(kl, "PARTITION", partition);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

int sync_folder_delete(char *mboxname, struct backend *sync_be, unsigned flags)
{
    const char *cmd =
	(flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_UNMAILBOX" :"UNMAILBOX";
    struct dlist *kl;

    kl = dlist_atom(NULL, cmd, mboxname);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

int sync_set_sub(const char *userid, const char *mboxname, int add,
		 struct backend *sync_be, unsigned flags)
{
    const char *cmd = add ? "SUB" : "UNSUB";
    struct dlist *kl;

    if (flags & SYNC_FLAG_VERBOSE) 
        printf("%s %s %s\n", cmd, userid, mboxname);

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s", cmd, userid, mboxname);

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "MBOXNAME", mboxname);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int folder_setannotation(const char *mboxname, const char *entry,
				const char *userid, const char *value,
				struct backend *sync_be)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "MBOXNAME", mboxname);
    dlist_atom(kl, "ENTRY", entry);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "VALUE", value);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int folder_unannotation(const char *mboxname, const char *entry,
				   const char *userid,
				   struct backend *sync_be)
{
    const char *cmd = "UNANNOTATION";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "MBOXNAME", mboxname);
    dlist_atom(kl, "ENTRY", entry);
    dlist_atom(kl, "USERID", userid);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

/* ====================================================================== */

static int sieve_upload(const char *userid, const char *filename,
			unsigned long last_update,
			struct backend *sync_be)
{
    const char *cmd = "SIEVE";
    struct dlist *kl;
    char *sieve;
    uint32_t size;

    sieve = sync_sieve_read(userid, filename, &size);
    if (!sieve) return IMAP_IOERROR;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    dlist_date(kl, "LAST_UPDATE", last_update);
    dlist_buf(kl, "CONTENT", sieve, size);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);
    free(sieve);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int sieve_delete(const char *userid, const char *filename,
			struct backend *sync_be)
{
    const char *cmd = "UNSIEVE";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int sieve_activate(const char *userid, const char *filename,
			  struct backend *sync_be)
{
    const char *cmd = "ACTIVATE_SIEVE";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int sieve_deactivate(const char *userid,
			    struct backend *sync_be)
{
    const char *cmd = "UNACTIVATE_SIEVE";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

/* ====================================================================== */

static int delete_quota(const char *root, struct backend *sync_be)
{
    const char *cmd = "UNQUOTA";
    struct dlist *kl;

    kl = dlist_atom(NULL, cmd, root);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int update_quota_work(struct quota *client,
			     struct sync_quota *server,
			     struct backend *sync_be)
{
    const char *cmd = "QUOTA";
    struct dlist *kl;
    int r;

    r = quota_read(client, NULL, 0);

    /* disappeared?  Delete it*/
    if (r == IMAP_QUOTAROOT_NONEXISTENT)
        return delete_quota(client->root, sync_be);

    if (r) {
        syslog(LOG_INFO, "Warning: failed to read quotaroot %s: %s",
               client->root, error_message(r));
        return r;
    }

    if (server && (client->limit == server->limit))
        return(0);

    kl = dlist_new(cmd);
    dlist_atom(kl, "ROOT", client->root);
    dlist_num(kl, "LIMIT", client->limit);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int copy_local(struct mailbox *mailbox, unsigned long uid)
{
    uint32_t recno;
    struct index_record oldrecord;
    int r;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &oldrecord);
	if (r) return r;

	/* found the record, renumber it */
	if (oldrecord.uid == uid) {
	    char *oldfname, *newfname;
	    struct index_record newrecord;

	    /* create the new record as a clone of the old record */
	    newrecord = oldrecord;
	    newrecord.uid = mailbox->i.last_uid + 1;

	    /* copy the file in to place */
	    oldfname = xstrdup(mailbox_message_fname(mailbox, oldrecord.uid));
	    newfname = xstrdup(mailbox_message_fname(mailbox, newrecord.uid));
	    r = mailbox_copyfile(oldfname, newfname, 0);
	    free(oldfname);
	    free(newfname);
	    if (r) return r;

	    /* append the new record */
	    r = mailbox_append_index_record(mailbox, &newrecord);
	    if (r) return r;

	    /* and expunge the old record */
	    oldrecord.system_flags |= FLAG_EXPUNGED;
	    r = mailbox_rewrite_index_record(mailbox, &oldrecord);

	    /* done - return */
	    return r;
	}
    }

    /* not finding the record is an error! (should never happen) */
    return IMAP_MAILBOX_NONEXISTENT;
}

static int fetch_file(struct mailbox *mailbox, unsigned long uid,
		      struct index_record *rp,
		      struct backend *sync_be)
{
    const char *cmd = "FETCH";
    struct dlist *kin = NULL;
    struct dlist *kl;
    int r = 0;
    const char *fname = dlist_reserve_path(mailbox->part, &rp->guid);
    struct stat sbuf;

    /* already reserved? great */
    if (stat(fname, &sbuf) == 0)
	return 0;

    kl = dlist_new(cmd);
    dlist_atom(kl, "MBOXNAME", mailbox->name);
    dlist_atom(kl, "PARTITION", mailbox->part);
    dlist_atom(kl, "GUID", message_guid_encode(&rp->guid));
    dlist_num(kl, "UID", uid);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_be->in, &kin);
    if (r) return r;

    kl = kin->head;
    if (!kl) {
	r = IMAP_MAILBOX_NONEXISTENT;
	goto done;
    }

    if (!message_guid_equal(&kl->gval, &rp->guid))
	r = IMAP_MAILBOX_CRC;

done:
    dlist_free(&kin);
    return r;
}

static int copy_remote(struct mailbox *mailbox, unsigned long uid,
		       struct dlist *kr)
{
    struct index_record record;
    struct dlist *ki;
    int r;

    for (ki = kr->head; ki; ki = ki->next) {
	r = parse_upload(ki, mailbox, &record);
	if (r) return r;
	if (record.uid == uid) {
	    /* choose the destination UID */
	    record.uid = mailbox->i.last_uid + 1;

	    /* already fetched the file in the parse phase */

	    /* append the file */
	    r = sync_append_copyfile(mailbox, &record);

	    return r;
	}
    }
    /* not finding the record is an error! (should never happen) */
    return IMAP_MAILBOX_NONEXISTENT;
}

static int copyback_one_record(struct mailbox *mailbox,
			       struct index_record *rp,
			       struct dlist *kaction,
			       struct backend *sync_be)
{
    int r;

    /* don't want to copy back expunged records! */
    if (rp->system_flags & FLAG_EXPUNGED)
	return 0;

    /* if the UID is lower than master's last_uid,
     * we'll need to renumber */
    if (rp->uid <= mailbox->i.last_uid) {
	/* Ok, now we need to check if it's just really stale
	 * (has been cleaned out locally) or an error.
	 * In the error case we copy back, stale
	 * we remove from the replica */
	if (rp->modseq < mailbox->i.deletedmodseq) {
	    if (kaction)
		dlist_num(kaction, "EXPUNGE", rp->uid);
	}
	else {
	    r = fetch_file(mailbox, rp->uid, rp, sync_be);
	    if (r) return r;
	    if (kaction)
		dlist_num(kaction, "COPYBACK", rp->uid);
	}
    }

    /* otherwise we can pull it in with the same UID,
     * which saves causing renumbering on the replica
     * end, so is preferable */
    else {
	/* grab the file */
	r = fetch_file(mailbox, rp->uid, rp, sync_be);
	if (r) return r;
	/* make sure we're actually making changes now */
	if (!kaction) return 0;
	/* append the file */
	r = sync_append_copyfile(mailbox, rp);
	if (r) return r;
    }

    return 0;
}

static int renumber_one_record(struct index_record *mp,
			       struct dlist *kaction)
{
    /* don't want to renumber expunged records */
    if (mp->system_flags & FLAG_EXPUNGED)
	return 0;

    if (kaction)
	dlist_num(kaction, "RENUMBER", mp->uid);

    return 0;
}

static const char *make_flags(struct mailbox *mailbox, struct index_record *record)
{
    static char buf[4096];
    const char *sep = "";
    int flag;

    if (record->system_flags & FLAG_DELETED) {
	snprintf(buf, 4096, "%s\\Deleted", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_ANSWERED) {
	snprintf(buf, 4096, "%s\\Answered", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_FLAGGED) {
	snprintf(buf, 4096, "%s\\Flagged", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_DRAFT) {
	snprintf(buf, 4096, "%s\\Draft", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_EXPUNGED) {
	snprintf(buf, 4096, "%s\\Expunged", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_SEEN) {
	snprintf(buf, 4096, "%s\\Seen", sep);
        sep = " ";
    }
        
    /* print user flags in mailbox order */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(record->user_flags[flag/32] & (1<<(flag&31))))
	    continue;
	snprintf(buf, 4096, "%s%s", sep, mailbox->flagname[flag]);
        sep = " ";
    }

    return buf;
}

static void log_record(const char *name, struct mailbox *mailbox,
		       struct index_record *record)
{
    syslog(LOG_NOTICE, "SYNCNOTICE: %s uid:%u modseq:" MODSEQ_FMT " "
	  "last_updated:%lu internaldate:%lu flags:(%s)",
	   name, record->uid, record->modseq,
	   record->last_updated, record->internaldate,
	   make_flags(mailbox, record));
}

static void log_mismatch(const char *reason, struct mailbox *mailbox,
			 struct index_record *mp,
			 struct index_record *rp)
{
    syslog(LOG_NOTICE, "SYNCNOTICE: record mismatch with replica: %s %s",
	   mailbox->name, reason);
    log_record("master", mailbox, mp);
    log_record("replica", mailbox, rp);
}

static int compare_one_record(struct mailbox *mailbox,
			      struct index_record *mp,
			      struct index_record *rp,
			      struct dlist *kaction,
			      struct backend *sync_be)
{
    int diff = 0;
    int i;
    int r;

    /* are there any differences? */
    if (mp->modseq != rp->modseq)
	diff = 1;
    else if (mp->last_updated != rp->last_updated)
	diff = 1;
    else if (mp->internaldate != rp->internaldate)
	diff = 1;
    else if (mp->system_flags != rp->system_flags)
	diff = 1;
    else if (!message_guid_equal(&mp->guid, &rp->guid))
	diff = 1;
    else {
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    if (mp->user_flags[i] != rp->user_flags[i])
		diff = 1;
	}
    }

    /* if differences we'll have to rewrite to bump the modseq
     * so that regular replication will cause an update */
    if (diff) {
	/* interesting case - expunged locally */
	if (mp->system_flags & FLAG_EXPUNGED) {
	    /* if expunged, fall through - the rewrite will lift
	     * the modseq to force the change to stick */
	}
	else if (rp->system_flags & FLAG_EXPUNGED) {
	    /* mark expunged - rewrite will cause both sides to agree
	     * again */
	    mp->system_flags |= FLAG_EXPUNGED;
	}

	/* general case */
	else {
	    if (!message_guid_equal(&mp->guid, &rp->guid)) {
		char *mguid = xstrdup(message_guid_encode(&mp->guid));
		char *rguid = xstrdup(message_guid_encode(&rp->guid));
		syslog(LOG_ERR, "SYNCERROR: guid mismatch %s %u (%s %s)",
		       mailbox->name, mp->uid, rguid, mguid);
		free(rguid);
		free(mguid);
		/* we will need to renumber both ends to get in sync */

		/* ORDERING - always lower GUID first */
		if (message_guid_cmp(&mp->guid, &rp->guid) < 0) {
		    r = copyback_one_record(mailbox, rp, kaction,
					    sync_be);
		    if (!r) r = renumber_one_record(mp, kaction);
		}
		else {
		    r = renumber_one_record(mp, kaction);
		    if (!r) r = copyback_one_record(mailbox, rp, kaction,
						    sync_be);
		}

		return r;
	    }

	    /* is the replica "newer"? */
	    if (rp->modseq > mp->modseq &&
		rp->last_updated >= mp->last_updated) {
		/* then copy all the flag data over from the replica */
		mp->system_flags = rp->system_flags;
		for (i = 0; i < MAX_USER_FLAGS/32; i++) 
		    mp->user_flags[i] = rp->user_flags[i];

		log_mismatch("more recent on replica", mailbox, mp, rp);
	    }
	    else {
		log_mismatch("more recent on master", mailbox, mp, rp);
	    }
	}

	/* are we making changes yet? */
	if (!kaction) return 0;

	/* this will bump the modseq and force a resync either way :) */
	r = mailbox_rewrite_index_record(mailbox, mp);
	if (r) return r;
    }

    return 0;
}


static int mailbox_update_loop(struct mailbox *mailbox,
			       struct dlist *ki,
			       uint32_t last_uid,
			       modseq_t highestmodseq,
			       struct dlist *kaction,
			       struct backend *sync_be)
{
    struct index_record mrecord;
    struct index_record rrecord;
    uint32_t recno = 1;
    uint32_t old_num_records = mailbox->i.num_records;
    int r;

    /* while there are more records on either master OR replica,
     * work out what to do with them */
    while (ki || recno <= old_num_records) {
	/* most common case - both a master AND a replica record exist */
	if (ki && recno <= old_num_records) {
	    r = mailbox_read_index_record(mailbox, recno, &mrecord);
	    if (r) return r;
	    r = parse_upload(ki, mailbox, &rrecord);
	    if (r) return r;

	    /* same UID - compare the records */
	    if (rrecord.uid == mrecord.uid) {
		r = compare_one_record(mailbox, &mrecord, &rrecord, kaction,
				       sync_be);
		if (r) return r;
		/* increment both */
		recno++;
		ki = ki->next;
	    }
	    else if (rrecord.uid > mrecord.uid) {
		/* record only exists on the master */
		if (!(mrecord.system_flags & FLAG_EXPUNGED)) {
		    syslog(LOG_ERR, "SYNCERROR: only exists on master %s %u (%s)",
			   mailbox->name, mrecord.uid,
			   message_guid_encode(&mrecord.guid));
		    r = renumber_one_record(&mrecord, kaction);
		    if (r) return r;
		}
		/* only increment master */
		recno++;
	    }
	    else {
		/* record only exists on the replica */
		if (!(rrecord.system_flags & FLAG_EXPUNGED)) {
		    if (kaction)
			syslog(LOG_ERR, "SYNCERROR: only exists on replica %s %u (%s)",
			       mailbox->name, rrecord.uid,
			       message_guid_encode(&rrecord.guid));
		    r = copyback_one_record(mailbox, &rrecord, kaction,
					    sync_be);
		    if (r) return r;
		}
		/* only increment replica */
		ki = ki->next;
	    }
	}

	/* no more replica records, but still master records */
	else if (recno <= old_num_records) {
	    r = mailbox_read_index_record(mailbox, recno, &mrecord);
	    if (r) return r;
	    /* if the replica has seen this UID, we need to renumber.
	     * Otherwise it will replicate fine as-is */
	    if (mrecord.uid <= last_uid) {
		r = renumber_one_record(&mrecord, kaction);
		if (r) return r;
	    }
	    else if (mrecord.modseq <= highestmodseq) {
		if (kaction) {
		    /* bump our modseq so we sync */
		    syslog(LOG_NOTICE, "SYNCNOTICE: bumping modseq %s %u",
			   mailbox->name, mrecord.uid);
		    r = mailbox_rewrite_index_record(mailbox, &mrecord);
		    if (r) return r;
		}
	    }
	    recno++;
	}

	/* record only exists on the replica */
	else {
	    r = parse_upload(ki, mailbox, &rrecord);
	    if (r) return r;

	    if (kaction)
		syslog(LOG_NOTICE, "SYNCNOTICE: only on replica %s %u",
		       mailbox->name, rrecord.uid);

	    /* going to need this one */
	    r = copyback_one_record(mailbox, &rrecord, kaction, sync_be);
	    if (r) return r;

	    ki = ki->next;
	}
    }

    return 0;
}

static int mailbox_full_update(struct sync_folder *local,
			       struct backend *sync_be,
			       unsigned flags)
{
    const char *cmd = "FULLMAILBOX";
    struct mailbox *mailbox = NULL;
    int r;
    struct dlist *kin = NULL;
    struct dlist *kr = NULL;
    struct dlist *ka = NULL;
    struct dlist *kuids = NULL;
    struct dlist *kl = NULL;
    struct dlist *kaction = NULL;
    struct dlist *kexpunge = NULL;
    modseq_t highestmodseq;
    uint32_t uidvalidity;
    uint32_t last_uid;

    if (flags & SYNC_FLAG_LOGGING) {
	syslog(LOG_INFO, "%s %s", cmd, local->name);
    }

    kl = dlist_atom(NULL, cmd, local->name);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_be->in, &kin);
    if (r) return r;

    kl = kin->head;

    if (!kl) {
	r = IMAP_MAILBOX_NONEXISTENT;
	goto done;
    }

    /* XXX - handle the header.  I want to do some ordering on timestamps
     * in particular here - if there's more recent data on the replica then
     * it should be copied back.  This depends on having a nice way to
     * parse the mailbox structure back in to a struct index_header rather
     * than the by hand stuff though, because that sucks.  NOTE - this
     * doesn't really matter too much, because we'll blat the replica's
     * values anyway! */

    if (!dlist_getmodseq(kl, "HIGHESTMODSEQ", &highestmodseq)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    if (!dlist_getnum(kl, "UIDVALIDITY", &uidvalidity)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    if (!dlist_getnum(kl, "LAST_UID", &last_uid)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    if (!dlist_getlist(kl, "RECORD", &kr)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    /* we'll be updating it! */
    if (local->mailbox) mailbox = local->mailbox;
    else r = mailbox_open_iwl(local->name, &mailbox);
    if (r) goto done;

    /* re-calculate our local CRC just in case it's out of sync */
    r = mailbox_index_recalc(mailbox);
    if (r) goto done;

    /* if local UIDVALIDITY is lower, copy from remote, otherwise
     * remote will copy ours when we sync */
    if (mailbox->i.uidvalidity < uidvalidity) {
	syslog(LOG_NOTICE, "SYNCNOTICE: uidvalidity higher on replica %s"
	       ", updating %u => %u",
	       mailbox->name, mailbox->i.uidvalidity, uidvalidity);
	mailbox_index_dirty(mailbox);
	mailbox->i.uidvalidity = uidvalidity;
    }

    if (mailbox->i.highestmodseq < highestmodseq) {
	mailbox_modseq_dirty(mailbox);
	/* highestmodseq on replica is dirty - we must go to at least 
	 * one higher! */
	syslog(LOG_NOTICE, "SYNCNOTICE: highestmodseq higher on replica %s"
	       ", updating " MODSEQ_FMT " => " MODSEQ_FMT,
	       mailbox->name, mailbox->i.highestmodseq, highestmodseq+1);
	mailbox->i.highestmodseq = highestmodseq+1;
    }

    r = mailbox_update_loop(mailbox, kr->head, last_uid,
			    highestmodseq, NULL, sync_be);
    if (r) {
	syslog(LOG_ERR, "SYNCNOTICE: failed to prepare update for %s: %s",
	       mailbox->name, error_message(r));
	goto done;
    }

    /* OK - now we're committed to make changes! */

    kaction = dlist_list(NULL, "ACTION");
    r = mailbox_update_loop(mailbox, kr->head, last_uid,
			    highestmodseq, kaction, sync_be);
    if (r) goto cleanup;

    /* if replica still has a higher last_uid, bump our local
     * number to match so future records don't clash */
    if (mailbox->i.last_uid < last_uid)
        mailbox->i.last_uid = last_uid;

    /* blatant reuse 'r' us */
    kexpunge = dlist_new("EXPUNGE");
    dlist_atom(kexpunge, "MBOXNAME", mailbox->name);
    dlist_atom(kexpunge, "UNIQUEID", mailbox->uniqueid); /* just for safety */
    kuids = dlist_list(kexpunge, "UID");
    for (ka = kaction->head; ka; ka = ka->next) {
	if (!strcmp(ka->name, "EXPUNGE")) {
	    dlist_num(kuids, "UID", ka->nval);
	}
	else if (!strcmp(ka->name, "COPYBACK")) {
	    r = copy_remote(mailbox, ka->nval, kr);
	    if (r) goto cleanup;
	    dlist_num(kuids, "UID", ka->nval);
	}
	else if (!strcmp(ka->name, "RENUMBER")) {
	    r = copy_local(mailbox, ka->nval);
	    if (r) goto cleanup;
	}
    }

    /* we still need to do the EXPUNGEs */
 cleanup:

    /* close the mailbox before sending any expunges
     * to avoid deadlocks */
    if (!local->mailbox) mailbox_close(&mailbox);

    /* only send expunge if we have some UIDs to expunge */
    if (kuids->head) {
	int r2;
	sync_send_apply(kexpunge, sync_be->out);
	r2 = sync_parse_response("EXPUNGE", sync_be->in, NULL);
	if (r2) {
	    syslog(LOG_ERR, "SYNCERROR: failed to expunge in cleanup %s",
		   local->name);
	}
    }

done:
    if (mailbox && !local->mailbox) mailbox_close(&mailbox);
    dlist_free(&kin);
    dlist_free(&kaction);
    dlist_free(&kexpunge);
    return r;
}

static int is_unchanged(struct mailbox *mailbox, struct sync_folder *remote)
{
    /* look for any mismatches */
    unsigned options = mailbox->i.options & MAILBOX_OPTIONS_MASK;
    if (!remote) return 0;
    if (remote->mbtype != (uint32_t) mailbox->mbtype) return 0;
    if (remote->last_uid != mailbox->i.last_uid) return 0;
    if (remote->highestmodseq != mailbox->i.highestmodseq) return 0;
    if (remote->sync_crc != mailbox->i.sync_crc) return 0;
    if (remote->recentuid != mailbox->i.recentuid) return 0;
    if (remote->recenttime != mailbox->i.recenttime) return 0;
    if (remote->pop3_last_login != mailbox->i.pop3_last_login) return 0;
    if (remote->options != options) return 0;
    if (strcmp(remote->acl, mailbox->acl)) return 0;

    /* otherwise it's unchanged! */
    return 1;
}

#define SYNC_FLAG_ISREPEAT	(1<<15)

static int update_mailbox_once(struct sync_folder *local,
			       struct sync_folder *remote,
			       const char *topart,
			       struct sync_reserve_list *reserve_guids,
			       struct backend *sync_be, unsigned flags)
{
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox = NULL;
    int r = 0;
    const char *cmd =
	(flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_MAILBOX" : "MAILBOX";
    struct dlist *kl = dlist_new(cmd);
    struct dlist *kupload = dlist_list(NULL, "MESSAGE");

    if (flags & SYNC_FLAG_LOGGING) {
	syslog(LOG_INFO, "%s %s", cmd, local->name);
    }

    if (local->mailbox) mailbox = local->mailbox;
    else r = mailbox_open_irl(local->name, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* been deleted in the meanwhile... */
	if (remote)
	    r = sync_folder_delete(remote->name, sync_be, flags);
	else
	    r = 0;
	goto done;
    }
    else if (r)
	goto done;

    /* definitely bad if these don't match! */
    if (strcmp(mailbox->uniqueid, local->uniqueid) ||
	strcmp(mailbox->part, local->part)) {
	r = IMAP_MAILBOX_MOVED;
	goto done;
    }

    /* check that replication stands a chance of succeeding */
    if (remote && !(flags & SYNC_FLAG_ISREPEAT)) {
	if (mailbox->i.deletedmodseq > remote->highestmodseq) {
	    syslog(LOG_NOTICE, "inefficient replication ("
		   MODSEQ_FMT " > " MODSEQ_FMT ") %s", 
		   mailbox->i.deletedmodseq, remote->highestmodseq,
		   local->name);
	    r = IMAP_AGAIN;
	    goto done;
	}
	/* need a full sync to fix uidvalidity issues so we get a
	 * writelocked mailbox */
	if (mailbox->i.uidvalidity < remote->uidvalidity) {
	    r = IMAP_AGAIN;
	    goto done;
	}
    }

    /* nothing changed - nothing to send */
    if (is_unchanged(mailbox, remote))
	goto done;

    if (!topart) topart = mailbox->part;
    part_list = sync_reserve_partlist(reserve_guids, topart);
    r = sync_mailbox(mailbox, remote, topart, part_list, kl, kupload, 1);
    if (r) goto done;

    /* upload any messages required */
    if (kupload->head) {
	/* keep the mailbox locked for shorter time! Unlock the index now
	 * but don't close it, because we need to guarantee that message 
	 * files don't get deleted until we're finished with them... */
	if (!local->mailbox) mailbox_unlock_index(mailbox, NULL);
	sync_send_apply(kupload, sync_be->out);
	r = sync_parse_response("MESSAGE", sync_be->in, NULL);
	if (!r) {
	    /* update our list of reserved messages on the replica */
	    struct dlist *ki;
	    struct sync_msgid *msgid;
	    for (ki = kupload->head; ki; ki = ki->next) {
		msgid = sync_msgid_lookup(part_list, &ki->gval);
		if (!msgid)
		    msgid = sync_msgid_add(part_list, &ki->gval);
		msgid->mark = 1;
		part_list->marked++; 
	    }
	}
    }

    /* close before sending the apply - all data is already read */
    if (!local->mailbox) mailbox_close(&mailbox);

    /* update the mailbox */
    sync_send_apply(kl, sync_be->out);
    r = sync_parse_response("MAILBOX", sync_be->in, NULL);

done:
    if (mailbox && !local->mailbox) mailbox_close(&mailbox);
    dlist_free(&kupload);
    dlist_free(&kl);
    return r;
}

int sync_update_mailbox(struct sync_folder *local,
			struct sync_folder *remote,
			const char *topart,
			struct sync_reserve_list *reserve_guids,
			struct backend *sync_be, unsigned flags)
{
    int r = update_mailbox_once(local, remote, topart,
				reserve_guids, sync_be, flags);

    flags |= SYNC_FLAG_ISREPEAT;

    if (r == IMAP_AGAIN) {
	r = mailbox_full_update(local, sync_be, flags);
	if (!r) r = update_mailbox_once(local, remote, topart,
					reserve_guids, sync_be, flags);
    }
    else if (r == IMAP_MAILBOX_CRC) {
	syslog(LOG_ERR, "CRC failure on sync for %s, trying full update",
	       local->name);
	r = mailbox_full_update(local, sync_be, flags);
	if (!r) r = update_mailbox_once(local, remote, topart,
					reserve_guids, sync_be, flags);
    }

    return r;
}

/* ====================================================================== */


static int update_seen_work(const char *user, const char *uniqueid,
			    struct seendata *sd,
			    struct backend *sync_be)
{
    const char *cmd = "SEEN";
    struct dlist *kl;

    /* Update seen list */
    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", user);
    dlist_atom(kl, "UNIQUEID", uniqueid);
    dlist_date(kl, "LASTREAD", sd->lastread);
    dlist_num(kl, "LASTUID", sd->lastuid);
    dlist_date(kl, "LASTCHANGE", sd->lastchange);
    dlist_atom(kl, "SEENUIDS", sd->seenuids);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

int sync_do_seen(char *user, char *uniqueid, struct backend *sync_be,
		 unsigned flags)
{
    int r = 0;
    struct seen *seendb = NULL;
    struct seendata sd = SEENDATA_INITIALIZER;

    if (flags & SYNC_FLAG_VERBOSE) 
        printf("SEEN %s %s\n", user, uniqueid);

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "SEEN %s %s", user, uniqueid);

    /* ignore read failures */
    r = seen_open(user, SEEN_SILENT, &seendb);
    if (r) return 0;

    r = seen_read(seendb, uniqueid, &sd);

    if (!r) r = update_seen_work(user, uniqueid, &sd, sync_be);

    seen_close(&seendb);
    seen_freedata(&sd);

    return r;
}

/* ====================================================================== */

int sync_do_quota(const char *root, struct backend *sync_be,
		  unsigned flags)
{
    int r = 0;
    struct quota q;

    if (flags & SYNC_FLAG_VERBOSE) 
        printf("SETQUOTA %s\n", root);

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "SETQUOTA: %s", root);

    q.root = root;
    r = update_quota_work(&q, NULL, sync_be);

    return r;
}

static int do_annotation_cb(const char *mailbox __attribute__((unused)),
			    const char *entry, const char *userid,
			    struct annotation_data *attrib, void *rock)
{
    struct sync_annot_list *l = (struct sync_annot_list *) rock;

    sync_annot_list_add(l, entry, userid, attrib->value);

    return 0;
}

static int parse_annotation(struct dlist *kin,
			    struct sync_annot_list *replica_annot)
{
    struct dlist *kl;
    const char *entry;
    const char *userid;
    const char *value;

    for (kl = kin->head; kl; kl = kl->next) {
	if (!dlist_getatom(kl, "ENTRY", &entry))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getatom(kl, "USERID", &userid))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getatom(kl, "VALUE", &value))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	sync_annot_list_add(replica_annot, entry, userid, value);
    }

    return 0;
}

static int do_getannotation(char *mboxname,
			    struct sync_annot_list *replica_annot,
			    struct backend *sync_be)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;
    struct dlist *kin = NULL;
    int r;

    /* Update seen list */
    kl = dlist_atom(NULL, cmd, mboxname);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_be->in, &kin);
    if (r) return r;

    r = parse_annotation(kin, replica_annot);
    dlist_free(&kin);

    return r;
}

int sync_do_annotation(char *mboxname, struct backend *sync_be,
		       unsigned flags __attribute__((unused)))
{
    int r;
    struct sync_annot_list *replica_annot = sync_annot_list_create();
    struct sync_annot_list *master_annot = sync_annot_list_create();
    struct sync_annot *ma, *ra;
    int n;

    r = do_getannotation(mboxname, replica_annot, sync_be);
    if (r) goto bail;

    r = annotatemore_findall(mboxname, "*",
			     &do_annotation_cb, master_annot, NULL);
    if (r) {
	syslog(LOG_ERR, "IOERROR: fetching annotations for %s", mboxname);
	r = IMAP_IOERROR;
	goto bail;
    }

    /* both lists are sorted, so we work our way through the lists
       top-to-bottom and determine what we need to do based on order */
    ma = master_annot->head;
    ra = replica_annot->head;
    while (ma || ra) {
	if (!ra) n = -1;		/* add all master annotations */
	else if (!ma) n = 1;		/* remove all replica annotations */
	else if ((n = strcmp(ma->entry, ra->entry)) == 0)
	    n = strcmp(ma->userid, ra->userid);

	if (n > 0) {
	    /* remove replica annotation */
	    r = folder_unannotation(mboxname, ra->entry, ra->userid, sync_be);
	    if (r) goto bail;
	    ra = ra->next;
	    continue;
	}

	if (n == 0) {
	    /* already have the annotation, but is the value different? */
	    if (!strcmp(ra->value, ma->value)) {
		ra = ra->next;
		ma = ma->next;
		continue;
	    }
	    ra = ra->next;
	}

	/* add the current client annotation */
	r = folder_setannotation(mboxname, ma->entry, ma->userid, ma->value,
				 sync_be);
	if (r) goto bail;

	ma = ma->next;
    }

bail:
    sync_annot_list_free(&master_annot);
    sync_annot_list_free(&replica_annot);
    return r;
}

/* ====================================================================== */

static int do_folders(struct sync_name_list *mboxname_list, const char *topart,
		      struct sync_folder_list *replica_folders,
		      struct backend *sync_be,
		      unsigned flags)
{
    int r;
    struct sync_folder_list *master_folders;
    struct sync_rename_list *rename_folders;
    struct sync_reserve_list *reserve_guids;
    struct sync_folder *mfolder, *rfolder;
    const char *part;

    master_folders = sync_folder_list_create();
    rename_folders = sync_rename_list_create();
    reserve_guids = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    r = reserve_messages(mboxname_list, topart, master_folders,
			 replica_folders, reserve_guids, sync_be);
    if (r) {
	syslog(LOG_ERR, "reserve messages: failed: %s", error_message(r));
	goto bail;
    }

    /* Tag folders on server which still exist on the client. Anything
     * on the server which remains untagged can be deleted immediately */
    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
	rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
	if (!rfolder) continue;
	rfolder->mark = 1;

	/* does it need a rename? */
	part = topart ? topart : mfolder->part;
	if (strcmp(mfolder->name, rfolder->name) || strcmp(part, rfolder->part))
	    sync_rename_list_add(rename_folders, mfolder->uniqueid, rfolder->name, 
				 mfolder->name, part);
    }

    /* Delete folders on server which no longer exist on client */
    for (rfolder = replica_folders->head; rfolder; rfolder = rfolder->next) {
	if (rfolder->mark) continue;
	r = sync_folder_delete(rfolder->name, sync_be, flags);
	if (r) {
	    syslog(LOG_ERR, "sync_folder_delete(): failed: %s '%s'", 
		   rfolder->name, error_message(r));
	    goto bail;
	}
    }

    /* Need to rename folders in an order which avoids dependancy conflicts
     * following isn't wildly efficient, but rename_folders will typically be
     * short and contain few dependancies.  Algorithm is to simply pick a
     * rename operation which has no dependancy and repeat until done */

    while (rename_folders->done < rename_folders->count) {
	int rename_success = 0;
	struct sync_rename *item, *item2;

	for (item = rename_folders->head; item; item = item->next) {
	    if (item->done) continue;

	    /* don't skip rename to different partition */
	    if (strcmp(item->oldname, item->newname)) {
		item2 = sync_rename_lookup(rename_folders, item->newname);
		if (item2 && !item2->done) continue;
	    }

	    /* Found unprocessed item which should rename cleanly */
	    r = folder_rename(item->oldname, item->newname, item->part,
			      sync_be, flags);
	    if (r) {
		syslog(LOG_ERR, "do_folders(): failed to rename: %s -> %s ",
		       item->oldname, item->newname);
		goto bail;
	    }

	    rename_folders->done++;
	    item->done = 1;
	    rename_success = 1;
	}

	if (!rename_success) {
	    /* Scanned entire list without a match */
	    syslog(LOG_ERR,
		   "do_folders(): failed to order folders correctly");
	    r = IMAP_AGAIN;
	    goto bail;
	}
    }

    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
	/* NOTE: rfolder->name may now be wrong, but we're guaranteed that
	 * it was successfully renamed above, so just use mfolder->name for
	 * all commands */
	rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
	r = sync_update_mailbox(mfolder, rfolder, topart, reserve_guids,
				sync_be, flags);
	if (r) {
	    syslog(LOG_ERR, "do_folders(): update failed: %s '%s'", 
		   mfolder->name, error_message(r));
	    goto bail;
	}
    }

 bail:
    sync_folder_list_free(&master_folders);
    sync_rename_list_free(&rename_folders);
    sync_reserve_list_free(&reserve_guids);
    return r;
}

int sync_do_mailboxes(struct sync_name_list *mboxname_list, const char *topart,
		      struct backend *sync_be, unsigned flags)

{
    struct sync_name *mbox;
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct dlist *kl = NULL;
    int r;

    if (flags & SYNC_FLAG_VERBOSE) {
	printf("MAILBOXES");
	for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
	    printf(" %s", mbox->name);
	}
	printf("\n");
    }

    if (flags & SYNC_FLAG_LOGGING) {
	struct buf buf = BUF_INITIALIZER;

	buf_setcstr(&buf, "MAILBOXES");
	for (mbox = mboxname_list->head; mbox; mbox = mbox->next)
	    buf_printf(&buf, " %s", mbox->name);
	syslog(LOG_INFO, "%s", buf_cstring(&buf));
	buf_free(&buf);
    }

    kl = dlist_list(NULL, "MAILBOXES");
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next)
	dlist_atom(kl, "MBOXNAME", mbox->name);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_be->in, "MAILBOXES", replica_folders,
			    NULL, NULL, NULL, NULL);

    if (!r) r = do_folders(mboxname_list, topart,
			   replica_folders, sync_be, flags);

    sync_folder_list_free(&replica_folders);

    return r;
}

/* ====================================================================== */

struct mboxinfo {
    struct sync_name_list *mboxlist;
    struct sync_name_list *quotalist;
};

static int do_mailbox_info(char *name,
			   int matchlen __attribute__((unused)),
			   int maycreate __attribute__((unused)),
			   void *rock)
{
    int r;
    struct mailbox *mailbox = NULL;
    struct mboxinfo *info = (struct mboxinfo *)rock;

    r = mailbox_open_irl(name, &mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT) return 0;
    if (r == IMAP_MAILBOX_RESERVED) return 0;
    if (r) return r;

    if (info->quotalist && mailbox->quotaroot) {
	if (!sync_name_lookup(info->quotalist, mailbox->quotaroot))
	    sync_name_list_add(info->quotalist, mailbox->quotaroot);
    }

    mailbox_close(&mailbox);

    addmbox(name, 0, 0, info->mboxlist);

    return 0;
}

int sync_do_user_quota(struct sync_name_list *master_quotaroots,
		       struct sync_quota_list *replica_quota,
		       struct backend *sync_be)
{
    int r;
    struct sync_name *mitem;
    struct sync_quota *rquota;
    struct quota q;

    /* set any new or changed quotas */
    for (mitem = master_quotaroots->head; mitem; mitem = mitem->next) {
	rquota = sync_quota_lookup(replica_quota, mitem->name);
	q.root = mitem->name;
	if (rquota)
	    rquota->done = 1;
	r = update_quota_work(&q, rquota, sync_be);
	if (r) return r;
    }

    /* delete any quotas no longer on the master */
    for (rquota = replica_quota->head; rquota; rquota = rquota->next) {
	if (rquota->done) continue;
	r = delete_quota(rquota->root, sync_be);
	if (r) return r;
    }

    return 0;
}

static int do_user_main(char *user, const char *topart,
			struct sync_folder_list *replica_folders,
			struct sync_quota_list *replica_quota,
			struct namespace *sync_namespace,
			struct backend *sync_be,
			unsigned flags)
{
    char buf[MAX_MAILBOX_BUFFER];
    int r = 0;
    struct sync_name_list *mboxname_list = sync_name_list_create();
    struct sync_name_list *master_quotaroots = sync_name_list_create();
    struct mboxinfo info;

    info.mboxlist = mboxname_list;
    info.quotalist = master_quotaroots;

    /* Generate full list of folders on client side */
    (*sync_namespace->mboxname_tointernal)(sync_namespace, "INBOX",
					   user, buf);
    do_mailbox_info(buf, 0, 0, &info);

    /* deleted namespace items if enabled */
    if (mboxlist_delayed_delete_isenabled()) {
	char deletedname[MAX_MAILBOX_BUFFER];
	mboxname_todeleted(buf, deletedname, 0);
	strlcat(deletedname, ".*", sizeof(deletedname));
	r = (*sync_namespace->mboxlist_findall)(sync_namespace, deletedname, 1,
						user, NULL, do_mailbox_info,
						&info);
    }

    /* subfolders */
    if (!r) {
	strlcat(buf, ".*", sizeof(buf));
        r = (*sync_namespace->mboxlist_findall)(sync_namespace, buf, 1,
						user, NULL, do_mailbox_info,
						&info);
    }

    if (!r) r = do_folders(mboxname_list, topart,
			   replica_folders, sync_be, flags);
    if (!r) r = sync_do_user_quota(master_quotaroots, replica_quota, sync_be);

    sync_name_list_free(&mboxname_list);
    sync_name_list_free(&master_quotaroots);

    if (r) syslog(LOG_ERR, "IOERROR: %s", error_message(r));

    return r;
}

int sync_do_user_sub(const char *userid, struct sync_name_list *replica_subs,
		     struct backend *sync_be, unsigned flags)
{
    struct sync_name_list *master_subs = sync_name_list_create();
    struct sync_name *msubs, *rsubs;
    int r = 0;

    /* Includes subsiduary nodes automatically */
    r = mboxlist_allsubs(userid, addmbox_sub, master_subs);
    if (r) {
	syslog(LOG_ERR, "IOERROR: fetching subscriptions for %s", userid);
	r = IMAP_IOERROR;
	goto bail;
    }

    /* add any folders that need adding, and mark any which
     * still exist */
    for (msubs = master_subs->head; msubs; msubs = msubs->next) {
	rsubs = sync_name_lookup(replica_subs, msubs->name);
	if (rsubs) {
	    rsubs->mark = 1;
	    continue;
	}
	r = sync_set_sub(userid, msubs->name, 1, sync_be, flags);
	if (r) goto bail;
    }

    /* remove any no-longer-subscribed folders */
    for (rsubs = replica_subs->head; rsubs; rsubs = rsubs->next) {
	if (rsubs->mark)
	    continue;
	r = sync_set_sub(userid, rsubs->name, 0, sync_be, flags);
	if (r) goto bail;
    }

 bail:
    sync_name_list_free(&master_subs);
    return r;
}

static int get_seen(const char *uniqueid, struct seendata *sd, void *rock)
{
    struct sync_seen_list *list = (struct sync_seen_list *)rock;

    sync_seen_list_add(list, uniqueid, sd->lastread, sd->lastuid,
		       sd->lastchange, sd->seenuids);

    return 0;
}

int sync_do_user_seen(char *user, struct sync_seen_list *replica_seen,
		      struct backend *sync_be)
{
    int r;
    struct sync_seen *mseen, *rseen;
    struct seen *seendb = NULL;
    struct sync_seen_list *list;

    /* silently ignore errors */
    r = seen_open(user, SEEN_SILENT, &seendb);
    if (r) return 0;

    list = sync_seen_list_create();

    seen_foreach(seendb, get_seen, list);
    seen_close(&seendb);

    for (mseen = list->head; mseen; mseen = mseen->next) {
	rseen = sync_seen_list_lookup(replica_seen, mseen->uniqueid);
	if (rseen) {
	    rseen->mark = 1;
	    if (seen_compare(&rseen->sd, &mseen->sd))
		continue; /* nothing changed */
	}
	r = update_seen_work(user, mseen->uniqueid, &mseen->sd, sync_be);
    }

    /* XXX - delete seen on the replica for records that don't exist? */

    sync_seen_list_free(&list);

    return 0;
}

int sync_do_user_sieve(char *userid, struct sync_sieve_list *replica_sieve,
		       struct backend *sync_be)
{
    int r = 0;
    struct sync_sieve_list *master_sieve;
    struct sync_sieve *mitem, *ritem;
    int master_active = 0;
    int replica_active = 0;

    master_sieve = sync_sieve_list_generate(userid);
    if (!master_sieve) {
        syslog(LOG_ERR, "Unable to list sieve scripts for %s", userid);
        return IMAP_IOERROR;
    }

    /* Upload missing and out of date scripts */
    for (mitem = master_sieve->head; mitem; mitem = mitem->next) {
        ritem = sync_sieve_lookup(replica_sieve, mitem->name);
	if (ritem) {
	    ritem->mark = 1;
	    if (ritem->last_update >= mitem->last_update)
		continue; /* doesn't need updating */
	}
	r = sieve_upload(userid, mitem->name, mitem->last_update, sync_be);
	if (r) goto bail;
    }

    /* Delete scripts which no longer exist on the master */
    replica_active = 0;
    for (ritem = replica_sieve->head; ritem; ritem = ritem->next) {
	if (ritem->mark) {
	    if (ritem->active)
		replica_active = 1;
	} else {
	    r = sieve_delete(userid, ritem->name, sync_be);
	    if (r) goto bail;
	}
    }

    /* Change active script if necessary */
    master_active = 0;
    for (mitem = master_sieve->head; mitem; mitem = mitem->next) {
	if (!mitem->active)
	    continue;

	master_active = 1;
	ritem = sync_sieve_lookup(replica_sieve, mitem->name);
	if (ritem && ritem->active)
	    break;

	r = sieve_activate(userid, mitem->name, sync_be);
	if (r) goto bail;

	replica_active = 1;
	break;
    }

    if (!master_active && replica_active)
	r = sieve_deactivate(userid, sync_be);

 bail:
    sync_sieve_list_free(&master_sieve);
    return(r);
}

int sync_do_user(char *userid, const char *topart,
		 struct backend *sync_be, unsigned flags)
{
    char buf[MAX_MAILBOX_BUFFER];
    int r = 0;
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct sync_name_list *replica_subs = sync_name_list_create();
    struct sync_sieve_list *replica_sieve = sync_sieve_list_create();
    struct sync_seen_list *replica_seen = sync_seen_list_create();
    struct sync_quota_list *replica_quota = sync_quota_list_create();
    struct dlist *kl = NULL;
    struct mailbox *mailbox = NULL;
    static struct namespace sync_namespace = NAMESPACE_INITIALIZER;

    if (flags & SYNC_FLAG_VERBOSE) 
        printf("USER %s\n", userid);

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "USER %s", userid);

    kl = dlist_atom(NULL, "USER", userid);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_be->in, "USER", replica_folders, replica_subs,
			    replica_sieve, replica_seen, replica_quota);
    /* can happen! */
    if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    if (r) goto done;

    if (!sync_namespace.mboxname_tointernal &&
	(r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
	fatal(error_message(r), EC_CONFIG);
    }

    (*sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					  userid, buf);
    r = mailbox_open_irl(buf, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* user has been removed, RESET server */
	syslog(LOG_ERR, "Inbox missing on master for %s", userid);
	r = user_reset(userid, sync_be);
	goto done;
    }
    if (r) goto done;

    /* we don't hold locks while sending commands */
    mailbox_close(&mailbox);
    r = do_user_main(userid, topart, replica_folders, replica_quota,
		     &sync_namespace, sync_be, flags);
    if (r) goto done;
    r = sync_do_user_sub(userid, replica_subs, sync_be, flags);
    if (r) goto done;
    r = sync_do_user_sieve(userid, replica_sieve, sync_be);
    if (r) goto done;
    r = sync_do_user_seen(userid, replica_seen, sync_be);

done:
    sync_folder_list_free(&replica_folders);
    sync_name_list_free(&replica_subs);
    sync_sieve_list_free(&replica_sieve);
    sync_seen_list_free(&replica_seen);
    sync_quota_list_free(&replica_quota);

    return r;
}

/* ====================================================================== */

int sync_do_meta(char *userid, struct backend *sync_be, unsigned flags)
{
    struct sync_name_list *replica_subs = sync_name_list_create();
    struct sync_sieve_list *replica_sieve = sync_sieve_list_create();
    struct sync_seen_list *replica_seen = sync_seen_list_create();
    struct dlist *kl = NULL;
    int r = 0;

    if (flags & SYNC_FLAG_VERBOSE)
	printf("META %s\n", userid);

    if (flags & SYNC_FLAG_LOGGING)
	syslog(LOG_INFO, "META %s", userid);

    kl = dlist_atom(NULL, "META", userid);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_be->in, "META", NULL,
			    replica_subs, replica_sieve, replica_seen, NULL);
    if (!r) r = sync_do_user_seen(userid, replica_seen, sync_be);
    if (!r) r = sync_do_user_sub(userid, replica_subs, sync_be, flags);
    if (!r) r = sync_do_user_sieve(userid, replica_sieve, sync_be);
    sync_seen_list_free(&replica_seen);
    sync_name_list_free(&replica_subs);
    sync_sieve_list_free(&replica_sieve);

    return r;
}

/* ====================================================================== */
