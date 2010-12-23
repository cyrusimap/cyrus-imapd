/* sync_support.c -- Cyrus synchonization support functions
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
#include "crc32.h"

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
int sync_getline(struct protstream *in, struct buf *buf)
{
    int c;

    buf_reset(buf);

    for (;;) {
	c = prot_getc(in);

	if (c == EOF || (c == '\r') || (c == '\n')) {
	    /* Munch optional LF after CR */
	    if (c == '\r' && ((c = prot_getc(in)) != EOF && c != '\n')) {
		prot_ungetc(c, in);
		c = '\r';
	    }
	    buf_cstring(buf);
	    return c;
	}
	if (buf->len > config_maxword)
	    fatal("word too long", EC_IOERR);
	buf_putc(buf, c);
    }
    return c;
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
					 const char *part, const char *acl, 
					 uint32_t options,
					 uint32_t uidvalidity, 
					 uint32_t last_uid,
					 modseq_t highestmodseq,
					 const char *crc,
					 uint32_t recentuid,
					 time_t recenttime,
					 time_t pop3_last_login,
					 const char *specialuse)
{
    struct sync_folder *result = xzmalloc(sizeof(struct sync_folder));

    if (l->tail)
        l->tail = l->tail->next = result;
    else
        l->head = l->tail = result;

    l->count++;

    result->next = NULL;

    result->uniqueid = (uniqueid) ? xstrdup(uniqueid) : NULL;
    result->name = (name) ? xstrdup(name) : NULL;
    result->part = (part) ? xstrdup(part) : NULL;
    result->acl = (acl) ? xstrdup(acl)  : NULL;
    result->uidvalidity = uidvalidity;
    result->last_uid = last_uid;
    result->highestmodseq = highestmodseq;
    result->options = options;
    result->sync_crc = xstrdup(crc);
    result->recentuid = recentuid;
    result->recenttime = recenttime;
    result->pop3_last_login = pop3_last_login;
    result->specialuse = (specialuse) ? xstrdup(specialuse) : NULL;

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
	free(current->specialuse);
	free(current->sync_crc);
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

struct sync_sieve_list *sync_sieve_list_create(void)
{
    struct sync_sieve_list *l = xzmalloc(sizeof (struct sync_sieve_list));

    l->head   = NULL;
    l->tail   = NULL;
    l->count  = 0;

    return l;
}

void sync_sieve_list_add(struct sync_sieve_list *l, const char *name,
			 time_t last_update, struct message_guid *guidp,
			 int active)
{
    struct sync_sieve *item = xzmalloc(sizeof(struct sync_sieve));

    item->name = xstrdup(name);
    item->last_update = last_update;
    item->active = active;
    message_guid_copy(&item->guid, guidp);
    item->mark = 0;

    if (l->tail)
        l->tail = l->tail->next = item;
    else
        l->head = l->tail = item;

    l->count++;
}

struct sync_sieve *sync_sieve_lookup(struct sync_sieve_list *l, const char *name)
{
    struct sync_sieve *p;

    for (p = l->head; p; p = p->next) {
        if (!strcmp(p->name, name))
            return p;
    }

    return NULL;
}

void sync_sieve_list_set_active(struct sync_sieve_list *l, const char *name)
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

    mbdir = opendir(sieve_path);
    if (!mbdir) return list;

    active[0] = '\0';
    while((next = readdir(mbdir)) != NULL) {
	uint32_t size;
	char *result;
	struct message_guid guid;
	if (!strcmp(next->d_name, ".") || !strcmp(next->d_name, ".."))
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

	/* calculate the sha1 on the fly, relatively cheap */
	result = sync_sieve_read(userid, next->d_name, &size);
	if (!result) continue;
	message_guid_generate(&guid, result, size);

	sync_sieve_list_add(list, next->d_name, sbuf.st_mtime, &guid, 0);
	free(result);
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

struct sync_name_list *sync_name_list_create(void)
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

struct sync_seen_list *sync_seen_list_create(void)
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

struct sync_annot_list *sync_annot_list_create(void)
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

void sync_action_list_add(struct sync_action_list *l,
			  const char *name, const char *user)
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
    struct mboxlist_entry *mbentry = NULL;

    if (mboxlist_lookup(name, &mbentry, NULL))
	return 0;

    /* only want normal mailboxes... */
    if (!(mbentry->mbtype & (MBTYPE_RESERVE | MBTYPE_MOVING | MBTYPE_REMOTE))) 
	sync_name_list_add(list, name);

    mboxlist_entry_free(&mbentry);

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

/* these are one-shot commands for get and apply, so flush the stream
 * after sending */
void sync_send_apply(struct dlist *kl, struct protstream *out)
{
    prot_printf(out, "APPLY ");
    dlist_print(kl, 1, out);
    prot_printf(out, "\r\n");
    prot_flush(out);
}

void sync_send_lookup(struct dlist *kl, struct protstream *out)
{
    prot_printf(out, "GET ");
    dlist_print(kl, 1, out);
    prot_printf(out, "\r\n");
    prot_flush(out);
}

void sync_send_set(struct dlist *kl, struct protstream *out)
{
    prot_printf(out, "SET ");
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
			  struct index_record *record,
			  struct sync_msgid_list *part_list,
			  struct dlist *kupload)
{
    struct sync_msgid *msgid;
    char *fname;
    struct index_record record2;
    struct stat sbuf;
    int r;

    /* is it already reserved? */
    msgid = sync_msgid_lookup(part_list, &record->guid);
    if (msgid && msgid->mark) 
	return 0;

    /* have to make sure the file exists */
    fname = mailbox_message_fname(mailbox, record->uid);
    if (!fname) return IMAP_MAILBOX_BADNAME;

    if (stat(fname, &sbuf) < 0) {
	syslog(LOG_ERR, "IOERROR: failed to stat file %s", fname);
	return IMAP_IOERROR;
    }

    if ((unsigned) sbuf.st_size != record->size) {
	syslog(LOG_ERR, "IOERROR: size mismatch %s %u (%lu != %u)",
	       mailbox->name, record->uid, sbuf.st_size, record->size);
	return IMAP_IOERROR;
    }

    /* parse the file to make sure the GUID matches */
    memset(&record2, 0, sizeof(struct index_record));
    r = message_parse(fname, &record2);
    if (r) return r;
    if (!message_guid_equal(&record->guid, &record2.guid)) {
	syslog(LOG_ERR, "IOERROR: GUID mismatch %s %u",
	       mailbox->name, record->uid);
	return IMAP_IOERROR;
    }

    dlist_file(kupload, "MESSAGE", mailbox->part,
	       &record->guid, record->size, fname);

    return 0;
}

int sync_mailbox(struct mailbox *mailbox,
		 struct sync_folder *remote,
		 struct sync_msgid_list *part_list,
		 struct dlist *kl, struct dlist *kupload,
		 int printrecords)
{
    int r;
    char sync_crc[128];

    r = sync_crc_calc(mailbox, sync_crc, sizeof(sync_crc));
    if (r)
	return r;

    dlist_atom(kl, "UNIQUEID", mailbox->uniqueid);
    dlist_atom(kl, "MBOXNAME", mailbox->name);
    dlist_num(kl, "LAST_UID", mailbox->i.last_uid);
    dlist_modseq(kl, "HIGHESTMODSEQ", mailbox->i.highestmodseq);
    dlist_num(kl, "RECENTUID", mailbox->i.recentuid);
    dlist_date(kl, "RECENTTIME", mailbox->i.recenttime);
    dlist_date(kl, "LAST_APPENDDATE", mailbox->i.last_appenddate);
    dlist_date(kl, "POP3_LAST_LOGIN", mailbox->i.pop3_last_login);
    dlist_num(kl, "UIDVALIDITY", mailbox->i.uidvalidity);
    dlist_atom(kl, "PARTITION", mailbox->part);
    dlist_atom(kl, "ACL", mailbox->acl);
    dlist_atom(kl, "OPTIONS", sync_encode_options(mailbox->i.options));
    dlist_atom(kl, "SYNC_CRC", sync_crc);
    if (mailbox->quotaroot) 
	dlist_atom(kl, "QUOTAROOT", mailbox->quotaroot);
    if (mailbox->specialuse)
	dlist_atom(kl, "SPECIALUSE", mailbox->specialuse);

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
		int r = sync_send_file(mailbox, &record, part_list, kupload);
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

    if ((c = getword(in, &response)) == EOF)
        return IMAP_PROTOCOL_ERROR;

    if (c != ' ') goto parse_err;

    kl = dlist_new(cmd);
    while (!strcmp(response.s, "*")) {
	struct dlist *item = sync_parseline(in);
	if (!item) goto parse_err;
	dlist_stitch(kl, item);
	if ((c = getword(in, &response)) == EOF)
	    goto parse_err;
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
	 * this to the logic at print_response in sync_server */
        if (!strncmp(errmsg.s, "IMAP_INVALID_USER ",
                     strlen("IMAP_INVALID_USER ")))
            return IMAP_INVALID_USER;
        else if (!strncmp(errmsg.s, "IMAP_MAILBOX_NONEXISTENT ",
                          strlen("IMAP_MAILBOX_NONEXISTENT ")))
            return IMAP_MAILBOX_NONEXISTENT;
        else if (!strncmp(errmsg.s, "IMAP_SYNC_CHECKSUM ",
                          strlen("IMAP_SYNC_CHECKSUM ")))
            return IMAP_SYNC_CHECKSUM;
        else if (!strncmp(errmsg.s, "IMAP_PROTOCOL_ERROR ",
                          strlen("IMAP_PROTOCOL_ERROR ")))
            return IMAP_PROTOCOL_ERROR;
        else if (!strncmp(errmsg.s, "IMAP_PROTOCOL_BAD_PARAMETERS ",
                          strlen("IMAP_PROTOCOL_BAD_PARAMETERS ")))
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        else
            return IMAP_REMOTE_DENIED;
    }

 parse_err:
    dlist_free(&kl);
    sync_getline(in, &errmsg);
    syslog(LOG_ERR, "%s received %s response: %s",
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
	return IMAP_IOERROR;
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

/* ====================================================================== */

#define SYNC_CRC_BASIC	(1<<0)

struct sync_crc_algorithm {
    const char *name;
    int (*setup)(int);
    void (*begin)(void);
    void (*update)(const struct mailbox *, const struct index_record *, int);
    int (*end)(char *, int);
};



static bit32 sync_crc32;

static int sync_crc32_setup(int cflags __attribute__((unused)))
{
    return 0;
}

static void sync_crc32_begin(void)
{
    sync_crc32 = 0;
}

static void sync_crc32_update(const struct mailbox *mailbox,
			      const struct index_record *record,
			      int cflags __attribute__((unused)))
{
    char buf[4096];
    bit32 flagcrc = 0;
    int flag;

    /* calculate an XORed CRC32 over all the flags on the message, so no
     * matter what order they are store in the header, the final value 
     * is the same */
    if (record->system_flags & FLAG_DELETED)
	flagcrc ^= crc32_cstring("\\deleted");
    if (record->system_flags & FLAG_ANSWERED)
	flagcrc ^= crc32_cstring("\\answered");
    if (record->system_flags & FLAG_FLAGGED)
	flagcrc ^= crc32_cstring("\\flagged");
    if (record->system_flags & FLAG_DRAFT)
	flagcrc ^= crc32_cstring("\\draft");
    if (record->system_flags & FLAG_SEEN)
	flagcrc ^= crc32_cstring("\\seen");

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(record->user_flags[flag/32] & (1<<(flag&31))))
	    continue;
	/* need to compare without case being significant */
	strlcpy(buf, mailbox->flagname[flag], 4096);
	lcase(buf);
	flagcrc ^= crc32_cstring(buf);
    }

    snprintf(buf, 4096, "%u " MODSEQ_FMT " %lu (%u) %lu %s",
	    record->uid, record->modseq, record->last_updated,
	    flagcrc,
	    record->internaldate,
	    message_guid_encode(&record->guid));

    sync_crc32 ^= crc32_cstring(buf);
}

static int sync_crc32_end(char *buf, int maxlen)
{
    snprintf(buf, maxlen, "%u", sync_crc32);
    return 0;
}

static const struct sync_crc_algorithm sync_crc_algorithms[] = {
    { "CRC32",
	sync_crc32_setup,
	sync_crc32_begin,
	sync_crc32_update,
	sync_crc32_end },
    { NULL, NULL, NULL, NULL, NULL }
};

static const struct sync_crc_algorithm *find_algorithm(const char *string)
{
    char *b;	    /* temporary writable copy, for tokenising */
    char *word;
    const struct sync_crc_algorithm *alg;
    static const char sep[] = " \t,";

    b = xstrdup(string);
    for (word = strtok(b, sep) ; word != NULL ; word = strtok(NULL, sep)) {
	for (alg = sync_crc_algorithms ; alg->name ; alg++) {
	    if (!strcasecmp(alg->name, word)) {
		free(b);
		return alg;
	    }
	}
    }

    free(b);
    return NULL;
}

const char *sync_crc_list_algorithms(void)
{
    static char *buf;

    if (!buf) {
	/* TODO: we really need an expanding string class */
	const struct sync_crc_algorithm *alg;
	int len = 0;

	for (alg = sync_crc_algorithms ; alg->name ; alg++)
	    len += 1 + strlen(alg->name);
	buf = xmalloc(len);
	buf[0] = '\0';
	for (alg = sync_crc_algorithms ; alg->name ; alg++) {
	    if (buf[0])
		strcat(buf, " ");
	    strcat(buf, alg->name);
	}
    }

    return buf;
}

static int covers_from_string(const char *str, int strict)
{
    int flags = 0;
    char *b;	    /* temporary writable copy, for tokenising */
    const char *p;
    static const char sep[] = " \t,";

    b = xstrdup(str);
    for (p = strtok(b, sep) ; p ; p = strtok(NULL, sep)) {
	if (!strcasecmp(p, "BASIC"))
	    flags |= SYNC_CRC_BASIC;
	else if (strict) {
	    flags = IMAP_INVALID_IDENTIFIER;
	    goto done;
	}
    }
done:
    free(b);
    return flags;
}

static const char *covers_to_string(int flags)
{
    static char buf[128];

    /* TODO: we really need an expanding string class */
    buf[0] = '\0';
    if ((flags & SYNC_CRC_BASIC))
	strcat(buf, " BASIC");
    return (buf[0] ? buf+1 : NULL);
}

const char *sync_crc_list_covers(void)
{
    int cflags = SYNC_CRC_BASIC;
    return covers_to_string(cflags);
}

static const struct sync_crc_algorithm *sync_crc_algorithm;
static int sync_crc_covers;

int sync_crc_setup(const char *algorithm, const char *covers,
		   int strict_covers)
{
    const struct sync_crc_algorithm *alg;
    int cflags;
    int r;

    if (!algorithm || !*algorithm) {
	/* default is first one */
	alg = &sync_crc_algorithms[0];
    } else {
	alg = find_algorithm(algorithm);
	if (!alg)
	    return IMAP_INVALID_IDENTIFIER;
    }

    if (!covers || !*covers) {
	/* default is BASIC only: the sync_client must
	 * explicitly request anything more */
	cflags = SYNC_CRC_BASIC;
    } else {
	cflags = covers_from_string(covers, strict_covers);
	if (cflags < 0)
	    return cflags;
    }

    r = alg->setup(cflags);
    if (r < 0)
	return r;

    sync_crc_algorithm = alg;
    sync_crc_covers = cflags;
    return 0;
}

const char *sync_crc_get_algorithm(void)
{
    return (sync_crc_algorithm ? sync_crc_algorithm->name : "");
}

const char *sync_crc_get_covers(void)
{
    return covers_to_string(sync_crc_covers);
}

/*
 * Calculate a sync CRC for the entire mailbox, and store the result
 * formatted as a nul-terminated ASCII string (suitable for use as an
 * IMAP atom) in @buf.
 * Returns: 0 on success, -ve on error.
 */
int sync_crc_calc(struct mailbox *mailbox, char *buf, int maxlen)
{
    struct index_record record;
    uint32_t recno;

    sync_crc_algorithm->begin();

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	/* we can't send bogus records, just skip them! */
	if (mailbox_read_index_record(mailbox, recno, &record))
	    continue;

	/* expunged flags have no sync CRC */
	if (record.system_flags & FLAG_EXPUNGED)
	    continue;

	sync_crc_algorithm->update(mailbox, &record, sync_crc_covers);
    }

    return sync_crc_algorithm->end(buf, maxlen);
}

/* ====================================================================== */
