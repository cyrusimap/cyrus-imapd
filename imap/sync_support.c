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
#include <dirent.h>
#include <utime.h>
#include <limits.h>

#include "assert.h"
#include "global.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap/imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "message.h"
#include "util.h"
#include "user.h"
#include "prot.h"
#include "dlist.h"
#include "xstrlcat.h"

#include "message_guid.h"
#include "sync_support.h"
#include "sync_log.h"

static int opt_force = 0; // FIXME

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
static int sync_getline(struct protstream *in, struct buf *buf)
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

/* ====================================================================== */

void sync_print_flags(struct dlist *kl,
		      struct mailbox *mailbox,
		      const struct index_record *record)
{
    int flag;
    struct dlist *fl = dlist_newlist(kl, "FLAGS");

    if (record->system_flags & FLAG_DELETED)
	dlist_setflag(fl, "FLAG", "\\Deleted");
    if (record->system_flags & FLAG_ANSWERED)
	dlist_setflag(fl, "FLAG", "\\Answered");
    if (record->system_flags & FLAG_FLAGGED)
	dlist_setflag(fl, "FLAG", "\\Flagged");
    if (record->system_flags & FLAG_DRAFT)
	dlist_setflag(fl, "FLAG", "\\Draft");
    if (record->system_flags & FLAG_EXPUNGED)
	dlist_setflag(fl, "FLAG", "\\Expunged");
    if (record->system_flags & FLAG_SEEN)
	dlist_setflag(fl, "FLAG", "\\Seen");

    /* print user flags in mailbox order */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(record->user_flags[flag/32] & (1<<(flag&31))))
	    continue;
	dlist_setflag(fl, "FLAG", mailbox->flagname[flag]);
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
	    if (mailbox_user_flag(mailbox, s, &userflag, /*allow all*/2)) {
		syslog(LOG_ERR, "Unable to record user flag: %s", s);
		free(s);
		return IMAP_IOERROR;
	    }
	    record->user_flags[userflag/32] |= 1<<(userflag&31);
	}

	free(s);
    }

    return 0;
}

int parse_upload(struct dlist *kr, struct mailbox *mailbox,
		 struct index_record *record,
		 struct sync_annot_list **salp)
{
    struct dlist *fl;
    struct message_guid *tmpguid;
    int r;

    memset(record, 0, sizeof(struct index_record));

    if (!dlist_getnum32(kr, "UID", &record->uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum64(kr, "MODSEQ", &record->modseq))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kr, "LAST_UPDATED", &record->last_updated))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kr, "FLAGS", &fl))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kr, "INTERNALDATE", &record->internaldate))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kr, "SIZE", &record->size))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getguid(kr, "GUID", &tmpguid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    record->guid = *tmpguid;

    /* parse the flags */
    r = sync_getflags(fl, mailbox, record);
    if (r) return r;

    /* the ANNOTATIONS list is optional too */
    if (salp && dlist_getlist(kr, "ANNOTATIONS", &fl))
	decode_annotations(fl, salp, record);

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
    l->toupload  = 0;

    return(l);
}

struct sync_msgid *sync_msgid_insert(struct sync_msgid_list *l,
				     const struct message_guid *guid)
{
    struct sync_msgid *msgid;
    int offset;

    if (message_guid_isnull(guid))
	return NULL;

    offset = message_guid_hash(guid, l->hash_size);

    /* do we already have it?  Don't add it again */
    for (msgid = l->hash[offset] ; msgid ; msgid = msgid->hash_next) {
	if (message_guid_equal(&msgid->guid, guid))
	    return msgid;
    }

    msgid = xzmalloc(sizeof(struct sync_msgid));
    msgid->need_upload = 1;
    message_guid_copy(&msgid->guid, guid);

    l->count++;
    l->toupload++;

    if (l->tail)
	l->tail = l->tail->next = msgid;
    else
	l->head = l->tail = msgid;

    /* Insert at start of list */
    msgid->hash_next = l->hash[offset];
    l->hash[offset]   = msgid;

    return msgid;
}

void sync_msgid_list_free(struct sync_msgid_list **lp)
{
    struct sync_msgid_list *l = *lp;
    struct sync_msgid *current, *next;

    current = l->head;
    while (current) {
	next = current->next;
	free(current->fname);
	free(current);
	current = next;
    }
    free(l->hash);
    free(l);

    *lp = NULL;
}

struct sync_msgid *sync_msgid_lookup(const struct sync_msgid_list *l,
				     const struct message_guid *guid)
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
					 struct synccrcs synccrcs,
					 uint32_t recentuid,
					 time_t recenttime,
					 time_t pop3_last_login,
					 time_t pop3_show_after,
					 struct sync_annot_list *annots,
					 modseq_t xconvmodseq)
{
    struct sync_folder *result = xzmalloc(sizeof(struct sync_folder));

    if (l->tail)
	l->tail = l->tail->next = result;
    else
	l->head = l->tail = result;

    l->count++;

    result->next = NULL;
    result->mailbox = NULL;

    result->uniqueid = xstrdupnull(uniqueid);
    result->name = xstrdupnull(name);
    result->mbtype = mbtype;
    result->part = xstrdupnull(part);
    result->acl = xstrdupnull(acl);
    result->uidvalidity = uidvalidity;
    result->last_uid = last_uid;
    result->highestmodseq = highestmodseq;
    result->options = options;
    result->synccrcs = synccrcs;
    result->recentuid = recentuid;
    result->recenttime = recenttime;
    result->pop3_last_login = pop3_last_login;
    result->pop3_show_after = pop3_show_after;
    result->annots = annots; /* NOTE: not a copy! */
    result->xconvmodseq = xconvmodseq;

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
	sync_annot_list_free(&current->annots);
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
					 const char *newname, const char *partition,
					 unsigned uidvalidity)
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
    result->uidvalidity = uidvalidity;
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
				       const char *root)
{
    struct sync_quota *result
	= xzmalloc(sizeof(struct sync_quota));
    int res;

    if (l->tail)
	l->tail = l->tail->next = result;
    else
	l->head = l->tail = result;

    l->count++;

    result->next = NULL;
    result->root = xstrdup(root);
    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
	result->limits[res] = QUOTA_UNLIMITED;
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

void sync_encode_quota_limits(struct dlist *kl, const quota_t limits[QUOTA_NUMRESOURCES])
{
    int res;

    /*
     * For backwards compatibility, we encode the STORAGE limit as LIMIT
     * and we always report it even if it's QUOTA_UNLIMITED.  This is
     * kinda screwed up but should work.  For QUOTA_UNLIMITED < 0, we
     * send a very large unsigned number across the wire, and parse it
     * back as QUOTA_UNLIMITED at the other end.  Spit and string.
     */
    dlist_setnum32(kl, "LIMIT", limits[QUOTA_STORAGE]);

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
	if (limits[res] >= 0)
	    dlist_setnum32(kl, quota_names[res], limits[res]);
    }
}

void sync_decode_quota_limits(/*const*/ struct dlist *kl, quota_t limits[QUOTA_NUMRESOURCES])
{
    uint32_t limit = 0;
    int res;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
	limits[res] = QUOTA_UNLIMITED;

    /* For backwards compatibility */
    if (dlist_getnum32(kl, "LIMIT", &limit)) {
	if (limit == UINT_MAX)
	    limits[QUOTA_STORAGE] = -1;
	else
	    limits[QUOTA_STORAGE] = limit;
    }

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
	if (dlist_getnum32(kl, quota_names[res], &limit))
	    limits[res] = limit;
    }
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
			 const struct buf *value)
{
    struct sync_annot *item = xzmalloc(sizeof(struct sync_annot));

    item->entry = xstrdupnull(entry);
    item->userid = xstrdupnull(userid);
    buf_copy(&item->value, value);
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

    if (!l)
	return;
    current = l->head;
    while (current) {
	next = current->next;
	free(current->entry);
	free(current->userid);
	buf_free(&current->value);
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
    current->name     = xstrdupnull(name);
    current->user     = xstrdupnull(user);
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

int addmbox(char *name,
	    int matchlen __attribute__((unused)),
	    int maycreate __attribute__((unused)),
	    void *rock)
{
    struct sync_name_list *list = (struct sync_name_list *) rock;
    mbentry_t *mbentry = NULL;

    if (mboxlist_lookup(name, &mbentry, NULL))
	return 0;

    /* only want normal mailboxes... */
    if (!(mbentry->mbtype & (MBTYPE_RESERVE | MBTYPE_MOVING | MBTYPE_REMOTE)))
	sync_name_list_add(list, name);

    mboxlist_entry_free(&mbentry);

    return 0;
}

int addmbox_sub(void *rock, const char *key, size_t keylen,
		const char *data __attribute__((unused)),
		size_t datalen __attribute__((unused)))
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
			  const struct index_record *record,
			  struct sync_msgid_list *part_list,
			  struct dlist *kupload)
{
    struct sync_msgid *msgid;
    const char *fname;

    /* we'll trust that it exists - if not, we'll bail later,
     * but right now we're under locks, so be fast */
    fname = mailbox_record_fname(mailbox, record);
    if (!fname) return IMAP_MAILBOX_BADNAME;

    msgid = sync_msgid_insert(part_list, &record->guid);

    /* already uploaded, great */
    if (!msgid->need_upload)
	return 0;

    dlist_setfile(kupload, "MESSAGE", mailbox->part,
		  &record->guid, record->size, fname);

    /* note that we will be sending it, so it doesn't need to be
     * sent again */
    msgid->size = record->size;
    if (!msgid->fname) msgid->fname = xstrdup(fname);
    msgid->need_upload = 0;
    msgid->is_archive = record->system_flags & FLAG_ARCHIVED ? 1 : 0;
    part_list->toupload--;

    return 0;
}

static int sync_prepare_dlists(struct mailbox *mailbox,
			       struct sync_folder *remote,
			       struct sync_msgid_list *part_list,
			       struct dlist *kl, struct dlist *kupload,
			       int printrecords)
{
    struct sync_annot_list *annots = NULL;
    struct synccrcs synccrcs = mailbox_synccrcs(mailbox, /*force*/0);
    struct mailbox_iter *iter = NULL;
    modseq_t xconvmodseq = 0;
    int r = 0;

    dlist_setatom(kl, "UNIQUEID", mailbox->uniqueid);
    dlist_setatom(kl, "MBOXNAME", mailbox->name);
    if (mailbox->mbtype)
	dlist_setatom(kl, "MBOXTYPE", mboxlist_mbtype_to_string(mailbox->mbtype));
    dlist_setnum32(kl, "LAST_UID", mailbox->i.last_uid);
    dlist_setnum64(kl, "HIGHESTMODSEQ", mailbox->i.highestmodseq);
    dlist_setnum32(kl, "RECENTUID", mailbox->i.recentuid);
    dlist_setdate(kl, "RECENTTIME", mailbox->i.recenttime);
    dlist_setdate(kl, "LAST_APPENDDATE", mailbox->i.last_appenddate);
    dlist_setdate(kl, "POP3_LAST_LOGIN", mailbox->i.pop3_last_login);
    dlist_setdate(kl, "POP3_SHOW_AFTER", mailbox->i.pop3_show_after);
    dlist_setnum32(kl, "UIDVALIDITY", mailbox->i.uidvalidity);
    dlist_setatom(kl, "PARTITION", mailbox->part);
    dlist_setatom(kl, "ACL", mailbox->acl);
    dlist_setatom(kl, "OPTIONS", sync_encode_options(mailbox->i.options));
    dlist_setnum32(kl, "SYNC_CRC", synccrcs.basic);
    dlist_setnum32(kl, "SYNC_CRC_ANNOT", synccrcs.annot);
    if (mailbox->quotaroot)
	dlist_setatom(kl, "QUOTAROOT", mailbox->quotaroot);
    if (mailbox_has_conversations(mailbox)) {
	r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
	if (!r && xconvmodseq)
	    dlist_setnum64(kl, "XCONVMODSEQ", xconvmodseq);
    }

    /* always send mailbox annotations */
    r = read_annotations(mailbox, NULL, &annots);
    if (r) goto done;

    encode_annotations(kl, NULL, annots);
    sync_annot_list_free(&annots);

    if (printrecords) {
	const struct index_record *record;
	struct dlist *rl = dlist_newlist(kl, "RECORD");
	modseq_t modseq = remote ? remote->highestmodseq : 0;

	iter = mailbox_iter_init(mailbox, modseq, 0);
	while ((record = mailbox_iter_step(iter))) {
	    /* start off thinking we're sending the file too */
	    int send_file = 1;

	    /* does it exist at the other end?  Don't send it */
	    if (remote && record->uid <= remote->last_uid)
		send_file = 0;

	    /* if we're not uploading messages... don't send file */
	    if (!part_list || !kupload)
		send_file = 0;

	    /* if we don't HAVE the file we can't send it */
	    if (record->system_flags & FLAG_UNLINKED)
		send_file = 0;

	    if (send_file) {
		r = sync_send_file(mailbox, record, part_list, kupload);
		if (r) goto done;
	    }

	    struct dlist *il = dlist_newkvlist(rl, "RECORD");
	    dlist_setnum32(il, "UID", record->uid);
	    dlist_setnum64(il, "MODSEQ", record->modseq);
	    dlist_setdate(il, "LAST_UPDATED", record->last_updated);
	    sync_print_flags(il, mailbox, record);
	    dlist_setdate(il, "INTERNALDATE", record->internaldate);
	    dlist_setnum32(il, "SIZE", record->size);
	    dlist_setatom(il, "GUID", message_guid_encode(&record->guid));

	    r = read_annotations(mailbox, record, &annots);
	    if (r) goto done;

	    encode_annotations(il, record, annots);
	    sync_annot_list_free(&annots);
	}
    }

done:
    mailbox_iter_done(&iter);
    return r;
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

    kl = dlist_newlist(NULL, cmd);
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
	 * this to the logic at sync_print_response() */ /* FIXME */
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
    syslog(LOG_ERR, "IOERROR: %s received %s response: %s",
	   cmd, response.s, errmsg.s);
    return IMAP_PROTOCOL_ERROR;
}

int sync_append_copyfile(struct mailbox *mailbox,
			 struct index_record *record,
			 const struct sync_annot_list *annots,
			 const struct sync_msgid_list *part_list)
{
    const char *destname;
    struct message_guid tmp_guid;
    struct sync_msgid *item;
    int r = 0;

    message_guid_copy(&tmp_guid, &record->guid);

    item = sync_msgid_lookup(part_list, &record->guid);

    if (!item || !item->fname)
	r = IMAP_IOERROR;
    else
	r = message_parse(item->fname, record);

    if (r) {
	/* deal with unlinked master records */
	if (record->system_flags & FLAG_EXPUNGED) {
	    /* no need to set 'needs cleanup' here, it's already expunged */
	    record->system_flags |= FLAG_UNLINKED;
	    goto just_write;
	}
	syslog(LOG_ERR, "IOERROR: failed to parse %s", message_guid_encode(&record->guid));
	return r;
    }

    /* record->guid was rewritten in the parse, see if it changed */
    if (!message_guid_equal(&tmp_guid, &record->guid)) {
	syslog(LOG_ERR, "IOERROR: guid mismatch on parse %s (%s)",
	       item->fname, message_guid_encode(&record->guid));
	return IMAP_IOERROR;
    }

    /* put back to archive if original was archived, gain single instance store  */
    if (item->is_archive)
	record->system_flags |= FLAG_ARCHIVED;

    /* push it to archive if it should be archived now anyway */
    if (mailbox_should_archive(mailbox, record, NULL))
	record->system_flags |= FLAG_ARCHIVED;

    destname = mailbox_record_fname(mailbox, record);
    cyrus_mkdir(destname, 0755);
    r = mailbox_copyfile(item->fname, destname, 0);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Failed to copy %s to %s",
	       item->fname, destname);
	return r;
    }

 just_write:
    r = mailbox_append_index_record(mailbox, record);
    if (r) return r;

    /* apply the remote annotations */
    r = apply_annotations(mailbox, record, NULL, annots, 0);
    if (r) {
	syslog(LOG_ERR, "Failed to apply annotations: %s",
	       error_message(r));
    }

    return r;
}

/* ====================================================================== */

static int read_one_annot(const char *mailbox __attribute__((unused)),
			  uint32_t uid __attribute__((unused)),
			  const char *entry,
			  const char *userid,
			  const struct buf *value,
			  void *rock)
{
    struct sync_annot_list **salp = (struct sync_annot_list **)rock;

    if (!*salp)
	*salp = sync_annot_list_create();
    sync_annot_list_add(*salp, entry, userid, value);
    return 0;
}

/*
 * Read all the annotations in the local annotations database
 * for the message given by @mailbox and @record, returning them
 * as a new sync_annot_list.  The caller should free the new
 * list with sync_annot_list_free().
 * If record is NULL, return the mailbox annotations
 *
 * Returns: non-zero on error,
 *	    resulting sync_annot_list in *@resp
 */
int read_annotations(const struct mailbox *mailbox,
		     const struct index_record *record,
		     struct sync_annot_list **resp)
{
    *resp = NULL;
    return annotatemore_findall(mailbox->name, record ? record->uid : 0,
				/* all entries*/"*",
				read_one_annot, (void *)resp);
}

/*
 * Encode the given list of annotations @sal as a dlist
 * structure with the given @parent.
 */
void encode_annotations(struct dlist *parent,
			const struct index_record *record,
			const struct sync_annot_list *sal)
{
    const struct sync_annot *sa;
    struct dlist *annots = NULL;
    struct dlist *aa;

    if (sal) {
	for (sa = sal->head ; sa ; sa = sa->next) {
	    if (!annots)
		annots = dlist_newlist(parent, "ANNOTATIONS");

	    aa = dlist_newkvlist(annots, NULL);
	    dlist_setatom(aa, "ENTRY", sa->entry);
	    dlist_setatom(aa, "USERID", sa->userid);
	    dlist_setmap(aa, "VALUE", sa->value.s, sa->value.len);
	}
    }

    if (record && record->cid) {
	if (!annots)
	    annots = dlist_newlist(parent, "ANNOTATIONS");
	aa = dlist_newkvlist(annots, NULL);
	dlist_setatom(aa, "ENTRY", "/vendor/cmu/cyrus-imapd/thrid");
	dlist_setatom(aa, "USERID", NULL);
	dlist_sethex64(aa, "VALUE", record->cid);
    }
}

/*
 * Decode the given list of encoded annotations @annots and create
 * a new sync_annot_list in *@salp, which the caller should free
 * with sync_annot_list_free().
 *
 * Returns: zero on success or Cyrus error code.
 */
int decode_annotations(/*const*/struct dlist *annots,
		       struct sync_annot_list **salp,
		       struct index_record *record)
{
    struct dlist *aa;
    const char *entry;
    const char *userid;

    *salp = NULL;
    if (strcmp(annots->name, "ANNOTATIONS"))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    for (aa = annots->head ; aa ; aa = aa->next) {
	struct buf value = BUF_INITIALIZER;
	if (!*salp)
	    *salp = sync_annot_list_create();
	if (!dlist_getatom(aa, "ENTRY", &entry))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getatom(aa, "USERID", &userid))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getbuf(aa, "VALUE", &value))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!strcmp(entry, "/vendor/cmu/cyrus-imapd/thrid")) {
	    if (record) {
		const char *p = buf_cstring(&value);
		parsehex(p, &p, 16, &record->cid);
		/* XXX - check on p? */
	    }
	}
	else {
	    sync_annot_list_add(*salp, entry, userid, &value);
	}
	buf_free(&value);
    }
    return 0;
}

/*
 * Merge a local and remote list of annotations, and apply the resulting
 * list of annotations to the local annotation database, storing new values
 * or deleting old values as necessary.  Manages its own annotations
 * transaction.
 * Record may be null, to process mailbox annotations.
 */

static int diff_annotation(const struct sync_annot *a,
			   const struct sync_annot *b,
			   int diff_value)
{
    int diff = 0;

    if (!a && !b) return 0;

    if (a)
	diff--;
    if (b)
	diff++;

    if (!diff)
	diff = strcmpnull(a->entry, b->entry);
    if (!diff)
	diff = strcmpnull(a->userid, b->userid);
    if (!diff && diff_value)
	diff = buf_cmp(&a->value, &b->value);

    return diff;
}

int diff_annotations(const struct sync_annot_list *local_annots,
		     const struct sync_annot_list *remote_annots)
{
    const struct sync_annot *local = (local_annots ? local_annots->head : NULL);
    const struct sync_annot *remote = (remote_annots ? remote_annots->head : NULL);
    while (local || remote) {
	int r = diff_annotation(local, remote, 1);
	if (r) return r;
	if (local) local = local->next;
	if (remote) remote = remote->next;
    }

    return 0;
}

int apply_annotations(struct mailbox *mailbox,
		      const struct index_record *record,
		      const struct sync_annot_list *local_annots,
		      const struct sync_annot_list *remote_annots,
		      int local_wins)
{
    const struct sync_annot *local = (local_annots ? local_annots->head : NULL);
    const struct sync_annot *remote = (remote_annots ? remote_annots->head : NULL);
    const struct sync_annot *chosen;
    static const struct buf novalue = BUF_INITIALIZER;
    const struct buf *value;
    int r = 0;
    int diff;
    annotate_state_t *astate = NULL;

    if (record) {
	r = mailbox_get_annotate_state(mailbox, record->uid, &astate);
    }
    else {
	astate = annotate_state_new();
	r = annotate_state_set_mailbox(astate, mailbox);
    }
    if (r) goto out;

    /*
     * We rely here on the database scan order resulting in lists
     * of annotations that are ordered lexically on entry then userid.
     * We walk over both lists at once, choosing an annotation from
     * either the local list only (diff < 0), the remote list only
     * (diff > 0), or both lists (diff == 0).
     */
    while (local || remote) {
	diff = diff_annotation(local, remote, 0);
	chosen = 0;
	if (diff < 0) {
	    chosen = local;
	    value = (local_wins ? &local->value : &novalue);
	    local = local->next;
	}
	else if (diff > 0) {
	    chosen = remote;
	    value = (local_wins ? &novalue : &remote->value);
	    remote = remote->next;
	}
	else {
	    chosen = remote;
	    value = (local_wins ? &local->value : &remote->value);
	    diff = buf_cmp(&local->value, &remote->value);
	    local = local->next;
	    remote = remote->next;
	    if (!diff)
		continue;   /* same value, skip */
	}

	r = annotate_state_write(astate, chosen->entry,
				 chosen->userid, value);
	if (r)
	    break;
    }

out:
    if (!record) {
	/* need to manage our own txn for the global db */
	if (!r)
	    r = annotate_state_commit(&astate);
	else
	    annotate_state_abort(&astate);
    }
    /* else, the struct mailbox manages it for us */

    return r;
}

/* =======================  server-side sync  =========================== */

static void reserve_folder(const char *part, const char *mboxname,
		    struct sync_msgid_list *part_list)
{
    struct mailbox *mailbox = NULL;
    const struct index_record *record;
    int r;
    struct sync_msgid *item;
    const char *mailbox_msg_path, *stage_msg_path;

    /* Open and lock mailbox */
    r = mailbox_open_irl(mboxname, &mailbox);

    if (r) return;

    /* XXX - this is just on the replica, but still - we shouldn't hold
     * the lock for so long */
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((record = mailbox_iter_step(iter))) {
	/* do we need it? */
	item = sync_msgid_lookup(part_list, &record->guid);
	if (!item)
	    continue;

	/* have we already found it? */
	if (!item->need_upload)
	    continue;

	/* Attempt to reserve this message */
	mailbox_msg_path = mailbox_record_fname(mailbox, record);
	stage_msg_path = dlist_reserve_path(part, record->system_flags & FLAG_ARCHIVED, &record->guid);

	/* check that the sha1 of the file on disk is correct */
	struct index_record record2;
	memset(&record2, 0, sizeof(struct index_record));
	r = message_parse(mailbox_msg_path, &record2);
	if (r) {
	    syslog(LOG_ERR, "IOERROR: Unable to parse %s",
		   mailbox_msg_path);
	    continue;
	}
	if (!message_guid_equal(&record->guid, &record2.guid)) {
	    syslog(LOG_ERR, "IOERROR: GUID mismatch on parse for %s",
		   mailbox_msg_path);
	    continue;
	}

	if (mailbox_copyfile(mailbox_msg_path, stage_msg_path, 0) != 0) {
	    syslog(LOG_ERR, "IOERROR: Unable to link %s -> %s: %m",
		   mailbox_msg_path, stage_msg_path);
	    continue;
	}

	item->size = record->size;
	item->fname = xstrdup(stage_msg_path); /* track the correct location */
	item->is_archive = record->system_flags & FLAG_ARCHIVED ? 1 : 0;
	item->need_upload = 0;
	part_list->toupload--;

	/* already found everything, drop out */
	if (!part_list->toupload) break;
    }

    mailbox_iter_done(&iter);

    mailbox_close(&mailbox);
}

int sync_apply_reserve(struct dlist *kl,
		       struct sync_reserve_list *reserve_list,
		       struct sync_state *sstate)
{
    struct message_guid *tmpguid;
    struct sync_name_list *folder_names = sync_name_list_create();
    struct sync_msgid_list *part_list;
    struct sync_msgid *item;
    struct sync_name *folder;
    mbentry_t *mbentry = NULL;
    const char *partition = NULL;
    struct dlist *ml;
    struct dlist *gl;
    struct dlist *i;
    struct dlist *kout = NULL;

    if (!dlist_getatom(kl, "PARTITION", &partition)) goto parse_err;
    if (!dlist_getlist(kl, "MBOXNAME", &ml)) goto parse_err;
    if (!dlist_getlist(kl, "GUID", &gl)) goto parse_err;

    part_list = sync_reserve_partlist(reserve_list, partition);
    for (i = gl->head; i; i = i->next) {
	if (!dlist_toguid(i, &tmpguid))
	    goto parse_err;
	sync_msgid_insert(part_list, tmpguid);
    }

    /* need a list so we can mark items */
    for (i = ml->head; i; i = i->next) {
	sync_name_list_add(folder_names, i->sval);
    }

    for (folder = folder_names->head; folder; folder = folder->next) {
	if (!part_list->toupload) break;
	if (mboxlist_lookup(folder->name, &mbentry, 0))
	    continue;
	if (strcmp(mbentry->partition, partition)) {
	    mboxlist_entry_free(&mbentry);
	    continue; /* try folders on the same partition first! */
	}
	mboxlist_entry_free(&mbentry);
	reserve_folder(partition, folder->name, part_list);
	folder->mark = 1;
    }

    /* if we have other folders, check them now */
    for (folder = folder_names->head; folder; folder = folder->next) {
	if (!part_list->toupload) break;
	if (folder->mark)
	    continue;
	reserve_folder(partition, folder->name, part_list);
	folder->mark = 1;
    }

    /* check if we missed any */
    kout = dlist_newlist(NULL, "MISSING");
    for (i = gl->head; i; i = i->next) {
	if (!dlist_toguid(i, &tmpguid))
	    goto parse_err;
	item = sync_msgid_lookup(part_list, tmpguid);
	if (item->need_upload)
	    dlist_setguid(kout, "GUID", tmpguid);
    }

    if (kout->head)
	sync_send_response(kout, sstate->pout);
    dlist_free(&kout);

    sync_name_list_free(&folder_names);
    mboxlist_entry_free(&mbentry);

    return 0;

 parse_err:
    dlist_free(&kout);
    sync_name_list_free(&folder_names);
    mboxlist_entry_free(&mbentry);

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
    quota_t limits[QUOTA_NUMRESOURCES];

    if (!dlist_getatom(kin, "ROOT", &root))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    sync_decode_quota_limits(kin, limits);
    return mboxlist_setquotas(root, limits, 1);
}

/* ====================================================================== */

static int mailbox_compare_update(struct mailbox *mailbox,
				  struct dlist *kr, int doupdate,
				  struct sync_msgid_list *part_list)
{
    struct index_record mrecord;
    const struct index_record *rrecord;
    struct dlist *ki;
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int r;
    int i;
    int has_append = 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);

    rrecord = mailbox_iter_step(iter);
    for (ki = kr->head; ki; ki = ki->next) {
	sync_annot_list_free(&mannots);
	sync_annot_list_free(&rannots);

	r = parse_upload(ki, mailbox, &mrecord, &mannots);
	if (r) {
	    syslog(LOG_ERR, "SYNCERROR: failed to parse uploaded record");
	    return IMAP_PROTOCOL_ERROR;
	}

	while (rrecord && rrecord->uid < mrecord.uid) {
	    /* read another record */
	    rrecord = mailbox_iter_step(iter);
	}

	/* found a match, check for updates */
	if (rrecord && rrecord->uid == mrecord.uid) {
	    /* if they're both EXPUNGED then ignore everything else */
	    if ((mrecord.system_flags & FLAG_EXPUNGED) &&
		(rrecord->system_flags & FLAG_EXPUNGED))
		continue;

	    /* GUID mismatch is an error straight away, it only ever happens if we
	     * had a split brain - and it will take a full sync to sort out the mess */
	    if (!message_guid_equal(&mrecord.guid, &rrecord->guid)) {
		syslog(LOG_ERR, "SYNCERROR: guid mismatch %s %u",
		       mailbox->name, mrecord.uid);
		r = IMAP_SYNC_CHECKSUM;
		goto out;
	    }

	    /* higher modseq on the replica is an error */
	    if (rrecord->modseq > mrecord.modseq) {
		if (opt_force) {
		    syslog(LOG_NOTICE, "forcesync: higher modseq on replica %s %u (" MODSEQ_FMT " > " MODSEQ_FMT ")",
			   mailbox->name, mrecord.uid, rrecord->modseq, mrecord.modseq);
		}
		else {
		    syslog(LOG_ERR, "SYNCERROR: higher modseq on replica %s %u (" MODSEQ_FMT " > " MODSEQ_FMT ")",
			   mailbox->name, mrecord.uid, rrecord->modseq, mrecord.modseq);
		    r = IMAP_SYNC_CHECKSUM;
		    goto out;
		}
	    }

	    /* if it's already expunged on the replica, but alive on the master,
	     * that's bad */
	    if (!(mrecord.system_flags & FLAG_EXPUNGED) &&
		 (rrecord->system_flags & FLAG_EXPUNGED)) {
		syslog(LOG_ERR, "SYNCERROR: expunged on replica %s %u",
		       mailbox->name, mrecord.uid);
		r = IMAP_SYNC_CHECKSUM;
		goto out;
	    }

	    /* skip out on the first pass */
	    if (!doupdate) continue;

	    struct index_record copy = *rrecord;
	    copy.cid = mrecord.cid;
	    copy.modseq = mrecord.modseq;
	    copy.last_updated = mrecord.last_updated;
	    copy.internaldate = mrecord.internaldate;
	    copy.system_flags = (mrecord.system_flags & FLAGS_GLOBAL) |
				(rrecord->system_flags & FLAGS_LOCAL);
	    for (i = 0; i < MAX_USER_FLAGS/32; i++)
		copy.user_flags[i] = mrecord.user_flags[i];

	    r = read_annotations(mailbox, &copy, &rannots);
	    if (r) {
		syslog(LOG_ERR, "Failed to read local annotations %s %u: %s",
		       mailbox->name, rrecord->recno, error_message(r));
		goto out;
	    }

	    r = apply_annotations(mailbox, &copy, rannots, mannots, 0);
	    if (r) {
		syslog(LOG_ERR, "Failed to write merged annotations %s %u: %s",
		       mailbox->name, rrecord->recno, error_message(r));
		goto out;
	    }

	    copy.silent = 1;
	    r = mailbox_rewrite_index_record(mailbox, &copy);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to rewrite record %s %u",
		       mailbox->name, rrecord->recno);
		goto out;
	    }
	}

	/* not found and less than LAST_UID, bogus */
	else if (mrecord.uid <= mailbox->i.last_uid) {
	    /* Expunged, just skip it */
	    if (!(mrecord.system_flags & FLAG_EXPUNGED)) {
		r = IMAP_SYNC_CHECKSUM;
		goto out;
	    }
	}

	/* after LAST_UID, it's an append, that's OK */
	else {
	    /* skip out on the first pass */
	    if (!doupdate) continue;

	    mrecord.silent = 1;
	    r = sync_append_copyfile(mailbox, &mrecord, mannots, part_list);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to append file %s %d",
		       mailbox->name, mrecord.uid);
		goto out;
	    }

	    has_append = 1;
	}
    }

    if (has_append)
	sync_log_append(mailbox->name);

    r = 0;

out:
    mailbox_iter_done(&iter);
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);
    return r;
}

/* if either CRC is zero for a field, then we consider it to match.
 * this lets us bootstrap the case where CRCs weren't being calculated,
 * and also allows a client with incomplete local information to request
 * a change be made on a sync_server without having to fetch all the
 * data first just to calculate the CRC */
static int crceq(struct synccrcs a, struct synccrcs b)
{
    if (a.basic && b.basic && a.basic != b.basic) return 0;
    if (a.annot && b.annot && a.annot != b.annot) return 0;
    return 1;
}

int sync_apply_mailbox(struct dlist *kin,
		       struct sync_reserve_list *reserve_list,
		       struct sync_state *sstate)
{
    struct sync_msgid_list *part_list;
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
    time_t pop3_show_after = 0; /* optional */
    uint32_t uidvalidity;
    const char *acl;
    const char *options_str;
    struct synccrcs synccrcs = { 0, 0 };

    uint32_t options;

    /* optional fields */
    modseq_t xconvmodseq = 0;

    struct mailbox *mailbox = NULL;
    struct dlist *kr;
    struct dlist *ka = NULL;
    int r;

    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;

    annotate_state_t *astate = NULL;

    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "LAST_UID", &last_uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum64(kin, "HIGHESTMODSEQ", &highestmodseq))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "RECENTUID", &recentuid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "RECENTTIME", &recenttime))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LAST_APPENDDATE", &last_appenddate))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "POP3_LAST_LOGIN", &pop3_last_login))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "UIDVALIDITY", &uidvalidity))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ACL", &acl))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "OPTIONS", &options_str))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kin, "RECORD", &kr))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* optional */
    dlist_getlist(kin, "ANNOTATIONS", &ka);
    dlist_getdate(kin, "POP3_SHOW_AFTER", &pop3_show_after);
    dlist_getatom(kin, "MBOXTYPE", &mboxtype);
    dlist_getnum64(kin, "XCONVMODSEQ", &xconvmodseq);

    /* Get the CRCs */
    dlist_getnum32(kin, "SYNC_CRC", &synccrcs.basic);
    dlist_getnum32(kin, "SYNC_CRC_ANNOT", &synccrcs.annot);

    options = sync_parse_options(options_str);
    mbtype = mboxlist_string_to_mbtype(mboxtype);

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	r = mboxlist_createsync(mboxname, mbtype, partition,
				sstate->userid, sstate->authstate,
				options, uidvalidity,
				highestmodseq, acl,
				uniqueid, sstate->local_only, &mailbox);
	/* set a highestmodseq of 0 so ALL changes are future
	 * changes and get applied */
	if (!r) mailbox->i.highestmodseq = 0;
    }
    if (r) {
	syslog(LOG_ERR, "Failed to open mailbox %s to update: %s",
	       mboxname, error_message(r));
	goto done;
    }

    if (mailbox->mbtype != mbtype) {
	syslog(LOG_ERR, "INVALID MAILBOX TYPE %s (%d, %d)", mailbox->name, mailbox->mbtype, mbtype);
	/* is this even possible? */
	r = IMAP_MAILBOX_BADTYPE;
	goto done;
    }

    part_list = sync_reserve_partlist(reserve_list, mailbox->part);

    /* hold the annotate state open */
    mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    /* and make it hold a transaction open */
    annotate_state_begin(astate);

    if (strcmp(mailbox->uniqueid, uniqueid)) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: fixing uniqueid %s (%s => %s)",
		   mboxname, mailbox->uniqueid, uniqueid);
	    free(mailbox->uniqueid);
	    mailbox->uniqueid = xstrdup(uniqueid);
	    mailbox->header_dirty = 1;
	}
	else {
	    syslog(LOG_ERR, "Mailbox uniqueid changed %s (%s => %s) - retry",
		   mboxname, mailbox->uniqueid, uniqueid);
	    r = IMAP_MAILBOX_MOVED;
	    goto done;
	}
    }

    /* skip out now, it's going to mismatch for sure! */
    if (highestmodseq < mailbox->i.highestmodseq) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: higher modseq on replica %s - "
		   MODSEQ_FMT " < " MODSEQ_FMT,
		   mboxname, highestmodseq, mailbox->i.highestmodseq);
	}
	else {
	    syslog(LOG_ERR, "higher modseq on replica %s - "
		   MODSEQ_FMT " < " MODSEQ_FMT,
		   mboxname, highestmodseq, mailbox->i.highestmodseq);
	    r = IMAP_SYNC_CHECKSUM;
	    goto done;
	}
    }

    /* skip out now, it's going to mismatch for sure! */
    if (uidvalidity < mailbox->i.uidvalidity) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: higher uidvalidity on replica %s - %u < %u",
		   mboxname, uidvalidity, mailbox->i.uidvalidity);
	}
	else {
	    syslog(LOG_ERR, "higher uidvalidity on replica %s - %u < %u",
		   mboxname, uidvalidity, mailbox->i.uidvalidity);
	    r = IMAP_SYNC_CHECKSUM;
	    goto done;
	}
    }

    /* skip out now, it's going to mismatch for sure! */
    if (last_uid < mailbox->i.last_uid) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: higher last_uid on replica %s - %u < %u",
		   mboxname, last_uid, mailbox->i.last_uid);
	}
	else {
	    syslog(LOG_ERR, "higher last_uid on replica %s - %u < %u",
		   mboxname, last_uid, mailbox->i.last_uid);
	    r = IMAP_SYNC_CHECKSUM;
	    goto done;
	}
    }

    /* NOTE - this is optional */
    if (mailbox_has_conversations(mailbox) && xconvmodseq) {
	modseq_t ourxconvmodseq = 0;

	r = mailbox_get_xconvmodseq(mailbox, &ourxconvmodseq);
	if (r) {
	    syslog(LOG_ERR, "Failed to read xconvmodseq for %s: %s",
		   mboxname, error_message(r));
	    goto done;
	}

	/* skip out now, it's going to mismatch for sure! */
	if (xconvmodseq < ourxconvmodseq) {
	    if (opt_force) {
		syslog(LOG_NOTICE, "forcesync: higher xconvmodseq on replica %s - %llu < %llu",
		       mboxname, xconvmodseq, ourxconvmodseq);
	    }
	    else {
		syslog(LOG_ERR, "higher xconvmodseq on replica %s - %llu < %llu",
		       mboxname, xconvmodseq, ourxconvmodseq);
		r = IMAP_SYNC_CHECKSUM;
		goto done;
	    }
	}
    }

    r = mailbox_compare_update(mailbox, kr, 0, part_list);
    if (r) goto done;

    /* now we're committed to writing something no matter what happens! */

    /* always take the ACL from the master, it's not versioned */
    if (strcmp(mailbox->acl, acl)) {
	mailbox_set_acl(mailbox, acl, 0);
	r = mboxlist_sync_setacls(mboxname, acl);
	if (r) goto done;
    }

    /* take all mailbox (not message) annotations - aka metadata,
     * they're not versioned either */
    if (ka)
	decode_annotations(ka, &mannots, NULL);

    r = read_annotations(mailbox, NULL, &rannots);
    if (!r) r = apply_annotations(mailbox, NULL, rannots, mannots, 0);

    if (r) {
	syslog(LOG_ERR, "syncerror: annotations failed to apply to %s",
	       mailbox->name);
	goto done;
    }

    r = mailbox_compare_update(mailbox, kr, 1, part_list);
    if (r) {
	abort();
	return r;
    }

    mailbox_index_dirty(mailbox);
    if (!opt_force) {
	assert(mailbox->i.last_uid <= last_uid);
    }
    mailbox->i.last_uid = last_uid;
    mailbox->i.recentuid = recentuid;
    mailbox->i.recenttime = recenttime;
    mailbox->i.last_appenddate = last_appenddate;
    mailbox->i.pop3_last_login = pop3_last_login;
    mailbox->i.pop3_show_after = pop3_show_after;
    /* only alter the syncable options */
    mailbox->i.options = (options & MAILBOX_OPTIONS_MASK) |
			 (mailbox->i.options & ~MAILBOX_OPTIONS_MASK);

    /* this happens all the time! */
    if (mailbox->i.highestmodseq != highestmodseq) {
	mboxname_setmodseq(mailbox->name, highestmodseq, mailbox->mbtype);
	mailbox->i.highestmodseq = highestmodseq;
    }

    /* this happens rarely, so let us know */
    if (mailbox->i.uidvalidity != uidvalidity) {
	syslog(LOG_NOTICE, "%s uidvalidity changed, updating %u => %u",
	       mailbox->name, mailbox->i.uidvalidity, uidvalidity);
	/* make sure nothing new gets created with a lower value */
	mboxname_setuidvalidity(mailbox->name, uidvalidity, mailbox->mbtype);
	mailbox->i.uidvalidity = uidvalidity;
    }

    if (mailbox_has_conversations(mailbox)) {
	r = mailbox_update_xconvmodseq(mailbox, xconvmodseq, opt_force);
    }

done:
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);

    /* check the CRC too */
    if (!r && !crceq(synccrcs, mailbox_synccrcs(mailbox, 0))) {
	/* try forcing a recalculation */
	if (!crceq(synccrcs, mailbox_synccrcs(mailbox, 1)))
	    r = IMAP_SYNC_CHECKSUM;
    }

    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

static int getannotation_cb(const char *mailbox,
			    uint32_t uid __attribute__((unused)),
			    const char *entry, const char *userid,
			    const struct buf *value,
			    void *rock)
{
    struct protstream *pout = (struct protstream *)rock;
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, "ANNOTATION");
    dlist_setatom(kl, "MBOXNAME", mailbox);
    dlist_setatom(kl, "ENTRY", entry);
    dlist_setatom(kl, "USERID", userid);
    dlist_setmap(kl, "VALUE", value->s, value->len);
    sync_send_response(kl, pout);
    dlist_free(&kl);

    return 0;
}

int sync_get_annotation(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname = kin->sval;
    return annotatemore_findall(mboxname, 0, "*", &getannotation_cb,
				(void *) sstate->pout);
}

static void print_quota(struct quota *q, struct protstream *pout)
{
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, "QUOTA");
    dlist_setatom(kl, "ROOT", q->root);
    sync_encode_quota_limits(kl, q->limits);
    sync_send_response(kl, pout);
    dlist_free(&kl);
}

static int quota_work(const char *root, struct protstream *pout)
{
    struct quota q;

    quota_init(&q, root);
    if (!quota_read(&q, NULL, 0))
	print_quota(&q, pout);
    quota_free(&q);

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
    struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");
    annotate_state_t *astate = NULL;
    int r;

    /* XXX - we don't write anything, but there's no interface
     * to safely get read-only access to the annotation and
     * other "side" databases here */
    r = mailbox_open_iwl(name, &mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT ||
	r == IMAP_MAILBOX_RESERVED) {
	r = 0;
	goto out;
    }
    if (r) goto out;

    /* hold the annotate state open */
    mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    /* and make it hold a transaction open */
    annotate_state_begin(astate);

    if (qrl && mailbox->quotaroot &&
	 !sync_name_lookup(qrl, mailbox->quotaroot))
	sync_name_list_add(qrl, mailbox->quotaroot);

    r = sync_prepare_dlists(mailbox, NULL, NULL, kl, NULL, 0);
    if (!r) sync_send_response(kl, mrock->pout);

out:
    mailbox_close(&mailbox);
    dlist_free(&kl);

    return r;
}

int sync_get_fullmailbox(struct dlist *kin, struct sync_state *sstate)
{
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");
    int r;

    /* XXX again - this is a read-only request, but we
     * don't have a good way to express that, so we use
     * write locks anyway */
    r = mailbox_open_iwl(kin->sval, &mailbox);
    if (r) goto out;

    r = sync_prepare_dlists(mailbox, NULL, NULL, kl, NULL, 1);
    if (r) goto out;

    sync_send_response(kl, sstate->pout);

out:
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

    kl = dlist_newkvlist(NULL, "SEEN");
    dlist_setatom(kl, "UNIQUEID", uniqueid);
    dlist_setdate(kl, "LASTREAD", sd->lastread);
    dlist_setnum32(kl, "LASTUID", sd->lastuid);
    dlist_setdate(kl, "LASTCHANGE", sd->lastchange);
    dlist_setatom(kl, "SEENUIDS", sd->seenuids);
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

    kl = dlist_newlist(NULL, "LSUB");
    for (item = list->head; item; item = item->next) {
	dlist_setatom(kl, "MBOXNAME", item->name);
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
	kl = dlist_newkvlist(NULL, "SIEVE");
	dlist_setatom(kl, "FILENAME", sieve->name);
	dlist_setdate(kl, "LAST_UPDATE", sieve->last_update);
	dlist_setatom(kl, "GUID", message_guid_encode(&sieve->guid));
	dlist_setnum32(kl, "ISACTIVE", sieve->active ? 1 : 0);
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
    return mboxlist_deletemailbox(mboxname, sstate->userisadmin,
				  sstate->userid, sstate->authstate,
				  NULL, 0, sstate->local_only, 1);
}

int sync_apply_rename(struct dlist *kin, struct sync_state *sstate)
{
    const char *oldmboxname;
    const char *newmboxname;
    const char *partition;
    uint32_t uidvalidity = 0;

    if (!dlist_getatom(kin, "OLDMBOXNAME", &oldmboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "NEWMBOXNAME", &newmboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* optional */
    dlist_getnum32(kin, "UIDVALIDITY", &uidvalidity);

    return mboxlist_renamemailbox(oldmboxname, newmboxname, partition,
				  uidvalidity, 1, sstate->userid,
				  sstate->authstate, NULL, sstate->local_only, 1, 1);
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

    return mboxlist_changesub(mboxname, userid, sstate->authstate, add, add, 0);
}

/* ====================================================================== */

int sync_apply_annotation(struct dlist *kin, struct sync_state *sstate)
{
    struct entryattlist *entryatts = NULL;
    struct attvaluelist *attvalues = NULL;
    const char *mboxname = NULL;
    const char *entry = NULL;
    const char *mapval = NULL;
    size_t maplen = 0;
    struct buf value = BUF_INITIALIZER;
    const char *userid = NULL;
    char *name = NULL;
    struct mailbox *mailbox = NULL;
    annotate_state_t *astate = NULL;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ENTRY", &entry))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getmap(kin, "VALUE", &mapval, &maplen))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    buf_init_ro(&value, mapval, maplen);

    /* annotate_state_store() expects external mailbox names,
       so translate the separator character */
    name = xstrdup(mboxname);
    mboxname_hiersep_toexternal(sstate->namespace, name, 0);

    r = mailbox_open_iwl(name, &mailbox);
    if (r) goto done;

    appendattvalue(&attvalues,
		   *userid ? "value.priv" : "value.shared",
		   &value);
    appendentryatt(&entryatts, entry, attvalues);
    astate = annotate_state_new();
    annotate_state_set_auth(astate,
			    sstate->userisadmin, userid, sstate->authstate);
    r = annotate_state_set_mailbox(astate, mailbox);
    if (r) goto done;

    r = annotate_state_store(astate, entryatts);

done:
    if (!r)
	r = annotate_state_commit(&astate);
    else
	annotate_state_abort(&astate);

    mailbox_close(&mailbox);

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
    struct buf empty = BUF_INITIALIZER;
    char *name = NULL;
    struct mailbox *mailbox = NULL;
    annotate_state_t *astate = NULL;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ENTRY", &entry))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* (gnb)TODO: this is broken with unixhierarchysep */
    /* annotatemore_store() expects external mailbox names,
       so translate the separator character */
    name = xstrdup(mboxname);
    mboxname_hiersep_toexternal(sstate->namespace, name, 0);

    r = mailbox_open_iwl(name, &mailbox);
    if (r)
	goto done;

    appendattvalue(&attvalues,
		   *userid ? "value.priv" : "value.shared",
		   &empty);
    appendentryatt(&entryatts, entry, attvalues);
    astate = annotate_state_new();
    annotate_state_set_auth(astate,
			    sstate->userisadmin, userid, sstate->authstate);
    r = annotate_state_set_mailbox(astate, mailbox);
    if (r) goto done;

    r = annotate_state_store(astate, entryatts);

done:
    if (!r)
	r = annotate_state_commit(&astate);
    else
	annotate_state_abort(&astate);
    mailbox_close(&mailbox);
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
    if (!dlist_getmap(kin, "CONTENT", &content, &len))
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
			      struct sync_state *sstate __attribute((unused)))
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
    if (!dlist_getnum32(kin, "LASTUID", &sd.lastuid))
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
	mboxlist_changesub(item->name, userid, sstate->authstate, 0, 0, 0);
    }
    sync_name_list_free(&list);

    /* Nuke normal folders */
    list = sync_name_list_create();

    (*sstate->namespace->mboxname_tointernal)(sstate->namespace, "INBOX",
					   userid, buf);
    strlcat(buf, ".*", sizeof(buf));
    r = (*sstate->namespace->mboxlist_findall)(sstate->namespace, buf,
					    sstate->userisadmin,
					    sstate->userid, sstate->authstate,
					    addmbox, (void *)list);
    if (r) goto fail;

    for (item = list->head; item; item = item->next) {
	r = mboxlist_deletemailbox(item->name, sstate->userisadmin,
				   sstate->userid, sstate->authstate,
				   NULL, 0, sstate->local_only, 1);
	if (r) goto fail;
    }

    /* Nuke inbox (recursive nuke possible?) */
    (*sstate->namespace->mboxname_tointernal)(sstate->namespace, "INBOX",
					   userid, buf);
    r = mboxlist_deletemailbox(buf, sstate->userisadmin, sstate->userid,
			       sstate->authstate, NULL, 0, sstate->local_only, 0);
    if (r && (r != IMAP_MAILBOX_NONEXISTENT)) goto fail;

    r = user_deletedata(userid, 1);

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

    kl = dlist_newkvlist(NULL, "SIEVE");
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    dlist_setmap(kl, "CONTENT", sieve, size);
    sync_send_response(kl, sstate->pout);
    dlist_free(&kl);
    free(sieve);

    return 0;
}

/* NOTE - can't lock a mailbox here, because it could deadlock,
 * so just pick the file out from under the hood */
int sync_get_message(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname;
    const char *partition;
    const char *uniqueid;
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
    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "GUID", &guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "UID", &uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!message_guid_decode(&tmp_guid, guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    fname = mboxname_datapath(partition, mboxname, uniqueid, uid);
    if (stat(fname, &sbuf) == -1) {
	fname = mboxname_archivepath(partition, mboxname, uniqueid, uid);
	if (stat(fname, &sbuf) == -1)
	    return IMAP_MAILBOX_NONEXISTENT;
    }

    kl = dlist_setfile(NULL, "MESSAGE", partition, &tmp_guid, sbuf.st_size, fname);
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

    for (ui = ul->head; ui; ui = ui->next) {
	struct index_record oldrecord;
	r = mailbox_find_index_record(mailbox, dlist_num(ui), &oldrecord);
	if (r) continue; /* skip */
	oldrecord.system_flags |= FLAG_EXPUNGED;
	oldrecord.silent = 1; /* so the next sync will succeed */
	r = mailbox_rewrite_index_record(mailbox, &oldrecord);
	if (r) goto done;
    }

done:
    mailbox_close(&mailbox);
    return r;
}

int sync_apply_message(struct dlist *kin,
		       struct sync_reserve_list *reserve_list,
		       struct sync_state *sstate __attribute((unused)))
{
    struct sync_msgid_list *part_list;
    struct dlist *ki;
    struct sync_msgid *msgid;

    for (ki = kin->head; ki; ki = ki->next) {
	struct message_guid *guid;
	const char *part;
	size_t size;
	const char *fname;

	/* XXX - complain more? */
	if (!dlist_tofile(ki, &part, &guid, (ulong *) &size, &fname))
	    continue;

	part_list = sync_reserve_partlist(reserve_list, part);
	msgid = sync_msgid_insert(part_list, guid);
	if (!msgid->need_upload)
	    continue;

	msgid->size = size;
	if (!msgid->fname) msgid->fname = xstrdup(fname);
	msgid->need_upload = 0;
	part_list->toupload--;
    }

    return 0;
}

static const char *sync_response(int r)
{
    const char *resp;

    switch (r) {
    case 0:
	resp = "OK success";
	break;
    case IMAP_INVALID_USER:
	resp = "NO IMAP_INVALID_USER No Such User";
	break;
    case IMAP_MAILBOX_NONEXISTENT:
	resp = "NO IMAP_MAILBOX_NONEXISTENT No Such Mailbox";
	break;
    case IMAP_SYNC_CHECKSUM:
	resp = "NO IMAP_SYNC_CHECKSUM Checksum Failure";
	break;
    case IMAP_PROTOCOL_ERROR:
	resp = "NO IMAP_PROTOCOL_ERROR Protocol error";
	break;
    case IMAP_PROTOCOL_BAD_PARAMETERS:
	resp = "NO IMAP_PROTOCOL_BAD_PARAMETERS";
//	XXX resp = "NO IMAP_PROTOCOL_BAD_PARAMETERS near %s\r\n", dlist_lastkey());
	break;
    default:
	resp = "NO Unknown error";
    }

    return resp;
}

/* =======================  client-side sync  =========================== */

/* Routines relevant to reserve operation */

/* Find the messages that we will want to upload from this mailbox,
 * flag messages that are already available at the server end */

int sync_find_reserve_messages(struct mailbox *mailbox,
			       unsigned last_uid,
			       struct sync_msgid_list *part_list)
{
    const struct index_record *record;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    mailbox_iter_startuid(iter, last_uid+1); /* only read new records */
    while ((record = mailbox_iter_step(iter))) {
	sync_msgid_insert(part_list, &record->guid);
    }
    mailbox_iter_done(&iter);

    return(0);
}

static int find_reserve_all(struct sync_name_list *mboxname_list,
			    struct sync_folder_list *master_folders,
			    struct sync_folder_list *replica_folders,
			    struct sync_reserve_list *reserve_list)
{
    struct sync_name *mbox;
    struct sync_folder *rfolder;
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox = NULL;
    modseq_t xconvmodseq;
    int r = 0;

    /* Find messages we want to upload that are available on server */
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
	/* XXX - now this kinda sucks - we use a write lock here
	 * purely for conversations modseq - but we never actually
	 * USE the value... the whole "add to master folders" actually
	 * looks a bit pointless... */
	r = mailbox_open_iwl(mbox->name, &mailbox);

	/* Quietly skip over folders which have been deleted since we
	   started working (but record fact in case caller cares) */
	if (r == IMAP_MAILBOX_NONEXISTENT) {
	    r = 0;
	    continue;
	}

	if (r) {
	    syslog(LOG_ERR, "IOERROR: Failed to open %s: %s",
		   mbox->name, error_message(r));
	    goto bail;
	}

	xconvmodseq = 0;
	if (mailbox_has_conversations(mailbox)) {
	    r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: Failed to get xconvmodseq %s: %s",
		       mbox->name, error_message(r));
		goto bail;
	    }
	}

	/* mailbox is open from here, no exiting without closing it! */

	part_list = sync_reserve_partlist(reserve_list, mailbox->part);

	sync_folder_list_add(master_folders, mailbox->uniqueid, mailbox->name,
			     mailbox->mbtype,
			     mailbox->part, mailbox->acl, mailbox->i.options,
			     mailbox->i.uidvalidity, mailbox->i.last_uid,
			     mailbox->i.highestmodseq, mailbox->i.synccrcs,
			     mailbox->i.recentuid, mailbox->i.recenttime,
			     mailbox->i.pop3_last_login,
			     mailbox->i.pop3_show_after, NULL, xconvmodseq);

	rfolder = sync_folder_lookup(replica_folders, mailbox->uniqueid);
	if (rfolder)
	    sync_find_reserve_messages(mailbox, rfolder->last_uid, part_list);
	else
	    sync_find_reserve_messages(mailbox, 0, part_list);

	mailbox_close(&mailbox);
    }

bail:
    mailbox_close(&mailbox);
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

	/* afraid we will need this after all */
	msgid = sync_msgid_lookup(part_list, &tmp_guid);
	if (msgid && !msgid->need_upload) {
	    msgid->need_upload = 1;
	    part_list->toupload++;
	}
    }

    return 0;
}

int sync_reserve_partition(char *partition,
			   struct sync_folder_list *replica_folders,
			   struct sync_msgid_list *part_list,
			   struct backend *sync_be)
{
    const char *cmd = "RESERVE";
    struct sync_msgid *msgid = part_list->head;
    struct sync_folder *folder;
    struct dlist *kl = NULL;
    struct dlist *kin = NULL;
    struct dlist *ki;
    int r = 0;

    if (!replica_folders->head)
	return 0; /* nowhere to reserve */

    while (msgid) {
	int n = 0;

	if (!part_list->toupload)
	    goto done; /* got them all */

	kl = dlist_newkvlist(NULL, cmd);
	dlist_setatom(kl, "PARTITION", partition);

	ki = dlist_newlist(kl, "MBOXNAME");
	for (folder = replica_folders->head; folder; folder = folder->next)
	    dlist_setatom(ki, "MBOXNAME", folder->name);

	ki = dlist_newlist(kl, "GUID");
	for (; msgid; msgid = msgid->next) {
	    if (!msgid->need_upload) continue;
	    if (n > 8192) break;
	    dlist_setatom(ki, "GUID", message_guid_encode(&msgid->guid));
	    /* we will re-add the "need upload" if we get a MISSING response */
	    msgid->need_upload = 0;
	    part_list->toupload--;
	    n++;
	}

	sync_send_apply(kl, sync_be->out);

	r = sync_parse_response(cmd, sync_be->in, &kin);
	if (r) goto done;

	r = mark_missing(kin, part_list);
	if (r) goto done;

	dlist_free(&kl);
	dlist_free(&kin);
    }

done:
    dlist_free(&kl);
    dlist_free(&kin);
    return r;
}

static int reserve_messages(struct sync_name_list *mboxname_list,
			    struct sync_folder_list *master_folders,
			    struct sync_folder_list *replica_folders,
			    struct sync_reserve_list *reserve_list,
			    struct backend *sync_be)
{
    struct sync_reserve *reserve;
    int r;

    r = find_reserve_all(mboxname_list, master_folders,
			 replica_folders, reserve_list);
    if (r) return r;

    for (reserve = reserve_list->head; reserve; reserve = reserve->next) {
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
	    struct message_guid guid;
	    const char *filename = NULL;
	    const char *guidstr = NULL;
	    time_t modtime = 0;
	    uint32_t active = 0;
	    if (!sieve_list) goto parse_err;
	    if (!dlist_getatom(kl, "FILENAME", &filename)) goto parse_err;
	    if (!dlist_getdate(kl, "LAST_UPDATE", &modtime)) goto parse_err;
	    dlist_getatom(kl, "GUID", &guidstr); /* optional */
	    if (guidstr) {
		if (!message_guid_decode(&guid, guidstr)) goto parse_err;
	    }
	    else {
		message_guid_set_null(&guid);
	    }
	    dlist_getnum32(kl, "ISACTIVE", &active); /* optional */
	    sync_sieve_list_add(sieve_list, filename, modtime, &guid, active);
	}

	else if (!strcmp(kl->name, "QUOTA")) {
	    const char *root = NULL;
	    struct sync_quota *sq;
	    if (!quota_list) goto parse_err;
	    if (!dlist_getatom(kl, "ROOT", &root)) goto parse_err;
	    sq = sync_quota_list_add(quota_list, root);
	    sync_decode_quota_limits(kl, sq->limits);
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
	    if (!dlist_getnum32(kl, "LASTUID", &lastuid)) goto parse_err;
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
	    struct synccrcs synccrcs = { 0, 0 };
	    uint32_t recentuid = 0;
	    time_t recenttime = 0;
	    time_t pop3_last_login = 0;
	    time_t pop3_show_after = 0;
	    struct dlist *al = NULL;
	    struct sync_annot_list *annots = NULL;
	    modseq_t xconvmodseq = 0;

	    if (!folder_list) goto parse_err;
	    if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) goto parse_err;
	    if (!dlist_getatom(kl, "MBOXNAME", &mboxname)) goto parse_err;
	    if (!dlist_getatom(kl, "PARTITION", &part)) goto parse_err;
	    if (!dlist_getatom(kl, "ACL", &acl)) goto parse_err;
	    if (!dlist_getatom(kl, "OPTIONS", &options)) goto parse_err;
	    if (!dlist_getnum64(kl, "HIGHESTMODSEQ", &highestmodseq)) goto parse_err;
	    if (!dlist_getnum32(kl, "UIDVALIDITY", &uidvalidity)) goto parse_err;
	    if (!dlist_getnum32(kl, "LAST_UID", &last_uid)) goto parse_err;
	    if (!dlist_getnum32(kl, "SYNC_CRC", &synccrcs.basic)) goto parse_err;
	    if (!dlist_getnum32(kl, "RECENTUID", &recentuid)) goto parse_err;
	    if (!dlist_getdate(kl, "RECENTTIME", &recenttime)) goto parse_err;
	    if (!dlist_getdate(kl, "POP3_LAST_LOGIN", &pop3_last_login)) goto parse_err;
	    /* optional */
	    dlist_getdate(kl, "POP3_SHOW_AFTER", &pop3_show_after);
	    dlist_getatom(kl, "MBOXTYPE", &mboxtype);
	    dlist_getnum32(kl, "SYNC_CRC_ANNOT", &synccrcs.annot);
	    dlist_getnum64(kl, "XCONVMODSEQ", &xconvmodseq);

	    if (dlist_getlist(kl, "ANNOTATIONS", &al))
		decode_annotations(al, &annots, NULL);


	    sync_folder_list_add(folder_list, uniqueid, mboxname,
				 mboxlist_string_to_mbtype(mboxtype),
				 part, acl,
				 sync_parse_options(options),
				 uidvalidity, last_uid,
				 highestmodseq, synccrcs,
				 recentuid, recenttime,
				 pop3_last_login,
				 pop3_show_after, annots,
				 xconvmodseq);
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

static int user_reset(const char *userid, struct backend *sync_be)
{
    const char *cmd = "UNUSER";
    struct dlist *kl;

    kl = dlist_setatom(NULL, cmd, userid);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int folder_rename(const char *oldname, const char *newname,
			 const char *partition, unsigned uidvalidity,
			 struct backend *sync_be, unsigned flags)
{
    const char *cmd = (flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_RENAME" : "RENAME";
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "OLDMBOXNAME", oldname);
    dlist_setatom(kl, "NEWMBOXNAME", newname);
    dlist_setatom(kl, "PARTITION", partition);
    dlist_setnum32(kl, "UIDVALIDITY", uidvalidity);

    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

int sync_folder_delete(const char *mboxname, struct backend *sync_be, unsigned flags)
{
    const char *cmd =
	(flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_UNMAILBOX" :"UNMAILBOX";
    struct dlist *kl;
    int r;

    kl = dlist_setatom(NULL, cmd, mboxname);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_be->in, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT)
	r = 0;

    return r;
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

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "MBOXNAME", mboxname);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int folder_setannotation(const char *mboxname, const char *entry,
				const char *userid, const struct buf *value,
				struct backend *sync_be)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "MBOXNAME", mboxname);
    dlist_setatom(kl, "ENTRY", entry);
    dlist_setatom(kl, "USERID", userid);
    dlist_setmap(kl, "VALUE", value->s, value->len);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int folder_unannotation(const char *mboxname, const char *entry,
			       const char *userid, struct backend *sync_be)
{
    const char *cmd = "UNANNOTATION";
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "MBOXNAME", mboxname);
    dlist_setatom(kl, "ENTRY", entry);
    dlist_setatom(kl, "USERID", userid);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

/* ====================================================================== */

static int sieve_upload(const char *userid, const char *filename,
			unsigned long last_update, struct backend *sync_be)
{
    const char *cmd = "SIEVE";
    struct dlist *kl;
    char *sieve;
    uint32_t size;

    sieve = sync_sieve_read(userid, filename, &size);
    if (!sieve) return IMAP_IOERROR;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    dlist_setdate(kl, "LAST_UPDATE", last_update);
    dlist_setmap(kl, "CONTENT", sieve, size);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);
    free(sieve);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int sieve_delete(const char *userid, const char *filename, struct backend *sync_be)
{
    const char *cmd = "UNSIEVE";
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int sieve_activate(const char *userid, const char *filename, struct backend *sync_be)
{
    const char *cmd = "ACTIVATE_SIEVE";
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int sieve_deactivate(const char *userid, struct backend *sync_be)
{
    const char *cmd = "UNACTIVATE_SIEVE";
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

/* ====================================================================== */

static int delete_quota(const char *root, struct backend *sync_be)
{
    const char *cmd = "UNQUOTA";
    struct dlist *kl;

    kl = dlist_setatom(NULL, cmd, root);
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

    if (server) {
	int changed = 0;
	int res;
	for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
	    if (client->limits[res] != server->limits[res])
		changed++;
	}
	if (!changed)
	    return 0;
    }

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "ROOT", client->root);
    sync_encode_quota_limits(kl, client->limits);
    sync_send_apply(kl, sync_be->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_be->in, NULL);
}

static int copy_local(struct mailbox *mailbox, unsigned uid)
{
    char *oldfname, *newfname;
    struct index_record newrecord;
    struct index_record oldrecord;
    int r;
    annotate_state_t *astate = NULL;

    if (mailbox_find_index_record(mailbox, uid, &oldrecord)) {
	/* not finding the record is an error! (should never happen) */
	syslog(LOG_ERR, "IOERROR: copy_local didn't find the record for %u", uid);
	return IMAP_MAILBOX_NONEXISTENT;
    }

    /* create the new record as a clone of the old record */
    newrecord = oldrecord;
    newrecord.uid = mailbox->i.last_uid + 1;

    /* copy the file in to place */
    oldfname = xstrdup(mailbox_record_fname(mailbox, &oldrecord));
    newfname = xstrdup(mailbox_record_fname(mailbox, &newrecord));
    r = mailbox_copyfile(oldfname, newfname, 0);
    free(oldfname);
    free(newfname);
    if (r) return r;

    /* append the new record */
    r = mailbox_append_index_record(mailbox, &newrecord);
    if (r) return r;

    /* ensure we have an astate connected to the destination
     * mailbox, so that the annotation txn will be committed
     * when we close the mailbox */
    r = mailbox_get_annotate_state(mailbox, newrecord.uid, &astate);
    if (r) return r;

    /* Copy across any per-message annotations */
    r = annotate_msg_copy(mailbox, oldrecord.uid,
			  mailbox, newrecord.uid,
			  NULL);
    if (r) return r;

    /* and expunge the old record */
    oldrecord.system_flags |= FLAG_EXPUNGED;
    r = mailbox_rewrite_index_record(mailbox, &oldrecord);

    /* done - return */
    return r;
}

static int fetch_file(struct mailbox *mailbox, unsigned uid,
		      const struct index_record *rp, struct sync_msgid_list *part_list,
		      struct backend *sync_be)
{
    const char *cmd = "FETCH";
    struct dlist *kin = NULL;
    struct dlist *kl;
    int r = 0;
    struct sync_msgid *msgid;
    struct message_guid *guid = NULL;
    size_t size = 0;
    const char *fname = NULL;

    msgid = sync_msgid_lookup(part_list, &rp->guid);

    /* already reserved? great */
    if (msgid && msgid->fname) {
	syslog(LOG_NOTICE, "trying to get already uploaded %u: %s", uid, message_guid_encode(&rp->guid));
	return 0;
    }

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "MBOXNAME", mailbox->name);
    dlist_setatom(kl, "PARTITION", mailbox->part);
    dlist_setatom(kl, "UNIQUEID", mailbox->uniqueid);
    dlist_setguid(kl, "GUID", &rp->guid);
    dlist_setnum32(kl, "UID", uid);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_be->in, &kin);
    if (r) {
	syslog(LOG_ERR, "IOERROR: fetch_file failed %s", error_message(r));
	return r;
    }

    if (!dlist_tofile(kin->head, NULL, &guid, (ulong *) &size, &fname)) {
	r = IMAP_MAILBOX_NONEXISTENT;
	syslog(LOG_ERR, "IOERROR: fetch_file failed tofile %s", error_message(r));
	goto done;
    }

    /* well, we can copy it back or we can re-reserve... */
    if (message_guid_equal(guid, &rp->guid) && (size == rp->size)) {
	msgid = sync_msgid_insert(part_list, &rp->guid);
	msgid->need_upload = 1;
	msgid->size = size;
	if (!msgid->fname) msgid->fname = xstrdup(fname);
    }
    else {
	r = IMAP_MAILBOX_NONEXISTENT;
	syslog(LOG_ERR, "IOERROR: fetch_file GUID MISMATCH %s", error_message(r));
	r = IMAP_IOERROR;
    }

done:
    dlist_free(&kin);
    return r;
}

static int copy_remote(struct mailbox *mailbox, uint32_t uid,
		       struct dlist *kr, struct sync_msgid_list *part_list)
{
    struct index_record record;
    struct dlist *ki;
    int r;
    struct sync_annot_list *annots = NULL;

    for (ki = kr->head; ki; ki = ki->next) {
	r = parse_upload(ki, mailbox, &record, &annots);
	if (r) {
	    syslog(LOG_ERR, "IOERROR: failed to parse upload for %u", uid);
	    return r;
	}
	if (record.uid == uid) {
	    /* choose the destination UID */
	    record.uid = mailbox->i.last_uid + 1;

	    /* append the file */
	    r = sync_append_copyfile(mailbox, &record, annots, part_list);

	    sync_annot_list_free(&annots);

	    return r;
	}
	sync_annot_list_free(&annots);
    }
    /* not finding the record is an error! (should never happen) */
    syslog(LOG_ERR, "IOERROR: copy_remote didn't find the record for %u", uid);
    return IMAP_MAILBOX_NONEXISTENT;
}

static int copyback_one_record(struct mailbox *mailbox,
			       struct index_record *rp,
			       const struct sync_annot_list *annots,
			       struct dlist *kaction,
			       struct sync_msgid_list *part_list,
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
		dlist_setnum32(kaction, "EXPUNGE", rp->uid);
	}
	else {
	    r = fetch_file(mailbox, rp->uid, rp, part_list, sync_be);
	    if (r) return r;
	    if (kaction)
		dlist_setnum32(kaction, "COPYBACK", rp->uid);
	}
    }

    /* otherwise we can pull it in with the same UID,
     * which saves causing renumbering on the replica
     * end, so is preferable */
    else {
	/* grab the file */
	r = fetch_file(mailbox, rp->uid, rp, part_list, sync_be);
	if (r) return r;
	/* make sure we're actually making changes now */
	if (!kaction) return 0;
	/* append the file */
	r = sync_append_copyfile(mailbox, rp, annots, part_list);
	if (r) return r;
    }

    return 0;
}

static int renumber_one_record(const struct index_record *mp,
			       struct dlist *kaction)
{
    /* don't want to renumber expunged records */
    if (mp->system_flags & FLAG_EXPUNGED)
	return 0;

    if (kaction)
	dlist_setnum32(kaction, "RENUMBER", mp->uid);

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
	  "last_updated:%lu internaldate:%lu flags:(%s) cid:" CONV_FMT,
	   name, record->uid, record->modseq,
	   record->last_updated, record->internaldate,
	   make_flags(mailbox, record), record->cid);
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
			      const struct sync_annot_list *mannots,
			      const struct sync_annot_list *rannots,
			      struct dlist *kaction,
			      struct sync_msgid_list *part_list,
			      struct backend *sync_be)
{
    int i;
    int r;

    /* if both ends are expunged, then we do no more processing.  This
     * allows a split brain cleanup to not break things forever.  It
     * does mean that an expunged message might not replicate in that
     * case, but the only way to fix this is add ANOTHER special flag
     * for BROKEN and only ignore GUID mismatches in that case, after
     * moving the message up.  I guess we could force UNLINK immediately
     * too... hmm.  Not today. */

    if ((mp->system_flags & FLAG_EXPUNGED) && (rp->system_flags & FLAG_EXPUNGED))
	return 0;

    /* first of all, check that GUID matches.  If not, we have had a split
     * brain, so the messages both need to be fixed up to their new UIDs.
     * After this function succeeds, both the local and remote copies of this
     * current UID will be actually EXPUNGED, so the earlier return applies. */
    if (!message_guid_equal(&mp->guid, &rp->guid)) {
	char *mguid = xstrdup(message_guid_encode(&mp->guid));
	char *rguid = xstrdup(message_guid_encode(&rp->guid));
	syslog(LOG_ERR, "SYNCERROR: guid mismatch %s %u (%s %s)",
	       mailbox->name, mp->uid, rguid, mguid);
	free(rguid);
	free(mguid);
	/* we will need to renumber both ends to get in sync */

	/* ORDERING - always lower GUID first */
	if (message_guid_cmp(&mp->guid, &rp->guid) > 0) {
	    r = copyback_one_record(mailbox, rp, rannots, kaction, part_list, sync_be);
	    if (!r) r = renumber_one_record(mp, kaction);
	}
	else {
	    r = renumber_one_record(mp, kaction);
	    if (!r) r = copyback_one_record(mailbox, rp, rannots, kaction, part_list, sync_be);
	}

	return r;
    }

    /* are there any differences? */
    if (mp->modseq != rp->modseq)
	goto diff;
    if (mp->last_updated != rp->last_updated)
	goto diff;
    if (mp->internaldate != rp->internaldate)
	goto diff;
    if ((mp->system_flags & FLAGS_GLOBAL) != rp->system_flags)
	goto diff;
    if (mp->cid != rp->cid)
	goto diff;
    if (diff_annotations(mannots, rannots))
	goto diff;
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	if (mp->user_flags[i] != rp->user_flags[i])
	    goto diff;
    }

    /* no changes found, whoopee */
    return 0;

 diff:
    /* if differences we'll have to rewrite to bump the modseq
     * so that regular replication will cause an update */

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

    /* otherwise, is the replica "newer"?  Better grab those flags */
    else {
	if (rp->modseq > mp->modseq &&
	    rp->last_updated >= mp->last_updated) {
	    log_mismatch("more recent on replica", mailbox, mp, rp);
	    /* then copy all the flag data over from the replica */
	    mp->system_flags = (rp->system_flags & FLAGS_GLOBAL) |
			       (mp->system_flags & FLAGS_LOCAL);
	    mp->cid = rp->cid;
	    for (i = 0; i < MAX_USER_FLAGS/32; i++)
		mp->user_flags[i] = rp->user_flags[i];
	}
    }

    /* are we making changes yet? */
    if (!kaction) return 0;

    /* even expunged messages get annotations synced */
    r = apply_annotations(mailbox, mp, mannots, rannots, 0);
    if (r) return r;

    /* this will bump the modseq and force a resync either way :) */
    return mailbox_rewrite_index_record(mailbox, mp);
}

static int mailbox_update_loop(struct mailbox *mailbox,
			       struct dlist *ki,
			       uint32_t last_uid,
			       modseq_t highestmodseq,
			       struct dlist *kaction,
			       struct sync_msgid_list *part_list,
			       struct backend *sync_be)
{
    const struct index_record *mrecord;
    struct index_record rrecord;
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int r;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    mrecord = mailbox_iter_step(iter);

    /* while there are more records on either master OR replica,
     * work out what to do with them */
    while (ki || mrecord) {

	sync_annot_list_free(&mannots);
	sync_annot_list_free(&rannots);

	/* most common case - both a master AND a replica record exist */
	if (ki && mrecord) {
	    r = read_annotations(mailbox, mrecord, &mannots);
	    if (r) goto out;
	    r = parse_upload(ki, mailbox, &rrecord, &rannots);
	    if (r) goto out;

	    /* same UID - compare the records */
	    if (rrecord.uid == mrecord->uid) {
		r = compare_one_record(mailbox,
				       (struct index_record *)mrecord, &rrecord,
				       mannots, rannots,
				       kaction, part_list,
				       sync_be);
		if (r) goto out;
		/* increment both */
		mrecord = mailbox_iter_step(iter);
		ki = ki->next;
	    }
	    else if (rrecord.uid > mrecord->uid) {
		/* record only exists on the master */
		if (!(mrecord->system_flags & FLAG_EXPUNGED)) {
		    syslog(LOG_ERR, "SYNCERROR: only exists on master %s %u (%s)",
			   mailbox->name, mrecord->uid,
			   message_guid_encode(&mrecord->guid));
		    r = renumber_one_record(mrecord, kaction);
		    if (r) goto out;
		}
		/* only increment master */
		mrecord = mailbox_iter_step(iter);
	    }
	    else {
		/* record only exists on the replica */
		if (!(rrecord.system_flags & FLAG_EXPUNGED)) {
		    if (kaction)
			syslog(LOG_ERR, "SYNCERROR: only exists on replica %s %u (%s)",
			       mailbox->name, rrecord.uid,
			       message_guid_encode(&rrecord.guid));
		    r = copyback_one_record(mailbox, &rrecord, rannots, kaction, part_list, sync_be);
		    if (r) goto out;
		}
		/* only increment replica */
		ki = ki->next;
	    }
	}

	/* no more replica records, but still master records */
	else if (mrecord) {
	    /* if the replica has seen this UID, we need to renumber.
	     * Otherwise it will replicate fine as-is */
	    if (mrecord->uid <= last_uid) {
		r = renumber_one_record(mrecord, kaction);
		if (r) goto out;
	    }
	    else if (mrecord->modseq <= highestmodseq) {
		if (kaction) {
		    /* bump our modseq so we sync */
		    syslog(LOG_NOTICE, "SYNCNOTICE: bumping modseq %s %u",
			   mailbox->name, mrecord->uid);
		    r = mailbox_rewrite_index_record(mailbox, (struct index_record *)mrecord);
		    if (r) goto out;
		}
	    }
	    mrecord = mailbox_iter_step(iter);
	}

	/* record only exists on the replica */
	else {
	    r = parse_upload(ki, mailbox, &rrecord, &rannots);
	    if (r) goto out;

	    if (kaction)
		syslog(LOG_NOTICE, "SYNCNOTICE: only on replica %s %u",
		       mailbox->name, rrecord.uid);

	    /* going to need this one */
	    r = copyback_one_record(mailbox, &rrecord, rannots, kaction, part_list, sync_be);
	    if (r) goto out;

	    ki = ki->next;
	}
    }
    r = 0;

out:
    mailbox_iter_done(&iter);
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);
    return r;
}

static int mailbox_full_update(struct sync_folder *local,
			       struct sync_reserve_list *reserve_list,
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
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int remote_modseq_was_higher = 0;
    modseq_t xconvmodseq = 0;
    struct sync_msgid_list *part_list;

    if (flags & SYNC_FLAG_LOGGING) {
	syslog(LOG_INFO, "%s %s", cmd, local->name);
    }

    kl = dlist_setatom(NULL, cmd, local->name);
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

    if (!dlist_getnum64(kl, "HIGHESTMODSEQ", &highestmodseq)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    if (!dlist_getnum32(kl, "UIDVALIDITY", &uidvalidity)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    if (!dlist_getnum32(kl, "LAST_UID", &last_uid)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    if (!dlist_getlist(kl, "RECORD", &kr)) {
	r = IMAP_PROTOCOL_BAD_PARAMETERS;
	goto done;
    }

    /* optional */
    dlist_getnum64(kl, "XCONVMODSEQ", &xconvmodseq);

    /* we'll be updating it! */
    if (local->mailbox) mailbox = local->mailbox;
    else r = mailbox_open_iwl(local->name, &mailbox);
    if (r) goto done;

    part_list = sync_reserve_partlist(reserve_list, mailbox->part);

    /* if local UIDVALIDITY is lower, copy from remote, otherwise
     * remote will copy ours when we sync */
    if (mailbox->i.uidvalidity < uidvalidity) {
	syslog(LOG_NOTICE, "SYNCNOTICE: uidvalidity higher on replica %s"
	       ", updating %u => %u",
	       mailbox->name, mailbox->i.uidvalidity, uidvalidity);
	mailbox_index_dirty(mailbox);
	mboxname_setuidvalidity(mailbox->name, uidvalidity, mailbox->mbtype);
	mailbox->i.uidvalidity = uidvalidity;
    }

    if (mailbox->i.highestmodseq < highestmodseq) {
	/* highestmodseq on replica is dirty - we must copy and then dirty
	 * so we go one higher! */
	syslog(LOG_NOTICE, "SYNCNOTICE: highestmodseq higher on replica %s"
	       ", updating " MODSEQ_FMT " => " MODSEQ_FMT,
	       mailbox->name, mailbox->i.highestmodseq, highestmodseq+1);
	mailbox->modseq_dirty = 0;
	mailbox->i.highestmodseq = highestmodseq;
	mailbox_modseq_dirty(mailbox);
	remote_modseq_was_higher = 1;
    }

    r = mailbox_update_loop(mailbox, kr->head, last_uid,
			    highestmodseq, NULL, part_list, sync_be);
    if (r) {
	syslog(LOG_ERR, "SYNCNOTICE: failed to prepare update for %s: %s",
	       mailbox->name, error_message(r));
	goto done;
    }

    /* OK - now we're committed to make changes! */

    /* this is safe because "larger than" logic is embedded
     * inside update_xconvmodseq */
    if (mailbox_has_conversations(mailbox)) {
	r = mailbox_update_xconvmodseq(mailbox, xconvmodseq, /* force */0);
	if (r) goto done;
    }

    kaction = dlist_newlist(NULL, "ACTION");
    r = mailbox_update_loop(mailbox, kr->head, last_uid,
			    highestmodseq, kaction, part_list, sync_be);
    if (r) goto cleanup;

    /* if replica still has a higher last_uid, bump our local
     * number to match so future records don't clash */
    if (mailbox->i.last_uid < last_uid)
	mailbox->i.last_uid = last_uid;

    /* ugly variable reuse */
    dlist_getlist(kl, "ANNOTATIONS", &ka);

    if (ka) decode_annotations(ka, &rannots, NULL);
    r = read_annotations(mailbox, NULL, &mannots);
    if (r) goto cleanup;
    r = apply_annotations(mailbox, NULL, mannots, rannots,
			  !remote_modseq_was_higher);
    if (r) goto cleanup;

    /* blatant reuse 'r' us */
    kexpunge = dlist_newkvlist(NULL, "EXPUNGE");
    dlist_setatom(kexpunge, "MBOXNAME", mailbox->name);
    dlist_setatom(kexpunge, "UNIQUEID", mailbox->uniqueid); /* just for safety */
    kuids = dlist_newlist(kexpunge, "UID");
    for (ka = kaction->head; ka; ka = ka->next) {
	if (!strcmp(ka->name, "EXPUNGE")) {
	    dlist_setnum32(kuids, "UID", dlist_num(ka));
	}
	else if (!strcmp(ka->name, "COPYBACK")) {
	    r = copy_remote(mailbox, dlist_num(ka), kr, part_list);
	    if (r) goto cleanup;
	    dlist_setnum32(kuids, "UID", dlist_num(ka));
	}
	else if (!strcmp(ka->name, "RENUMBER")) {
	    r = copy_local(mailbox, dlist_num(ka));
	    if (r) goto cleanup;
	}
    }

    /* we still need to do the EXPUNGEs */
 cleanup:

    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);

    /* close the mailbox before sending any expunges
     * to avoid deadlocks */
    if (!local->mailbox) mailbox_close(&mailbox);

    /* only send expunge if we have some UIDs to expunge */
    if (kuids && kuids->head) {
	int r2;
	sync_send_apply(kexpunge, sync_be->out);
	r2 = sync_parse_response("EXPUNGE", sync_be->in, NULL);
	if (r2) {
	    syslog(LOG_ERR, "SYNCERROR: failed to expunge in cleanup %s",
		   local->name);
	}
    }

done:
    if (r && mailbox)
	annotate_state_abort(&mailbox->annot_state);

    if (mailbox && !local->mailbox) mailbox_close(&mailbox);

    dlist_free(&kin);
    dlist_free(&kaction);
    dlist_free(&kexpunge);
    /* kuids points into the tree rooted at kexpunge
     * so we don't need to free it explicitly here */

    return r;
}

static int is_unchanged(struct mailbox *mailbox, struct sync_folder *remote)
{
    /* look for any mismatches */
    unsigned options = mailbox->i.options & MAILBOX_OPTIONS_MASK;
    modseq_t xconvmodseq = 0;

    if (!remote) return 0;
    if (remote->mbtype != mailbox->mbtype) return 0;
    if (remote->last_uid != mailbox->i.last_uid) return 0;
    if (remote->highestmodseq != mailbox->i.highestmodseq) return 0;
    if (remote->uidvalidity != mailbox->i.uidvalidity) return 0;
    if (remote->recentuid != mailbox->i.recentuid) return 0;
    if (remote->recenttime != mailbox->i.recenttime) return 0;
    if (remote->pop3_last_login != mailbox->i.pop3_last_login) return 0;
    if (remote->pop3_show_after != mailbox->i.pop3_show_after) return 0;
    if (remote->options != options) return 0;
    if (strcmp(remote->acl, mailbox->acl)) return 0;

    if (mailbox_has_conversations(mailbox)) {
	int r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
	if (r) return 0;

	if (remote->xconvmodseq != xconvmodseq) return 0;
    }

    /* compare annotations */
    {
	struct sync_annot_list *mannots = NULL;
	int r = read_annotations(mailbox, NULL, &mannots);
	if (r) return 0;

	if (diff_annotations(mannots, remote->annots)) {
	    sync_annot_list_free(&mannots);
	    return 0;
	}
	sync_annot_list_free(&mannots);
    }

    /* if we got here then we should force check the CRCs */
    if (!crceq(remote->synccrcs, mailbox_synccrcs(mailbox, /*force*/0)))
	if (!crceq(remote->synccrcs, mailbox_synccrcs(mailbox, /*force*/1)))
	    return 0;

    /* otherwise it's unchanged! */
    return 1;
}

/* XXX kind of nasty having this here, but i think it probably
 * shouldn't be in .h with the rest of them */
#define SYNC_FLAG_ISREPEAT	(1<<15)

static int update_mailbox_once(struct sync_folder *local,
			       struct sync_folder *remote,
			       struct sync_reserve_list *reserve_list,
			       struct backend *sync_be,
			       unsigned flags)
{
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox = NULL;
    int r = 0;
    const char *cmd =
	(flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_MAILBOX" : "MAILBOX";
    struct dlist *kl = dlist_newkvlist(NULL, cmd);
    struct dlist *kupload = dlist_newlist(NULL, "MESSAGE");
    annotate_state_t *astate = NULL;

    if (flags & SYNC_FLAG_LOGGING) {
	syslog(LOG_INFO, "%s %s", cmd, local->name);
    }

    if (local->mailbox) mailbox = local->mailbox;
    else r = mailbox_open_iwl(local->name, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* been deleted in the meanwhile... it will get picked up by the
	 * delete call later */
	r = 0;
	goto done;
    }
    else if (r)
	goto done;

    /* hold the annotate state open */
    mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    /* and force it to hold a transaction while it does stuff */
    annotate_state_begin(astate);

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

    /* make sure CRC is updated if we're retrying */
    if (flags & SYNC_FLAG_ISREPEAT) {
	r = mailbox_index_recalc(mailbox);
	if (r) goto done;
    }

    /* nothing changed - nothing to send */
    if (is_unchanged(mailbox, remote))
	goto done;

    part_list = sync_reserve_partlist(reserve_list, mailbox->part);
    r = sync_prepare_dlists(mailbox, remote, part_list, kl, kupload, 1);
    if (r) goto done;

    /* keep the mailbox locked for shorter time! Unlock the index now
     * but don't close it, because we need to guarantee that message
     * files don't get deleted until we're finished with them... */
    if (!local->mailbox) mailbox_unlock_index(mailbox, NULL);

    /* upload in small(ish) blocks to avoid timeouts */
    while (kupload->head) {
	struct dlist *kul1 = dlist_splice(kupload, 1024);
	sync_send_apply(kul1, sync_be->out);
	r = sync_parse_response("MESSAGE", sync_be->in, NULL);
	dlist_free(&kul1);
	if (r) goto done; /* abort earlier */
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
			struct sync_reserve_list *reserve_list,
			struct backend *sync_be,
			unsigned flags)
{
    int r = update_mailbox_once(local, remote, reserve_list, sync_be, flags);

    /* never retry - other end should always sync cleanly */
    if (flags & SYNC_FLAG_NO_COPYBACK) return r;

    flags |= SYNC_FLAG_ISREPEAT;

    if (r == IMAP_AGAIN) {
	r = mailbox_full_update(local, reserve_list, sync_be, flags);
	if (!r) r = update_mailbox_once(local, remote, reserve_list, sync_be,
					flags);
    }
    else if (r == IMAP_SYNC_CHECKSUM) {
	syslog(LOG_ERR, "CRC failure on sync for %s, trying full update",
	       local->name);
	r = mailbox_full_update(local, reserve_list, sync_be, flags);
	if (!r) r = update_mailbox_once(local, remote, reserve_list, sync_be,
					flags);
    }

    return r;
}

/* ====================================================================== */

static int update_seen_work(const char *user, const char *uniqueid,
			    struct seendata *sd, struct backend *sync_be)
{
    const char *cmd = "SEEN";
    struct dlist *kl;

    /* Update seen list */
    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", user);
    dlist_setatom(kl, "UNIQUEID", uniqueid);
    dlist_setdate(kl, "LASTREAD", sd->lastread);
    dlist_setnum32(kl, "LASTUID", sd->lastuid);
    dlist_setdate(kl, "LASTCHANGE", sd->lastchange);
    dlist_setatom(kl, "SEENUIDS", sd->seenuids);
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

    quota_init(&q, root);
    r = update_quota_work(&q, NULL, sync_be);
    quota_free(&q);

    return r;
}

static int do_annotation_cb(const char *mailbox __attribute__((unused)),
			    uint32_t uid __attribute__((unused)),
			    const char *entry, const char *userid,
			    const struct buf *value, void *rock)
{
    struct sync_annot_list *l = (struct sync_annot_list *) rock;

    sync_annot_list_add(l, entry, userid, value);

    return 0;
}

static int parse_annotation(struct dlist *kin,
			    struct sync_annot_list *replica_annot)
{
    struct dlist *kl;
    const char *entry;
    const char *userid;
    const char *valmap = NULL;
    size_t vallen = 0;
    struct buf value = BUF_INITIALIZER;

    for (kl = kin->head; kl; kl = kl->next) {
	if (!dlist_getatom(kl, "ENTRY", &entry))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getatom(kl, "USERID", &userid))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getmap(kl, "VALUE", &valmap, &vallen))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	buf_init_ro(&value, valmap, vallen);
	sync_annot_list_add(replica_annot, entry, userid, &value);
    }

    return 0;
}

static int do_getannotation(const char *mboxname,
			    struct sync_annot_list *replica_annot,
			    struct backend *sync_be)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;
    struct dlist *kin = NULL;
    int r;

    /* Update seen list */
    kl = dlist_setatom(NULL, cmd, mboxname);
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

    r = annotatemore_findall(mboxname, 0, "*", &do_annotation_cb, master_annot);
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
	    if (!buf_cmp(&ra->value, &ma->value)) {
		ra = ra->next;
		ma = ma->next;
		continue;
	    }
	    ra = ra->next;
	}

	/* add the current client annotation */
	r = folder_setannotation(mboxname, ma->entry, ma->userid, &ma->value, sync_be);
	if (r) goto bail;

	ma = ma->next;
    }

bail:
    sync_annot_list_free(&master_annot);
    sync_annot_list_free(&replica_annot);
    return r;
}

/* ====================================================================== */

static int do_folders(struct sync_name_list *mboxname_list,
		      struct sync_folder_list *replica_folders,
		      struct backend *sync_be,
		      unsigned flags)
{
    int r;
    struct sync_folder_list *master_folders;
    struct sync_rename_list *rename_folders;
    struct sync_reserve_list *reserve_list;
    struct sync_folder *mfolder, *rfolder;

    master_folders = sync_folder_list_create();
    rename_folders = sync_rename_list_create();
    reserve_list = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    r = reserve_messages(mboxname_list, master_folders,
			 replica_folders, reserve_list, sync_be);
    if (r) {
	syslog(LOG_ERR, "reserve messages: failed: %s", error_message(r));
	goto bail;
    }

    /* Tag folders on server which still exist on the client. Anything
     * on the server which remains untagged can be deleted immediately */
    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
	if (mfolder->mark) continue;
	rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
	if (!rfolder) continue;
	if (rfolder->mark) continue;
	rfolder->mark = 1;

	/* does it need a rename? partition change is a rename too */
	if (strcmp(mfolder->name, rfolder->name) || strcmp(mfolder->part, rfolder->part)) {
	    sync_rename_list_add(rename_folders, mfolder->uniqueid, rfolder->name,
				 mfolder->name, mfolder->part, mfolder->uidvalidity);
	}
    }

    /* Delete folders on server which no longer exist on client */
    if (flags & SYNC_FLAG_DELETE_REMOTE) {
	for (rfolder = replica_folders->head; rfolder; rfolder = rfolder->next) {
	    if (rfolder->mark) continue;
	    r = sync_folder_delete(rfolder->name, sync_be, flags);
	    if (r) {
		syslog(LOG_ERR, "sync_folder_delete(): failed: %s '%s'",
		       rfolder->name, error_message(r));
		goto bail;
	    }
	}
    }

    /* Need to rename folders in an order which avoids dependancy conflicts
     * following isn't wildly efficient, but rename_folders will typically be
     * short and contain few dependancies.  Algorithm is to simply pick a
     * rename operation which has no dependancy and repeat until done */

    while (rename_folders->done < rename_folders->count) {
	int rename_success = 0;
	struct sync_rename *item, *item2 = NULL;

	for (item = rename_folders->head; item; item = item->next) {
	    if (item->done) continue;

	    /* don't skip rename to different partition */
	    if (strcmp(item->oldname, item->newname)) {
		item2 = sync_rename_lookup(rename_folders, item->newname);
		if (item2 && !item2->done) continue;
	    }

	    /* Found unprocessed item which should rename cleanly */
	    r = folder_rename(item->oldname, item->newname, item->part,
			      item->uidvalidity, sync_be, flags);
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
	    const char *name = "unknown";
	    if (item2) name = item2->oldname;
	    syslog(LOG_ERR,
		   "do_folders(): failed to order folders correctly at %s", name);
	    r = IMAP_AGAIN;
	    goto bail;
	}
    }

    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
	if (mfolder->mark) continue;
	/* NOTE: rfolder->name may now be wrong, but we're guaranteed that
	 * it was successfully renamed above, so just use mfolder->name for
	 * all commands */
	rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
	r = sync_update_mailbox(mfolder, rfolder, reserve_list, sync_be, flags);
	if (r) {
	    syslog(LOG_ERR, "do_folders(): update failed: %s '%s'",
		   mfolder->name, error_message(r));
	    goto bail;
	}
    }

 bail:
    sync_folder_list_free(&master_folders);
    sync_rename_list_free(&rename_folders);
    sync_reserve_list_free(&reserve_list);
    return r;
}

int sync_do_mailboxes(struct sync_name_list *mboxname_list,
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

    kl = dlist_newlist(NULL, "MAILBOXES");
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next)
	dlist_setatom(kl, "MBOXNAME", mbox->name);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_be->in, "MAILBOXES", replica_folders,
			    NULL, NULL, NULL, NULL);

    /* we don't want to delete remote folders which weren't found locally,
     * because we may be racing with a rename, and we don't want to lose
     * the remote files.  A real delete will always have inserted a
     * UNMAILBOX anyway */
    if (!r) {
	flags &= ~SYNC_FLAG_DELETE_REMOTE;
	r = do_folders(mboxname_list, replica_folders, sync_be, flags);
    }

    sync_folder_list_free(&replica_folders);

    return r;
}

/* ====================================================================== */

struct mboxinfo {
    struct sync_name_list *mboxlist;
    struct sync_name_list *quotalist;
};

static int do_mailbox_info(void *rock,
			   const char *key, size_t keylen,
			   const char *data __attribute__((unused)),
			   size_t datalen __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    struct mboxinfo *info = (struct mboxinfo *)rock;
    char *name = xstrndup(key, keylen);
    int r = 0;

    /* XXX - check for deleted? */

    r = mailbox_open_irl(name, &mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	r = 0;
	goto done;
    }
    if (r == IMAP_MAILBOX_RESERVED) {
	r = 0;
	goto done;
    }
    if (r) goto done;

    if (info->quotalist && mailbox->quotaroot) {
	if (!sync_name_lookup(info->quotalist, mailbox->quotaroot))
	    sync_name_list_add(info->quotalist, mailbox->quotaroot);
    }

    mailbox_close(&mailbox);

    addmbox(name, 0, 0, info->mboxlist);

done:
    free(name);

    return r;
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
	if (rquota)
	    rquota->done = 1;
	quota_init(&q, mitem->name);
	r = update_quota_work(&q, rquota, sync_be);
	quota_free(&q);
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

static int do_user_main(const char *user,
			struct sync_folder_list *replica_folders,
			struct sync_quota_list *replica_quota,
			struct backend *sync_be,
			unsigned flags)
{
    int r = 0;
    struct sync_name_list *mboxname_list = sync_name_list_create();
    struct sync_name_list *master_quotaroots = sync_name_list_create();
    struct mboxinfo info;

    info.mboxlist = mboxname_list;
    info.quotalist = master_quotaroots;

    r = mboxlist_allusermbox(user, do_mailbox_info, &info, /*incdel*/1);

    /* we know all the folders present on the master, so it's safe to delete
     * anything not mentioned here on the replica - at least until we get
     * real tombstones */
    flags |= SYNC_FLAG_DELETE_REMOTE;
    if (!r) r = do_folders(mboxname_list, replica_folders, sync_be, flags);
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

int sync_do_user_seen(const char *userid, struct sync_seen_list *replica_seen,
		      struct backend *sync_be)
{
    int r;
    struct sync_seen *mseen, *rseen;
    struct seen *seendb = NULL;
    struct sync_seen_list *list;

    /* silently ignore errors */
    r = seen_open(userid, SEEN_SILENT, &seendb);
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
	r = update_seen_work(userid, mseen->uniqueid, &mseen->sd, sync_be);
    }

    /* XXX - delete seen on the replica for records that don't exist? */

    sync_seen_list_free(&list);

    return 0;
}

int sync_do_user_sieve(const char *userid, struct sync_sieve_list *replica_sieve,
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

    /* Upload missing and out of date or mismatching scripts */
    for (mitem = master_sieve->head; mitem; mitem = mitem->next) {
	ritem = sync_sieve_lookup(replica_sieve, mitem->name);
	if (ritem) {
	    ritem->mark = 1;
	    /* compare the GUID if known */
	    if (!message_guid_isnull(&ritem->guid)) {
		if (message_guid_equal(&ritem->guid, &mitem->guid))
		    continue;
		/* XXX: copyback support */
	    }
	    /* fallback to date comparison */
	    else if (ritem->last_update >= mitem->last_update)
		continue; /* changed */
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

int sync_do_user(const char *userid, struct backend *sync_be, unsigned flags)
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

    kl = dlist_setatom(NULL, "USER", userid);
    sync_send_lookup(kl, sync_be->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_be->in, "USER", replica_folders, replica_subs,
			    replica_sieve, replica_seen, replica_quota);
    /* can happen! */
    if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    if (r) goto done;

    if (!sync_namespace.mboxname_tointernal &&
	( r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
	fatal(error_message(r), EC_CONFIG);
    }

    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
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
    r = do_user_main(userid, replica_folders, replica_quota,
		     sync_be, flags);
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

    kl = dlist_setatom(NULL, "META", userid);
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

EXPORTED const char *sync_apply(struct dlist *kin, struct sync_reserve_list *reserve_list, struct sync_state *state)
{
    int r = IMAP_PROTOCOL_ERROR;

    ucase(kin->name);

    if (!strcmp(kin->name, "MESSAGE"))
	r = sync_apply_message(kin, reserve_list, state);
    else if (!strcmp(kin->name, "EXPUNGE"))
	r = sync_apply_expunge(kin, state);

    /* dump protocol */
    else if (!strcmp(kin->name, "ACTIVATE_SIEVE"))
	r = sync_apply_activate_sieve(kin, state);
    else if (!strcmp(kin->name, "ANNOTATION"))
	r = sync_apply_annotation(kin, state);
    else if (!strcmp(kin->name, "MAILBOX"))
	r = sync_apply_mailbox(kin, reserve_list, state);
    else if (!strcmp(kin->name, "LOCAL_MAILBOX")) {
	state->local_only = 1;
	r = sync_apply_mailbox(kin, reserve_list, state);
    }
    else if (!strcmp(kin->name, "QUOTA"))
	r = sync_apply_quota(kin, state);
    else if (!strcmp(kin->name, "SEEN"))
	r = sync_apply_seen(kin, state);
    else if (!strcmp(kin->name, "RENAME"))
	r = sync_apply_rename(kin, state);
    else if (!strcmp(kin->name, "LOCAL_RENAME")) {
	state->local_only = 1;
	r = sync_apply_rename(kin, state);
    }
    else if (!strcmp(kin->name, "RESERVE"))
	r = sync_apply_reserve(kin, reserve_list, state);
    else if (!strcmp(kin->name, "SIEVE"))
	r = sync_apply_sieve(kin, state);
    else if (!strcmp(kin->name, "SUB"))
	r = sync_apply_changesub(kin, state);

    /* "un"dump protocol ;) */
    else if (!strcmp(kin->name, "UNACTIVATE_SIEVE"))
	r = sync_apply_unactivate_sieve(kin, state);
    else if (!strcmp(kin->name, "UNANNOTATION"))
	r = sync_apply_unannotation(kin, state);
    else if (!strcmp(kin->name, "UNMAILBOX"))
	r = sync_apply_unmailbox(kin, state);
    else if (!strcmp(kin->name, "LOCAL_UNMAILBOX")) {
	state->local_only = 1;
	r = sync_apply_unmailbox(kin, state);
    }
    else if (!strcmp(kin->name, "UNQUOTA"))
	r = sync_apply_unquota(kin, state);
    else if (!strcmp(kin->name, "UNSIEVE"))
	r = sync_apply_unsieve(kin, state);
    else if (!strcmp(kin->name, "UNSUB"))
	r = sync_apply_changesub(kin, state);

    /* user is a special case that's not paired, there's no "upload user"
     * as such - we just call the individual commands with their items */
    else if (!strcmp(kin->name, "UNUSER"))
	r = sync_apply_unuser(kin, state);
    else if (!strcmp(kin->name, "LOCAL_UNUSER")) {
	state->local_only = 1;
	r = sync_apply_unuser(kin, state);
    }

    else {
	syslog(LOG_ERR, "SYNCERROR: unknown command %s", kin->name);
	r = IMAP_PROTOCOL_ERROR;
    }

    return sync_response(r);
}

EXPORTED const char *sync_get(struct dlist *kin, struct sync_state *state)
{
    int r = IMAP_PROTOCOL_ERROR;

    ucase(kin->name);

    if (!strcmp(kin->name, "ANNOTATION"))
	r = sync_get_annotation(kin, state);
    else if (!strcmp(kin->name, "FETCH"))
	r = sync_get_message(kin, state);
    else if (!strcmp(kin->name, "FETCH_SIEVE"))
	r = sync_get_sieve(kin, state);
    else if (!strcmp(kin->name, "FULLMAILBOX"))
	r = sync_get_fullmailbox(kin, state);
    else if (!strcmp(kin->name, "MAILBOXES"))
	r = sync_get_mailboxes(kin, state);
    else if (!strcmp(kin->name, "META"))
	r = sync_get_meta(kin, state);
    else if (!strcmp(kin->name, "QUOTA"))
	r = sync_get_quota(kin, state);
    else if (!strcmp(kin->name, "USER"))
	r = sync_get_user(kin, state);
    else
	r = IMAP_PROTOCOL_ERROR;

    return sync_response(r);
}
