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
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>
#include <utime.h>
#include <limits.h>

#include "assert.h"
#include "bsearch.h"
#include "global.h"
#include "imap_proxy.h"
#include "mboxlist.h"
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
#include "strarray.h"
#include "ptrarray.h"
#include "sievedir.h"

#ifdef USE_CALALARMD
#include "caldav_alarm.h"
#endif

#ifdef USE_SIEVE
#include "sieve/sieve_interface.h"
#endif

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "message_guid.h"
#include "sync_support.h"
#include "sync_log.h"

static int opt_force = 0; // FIXME

struct sync_client_state rightnow_sync_cs;

/* protocol definitions */
static char *imap_sasl_parsesuccess(char *str, const char **status);
static void imap_postcapability(struct backend *s);

struct protocol_t imap_csync_protocol =
{ "imap", "imap", TYPE_STD,
  { { { 1, NULL },
      { "C01 CAPABILITY", NULL, "C01 ", imap_postcapability,
        CAPAF_MANY_PER_LINE,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
// FIXME doesn't work with compress at the moment for some reason
//        { "COMPRESS=DEFLATE", CAPA_COMPRESS },
// FIXME do we need these ones?
//        { "IDLE", CAPA_IDLE },
//        { "MUPDATE", CAPA_MUPDATE },
//        { "MULTIAPPEND", CAPA_MULTIAPPEND },
//        { "RIGHTS=kxte", CAPA_ACLRIGHTS },
//        { "LIST-EXTENDED", CAPA_LISTEXTENDED },
          { "SASL-IR", CAPA_SASL_IR },
          { "X-REPLICATION", CAPA_REPLICATION },
          { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*",
        &imap_sasl_parsesuccess, AUTO_CAPA_AUTH_OK },
      { "Z01 COMPRESS DEFLATE", "* ", "Z01 OK" },
      { "N01 NOOP", "* ", "N01 OK" },
      { "Q01 LOGOUT", "* ", "Q01 " } } }
};

struct protocol_t csync_protocol =
{ "csync", "csync", TYPE_STD,
  { { { 1, "* OK" },
      { NULL, NULL, "* OK", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_SKIP_FIRST_WORD,
        { { "SASL", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "COMPRESS=DEFLATE", CAPA_COMPRESS },
          { NULL, 0 } } },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", USHRT_MAX, 0, "OK", "NO", "+ ", "*", NULL, 0 },
      { "COMPRESS DEFLATE", NULL, "OK" },
      { "NOOP", NULL, "OK" },
      { "EXIT", NULL, "OK" } } }
};

/* parse_success api is undocumented but my current understanding
 * is that the caller expects it to return a pointer to the position
 * within str at which base64 encoded "success data" can be found.
 * status is for passing back other status data (if required) to
 * the original caller.
 *
 * in the case of what we're doing here, there is no base64 encoded
 * 'success data', but there is a capability string that we want to
 * save.  so we grab the capability string (including the []s) and
 * chuck that in status, and then we return NULL to indicate the
 * lack of base64 data.
 */
static char *imap_sasl_parsesuccess(char *str, const char **status)
{
    syslog(LOG_DEBUG, "imap_sasl_parsesuccess(): input is: %s", str);
    if (NULL == status)  return NULL; /* nothing useful we can do */

    const char *prelude = "A01 OK "; // FIXME don't hardcode this, get it from sasl_cmd->ok
    const size_t prelude_len = strlen(prelude);

    const char *capability = "[CAPABILITY ";
    const size_t capability_len = strlen(capability);

    char *start, *end;

    if (strncmp(str, prelude, prelude_len)) {
        /* this isn't the string we expected */
        syslog(LOG_INFO, "imap_sasl_parsesuccess(): unexpected initial string contents: %s", str);
        return NULL;
    }

    start = str + prelude_len;

    if (strncmp(start, capability, capability_len)) {
        /* this isn't a capability string */
        syslog(LOG_INFO, "imap_sasl_parsesuccess(): str does not contain a capability string: %s", str);
        return NULL;
    }

    end = start + capability_len;
    while (*end != ']' && *end != '\0') {
        end++;
    }

    if (*end == '\0') {
        /* didn't find end of capability string */
        syslog(LOG_INFO, "imap_sasl_parsesuccess(): did not find end of capability string: %s", str);
        return NULL;
    }

    /* we want to keep the ], but crop the rest off */
    *++end = '\0';

    /* status gets the capability string */
    syslog(LOG_DEBUG, "imap_sasl_parsesuccess(): found capability string: %s", start);
    *status = start;

    /* there's no base64 data, so return NULL */
    return NULL;
}

static void imap_postcapability(struct backend *s)
{
    if (CAPA(s, CAPA_SASL_IR)) {
        /* server supports initial response in AUTHENTICATE command */
        s->prot->u.std.sasl_cmd.maxlen = USHRT_MAX;
    }
}

static const char *_synclock_name(const char *hostname, const char *userid)
{
    const char *p;
    static struct buf buf = BUF_INITIALIZER;
    if (!userid) userid = ""; // no userid == global lock

    buf_setcstr(&buf, "*S*");

    for (p = hostname; *p; p++) {
        switch(*p) {
            case '.':
                buf_putc(&buf, '^');
                break;
            default:
                buf_putc(&buf, *p);
                break;
        }
    }

    buf_putc(&buf, '*');

    for (p = userid; *p; p++) {
        switch(*p) {
            case '.':
                buf_putc(&buf, '^');
                break;
            default:
                buf_putc(&buf, *p);
                break;
        }
    }

    return buf_cstring(&buf);
}


static struct mboxlock *sync_lock(struct sync_client_state *sync_cs,
                                  const char *userid)
{
    const char *name = _synclock_name(sync_cs->servername, userid);
    struct mboxlock *lock = NULL;
    int r = mboxname_lock(name, &lock, LOCK_EXCLUSIVE);
    return r ? NULL : lock;
}

/* channel-based configuration */

EXPORTED const char *sync_get_config(const char *channel, const char *val)
{
    const char *response = NULL;

    if (channel) {
        char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
        snprintf(name, MAX_MAILBOX_NAME, "%s_%s", channel, val);
        response = config_getoverflowstring(name, NULL);
    }

    if (!response) {
        /* get the core value */
        if (!strcmp(val, "sync_host"))
            response = config_getstring(IMAPOPT_SYNC_HOST);
        else if (!strcmp(val, "sync_authname"))
            response = config_getstring(IMAPOPT_SYNC_AUTHNAME);
        else if (!strcmp(val, "sync_password"))
            response = config_getstring(IMAPOPT_SYNC_PASSWORD);
        else if (!strcmp(val, "sync_realm"))
            response = config_getstring(IMAPOPT_SYNC_REALM);
        else if (!strcmp(val, "sync_port"))
            response = config_getstring(IMAPOPT_SYNC_PORT);
        else if (!strcmp(val, "sync_shutdown_file"))
            response = config_getstring(IMAPOPT_SYNC_SHUTDOWN_FILE);
        else if (!strcmp(val, "sync_cache_db_path"))
            response = config_getstring(IMAPOPT_SYNC_CACHE_DB_PATH);
        else
            fatal("unknown config variable requested", EX_SOFTWARE);
    }

    return response;
}

EXPORTED int sync_get_durationconfig(const char *channel, const char *val, int defunit)
{
    int response = -1;

    if (channel) {
        const char *result = NULL;
        char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
        snprintf(name, MAX_MAILBOX_NAME, "%s_%s", channel, val);
        result = config_getoverflowstring(name, NULL);
        if (result)
            config_parseduration(result, defunit, &response);
    }

    if (response == -1) {
        if (!strcmp(val, "sync_repeat_interval"))
            response = config_getduration(IMAPOPT_SYNC_REPEAT_INTERVAL, defunit);
    }

    return response;
}

EXPORTED int sync_get_switchconfig(const char *channel, const char *val)
{
    int response = -1;

    if (channel) {
        const char *result = NULL;
        char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
        snprintf(name, sizeof(name), "%s_%s", channel, val);
        result = config_getoverflowstring(name, NULL);
        if (result) response = atoi(result);
    }

    if (response == -1) {
        if (!strcmp(val, "sync_try_imap"))
            response = config_getswitch(IMAPOPT_SYNC_TRY_IMAP);
    }

    return response;
}

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
    if (options & OPT_IMAP_HAS_ALARMS)
        buf[i++] = 'A';
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
        case 'A':
            res |= OPT_IMAP_HAS_ALARMS;
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
            fatal("word too long", EX_IOERR);
        buf_putc(buf, c);
    }
    return c;
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

void sync_msgid_remove(struct sync_msgid_list *l,
                       const struct message_guid *guid)
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
                                         modseq_t xconvmodseq,
                                         modseq_t raclmodseq,
                                         modseq_t foldermodseq,
                                         int ispartial)
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
    result->raclmodseq = raclmodseq;
    result->foldermodseq = foldermodseq;
    result->ispartial = ispartial;

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
    result->uniqueid = xstrdupnull(uniqueid);
    result->oldname = xstrdupnull(oldname);
    result->newname = xstrdupnull(newname);
    result->part = xstrdupnull(partition);
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

static struct sync_sieve *sync_sieve_list_add(
                         struct sync_sieve_list *l, const char *name,
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

    return item;
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

static int list_cb(const char *sievedir,
                   const char *name, struct stat *sbuf,
                   const char *link_target __attribute__((unused)),
                   void *rock)
{
    struct sync_sieve_list *list = (struct sync_sieve_list *) rock;

    /* calculate the sha1 on the fly, relatively cheap */
    struct buf *buf = sievedir_get_script(sievedir, name);

    if (buf && buf_len(buf)) {
        struct message_guid guid;

        message_guid_generate(&guid, buf_base(buf), buf_len(buf));
        sync_sieve_list_add(list, name, sbuf->st_mtime, &guid, 0);
        buf_destroy(buf);
    }

    return SIEVEDIR_OK;
}

struct sync_sieve_list *sync_sieve_list_generate(const char *userid)
{
    struct sync_sieve_list *list = sync_sieve_list_create();
    const char *sieve_path = user_sieve_path(userid);
    const char *active = sievedir_get_active(sieve_path);

    sievedir_foreach(sieve_path, SIEVEDIR_SCRIPTS_ONLY, &list_cb, list);

    if (active) {
        char target[SIEVEDIR_MAX_NAME_LEN];
        struct message_guid guid;

        message_guid_set_null(&guid);
        snprintf(target, sizeof(target), "%s%s", active, BYTECODE_SUFFIX);

        sync_sieve_list_add(list, target, 0, &guid, 1);
    }

    return list;
}

char *sync_sieve_read(const char *userid, const char *name, uint32_t *sizep)
{
    const char *sieve_path = user_sieve_path(userid);
    struct buf *buf = sievedir_get_script(sieve_path, name);
    char *result = NULL;

    if (buf) {
        if (sizep) *sizep = buf_len(buf);
        result = buf_release(buf);
        buf_destroy(buf);
    }
    else if (sizep)
        *sizep = 0;

    return result;
}

int sync_sieve_upload(const char *userid, const char *name,
                      time_t last_update, const char *content,
                      size_t len)
{
    const char *sieve_path = user_sieve_path(userid);
    char tmpname[2048];
    char newname[2048];
    char *ext;
    FILE *file;
    int   r = 0;
    struct stat sbuf;
    struct utimbuf utimbuf;

    ext = strrchr(name, '.');
    if (ext && !strcmp(ext, ".bc")) {
        /* silently ignore attempts to upload compiled bytecode */
        return 0;
    }

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
        return IMAP_IOERROR;
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

#ifdef USE_SIEVE
    if (!r) {
        r = sieve_rebuild(newname, NULL, /*force*/ 1, NULL);
        if (r == SIEVE_PARSE_ERROR || r == SIEVE_FAIL)
            r = IMAP_SYNC_BADSIEVE;
    }
#endif

    sync_log_sieve(userid);

    return r;
}

int sync_sieve_activate(const char *userid, const char *bcname)
{
    const char *sieve_path = user_sieve_path(userid);
    char target[2048];
    int r;

#ifdef USE_SIEVE
    snprintf(target, sizeof(target), "%s/%s", sieve_path, bcname);
    sieve_rebuild(NULL, target, 0, NULL);
#endif

    snprintf(target, sizeof(target), "%.*s",
             (int) strlen(bcname) - BYTECODE_SUFFIX_LEN, bcname);

    r = sievedir_activate_script(sieve_path, target);
    if (r) return r;

    sync_log_sieve(userid);

    return 0;
}

int sync_sieve_deactivate(const char *userid)
{
    const char *sieve_path = user_sieve_path(userid);
    int r = sievedir_deactivate_script(sieve_path);

    if (r) return r;

    sync_log_sieve(userid);

    return(0);
}

int sync_sieve_delete(const char *userid, const char *script)
{
    const char *sieve_path = user_sieve_path(userid);
    char name[2048];

    snprintf(name, sizeof(name), "%.*s",
             (int) strlen(script) - SCRIPT_SUFFIX_LEN, script);

    /* XXX  Do we NOT care about errors? */
    if (sievedir_script_isactive(sieve_path, name)) {
        sievedir_deactivate_script(sieve_path);
    }

    sievedir_delete_script(sieve_path, name);

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
    struct sync_name * item = sync_name_lookup(l, name);
    if (item) return item;

    item = xzmalloc(sizeof(struct sync_name));

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
                         const struct buf *value,
                         modseq_t modseq)
{
    struct sync_annot *item = xzmalloc(sizeof(struct sync_annot));

    item->entry = xstrdupnull(entry);
    item->userid = xstrdupnull(userid);
    buf_copy(&item->value, value);
    item->mark = 0;
    item->modseq = modseq;

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

/* ====================================================================== */

static int read_one_annot(const char *mailbox __attribute__((unused)),
                          uint32_t uid __attribute__((unused)),
                          const char *entry,
                          const char *userid,
                          const struct buf *value,
                          const struct annotate_metadata *mdata,
                          void *rock)
{
    struct sync_annot_list **salp = (struct sync_annot_list **)rock;

    if (!*salp)
        *salp = sync_annot_list_create();
    sync_annot_list_add(*salp, entry, userid, value, mdata->modseq);
    return 0;
}

/*
 * Read all the annotations in the local annotations database
 * for the message given by @mailbox and @record, returning them
 * as a new sync_annot_list.  The caller should free the new
 * list with sync_annot_list_free().
 * If record is NULL, return the mailbox annotations
 * If since_modseq is greated than zero, return annotations
 * add or changed since modseq (exclusively since_modseq).
 * If flags is set to ANNOTATE_TOMBSTONES, also return
 * deleted annotations. Deleted annotations have a zero value.
 *
 * Returns: non-zero on error,
 *          resulting sync_annot_list in *@resp
 */
int read_annotations(const struct mailbox *mailbox,
                     const struct index_record *record,
                     struct sync_annot_list **resp,
                     modseq_t since_modseq __attribute__((unused)),
                     int flags)
{
    *resp = NULL;
    return annotatemore_findall(mailbox_name(mailbox), record ? record->uid : 0,
                                /* all entries*/"*", /*XXX since_modseq*/0,
                                read_one_annot, (void *)resp, flags);
}

/*
 * Encode the given list of annotations @sal as a dlist
 * structure with the given @parent.
 */
void encode_annotations(struct dlist *parent,
                        struct mailbox *mailbox,
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
            dlist_setnum64(aa, "MODSEQ", sa->modseq);
            dlist_setmap(aa, "VALUE", sa->value.s, sa->value.len);
        }
    }

    if (record && record->cid && mailbox->i.minor_version >= 13) {
        if (!annots)
            annots = dlist_newlist(parent, "ANNOTATIONS");
        aa = dlist_newkvlist(annots, NULL);
        dlist_setatom(aa, "ENTRY", IMAP_ANNOT_NS "thrid");
        dlist_setatom(aa, "USERID", "");
        dlist_setnum64(aa, "MODSEQ", 0);
        dlist_sethex64(aa, "VALUE", record->cid);
    }

    if (record && record->savedate && mailbox->i.minor_version >= 15) {
        if (!annots)
            annots = dlist_newlist(parent, "ANNOTATIONS");
        aa = dlist_newkvlist(annots, NULL);
        dlist_setatom(aa, "ENTRY", IMAP_ANNOT_NS "savedate");
        dlist_setatom(aa, "USERID", "");
        dlist_setnum64(aa, "MODSEQ", 0);
        dlist_setnum32(aa, "VALUE", record->savedate);
    }

    if (record && record->createdmodseq && mailbox->i.minor_version >= 16) {
        if (!annots)
            annots = dlist_newlist(parent, "ANNOTATIONS");
        aa = dlist_newkvlist(annots, NULL);
        dlist_setatom(aa, "ENTRY", IMAP_ANNOT_NS "createdmodseq");
        dlist_setatom(aa, "USERID", "");
        dlist_setnum64(aa, "MODSEQ", 0);
        dlist_setnum64(aa, "VALUE", record->createdmodseq);
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
                       struct mailbox *mailbox,
                       struct index_record *record)
{
    struct dlist *aa;
    const char *entry;
    const char *userid;
    modseq_t modseq;

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
        if (!dlist_getnum64(aa, "MODSEQ", &modseq))
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        if (!dlist_getbuf(aa, "VALUE", &value))
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        if (!strcmp(entry, IMAP_ANNOT_NS "thrid") &&
            record && mailbox->i.minor_version >= 13) {
            const char *p = buf_cstring(&value);
            parsehex(p, &p, 16, &record->cid);
        }
        else if (!strcmp(entry, IMAP_ANNOT_NS "savedate") &&
                 record && mailbox->i.minor_version >= 15) {
            const char *p = buf_cstring(&value);
            bit64 newval;
            parsenum(p, &p, 0, &newval);
            record->savedate = newval;
        }
        else if (!strcmp(entry, IMAP_ANNOT_NS "createdmodseq") &&
                 record && mailbox->i.minor_version >= 16) {
            const char *p = buf_cstring(&value);
            bit64 newval;
            parsenum(p, &p, 0, &newval);
            record->createdmodseq = newval;
        }
        else if (!strcmp(entry, IMAP_ANNOT_NS "basethrid") && record) {
            /* this might double-apply the annotation, but oh well.  It does mean that
             * basethrid is paired in here when we do a comparison against new values
             * from the replica later! */
            const char *p = buf_cstring(&value);
            parsehex(p, &p, 16, &record->basecid);
            /* XXX - check on p? */

            /* "basethrid" is special, since it is written during mailbox
             * appends and rewrites, using whatever modseq the index_record
             * has at this moment. This might differ from the modseq we
             * just parsed here, causing master and replica annotations
             * to get out of sync.
             * The fix is to set the basecid field both on the index
             * record *and* adding the annotation to the annotation list.
             * That way the local modseq of basethrid always gets over-
             * written by whoever wins to be master of this annotation */
            sync_annot_list_add(*salp, entry, userid, &value, modseq);
        }
        else {
            sync_annot_list_add(*salp, entry, userid, &value, modseq);
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
                      int local_wins, int *hadsnoozed)
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
            if (hadsnoozed && !strcmpsafe(chosen->entry, IMAP_ANNOT_NS "snoozed") && buf_len(value))
                *hadsnoozed = 1;
            local = local->next;
        }
        else if (diff > 0) {
            chosen = remote;
            value = (local_wins ? &novalue : &remote->value);
            if (hadsnoozed && !strcmpsafe(chosen->entry, IMAP_ANNOT_NS "snoozed") && buf_len(value))
                *hadsnoozed = 1;
            remote = remote->next;
        }
        else {
            chosen = remote;
            value = (local_wins ? &local->value : &remote->value);
            if (hadsnoozed && !strcmpsafe(chosen->entry, IMAP_ANNOT_NS "snoozed") && buf_len(value))
                *hadsnoozed = 1;
            diff = buf_cmp(&local->value, &remote->value);
            local = local->next;
            remote = remote->next;
            if (!diff)
                continue;   /* same value, skip */
        }

        /* Replicate the modseq of this record from master */
        struct annotate_metadata mdata = {
            chosen->modseq, /* modseq */
            0               /* flags - is determined by value */
        };
        r = annotate_state_writemdata(astate, chosen->entry,
                                      chosen->userid, value, &mdata);
        if (r)
            break;
    }

out:

    if (record) {
#ifdef USE_CALALARMD
        if (mbtype_isa(mailbox->mbtype) == MBTYPE_CALENDAR) {
            // NOTE: this is because we don't pass the annotations through
            // with the record as we create it, so we can't update the alarm
            // database properly.  Instead, we don't set anything when we append
            // by checking for .silentupdate, and instead update the database by touching
            // the alarm AFTER writing the record.
            caldav_alarm_sync_nextcheck(mailbox, record);
        }
#endif
    }
    else {
        /* need to manage our own txn for the global db */
        if (!r)
            r = annotate_state_commit(&astate);
        else
            annotate_state_abort(&astate);
    }
    /* else, the struct mailbox manages it for us */

    return r;
}

/* =========================================================================== */

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
    if (record->internal_flags & FLAG_INTERNAL_EXPUNGED)
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
                record->internal_flags |= FLAG_INTERNAL_EXPUNGED;
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
        r = decode_annotations(fl, salp, mailbox, record);

    return r;
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

void sync_send_restart(struct protstream *out)
{
    if (out->userdata) {
        /* IMAP flavor (w/ tag) */
        prot_printf(out, "%s SYNC", sync_gentag((struct buf *) out->userdata));
    }
    prot_printf(out, "RESTART\r\n");
    prot_flush(out);
}

void sync_send_restore(struct dlist *kl, struct protstream *out)
{
    if (out->userdata) {
        /* IMAP flavor (w/ tag) */
        prot_printf(out, "%s SYNC", sync_gentag((struct buf *) out->userdata));
    }
    prot_printf(out, "RESTORE ");
    dlist_print(kl, 1, out);
    prot_printf(out, "\r\n");
    prot_flush(out);
}

/*
 * Copied from imapparse.c:eatline(), and extended to also eat
 * dlist file literals
 * XXX potentially dedup back into original eatline
 */
void sync_eatline(struct protstream *pin, int c)
{
    for (;;) {
        if (c == '\n') return;

        /* Several of the parser helper functions return EOF
           even if an unexpected character (other than EOF) is received.
           We need to confirm that the stream is actually at EOF. */
        if (c == EOF && (prot_IS_EOF(pin) || prot_IS_ERROR(pin))) return;

        /* see if it's a literal */
        if (c == '{') {
            c = prot_getc(pin);
            uint64_t size = 0;
            while (cyrus_isdigit(c)) {
                if (size > 429496729 || (size == 429496729 && (c > '5')))
                    break; /* don't fatal, just drop out of literal parsing */
                size = size * 10 + c - '0';
                c = prot_getc(pin);
            }
            if (c != '+') continue;
            c = prot_getc(pin);
            if (c != '}') continue;
            c = prot_getc(pin);
            /* optional \r */
            if (c == '\r') c = prot_getc(pin);
            if (c != '\n') continue;
            /* successful literal, consume it */
            while (size--) {
                c = prot_getc(pin);
                if (c == EOF) return;
            }
        }
        else if (c == '%') {
            /* replication file literal */
            static struct buf discard = BUF_INITIALIZER;
            uint32_t size = 0;

            c = prot_getc(pin);
            if (c != '{') continue;
            c = getastring(pin, NULL, &discard); /* partition */
            if (c != ' ') continue;
            c = getastring(pin, NULL, &discard); /* guid */
            if (c != ' ') continue;
            c = getuint32(pin, &size);
            if (c != '}') continue;
            c = prot_getc(pin);
            /* optional \r */
            if (c == '\r') c = prot_getc(pin);
            if (c != '\n') continue;
            /* successful file literal, consume it */
            while (size--) {
                c = prot_getc(pin);
                if (c == EOF) return;
            }
        }

        c = prot_getc(pin);
    }
}

struct dlist *sync_parseline(struct protstream *in)
{
    struct dlist *dl = NULL;
    int c;

    c = dlist_parse(&dl, 1, 0, in);

    /* end line - or fail */
    if (c == '\r') c = prot_getc(in);
    if (c == '\n') return dl;

    dlist_free(&dl);
    sync_eatline(in, c);
    return NULL;
}

static int sync_send_file(struct mailbox *mailbox,
                          const char *topart,
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

    dlist_setfile(kupload, "MESSAGE", topart, &record->guid, record->size, fname);

    /* note that we will be sending it, so it doesn't need to be
     * sent again */
    msgid->size = record->size;
    if (!msgid->fname) msgid->fname = xstrdup(fname);
    msgid->need_upload = 0;
    msgid->is_archive = (record->internal_flags & FLAG_INTERNAL_ARCHIVED) ? 1 : 0;
    part_list->toupload--;

    return 0;
}

static int sync_prepare_dlists(struct mailbox *mailbox,
                               struct sync_folder *local,
                               struct sync_folder *remote,
                               const char *topart,
                               struct sync_msgid_list *part_list,
                               struct dlist *kl, struct dlist *kupload,
                               int printrecords, int fullannots, int sendsince)
{
    struct sync_annot_list *annots = NULL;
    struct mailbox_iter *iter = NULL;
    modseq_t xconvmodseq = 0;
    int r = 0;
    int ispartial = local ? local->ispartial : 0;

    if (!topart) topart = mailbox->part;

    dlist_setatom(kl, "UNIQUEID", mailbox->uniqueid);
    dlist_setatom(kl, "MBOXNAME", mailbox_name(mailbox));
    if (mbtypes_sync(mailbox->mbtype))
        dlist_setatom(kl, "MBOXTYPE", mboxlist_mbtype_to_string(mbtypes_sync(mailbox->mbtype)));
    if (ispartial) {
        /* send a zero to make older Cyrus happy */
        dlist_setnum32(kl, "SYNC_CRC", 0);
        /* calculated partial values */
        dlist_setnum32(kl, "LAST_UID", local->last_uid);
        dlist_setnum64(kl, "HIGHESTMODSEQ", local->highestmodseq);
        /* create synthetic values for the other fields */
        dlist_setnum32(kl, "RECENTUID", remote ? remote->recentuid : 0);
        dlist_setdate(kl, "RECENTTIME", remote ? remote->recenttime : 0);
        dlist_setdate(kl, "LAST_APPENDDATE", 0);
        dlist_setdate(kl, "POP3_LAST_LOGIN", remote ? remote->pop3_last_login : 0);
        dlist_setdate(kl, "POP3_SHOW_AFTER", remote ? remote->pop3_show_after : 0);
        if (remote && remote->xconvmodseq)
            dlist_setnum64(kl, "XCONVMODSEQ", remote->xconvmodseq);
        if (remote && remote->raclmodseq)
            dlist_setnum64(kl, "RACLMODSEQ", remote->raclmodseq);
    }
    else {
        struct synccrcs synccrcs = mailbox_synccrcs(mailbox, /*force*/0);
        dlist_setnum32(kl, "SYNC_CRC", synccrcs.basic);
        dlist_setnum32(kl, "SYNC_CRC_ANNOT", synccrcs.annot);
        dlist_setnum32(kl, "LAST_UID", mailbox->i.last_uid);
        dlist_setnum64(kl, "HIGHESTMODSEQ", mailbox->i.highestmodseq);
        dlist_setnum32(kl, "RECENTUID", mailbox->i.recentuid);
        dlist_setdate(kl, "RECENTTIME", mailbox->i.recenttime);
        dlist_setdate(kl, "LAST_APPENDDATE", mailbox->i.last_appenddate);
        dlist_setdate(kl, "POP3_LAST_LOGIN", mailbox->i.pop3_last_login);
        dlist_setdate(kl, "POP3_SHOW_AFTER", mailbox->i.pop3_show_after);
        if (mailbox_has_conversations(mailbox)) {
            r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
            if (!r && xconvmodseq)
                dlist_setnum64(kl, "XCONVMODSEQ", xconvmodseq);
        }
        modseq_t raclmodseq = mboxname_readraclmodseq(mailbox_name(mailbox));
        if (raclmodseq)
            dlist_setnum64(kl, "RACLMODSEQ", raclmodseq);
    }
    dlist_setnum32(kl, "UIDVALIDITY", mailbox->i.uidvalidity);
    dlist_setatom(kl, "PARTITION", topart);
    dlist_setatom(kl, "ACL", mailbox->acl);
    dlist_setatom(kl, "OPTIONS", sync_encode_options(mailbox->i.options));
    if (mailbox->quotaroot)
        dlist_setatom(kl, "QUOTAROOT", mailbox->quotaroot);

    if (mailbox->i.createdmodseq)
        dlist_setnum64(kl, "CREATEDMODSEQ", mailbox->i.createdmodseq);

    if (mailbox->foldermodseq)
        dlist_setnum64(kl, "FOLDERMODSEQ", mailbox->foldermodseq);

    /* always send mailbox annotations */
    r = read_annotations(mailbox, NULL, &annots, 0, 0);
    if (r) goto done;

    encode_annotations(kl, mailbox, NULL, annots);
    sync_annot_list_free(&annots);

    if (sendsince && remote && remote->highestmodseq) {
        dlist_setnum64(kl, "SINCE_MODSEQ", remote->highestmodseq);
        dlist_setnum32(kl, "SINCE_CRC", remote->synccrcs.basic);
        dlist_setnum32(kl, "SINCE_CRC_ANNOT", remote->synccrcs.annot);
    }

    if (printrecords) {
        const message_t *msg;
        struct dlist *rl = dlist_newlist(kl, "RECORD");
        modseq_t modseq = remote ? remote->highestmodseq : 0;

        iter = mailbox_iter_init(mailbox, modseq, 0);
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            modseq_t since_modseq = fullannots ? 0 : modseq;

            /* stop early for partial sync */
            modseq_t mymodseq = record->modseq;
            if (ispartial) {
                if (record->uid > local->last_uid)
                    break;
                /* something from past the modseq that we're sending now */
                if (mymodseq > local->highestmodseq) {
                    /* we will send this one later */
                    if (remote && record->uid <= remote->last_uid)
                        continue;
                    /* falsify modseq for now, we will resync this message later */
                    mymodseq = local->highestmodseq;
                }
            }


            /* start off thinking we're sending the file too */
            int send_file = 1;

            /* does it exist at the other end?  Don't send it */
            if (remote && record->uid <= remote->last_uid)
                send_file = 0;

            /* if we're not uploading messages... don't send file */
            if (!part_list || !kupload)
                send_file = 0;

            /* if we don't HAVE the file we can't send it */
            if (record->internal_flags & FLAG_INTERNAL_UNLINKED)
                send_file = 0;

            if (send_file) {
                r = sync_send_file(mailbox, topart,
                                 record, part_list, kupload);
                if (r) goto done;
            }

            struct dlist *il = dlist_newkvlist(rl, "RECORD");
            dlist_setnum32(il, "UID", record->uid);
            dlist_setnum64(il, "MODSEQ", mymodseq);
            dlist_setdate(il, "LAST_UPDATED", record->last_updated);
            sync_print_flags(il, mailbox, record);
            dlist_setdate(il, "INTERNALDATE", record->internaldate);
            dlist_setnum32(il, "SIZE", record->size);
            dlist_setatom(il, "GUID", message_guid_encode(&record->guid));

            r = read_annotations(mailbox, record, &annots, since_modseq,
                                /*XXX ANNOTATE_TOMBSTONES*/0);
            if (r) goto done;

            encode_annotations(il, mailbox, record, annots);
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
        xsyslog(LOG_ERR, "IOERROR: zero length response",
                         "command=<%s> prot_error=<%s>",
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
    if (!strcmp(response.s, "BYE")) {
        /* server is shutting down, don't be surprised by it */
        syslog(LOG_DEBUG, "received BYE: replica was shut down");
        dlist_free(&kl);
        eatline(in, c);
        return IMAP_BYE_LOGOUT;
    }
    if (!strcmp(response.s, "NO")) {
        dlist_free(&kl);
        sync_getline(in, &errmsg);
        syslog(LOG_ERR, "%s received NO response: %s", cmd, errmsg.s);

        /* Slight hack to transform certain error strings into equivalent
         * imap_err value so that caller has some idea of cause.  Match
         * this to the logic at sync_response() */
        if (!strncmp(errmsg.s, "IMAP_INVALID_USER ",
                     strlen("IMAP_INVALID_USER ")))
            return IMAP_INVALID_USER;
        else if (!strncmp(errmsg.s, "IMAP_MAILBOX_NONEXISTENT ",
                          strlen("IMAP_MAILBOX_NONEXISTENT ")))
            return IMAP_MAILBOX_NONEXISTENT;
        else if (!strncmp(errmsg.s, "IMAP_MAILBOX_LOCKED ",
                          strlen("IMAP_MAILBOX_LOCKED ")))
            return IMAP_MAILBOX_LOCKED;
        else if (!strncmp(errmsg.s, "IMAP_MAILBOX_MOVED ",
                          strlen("IMAP_MAILBOX_MOVED ")))
            return IMAP_MAILBOX_MOVED;
        else if (!strncmp(errmsg.s, "IMAP_MAILBOX_NOTSUPPORTED ",
                          strlen("IMAP_MAILBOX_NOTSUPPORTED ")))
            return IMAP_MAILBOX_NOTSUPPORTED;
        else if (!strncmp(errmsg.s, "IMAP_SYNC_CHECKSUM ",
                          strlen("IMAP_SYNC_CHECKSUM ")))
            return IMAP_SYNC_CHECKSUM;
        else if (!strncmp(errmsg.s, "IMAP_SYNC_CHANGED ",
                          strlen("IMAP_SYNC_CHANGED ")))
            return IMAP_SYNC_CHANGED;
        else if (!strncmp(errmsg.s, "IMAP_SYNC_BADSIEVE ",
                          strlen("IMAP_SYNC_BADSIEVE ")))
            return IMAP_SYNC_BADSIEVE;
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
    xsyslog(LOG_ERR, "IOERROR: received bad response",
                     "command=<%s> response=<%s> errmsg=<%s>",
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
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            /* no need to set 'needs cleanup' here, it's already expunged */
            record->internal_flags |= FLAG_INTERNAL_UNLINKED;
            goto just_write;
        }
        xsyslog(LOG_ERR, "IOERROR: parse failed",
                         "guid=<%s> error=<%s>",
                         message_guid_encode(&record->guid),
                         error_message(r));
        return r;
    }

    /* record->guid was rewritten in the parse, see if it changed */
    if (!message_guid_equal(&tmp_guid, &record->guid)) {
        xsyslog(LOG_ERR, "IOERROR: guid mismatch on parse",
                         "filename=<%s> guid=<%s>",
                         item->fname, message_guid_encode(&record->guid));
        return IMAP_IOERROR;
    }

    /* put back to archive if original was archived, gain single instance store  */
    if (item->is_archive)
        record->internal_flags |= FLAG_INTERNAL_ARCHIVED;

    /* push it to archive if it should be archived now anyway */
    if (mailbox_should_archive(mailbox, record, NULL))
        record->internal_flags |= FLAG_INTERNAL_ARCHIVED;

    destname = mailbox_record_fname(mailbox, record);
    cyrus_mkdir(destname, 0755);
    r = mailbox_copyfile(item->fname, destname, 0);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: copy file failed",
                         "filename=<%s> destination=<%s>",
                         item->fname, destname);
        return r;
    }

 just_write:
    /* Never apply GUID limits when replicating or repairing */
    record->ignorelimits = 1;

    r = mailbox_append_index_record(mailbox, record);
    if (r) return r;

    int hadsnoozed = 0;
    /* apply the remote annotations */
    r = apply_annotations(mailbox, record, NULL, annots, 0, &hadsnoozed);
    if (r) {
        syslog(LOG_ERR, "Failed to apply annotations: %s",
               error_message(r));
    }

    if (!r && hadsnoozed) {
        record->silentupdate = 1;
        record->internal_flags |= FLAG_INTERNAL_SNOOZED;
        r = mailbox_rewrite_index_record(mailbox, record);
    }

    return r;
}

/* ==================================================================== */

int sync_mailbox_version_check(struct mailbox **mailboxp)
{
    int r = 0;

    if ((*mailboxp)->i.minor_version < 10) {
        /* index records will definitely not have guids! */
        r = IMAP_MAILBOX_NOTSUPPORTED;
        goto done;
    }

    /* scan index records to ensure they have guids.  version 10 index records
     * have this field, but it might have never been initialised.
     * XXX this might be overkill for versions > 10, but let's be cautious */
    struct mailbox_iter *iter = mailbox_iter_init((*mailboxp), 0, 0);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (message_guid_isnull(&record->guid)) {
            syslog(LOG_WARNING, "%s: missing guid for record %u -- needs 'reconstruct -G'?",
                                mailbox_name(*mailboxp), record->recno);
            r = IMAP_MAILBOX_NOTSUPPORTED;
            break;
        }
    }
    mailbox_iter_done(&iter);

done:
    if (r) {
        syslog(LOG_DEBUG, "%s: %s failed version check: %s",
                          __func__, mailbox_name(*mailboxp), error_message(r));
        mailbox_close(mailboxp);
    }
    return r;
}

/* =======================  server-side sync  =========================== */

static void reserve_folder(const char *part, const char *mboxname,
                    struct sync_msgid_list *part_list)
{
    struct mailbox *mailbox = NULL;
    int r;
    struct sync_msgid *item;
    const char *mailbox_msg_path, *stage_msg_path;
    int num_reserved;

redo:

    num_reserved = 0;

    /* Open and lock mailbox */
    r = mailbox_open_irl(mboxname, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r) return;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* do we need it? */
        item = sync_msgid_lookup(part_list, &record->guid);
        if (!item)
            continue;

        /* have we already found it? */
        if (!item->need_upload)
            continue;

        /* Attempt to reserve this message */
        mailbox_msg_path = mailbox_record_fname(mailbox, record);
        stage_msg_path = dlist_reserve_path(part, record->internal_flags & FLAG_INTERNAL_ARCHIVED,
                                            0, &record->guid);

        /* check that the sha1 of the file on disk is correct */
        struct index_record record2;
        memset(&record2, 0, sizeof(struct index_record));
        r = message_parse(mailbox_msg_path, &record2);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: parse failed",
                             "filename=<%s>",
                             mailbox_msg_path);
            continue;
        }
        if (!message_guid_equal(&record->guid, &record2.guid)) {
            xsyslog(LOG_ERR, "IOERROR: guid mismatch on parse",
                            "filename=<%s>",
                            mailbox_msg_path);
            continue;
        }

        if (mailbox_copyfile(mailbox_msg_path, stage_msg_path, 0) != 0) {
            xsyslog(LOG_ERR, "IOERROR: link failed",
                             "mailbox_msg_path=<%s> stage_msg_path=<%s>",
                             mailbox_msg_path, stage_msg_path);
            continue;
        }

        item->size = record->size;
        item->fname = xstrdup(stage_msg_path); /* track the correct location */
        item->is_archive = (record->internal_flags & FLAG_INTERNAL_ARCHIVED) ? 1 : 0;
        item->need_upload = 0;
        part_list->toupload--;
        num_reserved++;

        /* already found everything, drop out */
        if (!part_list->toupload) break;

        /* arbitrary batch size */
        if (num_reserved >= 1024) {
            mailbox_iter_done(&iter);
            mailbox_close(&mailbox);
            goto redo;
        }
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

    modseq_t modseq = 0;
    dlist_getnum64(kin, "MODSEQ", &modseq);

    return mboxlist_setquotas(root, limits, modseq, 1);
}

/* ====================================================================== */

static int sync_mailbox_compare_update(struct mailbox *mailbox,
                                  struct dlist *kr, int doupdate,
                                  struct sync_msgid_list *part_list)
{
    struct index_record mrecord;
    struct dlist *ki;
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int r;
    int i;
    int has_append = 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);

    const message_t *msg = mailbox_iter_step(iter);
    const struct index_record *rrecord = msg ? msg_record(msg) : NULL;

    for (ki = kr->head; ki; ki = ki->next) {
        sync_annot_list_free(&mannots);
        sync_annot_list_free(&rannots);

        r = parse_upload(ki, mailbox, &mrecord, &mannots);
        if (r) {
            xsyslog(LOG_ERR, "SYNCERROR: failed to parse uploaded record", NULL);
            return IMAP_PROTOCOL_ERROR;
        }

        /* n.b. we assume the records in kr are in ascending uid order.
         * stuff will probably fail in interesting ways if they're ever not.
         */
        while (rrecord && rrecord->uid < mrecord.uid) {
            /* read another record */
            msg = mailbox_iter_step(iter);
            rrecord = msg ? msg_record(msg) : NULL;
        }

        /* found a match, check for updates */
        if (rrecord && rrecord->uid == mrecord.uid) {
            /* if they're both EXPUNGED then ignore everything else */
            if (mrecord.internal_flags & FLAG_INTERNAL_EXPUNGED &&
                rrecord->internal_flags & FLAG_INTERNAL_EXPUNGED)
                continue;

            /* GUID mismatch is an error straight away, it only ever happens if we
             * had a split brain - and it will take a full sync to sort out the mess */
            if (!message_guid_equal(&mrecord.guid, &rrecord->guid)) {
                xsyslog(LOG_ERR, "SYNCNOTICE: guid mismatch",
                                 "mailbox=<%s> uid=<%u>",
                                 mailbox_name(mailbox), mrecord.uid);
                r = IMAP_SYNC_CHECKSUM;
                goto out;
            }

            /* higher modseq on the replica is an error */
            if (rrecord->modseq > mrecord.modseq) {
                if (opt_force) {
                    syslog(LOG_NOTICE, "forcesync: higher modseq on replica %s %u (" MODSEQ_FMT " > " MODSEQ_FMT ")",
                           mailbox_name(mailbox), mrecord.uid, rrecord->modseq, mrecord.modseq);
                }
                else {
                    xsyslog(LOG_ERR, "SYNCNOTICE: higher modseq on replica",
                                     "mailbox=<%s> uid=<%u>"
                                        " replicamodseq=<" MODSEQ_FMT ">"
                                        " mastermodseq=<" MODSEQ_FMT ">",
                                     mailbox_name(mailbox), mrecord.uid,
                                     rrecord->modseq, mrecord.modseq);
                    r = IMAP_SYNC_CHECKSUM;
                    goto out;
                }
            }

            /* if it's already expunged on the replica, but alive on the master,
             * that's bad */
            if (!(mrecord.internal_flags & FLAG_INTERNAL_EXPUNGED) &&
                (rrecord->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                xsyslog(LOG_ERR, "SYNCNOTICE: expunged on replica",
                                 "mailbox=<%s> uid=<%u>",
                                 mailbox_name(mailbox), mrecord.uid);
                r = IMAP_SYNC_CHECKSUM;
                goto out;
            }

            /* skip out on the first pass */
            if (!doupdate) continue;

            struct index_record copy = *rrecord;
            copy.cid = mrecord.cid;
            copy.basecid = mrecord.basecid;
            copy.modseq = mrecord.modseq;
            copy.last_updated = mrecord.last_updated;
            copy.internaldate = mrecord.internaldate;
            copy.savedate = mrecord.savedate;
            copy.createdmodseq = mrecord.createdmodseq;
            copy.system_flags = mrecord.system_flags;
            /* FLAG_INTERNAL_EXPUNGED is a syncable flag, but it's internal.
             * The `internal_flags` contain replica's internal_flags for
             * non-EXPUNGED, but master's internal_flags for EXPUNGED */
            copy.internal_flags = rrecord->internal_flags & ~FLAG_INTERNAL_EXPUNGED;
            copy.internal_flags |= mrecord.internal_flags & FLAG_INTERNAL_EXPUNGED;

            for (i = 0; i < MAX_USER_FLAGS/32; i++)
                copy.user_flags[i] = mrecord.user_flags[i];

            r = read_annotations(mailbox, &copy, &rannots, rrecord->modseq,
                                 /*XXX ANNOTATE_TOMBSTONES*/0);
            if (r) {
                syslog(LOG_ERR, "Failed to read local annotations %s %u: %s",
                       mailbox_name(mailbox), rrecord->recno, error_message(r));
                goto out;
            }

            int hadsnoozed = 0;
            r = apply_annotations(mailbox, &copy, rannots, mannots, 0, &hadsnoozed);
            if (r) {
                syslog(LOG_ERR, "Failed to write merged annotations %s %u: %s",
                       mailbox_name(mailbox), rrecord->recno, error_message(r));
                goto out;
            }

            if (hadsnoozed) copy.internal_flags |= FLAG_INTERNAL_SNOOZED;
            else copy.internal_flags &= ~FLAG_INTERNAL_SNOOZED;
            copy.silentupdate = 1;
            copy.ignorelimits = 1;
            r = mailbox_rewrite_index_record(mailbox, &copy);
            if (r) {
                xsyslog(LOG_ERR, "IOERROR: rewrite record failed",
                                 "mboxname=<%s> recno=<%u>",
                                 mailbox_name(mailbox), rrecord->recno);
                goto out;
            }
        }

        /* not found and less than LAST_UID, bogus */
        else if (mrecord.uid <= mailbox->i.last_uid) {
            /* Expunged, just skip it */
            if (!(mrecord.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                r = IMAP_SYNC_CHECKSUM;
                goto out;
            }
        }

        /* after LAST_UID, it's an append, that's OK */
        else {
            /* skip out on the first pass */
            if (!doupdate) continue;

            mrecord.silentupdate = 1;
            r = sync_append_copyfile(mailbox, &mrecord, mannots, part_list);
            if (r) {
                xsyslog(LOG_ERR, "IOERROR: append file failed",
                                 "mboxname=<%s> uid=<%d>",
                                 mailbox_name(mailbox), mrecord.uid);
                goto out;
            }

            has_append = 1;
        }
    }

    if (has_append)
        sync_log_append(mailbox_name(mailbox));

    r = 0;

out:
    mailbox_iter_done(&iter);
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);
    return r;
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
    modseq_t foldermodseq = 0;
    const char *acl;
    const char *options_str;
    struct synccrcs synccrcs = { 0, 0 };

    uint32_t options;

    /* optional fields */
    modseq_t xconvmodseq = 0;
    modseq_t raclmodseq = 0;
    modseq_t createdmodseq = 0;

    /* previous state markers */
    modseq_t since_modseq = 0;
    struct synccrcs since_crcs = { 0, 0 };

    struct mailbox *mailbox = NULL;
    struct dlist *kr;
    struct dlist *ka = NULL;
    int r;

    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;

    annotate_state_t *astate = NULL;

    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum64(kin, "HIGHESTMODSEQ", &highestmodseq))
        return IMAP_PROTOCOL_BAD_PARAMETERS;

    dlist_getnum64(kin, "CREATEDMODSEQ", &createdmodseq);

    dlist_getatom(kin, "MBOXTYPE", &mboxtype);
    mbtype = mboxlist_string_to_mbtype(mboxtype);

    if (mbtype & (MBTYPE_INTERMEDIATE|MBTYPE_DELETED)) {
        // XXX - make sure what's already there is either nothing or compatible...
        mbentry_t *newmbentry = NULL;

        newmbentry = mboxlist_entry_create();
        newmbentry->name = xstrdupnull(mboxname);
        newmbentry->mbtype = mbtype;
        newmbentry->uniqueid = xstrdupnull(uniqueid);
        newmbentry->foldermodseq = highestmodseq;
        newmbentry->createdmodseq = createdmodseq;

        r = mboxlist_update(newmbentry, /*localonly*/1);
        mboxlist_entry_free(&newmbentry);

        return r;
    }


    if (!dlist_getatom(kin, "PARTITION", &partition))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "LAST_UID", &last_uid))
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
    dlist_getnum64(kin, "XCONVMODSEQ", &xconvmodseq);
    dlist_getnum64(kin, "RACLMODSEQ", &raclmodseq);
    dlist_getnum64(kin, "FOLDERMODSEQ", &foldermodseq);

    /* Get the CRCs */
    dlist_getnum32(kin, "SYNC_CRC", &synccrcs.basic);
    dlist_getnum32(kin, "SYNC_CRC_ANNOT", &synccrcs.annot);

    /* Get the previous state for this delta */
    dlist_getnum64(kin, "SINCE_MODSEQ", &since_modseq);
    dlist_getnum32(kin, "SINCE_CRC", &since_crcs.basic);
    dlist_getnum32(kin, "SINCE_CRC_ANNOT", &since_crcs.annot);

    options = sync_parse_options(options_str);

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        struct mboxlock *namespacelock = mboxname_usernamespacelock(mboxname);
        // try again under lock
        r = mailbox_open_iwl(mboxname, &mailbox);
        if (!r) r = sync_mailbox_version_check(&mailbox);
        if (r == IMAP_MAILBOX_NONEXISTENT) { // did we win a race?
            char *oldname = mboxlist_find_uniqueid(uniqueid, NULL, NULL);
            // if they have the same name it's probably an intermediate being
            // promoted.  Intermediates, the gift that keeps on giving.
            if (oldname && strcmp(oldname, mboxname)) {
                xsyslog(LOG_ERR, "SYNCNOTICE: mailbox uniqueid already in use",
                                 "mailbox=<%s> uniqueid=<%s> usedby=<%s>",
                                 mboxname, uniqueid, oldname);
                free(oldname);
                r = IMAP_MAILBOX_MOVED;
            }
            else {
                r = mboxlist_createsync(mboxname, mbtype, partition,
                                            sstate->userid, sstate->authstate,
                                            options, uidvalidity, createdmodseq,
                                            highestmodseq, foldermodseq, acl,
                                            uniqueid, sstate->local_only, 0, &mailbox);
            }
            /* set a highestmodseq of 0 so ALL changes are future
             * changes and get applied */
            if (!r) mailbox->i.highestmodseq = 0;
        }
        mboxname_release(&namespacelock);
    }
    if (r) {
        syslog(LOG_ERR, "Failed to open mailbox %s to update: %s",
               mboxname, error_message(r));
        goto done;
    }

    // immediate bail if we have an old state to compare
    if (since_modseq) {
        struct synccrcs mycrcs = mailbox_synccrcs(mailbox, 0);
        if (since_modseq != mailbox->i.highestmodseq ||
            !mailbox_crceq(since_crcs, mycrcs)) {
            xsyslog(LOG_ERR, "SYNCNOTICE: mailbox sync mismatch",
                             "mailbox=<%s>"
                                " hms_master=<" MODSEQ_FMT ">"
                                " hms_replica=<" MODSEQ_FMT ">"
                                " crcs_master=<%u/%u>"
                                " crcs_replica=<%u/%u>",
                             mailbox_name(mailbox),
                             since_modseq,
                             mailbox->i.highestmodseq,
                             since_crcs.basic, since_crcs.annot,
                             mycrcs.basic, mycrcs.annot);
            r = IMAP_SYNC_CHANGED;
            goto done;
        }
    }

    if ((mbtypes_sync(mailbox->mbtype)) != mbtype) {
        syslog(LOG_ERR, "INVALID MAILBOX TYPE %s (%d, %d)", mailbox_name(mailbox), mailbox->mbtype, mbtype);
        /* is this even possible? */
        r = IMAP_MAILBOX_BADTYPE;
        goto done;
    }

    part_list = sync_reserve_partlist(reserve_list, mailbox->part);

    /* hold the annotate state open */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    if (r) goto done;

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
            xsyslog(LOG_ERR, "SYNCNOTICE: mailbox uniqueid changed - retry",
                             "mailbox=<%s> origuniqueid=<%s> newuniqueid=<%s>",
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

    /* skip out now, it's going to mismatch for sure! */
    /* 0 is the default case, and should always be overwritten with the real value */
    if (createdmodseq > mailbox->i.createdmodseq && mailbox->i.createdmodseq != 0) {
        xsyslog(LOG_NOTICE, "SYNCNOTICE: lower createdmodseq on replica",
                            "mailbox=<%s> createdmodseq=<" MODSEQ_FMT ">"
                                " replica_createdmodseq=<" MODSEQ_FMT ">",
                            mboxname, createdmodseq, mailbox->i.createdmodseq);
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

    r = sync_mailbox_compare_update(mailbox, kr, 0, part_list);
    if (r) goto done;

    /* now we're committed to writing something no matter what happens! */

    mailbox_index_dirty(mailbox);

    mailbox->silentchanges = 1;

    /* always take the ACL from the master, it's not versioned */
    r = mboxlist_sync_setacls(mboxname, acl, foldermodseq ? foldermodseq : highestmodseq);
    if (!r) r = mailbox_set_acl(mailbox, acl);
    if (r) goto done;

    /* take all mailbox (not message) annotations - aka metadata,
     * they're not versioned either */
    if (ka)
        decode_annotations(ka, &mannots, mailbox, NULL);

    r = read_annotations(mailbox, NULL, &rannots, 0, 0);
    if (!r) r = apply_annotations(mailbox, NULL, rannots, mannots, 0, NULL);

    if (r) {
        syslog(LOG_ERR, "syncerror: annotations failed to apply to %s",
               mailbox_name(mailbox));
        goto done;
    }

    r = sync_mailbox_compare_update(mailbox, kr, 1, part_list);
    if (r) {
        abort();
        return r;
    }

    if (!opt_force) {
        assert(mailbox->i.last_uid <= last_uid);
    }
    mailbox->i.last_uid = last_uid;
    mailbox->i.recentuid = recentuid;
    mailbox->i.highestmodseq = highestmodseq;
    mailbox->i.recenttime = recenttime;
    mailbox->i.last_appenddate = last_appenddate;
    mailbox->i.pop3_last_login = pop3_last_login;
    mailbox->i.pop3_show_after = pop3_show_after;
    mailbox->i.createdmodseq = createdmodseq;
    /* only alter the syncable options */
    mailbox->i.options = (options & MAILBOX_OPTIONS_MASK) |
                         (mailbox->i.options & ~MAILBOX_OPTIONS_MASK);

    /* always set the highestmodseq */
    mboxname_setmodseq(mailbox_name(mailbox), highestmodseq, mailbox->mbtype, /*flags*/0);

    /* this happens rarely, so let us know */
    if (mailbox->i.uidvalidity != uidvalidity) {
        syslog(LOG_NOTICE, "%s uidvalidity changed, updating %u => %u",
               mailbox_name(mailbox), mailbox->i.uidvalidity, uidvalidity);
        /* make sure nothing new gets created with a lower value */
        mailbox->i.uidvalidity = mboxname_setuidvalidity(mailbox_name(mailbox), uidvalidity);
    }

    if (mailbox_has_conversations(mailbox)) {
        r = mailbox_update_xconvmodseq(mailbox, xconvmodseq, opt_force);
    }

    if (config_getswitch(IMAPOPT_REVERSEACLS) && raclmodseq) {
        mboxname_setraclmodseq(mailbox_name(mailbox), raclmodseq);
    }

done:
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);

    /* check the CRC too */
    if (!r && !mailbox_crceq(synccrcs, mailbox_synccrcs(mailbox, 0))) {
        /* try forcing a recalculation */
        if (!mailbox_crceq(synccrcs, mailbox_synccrcs(mailbox, 1)))
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
                            const struct annotate_metadata *mdata __attribute__((unused)),
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
    return annotatemore_findall(mboxname, 0, "*", /*modseq*/0,
                                &getannotation_cb, (void *) sstate->pout,
                                /*flags*/0);
}

static void print_quota(struct quota *q, struct protstream *pout)
{
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, "QUOTA");
    dlist_setatom(kl, "ROOT", q->root);
    sync_encode_quota_limits(kl, q->limits);
    dlist_setnum64(kl, "MODSEQ", q->modseq);
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

static int sync_mailbox_byentry(const mbentry_t *mbentry, void *rock)
{
    struct mbox_rock *mrock = (struct mbox_rock *) rock;
    struct sync_name_list *qrl = mrock->qrl;
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");
    annotate_state_t *astate = NULL;
    int r = 0;

    if (!mbentry) goto out;
    if (mbentry->mbtype & MBTYPE_DELETED) goto out;
    if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
        dlist_setatom(kl, "UNIQUEID", mbentry->uniqueid);
        dlist_setatom(kl, "MBOXNAME", mbentry->name);
        dlist_setatom(kl, "MBOXTYPE", mboxlist_mbtype_to_string(mbtypes_sync(mbentry->mbtype)));
        dlist_setnum32(kl, "SYNC_CRC", 0);
        // this stuff should be optional, but old sync_client will barf without it
        dlist_setnum32(kl, "LAST_UID", 0);
        dlist_setnum64(kl, "HIGHESTMODSEQ", 0);
        dlist_setnum32(kl, "RECENTUID", 0);
        dlist_setdate(kl, "RECENTTIME", 0);
        dlist_setdate(kl, "LAST_APPENDDATE", 0);
        dlist_setdate(kl, "POP3_LAST_LOGIN", 0);
        dlist_setdate(kl, "POP3_SHOW_AFTER", 0);
        // standard fields
        dlist_setnum32(kl, "UIDVALIDITY", mbentry->uidvalidity);
        dlist_setatom(kl, "PARTITION", mbentry->partition);
        dlist_setatom(kl, "ACL", mbentry->acl);
        dlist_setatom(kl, "OPTIONS", sync_encode_options(0));
        dlist_setnum64(kl, "CREATEDMODSEQ", mbentry->createdmodseq);
        dlist_setnum64(kl, "FOLDERMODSEQ", mbentry->foldermodseq);

        // send the intermediate response
        sync_send_response(kl, mrock->pout);
        goto out;
    }

    r = mailbox_open_irl(mbentry->name, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT ||
        r == IMAP_MAILBOX_RESERVED) {
        r = 0;
        goto out;
    }
    if (r) goto out;

    /* hold the annotate state open */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    if (r) goto out;

    /* and make it hold a transaction open */
    annotate_state_begin(astate);

    if (qrl && mailbox->quotaroot)
        sync_name_list_add(qrl, mailbox->quotaroot);

    r = sync_prepare_dlists(mailbox, NULL, NULL, NULL, NULL, kl, NULL, 0,
                            /*XXX fullannots*/1, 0);


    if (!r) sync_send_response(kl, mrock->pout);

out:
    mailbox_close(&mailbox);
    dlist_free(&kl);

    return r;
}

static int sync_mailbox_byuniqueid(const char *uniqueid, void *rock)
{
    char *name = mboxlist_find_uniqueid(uniqueid, NULL, NULL);
    mbentry_t *mbentry = NULL;
    int r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (!r) r = sync_mailbox_byentry(mbentry, rock);
    mboxlist_entry_free(&mbentry);
    free(name);
    return r;
}

int sync_get_fullmailbox(struct dlist *kin, struct sync_state *sstate)
{
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");
    int r;

    r = mailbox_open_irl(kin->sval, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r) goto out;

    r = sync_prepare_dlists(mailbox, NULL, NULL, NULL, NULL, kl, NULL, 1,
                            /*XXX fullannots*/1, 0);
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

    for (ki = kin->head; ki; ki = ki->next) {
        mbentry_t *mbentry = NULL;
        int r = mboxlist_lookup_allow_all(ki->sval, &mbentry, NULL);
        if (!r) sync_mailbox_byentry(mbentry, &mrock);
        mboxlist_entry_free(&mbentry);
    }

    return 0;
}

int sync_get_uniqueids(struct dlist *kin, struct sync_state *sstate)
{
    struct dlist *ki;
    struct mbox_rock mrock = { sstate->pout, NULL };

    for (ki = kin->head; ki; ki = ki->next)
        sync_mailbox_byuniqueid(ki->sval, &mrock);

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
    struct dlist *kl = dlist_newlist(NULL, "LSUB");
    strarray_t *sublist = mboxlist_sublist(userid);
    int i;

    for (i = 0; i < sublist->count; i++) {
        const char *name = strarray_nth(sublist, i);
        dlist_setatom(kl, "MBOXNAME", name);
    }

    if (kl->head)
        sync_send_response(kl, pout);

    dlist_free(&kl);
    strarray_free(sublist);

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
    int r;
    struct sync_name_list *quotaroots;
    struct sync_name *qr;
    const char *userid = kin->sval;
    struct mbox_rock mrock;

    quotaroots = sync_name_list_create();
    mrock.qrl = quotaroots;
    mrock.pout = sstate->pout;

    r = mboxlist_usermboxtree(userid, NULL, sync_mailbox_byentry, &mrock, MBOXTREE_DELETED|MBOXTREE_INTERMEDIATES);
    if (r) goto bail;

    for (qr = quotaroots->head; qr; qr = qr->next) {
        r = quota_work(qr->name, sstate->pout);
        if (r) goto bail;
    }

    r = user_meta(userid, sstate->pout);
    if (r) goto bail;

bail:
    sync_name_list_free(&quotaroots);
    return r;
}

/* ====================================================================== */

int sync_apply_unmailbox(struct dlist *kin, struct sync_state *sstate)
{
    const char *mboxname = kin->sval;

    struct mboxlock *namespacelock = mboxname_usernamespacelock(mboxname);

    /* Delete with admin privileges */
    int delflags = MBOXLIST_DELETE_FORCE | MBOXLIST_DELETE_SILENT;
    if (sstate->local_only) delflags |= MBOXLIST_DELETE_LOCALONLY;
    int r = mboxlist_deletemailbox(mboxname, sstate->userisadmin,
                                   sstate->userid, sstate->authstate,
                                   NULL, delflags);

    mboxname_release(&namespacelock);

    return r;
}

int sync_apply_rename(struct dlist *kin, struct sync_state *sstate)
{
    const char *oldmboxname;
    const char *newmboxname;
    const char *partition;
    uint32_t uidvalidity = 0;
    mbentry_t *mbentry = NULL;
    int r;

    if (!dlist_getatom(kin, "OLDMBOXNAME", &oldmboxname))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "NEWMBOXNAME", &newmboxname))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
        return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* optional */
    dlist_getnum32(kin, "UIDVALIDITY", &uidvalidity);

    struct mboxlock *oldlock = NULL;
    struct mboxlock *newlock = NULL;

    /* make sure we grab these locks in a stable order! */
    if (strcmpsafe(oldmboxname, newmboxname) < 0) {
        oldlock = mboxname_usernamespacelock(oldmboxname);
        newlock = mboxname_usernamespacelock(newmboxname);
    }
    else {
        // doesn't hurt to double lock, it's refcounted
        newlock = mboxname_usernamespacelock(newmboxname);
        oldlock = mboxname_usernamespacelock(oldmboxname);
    }

    r = mboxlist_lookup_allow_all(oldmboxname, &mbentry, 0);

    if (!r) r = mboxlist_renamemailbox(mbentry, newmboxname, partition,
                                       uidvalidity, 1, sstate->userid,
                                       sstate->authstate, NULL, sstate->local_only, 1, 1,
                                       1/*keep_intermediaries*/,
                                       0/*move_subscription*/,
                                       1/*silent*/);

    mboxlist_entry_free(&mbentry);
    mboxname_release(&oldlock);
    mboxname_release(&newlock);

    return r;
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

    appendattvalue(&attvalues,
                   *userid ? "value.priv" : "value.shared",
                   &value);
    appendentryatt(&entryatts, entry, attvalues);

    astate = annotate_state_new();
    if (*mboxname) {
        r = mailbox_open_iwl(mboxname, &mailbox);
        if (r) goto done;
        r = sync_mailbox_version_check(&mailbox);
        if (r) goto done;
        r = annotate_state_set_mailbox(astate, mailbox);
        if (r) goto done;
    }
    else {
        r = annotate_state_set_server(astate);
        if (r) goto done;
    }
    annotate_state_set_auth(astate,
                            sstate->userisadmin, userid, sstate->authstate);

    r = annotate_state_store(astate, entryatts);

done:
    if (!r)
        r = annotate_state_commit(&astate);
    else
        annotate_state_abort(&astate);

    mailbox_close(&mailbox);

    buf_free(&value);
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

    appendattvalue(&attvalues,
                   *userid ? "value.priv" : "value.shared",
                   &empty);
    appendentryatt(&entryatts, entry, attvalues);

    astate = annotate_state_new();
    if (*mboxname) {
        r = mailbox_open_iwl(mboxname, &mailbox);
        if (r) goto done;
        r = sync_mailbox_version_check(&mailbox);
        if (r) goto done;
        r = annotate_state_set_mailbox(astate, mailbox);
        if (r) goto done;
    }
    else {
        r = annotate_state_set_server(astate);
        if (r) goto done;
    }
    annotate_state_set_auth(astate,
                            sstate->userisadmin, userid, sstate->authstate);

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

EXPORTED int addmbox_cb(const mbentry_t *mbentry, void *rock)
{
    strarray_t *list = (strarray_t *)rock;
    strarray_append(list, mbentry->name);
    return 0;
}

int sync_apply_unuser(struct dlist *kin, struct sync_state *sstate)
{
    const char *userid = kin->sval;
    int r = 0;
    int i;

    /* nothing to do if there's no userid */
    if (!userid || !userid[0]) {
        xsyslog(LOG_WARNING, "ignoring attempt to sync_apply_unuser() without userid",
                             NULL);
        return 0;
    }

    struct mboxlock *namespacelock = user_namespacelock(userid);

    /* Nuke subscriptions */
    /* ignore failures here - the subs file gets deleted soon anyway */
    strarray_t *list = mboxlist_sublist(userid);
    for (i = 0; i < list->count; i++) {
        const char *name = strarray_nth(list, i);
        mboxlist_changesub(name, userid, sstate->authstate, 0, 0, 0);
    }

    strarray_truncate(list, 0);
    r = mboxlist_usermboxtree(userid, NULL, addmbox_cb, list, 0);
    if (r) goto done;

    /* delete in reverse so INBOX is last */
    int delflags = MBOXLIST_DELETE_FORCE;
    if (sstate->local_only) delflags |= MBOXLIST_DELETE_LOCALONLY;
    for (i = list->count; i; i--) {
        const char *name = strarray_nth(list, i-1);
        r = mboxlist_deletemailbox(name, sstate->userisadmin,
                                   sstate->userid, sstate->authstate,
                                   NULL, delflags);
        if (r) goto done;
    }

    r = user_deletedata(userid, 1);

 done:
    mboxname_release(&namespacelock);
    strarray_free(list);

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
    if (stat(fname, &sbuf) == -1) // try archive partition
        fname = mboxname_archivepath(partition, mboxname, uniqueid, uid);
    if (stat(fname, &sbuf) == -1) // try legacy data path
        fname = mboxname_datapath(partition, mboxname, NULL, uid);
    if (stat(fname, &sbuf) == -1) // try legacy archive partition
        fname = mboxname_archivepath(partition, mboxname, NULL, uid);
    if (stat(fname, &sbuf) == -1) // give up
        return IMAP_MAILBOX_NONEXISTENT;

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
    if (!r) r = sync_mailbox_version_check(&mailbox);
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
        oldrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        oldrecord.silentupdate = 1; /* so the next sync will succeed */
        oldrecord.ignorelimits = 1;
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
        if (!dlist_tofile(ki, &part, &guid, (unsigned long *) &size, &fname))
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

/* ====================================================================== */

int sync_restore_mailbox(struct dlist *kin,
                         struct sync_reserve_list *reserve_list,
                         struct sync_state *sstate)
{
    /* fields from the request, all but mboxname are optional */
    const char *mboxname;
    const char *uniqueid = NULL;
    const char *partition = NULL;
    const char *mboxtype = NULL;
    const char *acl = NULL;
    const char *options_str = NULL;
    modseq_t highestmodseq = 0;
    uint32_t uidvalidity = 0;
    struct dlist *kr = NULL;
    struct dlist *ka = NULL;
    modseq_t xconvmodseq = 0;
    modseq_t createdmodseq = 0;
    modseq_t foldermodseq = 0;

    /* derived fields */
    uint32_t options = 0;
    uint32_t mbtype = 0;

    struct mailbox *mailbox = NULL;
    struct sync_msgid_list *part_list;
    annotate_state_t *astate = NULL;
    struct dlist *ki;
    int has_append = 0;
    int is_new_mailbox = 0;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname)) {
        syslog(LOG_DEBUG, "%s: missing MBOXNAME", __func__);
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    /* optional */
    dlist_getatom(kin, "PARTITION", &partition);
    dlist_getatom(kin, "ACL", &acl);
    dlist_getatom(kin, "OPTIONS", &options_str);
    dlist_getlist(kin, "RECORD", &kr);
    dlist_getlist(kin, "ANNOTATIONS", &ka);
    dlist_getatom(kin, "MBOXTYPE", &mboxtype);
    dlist_getnum64(kin, "XCONVMODSEQ", &xconvmodseq);

    /* derived */
    options = sync_parse_options(options_str);
    mbtype = mboxlist_string_to_mbtype(mboxtype);

    /* XXX sanely handle deletedprefix mboxnames */

    /* If the mboxname being restored already exists, then restored messages
     * are appended to it.  The UNIQUEID, HIGHESTMODSEQ, UIDVALIDITY and
     * MBOXTYPE fields in the dlist, and the UID, MODSEQ and LAST_UPDATED fields
     * in the restored message records, are ignored entirely.
     *
     * If the mboxname does not exist, we create it.  If UNIQUEID, HIGHESTMODSEQ
     * and UIDVALIDITY were provided, we try to preserve them, and if we can, we
     * also try to preserve the UID, MODSEQ and LAST_UPDATED fields of the
     * restored messages.  This is useful when e.g. rebuilding a server from a
     * backup, and wanting clients' IMAP states to match.
     *
     * If UNIQUEID, HIGHESTMODSEQ or UIDVALIDITY are not provided, we don't try
     * to preserve them.  We create the mailbox, but then append the restored
     * messages to it as if it already existed (new UID et al).
     */

    /* open/create mailbox */
    r = mailbox_open_iwl(mboxname, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    syslog(LOG_DEBUG, "%s: mailbox_open_iwl %s: %s",
           __func__, mboxname, error_message(r));
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        dlist_getatom(kin, "UNIQUEID", &uniqueid);
        dlist_getnum64(kin, "HIGHESTMODSEQ", &highestmodseq);
        dlist_getnum32(kin, "UIDVALIDITY", &uidvalidity);
        dlist_getnum64(kin, "CREATEDMODSEQ", &createdmodseq);
        dlist_getnum64(kin, "FOLDERMODSEQ", &foldermodseq);

        /* if any of these three weren't set, disregard the others too */
        if (!uniqueid || !highestmodseq || !uidvalidity) {
            uniqueid = NULL;
            highestmodseq = 0;
            uidvalidity = 0;
        }

        struct mboxlock *namespacelock = mboxname_usernamespacelock(mboxname);
        // try again under lock
        r = mailbox_open_iwl(mboxname, &mailbox);
        if (!r) r = sync_mailbox_version_check(&mailbox);
        if (r == IMAP_MAILBOX_NONEXISTENT) { // did we win a race?
            r = mboxlist_createsync(mboxname, mbtype, partition,
                                    sstate->userid, sstate->authstate,
                                    options, uidvalidity, createdmodseq,
                                    highestmodseq, foldermodseq, acl,
                                    uniqueid, sstate->local_only, 0, &mailbox);
            syslog(LOG_DEBUG, "%s: mboxlist_createsync %s: %s",
                __func__, mboxname, error_message(r));
            is_new_mailbox = 1;
        }
        mboxname_release(&namespacelock);
    }
    if (r) {
        syslog(LOG_ERR, "Failed to open mailbox %s to restore: %s",
               mboxname, error_message(r));
        return r;
    }

    /* XXX what if we've opened a deleted mailbox? */

    /* XXX verify mailbox is suitable? */

    /* make sure mailbox types match */
    if (mbtypes_sync(mailbox->mbtype) != mbtype) {
        syslog(LOG_ERR, "restore mailbox %s: mbtype mismatch (%d, %d)",
               mailbox_name(mailbox), mailbox->mbtype, mbtype);
        r = IMAP_MAILBOX_BADTYPE;
        goto bail;
    }

    part_list = sync_reserve_partlist(reserve_list, mailbox->part);

    /* hold the annotate state open */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    syslog(LOG_DEBUG, "%s: mailbox_get_annotate_state %s: %s",
        __func__, mailbox_name(mailbox), error_message(r));
    if (r) goto bail;

    /* and make it hold a transaction open */
    annotate_state_begin(astate);

    /* XXX do we need to hold the conversation state open? */

    /* restore mailbox annotations */
    if (ka) {
        struct sync_annot_list *restore_annots = NULL;
        struct sync_annot_list *mailbox_annots = NULL;

        r = decode_annotations(ka, &restore_annots, mailbox, NULL);

        if (!r) r = read_annotations(mailbox, NULL, &mailbox_annots, 0, 0);

        if (!r) r = apply_annotations(mailbox, NULL,
                                      mailbox_annots, restore_annots,
                                      !is_new_mailbox, NULL);
        if (r)
            syslog(LOG_WARNING,
                   "restore mailbox %s: unable to apply mailbox annotations: %s",
                   mailbox_name(mailbox), error_message(r));

        /* keep going on annotations failure*/
        r = 0;

        sync_annot_list_free(&restore_annots);
        sync_annot_list_free(&mailbox_annots);
    }

    /* n.b. undocumented assumption here and in sync_apply_mailbox
     * that records will be provided sorted by ascending uid */
    for (ki = kr->head; ki; ki = ki->next) {
        struct sync_annot_list *annots = NULL;
        struct index_record record = {0};

        /* XXX skip if the guid is already in this folder? */

        r = parse_upload(ki, mailbox, &record, &annots);
        syslog(LOG_DEBUG, "%s: parse_upload %s: %s",
               __func__, mailbox_name(mailbox), error_message(r));
        if (r) goto bail;

        /* generate a uid if we can't reuse a provided one */
        if (!uidvalidity || record.uid <= mailbox->i.last_uid)
            record.uid = mailbox->i.last_uid + 1;

        /* reuse a provided modseq/last_updated if safe */
        if (highestmodseq && record.modseq && record.modseq <= mailbox->i.highestmodseq)
            record.silentupdate = 1;

        r = sync_append_copyfile(mailbox, &record, annots, part_list);

        has_append = 1;
        sync_annot_list_free(&annots);

        if (r) goto bail;
    }

    r = mailbox_commit(mailbox);
    syslog(LOG_DEBUG, "%s: mailbox_commit %s: %s",
        __func__, mailbox_name(mailbox), error_message(r));
    if (r) {
        syslog(LOG_ERR, "%s: mailbox_commit(%s): %s",
               __func__, mailbox_name(mailbox), error_message(r));
    }

    if (!r && has_append)
        sync_log_append(mailbox_name(mailbox));

    mailbox_close(&mailbox);

    return r;

bail:
    mailbox_abort(mailbox);
    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

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
    case IMAP_MAILBOX_LOCKED:
        resp = "NO IMAP_MAILBOX_LOCKED Mailbox locked";
        break;
    case IMAP_MAILBOX_MOVED:
        resp = "NO IMAP_MAILBOX_MOVED Mailbox exists with another name or uniqueid";
        break;
    case IMAP_MAILBOX_NOTSUPPORTED:
        resp = "NO IMAP_MAILBOX_NOTSUPPORTED Operation is not supported on mailbox";
        break;
    case IMAP_SYNC_CHECKSUM:
        resp = "NO IMAP_SYNC_CHECKSUM Checksum Failure";
        break;
    case IMAP_SYNC_CHANGED:
        resp = "NO IMAP_SYNC_CHANGED Changed since last sync";
        break;
    case IMAP_SYNC_BADSIEVE:
        resp = "NO IMAP_SYNC_BADSIEVE Sieve script compilation failure";
        break;
    case IMAP_PROTOCOL_ERROR:
        resp = "NO IMAP_PROTOCOL_ERROR Protocol error";
        break;
    case IMAP_PROTOCOL_BAD_PARAMETERS:
        resp = "NO IMAP_PROTOCOL_BAD_PARAMETERS";
//      XXX resp = "NO IMAP_PROTOCOL_BAD_PARAMETERS near %s\r\n", dlist_lastkey());
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
                               uint32_t fromuid,
                               uint32_t touid,
                               struct sync_msgid_list *part_list)
{

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    mailbox_iter_startuid(iter, fromuid+1); /* only read new records */
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        sync_msgid_insert(part_list, &record->guid);
        if (record->uid >= touid) break;
    }
    mailbox_iter_done(&iter);

    return 0;
}

static int calculate_intermediate_state(struct mailbox *mailbox,
                                        modseq_t frommodseq,
                                        uint32_t fromuid,
                                        uint32_t batchsize,
                                        uint32_t *touidp,
                                        modseq_t *tomodseqp)
{
    modseq_t tomodseq = mailbox->i.highestmodseq;
    uint32_t touid = fromuid;
    uint32_t seen = 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    mailbox_iter_startuid(iter, fromuid+1); /* only read new records */
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (seen < batchsize) {
            touid = record->uid;
        }
        else if (record->modseq <= tomodseq)
            tomodseq = record->modseq - 1;
        seen++;
    }
    mailbox_iter_done(&iter);

    /* no need to batch if there are fewer than batchsize records */
    if (seen <= batchsize)
        return 0;

    /* must have found at least one record past the end to do a partial batch,
     * and we need a highestmodseq at least one less than that records so that
     * it can successfully sync */
    if (tomodseq > frommodseq && tomodseq < mailbox->i.highestmodseq) {
        *tomodseqp = tomodseq;
        *touidp = touid;
        return 1;
    }

    /* can't find an intermediate modseq */
    return 0;
}

static int find_reserve_all(struct sync_name_list *mboxname_list,
                            const char *topart,
                            struct sync_folder_list *master_folders,
                            struct sync_folder_list *replica_folders,
                            struct sync_reserve_list *reserve_list,
                            uint32_t batchsize)
{
    struct sync_name *mbox;
    struct sync_folder *rfolder;
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox = NULL;
    int r = 0;

    /* Find messages we want to upload that are available on server */
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
        mbentry_t *mbentry = NULL;

        if (mboxlist_lookup_allow_all(mbox->name, &mbentry, NULL))
            continue;

        if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            struct synccrcs synccrcs = {0, 0};
            sync_folder_list_add(master_folders, mbentry->uniqueid, mbentry->name,
                                 mbentry->mbtype,
                                 mbentry->partition, mbentry->acl, 0,
                                 mbentry->uidvalidity, 0,
                                 0, synccrcs,
                                 0, 0,
                                 0, 0,
                                 NULL, 0,
                                 0, mbentry->foldermodseq, 0);
            mboxlist_entry_free(&mbentry);
            continue;
        }

        mboxlist_entry_free(&mbentry);

        r = mailbox_open_irl(mbox->name, &mailbox);
        if (!r) r = sync_mailbox_version_check(&mailbox);

        /* Quietly skip over folders which have been deleted since we
           started working (but record fact in case caller cares) */
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            r = 0;
            continue;
        }

        if (r) {
            xsyslog(LOG_ERR, "IOERROR: mailbox open failed",
                             "mboxname=<%s> error=<%s>",
                             mbox->name, error_message(r));
            goto bail;
        }

        modseq_t xconvmodseq = 0;
        if (mailbox_has_conversations(mailbox)) {
            r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
            if (r) {
                xsyslog(LOG_ERR, "IOERROR: get xconvmodseq failed",
                                 "mboxname=<%s> error=<%s>",
                                 mbox->name, error_message(r));
                goto bail;
            }
        }
        modseq_t raclmodseq = mboxname_readraclmodseq(mbox->name);

        /* mailbox is open from here, no exiting without closing it! */

        rfolder = sync_folder_lookup(replica_folders, mailbox->uniqueid);
        uint32_t fromuid = rfolder ? rfolder->last_uid : 0;
        uint32_t touid = mailbox->i.last_uid;
        modseq_t tomodseq = mailbox->i.highestmodseq;
        int ispartial = 0;

        if (batchsize && touid - fromuid > batchsize) {
            /* see if we actually need to calculate an intermediate state */
            modseq_t frommodseq = rfolder ? rfolder->highestmodseq : 0;
            /* is there an intermediate modseq available and enough records to make a batch? */
            ispartial = calculate_intermediate_state(mailbox, frommodseq, fromuid,
                                                     batchsize, &touid, &tomodseq);
            if (ispartial) {
                syslog(LOG_DEBUG, "doing partial sync: %s (%u/%u/%u) (%llu/%llu/%llu)",
                       mailbox_name(mailbox), fromuid, touid, mailbox->i.last_uid,
                       frommodseq, tomodseq, mailbox->i.highestmodseq);
            }
        }

        sync_folder_list_add(master_folders, mailbox->uniqueid, mailbox_name(mailbox),
                             mailbox->mbtype,
                             mailbox->part, mailbox->acl, mailbox->i.options,
                             mailbox->i.uidvalidity, touid,
                             tomodseq, mailbox->i.synccrcs,
                             mailbox->i.recentuid, mailbox->i.recenttime,
                             mailbox->i.pop3_last_login,
                             mailbox->i.pop3_show_after, NULL, xconvmodseq,
                             raclmodseq, mailbox->foldermodseq, ispartial);


        part_list = sync_reserve_partlist(reserve_list, topart ? topart : mailbox->part);
        sync_find_reserve_messages(mailbox, fromuid, touid, part_list);
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
        xsyslog(LOG_ERR, "SYNCERROR: Illegal response to RESERVE",
                         "name=<%s>", kl->name);
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    /* unmark each missing item */
    for (ki = kl->head; ki; ki = ki->next) {
        if (!message_guid_decode(&tmp_guid, ki->sval)) {
            xsyslog(LOG_ERR, "SYNCERROR: reserve: failed to parse GUID",
                             "sval=<%s>", ki->sval);
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

int sync_reserve_partition(struct sync_client_state *sync_cs, char *partition,
                           struct sync_folder_list *replica_folders,
                           struct sync_msgid_list *part_list)
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

        sync_send_apply(kl, sync_cs->backend->out);

        r = sync_parse_response(cmd, sync_cs->backend->in, &kin);
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

static int reserve_messages(struct sync_client_state *sync_cs,
                            struct sync_name_list *mboxname_list,
                            const char *topart,
                            struct sync_folder_list *master_folders,
                            struct sync_folder_list *replica_folders,
                            struct sync_reserve_list *reserve_list,
                            uint32_t batchsize)
{
    struct sync_reserve *reserve;
    int r;

    r = find_reserve_all(mboxname_list, topart, master_folders,
                         replica_folders, reserve_list, batchsize);
    if (r) return r;

    for (reserve = reserve_list->head; reserve; reserve = reserve->next) {
        r = sync_reserve_partition(sync_cs, reserve->part,
                                   replica_folders, reserve->list);
        if (r) return r;
    }

    return 0;
}

static struct db *sync_getcachedb(struct sync_client_state *sync_cs)
{
    if (sync_cs->cachedb) return sync_cs->cachedb;

    const char *dbtype = config_getstring(IMAPOPT_SYNC_CACHE_DB);
    if (!dbtype) return NULL;

    const char *dbpath = sync_get_config(sync_cs->channel, "sync_cache_db_path");
    if (!dbpath) return NULL;

    int flags = CYRUSDB_CREATE;

    int r = cyrusdb_open(dbtype, dbpath, flags, &sync_cs->cachedb);
    if (r) {
        xsyslog(LOG_ERR, "DBERROR: failed to open sync cache db",
                         "dbpath=<%s> error=<%s>",
                         dbpath, cyrusdb_strerror(r));
    }

    return sync_cs->cachedb;
}

static int sync_readcache(struct sync_client_state *sync_cs, const char *mboxname,
                          struct dlist **klp)
{
    struct db *db = sync_getcachedb(sync_cs);
    if (!db) return 0;

    const char *base;
    size_t len;

    int r = cyrusdb_fetch(db, mboxname, strlen(mboxname), &base, &len, /*tid*/NULL);
    if (r) return r;


    dlist_parsemap(klp, 0, 0, base, len);

    // we need the name so the parser can parse it
    if (*klp) (*klp)->name = xstrdup("MAILBOX");

    return 0;
}

// NOTE: this is destructive of kl - it removes the RECORD section!
// this is always safe because of where we call it
static int sync_cache(struct sync_client_state *sync_cs, const char *mboxname,
                      struct dlist *kl)
{
    struct db *db = sync_getcachedb(sync_cs);
    if (!db) return 0;

    struct dlist *ritem = dlist_getchild(kl, "RECORD");
    if (ritem) {
        dlist_unstitch(kl, ritem);
        dlist_free(&ritem);
    }

    struct buf buf = BUF_INITIALIZER;
    dlist_printbuf(kl, 0, &buf);
    int r = cyrusdb_store(db, mboxname, strlen(mboxname),
                          buf_base(&buf), buf_len(&buf), /*tid*/NULL);
    buf_free(&buf);
    return r;
}

static void sync_uncache(struct sync_client_state *sync_cs, const char *mboxname)
{
    struct db *db = sync_getcachedb(sync_cs);
    if (!db) return;
    cyrusdb_delete(db, mboxname, strlen(mboxname), /*tid*/NULL, /*force*/1);
}

static int sync_kl_parse(struct dlist *kin,
                         struct sync_folder_list *folder_list,
                         struct sync_name_list *sub_list,
                         struct sync_sieve_list *sieve_list,
                         struct sync_seen_list *seen_list,
                         struct sync_quota_list *quota_list)
{
    struct dlist *kl;

    for (kl = kin->head; kl; kl = kl->next) {
        if (!strcmp(kl->name, "SIEVE")) {
            struct message_guid guid;
            const char *filename = NULL;
            const char *guidstr = NULL;
            time_t modtime = 0;
            uint32_t active = 0;
            if (!sieve_list) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "FILENAME", &filename)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getdate(kl, "LAST_UPDATE", &modtime)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            dlist_getatom(kl, "GUID", &guidstr); /* optional */
            if (guidstr) {
                if (!message_guid_decode(&guid, guidstr)) return IMAP_PROTOCOL_BAD_PARAMETERS;
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
            if (!quota_list) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "ROOT", &root)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            sq = sync_quota_list_add(quota_list, root);
            sync_decode_quota_limits(kl, sq->limits);
        }

        else if (!strcmp(kl->name, "LSUB")) {
            struct dlist *i;
            if (!sub_list) return IMAP_PROTOCOL_BAD_PARAMETERS;
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
            if (!seen_list) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getdate(kl, "LASTREAD", &lastread)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getnum32(kl, "LASTUID", &lastuid)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getdate(kl, "LASTCHANGE", &lastchange)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "SEENUIDS", &seenuids)) return IMAP_PROTOCOL_BAD_PARAMETERS;
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
            modseq_t raclmodseq = 0;
            modseq_t foldermodseq = 0;

            if (!folder_list) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "MBOXNAME", &mboxname)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "PARTITION", &part)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "ACL", &acl)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getatom(kl, "OPTIONS", &options)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getnum64(kl, "HIGHESTMODSEQ", &highestmodseq)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getnum32(kl, "UIDVALIDITY", &uidvalidity)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getnum32(kl, "LAST_UID", &last_uid)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getnum32(kl, "RECENTUID", &recentuid)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getdate(kl, "RECENTTIME", &recenttime)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            if (!dlist_getdate(kl, "POP3_LAST_LOGIN", &pop3_last_login)) return IMAP_PROTOCOL_BAD_PARAMETERS;
            /* optional */
            dlist_getdate(kl, "POP3_SHOW_AFTER", &pop3_show_after);
            dlist_getatom(kl, "MBOXTYPE", &mboxtype);
            dlist_getnum32(kl, "SYNC_CRC", &synccrcs.basic);
            dlist_getnum32(kl, "SYNC_CRC_ANNOT", &synccrcs.annot);
            dlist_getnum64(kl, "XCONVMODSEQ", &xconvmodseq);
            dlist_getnum64(kl, "RACLMODSEQ", &raclmodseq);
            dlist_getnum64(kl, "FOLDERMODSEQ", &foldermodseq);

            if (dlist_getlist(kl, "ANNOTATIONS", &al))
                decode_annotations(al, &annots, NULL, NULL);

            sync_folder_list_add(folder_list, uniqueid, mboxname,
                                 mboxlist_string_to_mbtype(mboxtype),
                                 part, acl,
                                 sync_parse_options(options),
                                 uidvalidity, last_uid,
                                 highestmodseq, synccrcs,
                                 recentuid, recenttime,
                                 pop3_last_login,
                                 pop3_show_after, annots,
                                 xconvmodseq, raclmodseq,
                                 foldermodseq, /*ispartial*/0);
        }

        else {
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        }
    }

    return 0;
}

int sync_response_parse(struct sync_client_state *sync_cs, const char *cmd,
                        struct sync_folder_list *folder_list,
                        struct sync_name_list *sub_list,
                        struct sync_sieve_list *sieve_list,
                        struct sync_seen_list *seen_list,
                        struct sync_quota_list *quota_list)
{
    struct dlist *kin = NULL;
    int r;

    r = sync_parse_response(cmd, sync_cs->backend->in, &kin);

    /* Unpleasant: translate remote access error into "please reset me" */
    if (r == IMAP_MAILBOX_NONEXISTENT)
        return 0;

    if (r) return r;

    r = sync_kl_parse(kin, folder_list, sub_list,
                      sieve_list, seen_list, quota_list);
    if (r)
        xsyslog(LOG_ERR, "SYNCERROR: invalid response",
                         "command=<%s> response=<%s>",
                         cmd, dlist_lastkey());
    else {
        // do we have mailboxes to cache?
        struct dlist *kl = NULL;
        for (kl = kin->head; kl; kl = kl->next) {
            if (strcmp(kl->name, "MAILBOX")) continue;
            const char *mboxname = NULL;
            if (!dlist_getatom(kl, "MBOXNAME", &mboxname)) continue;
            sync_cache(sync_cs, mboxname, kl);
        }
    }

    dlist_free(&kin);
    return r;
}

static int folder_rename(struct sync_client_state *sync_cs,
                         const char *oldname, const char *newname,
                         const char *partition, unsigned uidvalidity)
{
    const char *cmd = (sync_cs->flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_RENAME" : "RENAME";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s -> %s (%s)\n", cmd, oldname, newname, partition);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s -> %s (%s)", cmd, oldname, newname, partition);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "OLDMBOXNAME", oldname);
    dlist_setatom(kl, "NEWMBOXNAME", newname);
    dlist_setatom(kl, "PARTITION", partition);
    dlist_setnum32(kl, "UIDVALIDITY", uidvalidity);

    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    int r = sync_parse_response(cmd, sync_cs->backend->in, NULL);

    // this means that newname won't be cached, but we'll cache it next sync
    sync_uncache(sync_cs, oldname);

    return r;
}

int sync_do_folder_delete(struct sync_client_state *sync_cs, const char *mboxname)
{
    const char *cmd =
        (sync_cs->flags & SYNC_FLAG_LOCALONLY) ? "LOCAL_UNMAILBOX" :"UNMAILBOX";
    struct dlist *kl;
    int r;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s\n", cmd, mboxname);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s", cmd, mboxname);

    kl = dlist_setatom(NULL, cmd, mboxname);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_cs->backend->in, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT)
        r = 0;

    sync_uncache(sync_cs, mboxname);

    return r;
}

int sync_set_sub(struct sync_client_state *sync_cs,
                 const char *userid, const char *mboxname, int add)
{
    const char *cmd = add ? "SUB" : "UNSUB";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s %s\n", cmd, userid, mboxname);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s", cmd, userid, mboxname);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "MBOXNAME", mboxname);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

static int folder_setannotation(struct sync_client_state *sync_cs,
                                const char *mboxname, const char *entry,
                                const char *userid, const struct buf *value)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s %s %s\n", cmd, mboxname, entry, userid);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s %s", cmd, mboxname, entry, userid);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "MBOXNAME", mboxname);
    dlist_setatom(kl, "ENTRY", entry);
    dlist_setatom(kl, "USERID", userid);
    dlist_setmap(kl, "VALUE", value->s, value->len);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

static int folder_unannotation(struct sync_client_state *sync_cs,
                               const char *mboxname, const char *entry,
                               const char *userid)
{
    const char *cmd = "UNANNOTATION";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s %s %s\n", cmd, mboxname, entry, userid);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s %s", cmd, mboxname, entry, userid);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "MBOXNAME", mboxname);
    dlist_setatom(kl, "ENTRY", entry);
    dlist_setatom(kl, "USERID", userid);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

/* ====================================================================== */

static int sieve_upload(struct sync_client_state *sync_cs,
                        const char *userid, const char *filename,
                        unsigned long last_update)
{
    const char *cmd = "SIEVE";
    struct dlist *kl;
    char *sieve;
    uint32_t size;

    sieve = sync_sieve_read(userid, filename, &size);
    if (!sieve) return IMAP_IOERROR;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s %s\n", cmd, userid, filename);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s", cmd, userid, filename);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    dlist_setdate(kl, "LAST_UPDATE", last_update);
    dlist_setmap(kl, "CONTENT", sieve, size);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);
    free(sieve);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

static int sieve_delete(struct sync_client_state *sync_cs,
                        const char *userid, const char *filename)
{
    const char *cmd = "UNSIEVE";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s %s\n", cmd, userid, filename);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s", cmd, userid, filename);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

static int sieve_activate(struct sync_client_state *sync_cs,
                          const char *userid, const char *filename)
{
    const char *cmd = "ACTIVATE_SIEVE";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s %s\n", cmd, userid, filename);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s %s", cmd, userid, filename);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

static int sieve_deactivate(struct sync_client_state *sync_cs,
                            const char *userid)
{
    const char *cmd = "UNACTIVATE_SIEVE";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s\n", cmd, userid);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s", cmd, userid);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", userid);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

/* ====================================================================== */

static int delete_quota(struct sync_client_state *sync_cs, const char *root)
{
    const char *cmd = "UNQUOTA";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s\n", cmd, root);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s", cmd, root);

    kl = dlist_setatom(NULL, cmd, root);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

static int update_quota_work(struct sync_client_state *sync_cs,
                             struct quota *client,
                             struct sync_quota *server)
{
    const char *cmd = "QUOTA";
    struct dlist *kl;
    int r;

    r = quota_read(client, NULL, 0);

    /* disappeared?  Delete it*/
    if (r == IMAP_QUOTAROOT_NONEXISTENT)
        return delete_quota(sync_cs, client->root);

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

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("%s %s\n", cmd, client->root);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s", cmd, client->root);

    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "ROOT", client->root);
    sync_encode_quota_limits(kl, client->limits);
    dlist_setnum64(kl, "MODSEQ", client->modseq);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
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
        xsyslog(LOG_ERR, "IOERROR: couldn't find index record",
                         "uid=<%u>",
                         uid);
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
    oldrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;
    r = mailbox_rewrite_index_record(mailbox, &oldrecord);

    /* done - return */
    return r;
}

static int fetch_file(struct sync_client_state *sync_cs,
                      struct mailbox *mailbox, unsigned uid,
                      const struct index_record *rp,
                      struct sync_msgid_list *part_list)
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
    dlist_setatom(kl, "MBOXNAME", mailbox_name(mailbox));
    dlist_setatom(kl, "PARTITION", mailbox->part);
    dlist_setatom(kl, "UNIQUEID", mailbox->uniqueid);
    dlist_setguid(kl, "GUID", &rp->guid);
    dlist_setnum32(kl, "UID", uid);
    sync_send_lookup(kl, sync_cs->backend->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_cs->backend->in, &kin);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: parse response failed",
                         "error=<%s>",
                         error_message(r));
        return r;
    }

    if (!dlist_tofile(kin->head, NULL, &guid, (unsigned long *) &size, &fname)) {
        r = IMAP_MAILBOX_NONEXISTENT;
        xsyslog(LOG_ERR, "IOERROR: dlist_tofile failed",
                         "error=<%s>",
                         error_message(r));
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
        xsyslog(LOG_ERR, "IOERROR: GUID MISMATCH",
                         "error=<%s>",
                         error_message(r));
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
            xsyslog(LOG_ERR, "IOERROR: parse_upload failed",
                             "uid=<%u>",
                             uid);
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
    xsyslog(LOG_ERR, "IOERROR: couldn't find index record",
                     "uid=<%u>",
                     uid);
    return IMAP_MAILBOX_NONEXISTENT;
}

static int copyback_one_record(struct sync_client_state *sync_cs,
                               struct mailbox *mailbox,
                               struct index_record *rp,
                               const struct sync_annot_list *annots,
                               struct dlist *kaction,
                               struct sync_msgid_list *part_list)
{
    int r;

    /* don't want to copy back expunged records! */
    if (rp->internal_flags & FLAG_INTERNAL_EXPUNGED)
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
            r = fetch_file(sync_cs, mailbox, rp->uid, rp, part_list);
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
        r = fetch_file(sync_cs, mailbox, rp->uid, rp, part_list);
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
    if (mp->internal_flags & FLAG_INTERNAL_EXPUNGED)
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
    if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
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
          "last_updated:" TIME_T_FMT " internaldate:" TIME_T_FMT " flags:(%s) cid:" CONV_FMT,
           name, record->uid, record->modseq,
           record->last_updated, record->internaldate,
           make_flags(mailbox, record), record->cid);
}

static void log_mismatch(const char *reason, struct mailbox *mailbox,
                         struct index_record *mp,
                         struct index_record *rp)
{
    syslog(LOG_NOTICE, "SYNCNOTICE: record mismatch with replica: %s %s",
           mailbox_name(mailbox), reason);
    log_record("master", mailbox, mp);
    log_record("replica", mailbox, rp);
}

static int compare_one_record(struct sync_client_state *sync_cs,
                              struct mailbox *mailbox,
                              struct index_record *mp,
                              struct index_record *rp,
                              const struct sync_annot_list *mannots,
                              const struct sync_annot_list *rannots,
                              struct dlist *kaction,
                              struct sync_msgid_list *part_list)
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

    if ((mp->internal_flags & FLAG_INTERNAL_EXPUNGED) &&
        (rp->internal_flags & FLAG_INTERNAL_EXPUNGED))
        return 0;

    /* first of all, check that GUID matches.  If not, we have had a split
     * brain, so the messages both need to be fixed up to their new UIDs.
     * After this function succeeds, both the local and remote copies of this
     * current UID will be actually EXPUNGED, so the earlier return applies. */
    if (!message_guid_equal(&mp->guid, &rp->guid)) {
        char *mguid = xstrdup(message_guid_encode(&mp->guid));
        char *rguid = xstrdup(message_guid_encode(&rp->guid));
        xsyslog(LOG_ERR, "SYNCERROR: guid mismatch",
                         "mailbox=<%s> uid=<%u> rguid=<%s> mguid=<%s>",
                         mailbox_name(mailbox), mp->uid, rguid, mguid);
        free(rguid);
        free(mguid);
        /* we will need to renumber both ends to get in sync */

        /* ORDERING - always lower GUID first */
        if (message_guid_cmp(&mp->guid, &rp->guid) > 0) {
            r = copyback_one_record(sync_cs, mailbox, rp, rannots, kaction, part_list);
            if (!r) r = renumber_one_record(mp, kaction);
        }
        else {
            r = renumber_one_record(mp, kaction);
            if (!r) r = copyback_one_record(sync_cs, mailbox, rp, rannots, kaction, part_list);
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
    if (mp->system_flags != rp->system_flags)
        goto diff;
    if ((mp->internal_flags & FLAG_INTERNAL_EXPUNGED) !=
        (rp->internal_flags & FLAG_INTERNAL_EXPUNGED))
        goto diff;
    if (mp->cid != rp->cid)
        goto diff;
    if (mp->basecid != rp->basecid)
        goto diff;
    if (mp->savedate != rp->savedate)
        goto diff;
    if (mp->createdmodseq != rp->createdmodseq)
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
    if (mp->internal_flags & FLAG_INTERNAL_EXPUNGED) {
        /* if expunged, fall through - the rewrite will lift
         * the modseq to force the change to stick */
    }
    else if (rp->internal_flags & FLAG_INTERNAL_EXPUNGED) {
        /* mark expunged - rewrite will cause both sides to agree
         * again */
        mp->internal_flags |= FLAG_INTERNAL_EXPUNGED;
    }

    /* otherwise, is the replica "newer"?  Better grab those flags */
    else {
        if (rp->modseq > mp->modseq &&
            rp->last_updated >= mp->last_updated) {
            log_mismatch("more recent on replica", mailbox, mp, rp);
            /* then copy all the flag data over from the replica */
            mp->system_flags = rp->system_flags;
            mp->internal_flags &= ~FLAG_INTERNAL_EXPUNGED;
            mp->internal_flags |= rp->internal_flags & FLAG_INTERNAL_EXPUNGED;

            mp->cid = rp->cid;
            for (i = 0; i < MAX_USER_FLAGS/32; i++)
                mp->user_flags[i] = rp->user_flags[i];
        }
    }

    /* are we making changes yet? */
    if (!kaction) return 0;

    int hadsnoozed = 0;
    /* even expunged messages get annotations synced */
    r = apply_annotations(mailbox, mp, mannots, rannots, 0, &hadsnoozed);
    if (r) return r;

    if (hadsnoozed) mp->internal_flags |= FLAG_INTERNAL_SNOOZED;
    else mp->internal_flags &= ~FLAG_INTERNAL_SNOOZED;

    /* this will bump the modseq and force a resync either way :) */
    return mailbox_rewrite_index_record(mailbox, mp);
}

static int mailbox_update_loop(struct sync_client_state *sync_cs,
                               struct mailbox *mailbox,
                               struct dlist *ki,
                               uint32_t last_uid,
                               modseq_t highestmodseq,
                               struct dlist *kaction,
                               struct sync_msgid_list *part_list)
{
    struct index_record rrecord;
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int r;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    const message_t *msg = mailbox_iter_step(iter);
    const struct index_record *mrecord = msg ? msg_record(msg) : NULL;

    /* while there are more records on either master OR replica,
     * work out what to do with them */
    while (ki || msg) {

        sync_annot_list_free(&mannots);
        sync_annot_list_free(&rannots);

        /* most common case - both a master AND a replica record exist */
        if (ki && mrecord) {
            r = read_annotations(mailbox, mrecord, &mannots, 0, 0);
            if (r) goto out;
            r = parse_upload(ki, mailbox, &rrecord, &rannots);
            if (r) goto out;

            /* same UID - compare the records */
            if (rrecord.uid == mrecord->uid) {
                mailbox_read_basecid(mailbox, mrecord);
                r = compare_one_record(sync_cs, mailbox,
                                       (struct index_record *)mrecord, &rrecord,
                                       mannots, rannots,
                                       kaction, part_list);
                if (r) goto out;
                /* increment both */
                msg = mailbox_iter_step(iter);
                mrecord = msg ? msg_record(msg) : NULL;
                ki = ki->next;
            }
            else if (rrecord.uid > mrecord->uid) {
                /* record only exists on the master */
                if (!(mrecord->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                    xsyslog(LOG_ERR, "SYNCNOTICE: record only exists on master",
                                     "mailbox=<%s> uid=<%u> guid=<%s>",
                                     mailbox_name(mailbox), mrecord->uid,
                                     message_guid_encode(&mrecord->guid));
                    r = renumber_one_record(mrecord, kaction);
                    if (r) goto out;
                }
                /* only increment master */
                msg = mailbox_iter_step(iter);
                mrecord = msg ? msg_record(msg) : NULL;
            }
            else {
                /* record only exists on the replica */
                if (!(rrecord.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                    if (kaction)
                        xsyslog(LOG_ERR, "SYNCNOTICE: record only exists on replica",
                                         "mailbox=<%s> uid=<%u> guid=<%s>",
                                         mailbox_name(mailbox), rrecord.uid,
                                         message_guid_encode(&rrecord.guid));
                    r = copyback_one_record(sync_cs, mailbox, &rrecord, rannots, kaction, part_list);
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
                    xsyslog(LOG_NOTICE, "SYNCNOTICE: bumping modseq",
                                        "mailbox=<%s> record=<%u>",
                                        mailbox_name(mailbox), mrecord->uid);
                    r = mailbox_rewrite_index_record(mailbox, (struct index_record *)mrecord);
                    if (r) goto out;
                }
            }
            msg = mailbox_iter_step(iter);
            mrecord = msg ? msg_record(msg) : NULL;
        }

        /* record only exists on the replica */
        else {
            r = parse_upload(ki, mailbox, &rrecord, &rannots);
            if (r) goto out;

            if (kaction)
                xsyslog(LOG_NOTICE, "SYNCNOTICE: record only exists on replica",
                                    "mailbox=<%s> uid=<%u>",
                                    mailbox_name(mailbox), rrecord.uid);

            /* going to need this one */
            r = copyback_one_record(sync_cs, mailbox, &rrecord, rannots, kaction, part_list);
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

static int mailbox_full_update(struct sync_client_state *sync_cs,
                               struct sync_folder *local,
                               struct sync_reserve_list *reserve_list,
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
    modseq_t foldermodseq = 0;
    uint32_t uidvalidity;
    uint32_t last_uid;
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int remote_modseq_was_higher = 0;
    modseq_t xconvmodseq = 0;
    struct sync_msgid_list *part_list;
    annotate_state_t *astate = NULL;

    if (flags & SYNC_FLAG_VERBOSE)
        printf("%s %s\n", cmd, local->name);

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s", cmd, local->name);

    kl = dlist_setatom(NULL, cmd, local->name);
    sync_send_lookup(kl, sync_cs->backend->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_cs->backend->in, &kin);
    if (r) return r;

    // we know the remote state, so cache it
    r = sync_cache(sync_cs, local->name, kin);
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
    dlist_getnum64(kl, "FOLDERMODSEQ", &foldermodseq);

    /* we'll be updating it! */
    if (local->mailbox) {
        mailbox = local->mailbox;
    }
    else {
        r = mailbox_open_iwl(local->name, &mailbox);
        if (!r) r = sync_mailbox_version_check(&mailbox);
    }
    if (r) goto done;

    part_list = sync_reserve_partlist(reserve_list, mailbox->part);

    /* if local UIDVALIDITY is lower, copy from remote, otherwise
     * remote will copy ours when we sync */
    if (mailbox->i.uidvalidity < uidvalidity) {
        xsyslog(LOG_NOTICE, "SYNCNOTICE: uidvalidity higher on replica, updating",
                            "mailbox=<%s> olduidvalidity=<%u> newuidvalidity=<%u>",
                            mailbox_name(mailbox), mailbox->i.uidvalidity, uidvalidity);
        mailbox_index_dirty(mailbox);
        mailbox->i.uidvalidity = mboxname_setuidvalidity(mailbox_name(mailbox), uidvalidity);
    }

    if (mailbox->i.highestmodseq < highestmodseq) {
        /* highestmodseq on replica is dirty - we must copy and then dirty
         * so we go one higher! */
        xsyslog(LOG_NOTICE, "SYNCNOTICE: highestmodseq higher on replica, updating",
                            "mailbox=<%s> oldhighestmodseq=<" MODSEQ_FMT ">"
                                " newhighestmodseq=<" MODSEQ_FMT ">",
                            mailbox_name(mailbox), mailbox->i.highestmodseq, highestmodseq+1);
        mailbox->modseq_dirty = 0;
        mailbox->i.highestmodseq = highestmodseq;
        mailbox_modseq_dirty(mailbox);
        remote_modseq_was_higher = 1;
    }

    /* hold the annotate state open */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    if (r) goto done;

    annotate_state_begin(astate);

    r = mailbox_update_loop(sync_cs, mailbox, kr->head, last_uid,
                            highestmodseq, NULL, part_list);
    if (r) {
        xsyslog(LOG_ERR, "SYNCNOTICE: failed to prepare update",
                         "mailbox=<%s> error=<%s>",
                         mailbox_name(mailbox), error_message(r));
        goto done;
    }

    /* OK - now we're committed to make changes! */

    /* this is safe because "larger than" logic is embedded
     * inside update_xconvmodseq */
    if (mailbox_has_conversations(mailbox)) {
        r = mailbox_update_xconvmodseq(mailbox, xconvmodseq, /* force */0);
        if (r) goto done;
    }

    if (foldermodseq) {
        // by writing the same ACL with the updated foldermodseq, this will bounce it
        // if needed
        r = mboxlist_sync_setacls(mailbox_name(mailbox), mailbox->acl, foldermodseq);
        if (r) goto done;
    }

    kaction = dlist_newlist(NULL, "ACTION");
    r = mailbox_update_loop(sync_cs, mailbox, kr->head, last_uid,
                            highestmodseq, kaction, part_list);
    if (r) goto cleanup;

    /* if replica still has a higher last_uid, bump our local
     * number to match so future records don't clash */
    if (mailbox->i.last_uid < last_uid) {
        mailbox_index_dirty(mailbox);
        mailbox->i.last_uid = last_uid;
    }

    /* ugly variable reuse */
    dlist_getlist(kl, "ANNOTATIONS", &ka);

    if (ka) decode_annotations(ka, &rannots, mailbox, NULL);
    r = read_annotations(mailbox, NULL, &mannots, 0, 0);
    if (r) goto cleanup;
    r = apply_annotations(mailbox, NULL, mannots, rannots,
                          !remote_modseq_was_higher, NULL);
    if (r) goto cleanup;

    /* blatant reuse 'r' us */
    kexpunge = dlist_newkvlist(NULL, "EXPUNGE");
    dlist_setatom(kexpunge, "MBOXNAME", mailbox_name(mailbox));
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
        sync_send_apply(kexpunge, sync_cs->backend->out);
        r2 = sync_parse_response("EXPUNGE", sync_cs->backend->in, NULL);
        if (r2) {
            xsyslog(LOG_ERR, "SYNCERROR: failed to expunge in cleanup",
                             "name=<%s>",
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
    if (remote->mbtype != mbtypes_sync(mailbox->mbtype)) return 0;
    if (remote->last_uid != mailbox->i.last_uid) return 0;
    if (remote->highestmodseq != mailbox->i.highestmodseq) return 0;
    if (remote->uidvalidity != mailbox->i.uidvalidity) return 0;
    if (remote->recentuid != mailbox->i.recentuid) return 0;
    if (remote->recenttime != mailbox->i.recenttime) return 0;
    if (remote->pop3_last_login != mailbox->i.pop3_last_login) return 0;
    if (remote->pop3_show_after != mailbox->i.pop3_show_after) return 0;
    if (remote->options != options) return 0;
    if (remote->foldermodseq && remote->foldermodseq != mailbox->foldermodseq) return 0;
    if (strcmp(remote->acl, mailbox->acl)) return 0;

    if (config_getswitch(IMAPOPT_REVERSEACLS)) {
        modseq_t raclmodseq = mboxname_readraclmodseq(mailbox_name(mailbox));
        // don't bail if either are zero, that could be version skew
        if (raclmodseq && remote->raclmodseq && remote->raclmodseq != raclmodseq) return 0;
    }

    if (mailbox_has_conversations(mailbox)) {
        int r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
        if (r) return 0;

        if (remote->xconvmodseq != xconvmodseq) return 0;
    }

    /* compare annotations */
    {
        struct sync_annot_list *mannots = NULL;
        int r = read_annotations(mailbox, NULL, &mannots, 0, 0);
        if (r) return 0;

        if (diff_annotations(mannots, remote->annots)) {
            sync_annot_list_free(&mannots);
            return 0;
        }
        sync_annot_list_free(&mannots);
    }

    /* if we got here then we should force check the CRCs */
    if (!mailbox_crceq(remote->synccrcs, mailbox_synccrcs(mailbox, /*force*/0)))
        if (!mailbox_crceq(remote->synccrcs, mailbox_synccrcs(mailbox, /*force*/1)))
            return 0;

    /* otherwise it's unchanged! */
    return 1;
}

/* XXX kind of nasty having this here, but i think it probably
 * shouldn't be in .h with the rest of them */
#define SYNC_FLAG_ISREPEAT      (1<<15)
#define SYNC_FLAG_FULLANNOTS    (1<<16)

static int update_mailbox_once(struct sync_client_state *sync_cs,
                               struct sync_folder *local,
                               struct sync_folder *remote,
                               const char *topart,
                               struct sync_reserve_list *reserve_list,
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
    struct sync_folder_list *myremotes = NULL;

    if (flags & SYNC_FLAG_ISREPEAT) {
        // we have to fetch the sync_folder again!
        myremotes = sync_folder_list_create();
        struct dlist *mbkl = dlist_newlist(NULL, "MAILBOXES");
        dlist_setatom(mbkl, "MBOXNAME", local->name);
        if (flags & SYNC_FLAG_VERBOSE)
            printf("MAILBOXES %s\n", local->name);
        sync_send_lookup(mbkl, sync_cs->backend->out);
        dlist_free(&mbkl);
        r = sync_response_parse(sync_cs, "MAILBOXES", myremotes,
                                NULL, NULL, NULL, NULL);
        if (r) goto done;
        remote = myremotes->head;
    }

    if (local->mailbox) {
        mailbox = local->mailbox;
    }
    else {
        r = mailbox_open_iwl(local->name, &mailbox);
        if (!r) r = sync_mailbox_version_check(&mailbox);
    }

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* been deleted in the meanwhile... it will get picked up by the
         * delete call later */
        r = 0;
        goto done;
    }
    else if (r)
        goto done;

    if (!topart) topart = mailbox->part;

    /* hold the annotate state open */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    if (r) goto done;

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
    }

    /* if local UIDVALIDITY is lower, copy from remote, otherwise
     * remote will copy ours when we sync */
    if (remote && mailbox->i.uidvalidity < remote->uidvalidity) {
        xsyslog(LOG_NOTICE, "SYNCNOTICE: uidvalidity higher on replica, updating",
                            "mailbox=<%s> olduidvalidity=<%u> newuidvalidity=<%u>",
                            mailbox_name(mailbox), mailbox->i.uidvalidity, remote->uidvalidity);
        mailbox_index_dirty(mailbox);
        mailbox->i.uidvalidity = mboxname_setuidvalidity(mailbox_name(mailbox), remote->uidvalidity);
    }

    /* make sure CRC is updated if we're retrying */
    if (flags & SYNC_FLAG_ISREPEAT) {
        r = mailbox_index_recalc(mailbox);
        if (r) goto done;
    }

    /* bump the raclmodseq if it's higher on the replica */
    if (remote && remote->raclmodseq) {
        mboxname_setraclmodseq(mailbox_name(mailbox), remote->raclmodseq);
    }

    /* bump the foldermodseq if it's higher on the replica */
    if (remote && remote->foldermodseq > mailbox->foldermodseq) {
        mboxlist_sync_setacls(mailbox_name(mailbox), mailbox->acl, remote->foldermodseq);
        mailbox->foldermodseq = remote->foldermodseq;
    }

    /* nothing changed - nothing to send */
    if (is_unchanged(mailbox, remote))
        goto done;

    if (!topart) topart = mailbox->part;
    part_list = sync_reserve_partlist(reserve_list, topart);
    r = sync_prepare_dlists(mailbox, local, remote, topart, part_list, kl,
                            kupload, 1, /*XXX flags & SYNC_FLAG_FULLANNOTS*/1, !(flags & SYNC_FLAG_ISREPEAT));
    if (r) goto done;

    /* keep the mailbox locked for shorter time! Unlock the index now
     * but don't close it, because we need to guarantee that message
     * files don't get deleted until we're finished with them... */
    if (!local->mailbox) mailbox_unlock_index(mailbox, NULL);

    if (flags & SYNC_FLAG_VERBOSE)
        printf("%s %s\n", cmd, local->name);

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "%s %s", cmd, local->name);

    /* upload in small(ish) blocks to avoid timeouts */
    while (kupload->head) {
        struct dlist *kul1 = dlist_splice(kupload, 1024);
        sync_send_apply(kul1, sync_cs->backend->out);
        r = sync_parse_response("MESSAGE", sync_cs->backend->in, NULL);
        dlist_free(&kul1);
        if (r) goto done; /* abort earlier */
    }

    /* close before sending the apply - all data is already read */
    if (!local->mailbox) mailbox_close(&mailbox);

    /* update the mailbox */
    sync_send_apply(kl, sync_cs->backend->out);
    r = sync_parse_response("MAILBOX", sync_cs->backend->in, NULL);

    // if we succeeded, cache!
    if (!r) r = sync_cache(sync_cs, local->name, kl);

done:
    if (mailbox && !local->mailbox) mailbox_close(&mailbox);

    // any error, nuke our remote cache.
    if (r) sync_uncache(sync_cs, local->name);

    sync_folder_list_free(&myremotes);
    dlist_free(&kupload);
    dlist_free(&kl);
    return r;
}

int sync_do_update_mailbox(struct sync_client_state *sync_cs,
                        struct sync_folder *local,
                        struct sync_folder *remote,
                        const char *topart,
                        struct sync_reserve_list *reserve_list)
{
    mbentry_t *mbentry = NULL;

    // it should exist!  Guess we lost a race, force it to retry
    int r = mboxlist_lookup_allow_all(local->name, &mbentry, NULL);
    if (r) return r;

    if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
        struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");

        dlist_setatom(kl, "UNIQUEID", mbentry->uniqueid);
        dlist_setatom(kl, "MBOXNAME", mbentry->name);
        dlist_setatom(kl, "MBOXTYPE",
                      mboxlist_mbtype_to_string(mbtypes_sync(mbentry->mbtype)));
        dlist_setnum64(kl, "HIGHESTMODSEQ", mbentry->foldermodseq);
        dlist_setnum64(kl, "CREATEDMODSEQ", mbentry->createdmodseq);
        dlist_setnum64(kl, "FOLDERMODSEQ", mbentry->foldermodseq);

        sync_send_apply(kl, sync_cs->backend->out);
        r = sync_parse_response("MAILBOX", sync_cs->backend->in, NULL);

        // on error, clear cache - otherwise cache this state
        if (r) sync_uncache(sync_cs, mbentry->name);
        else r = sync_cache(sync_cs, mbentry->name, kl);

        dlist_free(&kl);
        mboxlist_entry_free(&mbentry);

        return 0;
    }

    mboxlist_entry_free(&mbentry);

    int flags = sync_cs->flags;
    r = update_mailbox_once(sync_cs, local, remote, topart, reserve_list, flags);

    flags |= SYNC_FLAG_ISREPEAT;

    if (r == IMAP_SYNC_CHECKSUM) {
        syslog(LOG_NOTICE, "SYNC_NOTICE: CRC failure on sync %s, recalculating counts and trying again", local->name);
        r = update_mailbox_once(sync_cs, local, remote, topart, reserve_list, flags);
    }

    /* never retry - other end should always sync cleanly */
    if (flags & SYNC_FLAG_NO_COPYBACK) return r;

    if (r == IMAP_AGAIN) {
        local->ispartial = 0; /* don't batch the re-update, means sync to 2.4 will still work after fullsync */
        r = mailbox_full_update(sync_cs, local, reserve_list, flags);
        if (!r) r = update_mailbox_once(sync_cs, local, remote, topart,
                                        reserve_list, flags);
    }
    else if (r == IMAP_SYNC_CHECKSUM) {
        syslog(LOG_ERR, "CRC failure on sync for %s, trying full update",
               local->name);
        r = mailbox_full_update(sync_cs, local, reserve_list, flags);
        if (!r) r = update_mailbox_once(sync_cs, local, remote, topart,
                                        reserve_list, flags|SYNC_FLAG_FULLANNOTS);
    }

    return r;
}

/* ====================================================================== */

static int update_seen_work(struct sync_client_state *sync_cs,
                            const char *user, const char *uniqueid,
                            struct seendata *sd)
{
    const char *cmd = "SEEN";
    struct dlist *kl;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("SEEN %s %s\n", user, uniqueid);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "SEEN %s %s", user, uniqueid);

    /* Update seen list */
    kl = dlist_newkvlist(NULL, cmd);
    dlist_setatom(kl, "USERID", user);
    dlist_setatom(kl, "UNIQUEID", uniqueid);
    dlist_setdate(kl, "LASTREAD", sd->lastread);
    dlist_setnum32(kl, "LASTUID", sd->lastuid);
    dlist_setdate(kl, "LASTCHANGE", sd->lastchange);
    dlist_setatom(kl, "SEENUIDS", sd->seenuids);
    sync_send_apply(kl, sync_cs->backend->out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_cs->backend->in, NULL);
}

int sync_do_seen(struct sync_client_state *sync_cs,
                 const char *userid, char *uniqueid)
{
    int r = 0;
    struct seen *seendb = NULL;
    struct seendata sd = SEENDATA_INITIALIZER;

    /* ignore read failures */
    r = seen_open(userid, SEEN_SILENT, &seendb);
    if (r) return 0;

    // XXX: we should pipe the channel through to here
    struct mboxlock *synclock = sync_lock(sync_cs, userid);
    if (!synclock) {
        r = IMAP_MAILBOX_LOCKED;
        goto done;
    }

    r = seen_read(seendb, uniqueid, &sd);

    if (!r) r = update_seen_work(sync_cs, userid, uniqueid, &sd);

done:

    seen_close(&seendb);
    seen_freedata(&sd);
    mboxname_release(&synclock);

    return r;
}

/* ====================================================================== */

int sync_do_quota(struct sync_client_state *sync_cs,
                  const char *root)
{
    int r = 0;

    char *userid = mboxname_to_userid(root);
    struct mboxlock *synclock = sync_lock(sync_cs, userid);
    if (!synclock) {
        r = IMAP_MAILBOX_LOCKED;
        goto done;
    }

    struct quota q;
    quota_init(&q, root);
    r = update_quota_work(sync_cs, &q, NULL);
    quota_free(&q);

done:

    mboxname_release(&synclock);
    free(userid);

    return r;
}

static int do_annotation_cb(const char *mailbox __attribute__((unused)),
                            uint32_t uid __attribute__((unused)),
                            const char *entry, const char *userid,
                            const struct buf *value,
                            const struct annotate_metadata *mdata,
                            void *rock)
{
    struct sync_annot_list *l = (struct sync_annot_list *) rock;

    sync_annot_list_add(l, entry, userid, value, mdata->modseq);

    return 0;
}

static int parse_annotation(struct dlist *kin,
                            struct sync_annot_list *replica_annot)
{
    struct dlist *kl;
    const char *entry;
    const char *userid = "";
    const char *valmap = NULL;
    size_t vallen = 0;
    struct buf value = BUF_INITIALIZER;
    modseq_t modseq = 0;

    for (kl = kin->head; kl; kl = kl->next) {
        if (!dlist_getatom(kl, "ENTRY", &entry))
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        if (!dlist_getmap(kl, "VALUE", &valmap, &vallen))
            return IMAP_PROTOCOL_BAD_PARAMETERS;

        dlist_getatom(kl, "USERID", &userid); /* optional */
        dlist_getnum64(kl, "MODSEQ", &modseq); /* optional */

        buf_init_ro(&value, valmap, vallen);
        sync_annot_list_add(replica_annot, entry, userid, &value, modseq);
        buf_free(&value);
    }

    return 0;
}

static int do_getannotation(struct sync_client_state *sync_cs, const char *mboxname,
                            struct sync_annot_list *replica_annot)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;
    struct dlist *kin = NULL;
    int r;

    /* Update seen list */
    kl = dlist_setatom(NULL, cmd, mboxname);
    sync_send_lookup(kl, sync_cs->backend->out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_cs->backend->in, &kin);
    if (r) return r;

    r = parse_annotation(kin, replica_annot);
    dlist_free(&kin);

    return r;
}

int sync_do_annotation(struct sync_client_state *sync_cs, const char *mboxname)
{
    int r;
    struct sync_annot_list *replica_annot = sync_annot_list_create();
    struct sync_annot_list *master_annot = sync_annot_list_create();
    struct sync_annot *ma, *ra;
    int n;

    char *userid = mboxname_to_userid(mboxname);
    // XXX: we should pipe the channel through to here
    struct mboxlock *synclock = sync_lock(sync_cs, userid);
    if (!synclock) {
        r = IMAP_MAILBOX_LOCKED;
        goto bail;
    }

    r = do_getannotation(sync_cs, mboxname, replica_annot);
    if (r) goto bail;

    r = annotatemore_findall(mboxname, 0, "*", /*modseq*/0, &do_annotation_cb,
                             master_annot, /*flags*/0);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: fetching annotations failed",
                         "mboxname=<%s>", mboxname);
        r = IMAP_IOERROR;
        goto bail;
    }

    /* both lists are sorted, so we work our way through the lists
       top-to-bottom and determine what we need to do based on order */
    ma = master_annot->head;
    ra = replica_annot->head;
    while (ma || ra) {
        if (!ra) n = -1;                /* add all master annotations */
        else if (!ma) n = 1;            /* remove all replica annotations */
        else if ((n = strcmp(ma->entry, ra->entry)) == 0)
            n = strcmp(ma->userid, ra->userid);

        if (n > 0) {
            /* remove replica annotation */
            r = folder_unannotation(sync_cs, mboxname, ra->entry, ra->userid);
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
        r = folder_setannotation(sync_cs, mboxname, ma->entry, ma->userid, &ma->value);
        if (r) goto bail;

        ma = ma->next;
    }

bail:
    sync_annot_list_free(&master_annot);
    sync_annot_list_free(&replica_annot);
    mboxname_release(&synclock);
    free(userid);
    return r;
}

/* ====================================================================== */

static int do_folders(struct sync_client_state *sync_cs,
                      struct sync_name_list *mboxname_list, const char *topart,
                      struct sync_folder_list *replica_folders,
                      int flags)
{
    int r = 0;
    struct sync_folder_list *master_folders;
    struct sync_rename_list *rename_folders;
    struct sync_reserve_list *reserve_list;
    struct sync_folder *mfolder, *rfolder;
    const char *part;
    uint32_t batchsize = 0;

    if (flags & SYNC_FLAG_BATCH) {
        batchsize = config_getint(IMAPOPT_SYNC_BATCHSIZE);
    }

    master_folders = sync_folder_list_create();
    rename_folders = sync_rename_list_create();
    reserve_list = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    r = reserve_messages(sync_cs, mboxname_list, topart, master_folders,
                         replica_folders, reserve_list, batchsize);
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
        part = topart ? topart : mfolder->part;
        if (strcmp(mfolder->name, rfolder->name) || (rfolder->part && strcmpsafe(part, rfolder->part))) {
            sync_rename_list_add(rename_folders, mfolder->uniqueid, rfolder->name,
                                 mfolder->name, part, mfolder->uidvalidity);
        }
    }

    /* XXX - sync_log_channel_user on any issue here rather than trying to solve,
     * and remove all entries related to that user from both lists */

    /* Delete folders on server which no longer exist on client */
    if (flags & SYNC_FLAG_DELETE_REMOTE) {
        for (rfolder = replica_folders->head; rfolder; rfolder = rfolder->next) {
            if (rfolder->mark) continue;

            mbentry_t *tombstone = NULL;
            r = mboxlist_lookup_allow_all(rfolder->name, &tombstone, NULL);

            if (r == 0 && (tombstone->mbtype & MBTYPE_DELETED) == MBTYPE_DELETED) {
                r = sync_do_folder_delete(sync_cs, rfolder->name);
                if (r) {
                    syslog(LOG_ERR, "sync_do_folder_delete(): failed: %s '%s'",
                                    rfolder->name, error_message(r));
                    goto bail;
                }
            }
            else {
                syslog(LOG_ERR, "%s: no tombstone for deleted mailbox %s (%s)",
                                __func__, rfolder->name, error_message(r));

                /* XXX copy the missing local mailbox back from the replica? */
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
            r = folder_rename(sync_cs, item->oldname, item->newname, item->part,
                              item->uidvalidity);
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

    /* if we renamed anything, we want to resync the mailbox list before doing the
     * mailbox contents */
    if (rename_folders->count) {
        syslog(LOG_DEBUG,
               "do_folders(): did some renames, so retrying");
        r = IMAP_AGAIN;
        goto bail;
    }

    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
        if (mfolder->mark) continue;
        /* NOTE: rfolder->name may now be wrong, but we're guaranteed that
         * it was successfully renamed above, so just use mfolder->name for
         * all commands */
        rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
        r = sync_do_update_mailbox(sync_cs, mfolder, rfolder, topart, reserve_list);
        if (r) {
            syslog(LOG_ERR, "do_folders(): update failed: %s '%s'",
                   mfolder->name, error_message(r));
            goto bail;
        }
        if (sync_cs->channel && mfolder->ispartial) {
            sync_log_channel_mailbox(sync_cs->channel, mfolder->name);
        }
    }

 bail:
    sync_folder_list_free(&master_folders);
    sync_rename_list_free(&rename_folders);
    sync_reserve_list_free(&reserve_list);
    return r;
}

int sync_do_mailboxes(struct sync_client_state *sync_cs,
                      struct sync_name_list *mboxname_list,
                      const char *topart, int flags)

{
    struct sync_name *mbox;
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct buf buf = BUF_INITIALIZER;
    int r;
    strarray_t userids = STRARRAY_INITIALIZER;
    ptrarray_t locks = PTRARRAY_INITIALIZER;

    // what a pain, we need to lock all the users in order, so..
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
        char *userid = mboxname_to_userid(mbox->name);
        strarray_add(&userids, userid ? userid : "");
        free(userid);
    }
    strarray_sort(&userids, cmpstringp_raw);

    int i;
    for (i = 0; i < strarray_size(&userids); i++) {
        const char *userid = strarray_nth(&userids, i);
        struct mboxlock *lock = sync_lock(sync_cs, userid);
        if (!lock) {
            r = IMAP_MAILBOX_LOCKED;
            goto done;
        }
        ptrarray_append(&locks, lock);
    }

    int tries = 0;

redo:
    tries++;
    if (tries > 3) {
        syslog(LOG_ERR, "failed to settle renames after 3 tries!");
        r = IMAP_SYNC_CHANGED;
        goto done;
    }

    struct dlist *kl = NULL;
    struct dlist *cachel = NULL;

    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
        struct dlist *cl = NULL;
        // check if it's in the cache, then we don't need to look it up
        if (!sync_readcache(sync_cs, mbox->name, &cl) && cl) {
            if (!cachel) cachel = dlist_newlist(NULL, "MAILBOXES");
            dlist_stitch(cachel, cl);
            if ((flags & SYNC_FLAG_VERBOSE) || (flags & SYNC_FLAG_LOGGING))
                buf_printf(&buf, " (%s)", mbox->name);
        }
        // if it's not in the cache, then we need to ask for it
        else {
            if (!kl) kl = dlist_newlist(NULL, "MAILBOXES");
            dlist_setatom(kl, "MBOXNAME", mbox->name);
            if ((flags & SYNC_FLAG_VERBOSE) || (flags & SYNC_FLAG_LOGGING))
                buf_printf(&buf, " %s", mbox->name);
        }
    }

    if (flags & SYNC_FLAG_VERBOSE)
        printf("MAILBOXES%s\n", buf_cstring(&buf));

    if (flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "MAILBOXES%s", buf_cstring(&buf));

    buf_free(&buf);

    if (kl) {
        sync_send_lookup(kl, sync_cs->backend->out);
        dlist_free(&kl);
        r = sync_response_parse(sync_cs, "MAILBOXES", replica_folders,
                                NULL, NULL, NULL, NULL);
        if (r) goto done;
    }

    if (cachel) {
        r = sync_kl_parse(cachel, replica_folders, NULL, NULL, NULL, NULL);
        dlist_free(&cachel);
        if (r) goto done;
    }

    /* we don't want to delete remote folders which weren't found locally,
     * because we may be racing with a rename, and we don't want to lose
     * the remote files.  A real delete will always have inserted a
     * UNMAILBOX anyway */
    flags &= ~SYNC_FLAG_DELETE_REMOTE;
    r = do_folders(sync_cs, mboxname_list, topart, replica_folders, flags);

    if (r == IMAP_AGAIN) {
        sync_folder_list_free(&replica_folders);
        replica_folders = sync_folder_list_create();
        goto redo;
    }

done:

    sync_folder_list_free(&replica_folders);
    strarray_fini(&userids);
    for (i = 0; i < ptrarray_size(&locks); i++) {
        struct mboxlock *lock = ptrarray_nth(&locks, i);
        mboxname_release(&lock);
    }
    ptrarray_fini(&locks);

    return r;
}

/* ====================================================================== */

struct mboxinfo {
    struct sync_name_list *mboxlist;
    struct sync_name_list *quotalist;
};

static int do_mailbox_info(const mbentry_t *mbentry, void *rock)
{
    struct mailbox *mailbox = NULL;
    struct mboxinfo *info = (struct mboxinfo *)rock;
    int r = 0;

    /* XXX - check for deleted? */

    if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
        sync_name_list_add(info->mboxlist, mbentry->name);
        return 0;
    }

    r = mailbox_open_irl(mbentry->name, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
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
        sync_name_list_add(info->quotalist, mailbox->quotaroot);
    }

    sync_name_list_add(info->mboxlist, mbentry->name);

done:
    mailbox_close(&mailbox);
    return r;
}

int sync_do_user_quota(struct sync_client_state *sync_cs,
                       struct sync_name_list *master_quotaroots,
                       struct sync_quota_list *replica_quota)
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
        r = update_quota_work(sync_cs, &q, rquota);
        quota_free(&q);
        if (r) return r;
    }

    /* delete any quotas no longer on the master */
    for (rquota = replica_quota->head; rquota; rquota = rquota->next) {
        if (rquota->done) continue;
        r = delete_quota(sync_cs, rquota->root);
        if (r) return r;
    }

    return 0;
}

static int do_user_main(struct sync_client_state *sync_cs,
                        const char *userid, const char *topart,
                        struct sync_folder_list *replica_folders,
                        struct sync_quota_list *replica_quota)
{
    int r = 0;
    struct mboxinfo info;

    info.mboxlist = sync_name_list_create();
    info.quotalist = sync_name_list_create();

    r = mboxlist_usermboxtree(userid, NULL, do_mailbox_info, &info, MBOXTREE_DELETED);

    /* we know all the folders present on the master, so it's safe to delete
     * anything not mentioned here on the replica - at least until we get
     * real tombstones */
    int flags = sync_cs->flags;
    flags |= SYNC_FLAG_DELETE_REMOTE;
    if (!r) r = do_folders(sync_cs, info.mboxlist, topart, replica_folders, flags);
    if (!r) r = sync_do_user_quota(sync_cs, info.quotalist, replica_quota);

    sync_name_list_free(&info.mboxlist);
    sync_name_list_free(&info.quotalist);

    if (r && r != IMAP_AGAIN) {
        xsyslog(LOG_ERR, "IOERROR: user replication failed",
                         "error=<%s> userid=<%s> channel=<%s> servername=<%s>",
                         error_message(r), userid,
                         sync_cs->channel, sync_cs->servername);
    }

    return r;
}

int sync_do_user_sub(struct sync_client_state *sync_cs, const char *userid,
                     struct sync_name_list *replica_subs)
{
    struct sync_name *rsubs;
    int r = 0;
    int i;

    /* Includes subsidiary nodes automatically */
    strarray_t *msubs = mboxlist_sublist(userid);
    if (!msubs) {
        xsyslog(LOG_ERR, "IOERROR: fetching subscriptions failed",
                         "userid=<%s>", userid);
        r = IMAP_IOERROR;
        goto bail;
    }

    /* add any folders that need adding, and mark any which
     * still exist */
    for (i = 0; i < msubs->count; i++) {
        const char *name = strarray_nth(msubs, i);
        rsubs = sync_name_lookup(replica_subs, name);
        if (rsubs) {
            rsubs->mark = 1;
            continue;
        }
        r = sync_set_sub(sync_cs, userid, name, 1);
        if (r) goto bail;
    }

    /* remove any no-longer-subscribed folders */
    for (rsubs = replica_subs->head; rsubs; rsubs = rsubs->next) {
        if (rsubs->mark)
            continue;
        r = sync_set_sub(sync_cs, userid, rsubs->name, 0);
        if (r) goto bail;
    }

 bail:
    strarray_free(msubs);
    return r;
}

static int get_seen(const char *uniqueid, struct seendata *sd, void *rock)
{
    struct sync_seen_list *list = (struct sync_seen_list *)rock;

    sync_seen_list_add(list, uniqueid, sd->lastread, sd->lastuid,
                       sd->lastchange, sd->seenuids);

    return 0;
}

int sync_do_user_seen(struct sync_client_state *sync_cs, const char *userid,
                      struct sync_seen_list *replica_seen)
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
        r = update_seen_work(sync_cs, userid, mseen->uniqueid, &mseen->sd);
    }

    /* XXX - delete seen on the replica for records that don't exist? */

    sync_seen_list_free(&list);

    return 0;
}

int sync_do_user_sieve(struct sync_client_state *sync_cs, const char *userid,
                       struct sync_sieve_list *replica_sieve)
{
    int r = 0;
    struct sync_sieve_list *master_sieve;
    struct sync_sieve *mitem, *ritem;
    int master_active = 0;
    int replica_active = 0;
    char *ext;

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

        /* Don't upload compiled bytecode */
        ext = strrchr(mitem->name, '.');
        if (!ext || strcmp(ext, ".bc")) {
             r = sieve_upload(sync_cs, userid, mitem->name, mitem->last_update);
             if (r) goto bail;
        }

        /* but still log it as having been created, since it will be automatically */
        if (!ritem) {
            ritem = sync_sieve_list_add(replica_sieve, mitem->name,
                                        mitem->last_update, &mitem->guid, 0);
            ritem->mark = 1;
        }
    }

    /* Delete scripts which no longer exist on the master */
    replica_active = 0;
    for (ritem = replica_sieve->head; ritem; ritem = ritem->next) {
        if (ritem->mark) {
            if (ritem->active)
                replica_active = 1;
        } else {
            r = sieve_delete(sync_cs, userid, ritem->name);
            if (r) goto bail;

            ritem->mark = -1;
        }
    }

    /* Change active script if necessary */
    master_active = 0;
    for (mitem = master_sieve->head; mitem; mitem = mitem->next) {
        if (!mitem->active)
            continue;

        master_active = 1;
        ritem = sync_sieve_lookup(replica_sieve, mitem->name);
        if (ritem) {
            if (ritem->active) break;

            if (ritem->mark != -1) {
                r = sieve_activate(sync_cs, userid, mitem->name);
                if (r) goto bail;

                replica_active = 1;
            }
        }
        break;
    }

    if (!master_active && replica_active)
        r = sieve_deactivate(sync_cs, userid);

 bail:
    sync_sieve_list_free(&master_sieve);
    return(r);
}

int sync_do_user(struct sync_client_state *sync_cs,
                 const char *userid, const char *topart)
{
    int r = 0;
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct sync_name_list *replica_subs = sync_name_list_create();
    struct sync_sieve_list *replica_sieve = sync_sieve_list_create();
    struct sync_seen_list *replica_seen = sync_seen_list_create();
    struct sync_quota_list *replica_quota = sync_quota_list_create();
    struct dlist *kl = NULL;
    struct mailbox *mailbox = NULL;

    struct mboxlock *userlock = sync_lock(sync_cs, userid);
    if (!userlock) {
        r = IMAP_MAILBOX_LOCKED;
        goto done;
    }

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("USER %s\n", userid);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "USER %s", userid);

    int tries = 0;

redo:
    tries++;
    if (tries > 3) {
        syslog(LOG_ERR, "failed to sync user %s after 3 tries", userid);
        r = IMAP_SYNC_CHANGED;
        goto done;
    }

    kl = dlist_setatom(NULL, "USER", userid);
    sync_send_lookup(kl, sync_cs->backend->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_cs, "USER", replica_folders, replica_subs,
                            replica_sieve, replica_seen, replica_quota);
    /* can happen! */
    if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    if (r) goto done;

    /* check that the inbox exists locally to be allowed to sync this user at all */
    char *inbox = mboxname_user_mbox(userid, NULL);
    r = mailbox_open_irl(inbox, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    free(inbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (sync_cs->flags & SYNC_FLAG_VERBOSE)
            printf("Does not exist locally %s\n", userid);
        if (sync_cs->flags & SYNC_FLAG_LOGGING)
            syslog(LOG_INFO, "Does not exist locally %s", userid);

        // just skip this user.  XXX - tombstone for user -> sync_reset?
        r = 0;
        goto done;
    }
    if (r) goto done;

    /* we don't hold locks while sending commands */
    mailbox_close(&mailbox);
    r = do_user_main(sync_cs, userid, topart, replica_folders, replica_quota);
    if (r == IMAP_AGAIN) {
        // we've done a rename - have to try again!
        sync_folder_list_free(&replica_folders);
        sync_name_list_free(&replica_subs);
        sync_sieve_list_free(&replica_sieve);
        sync_seen_list_free(&replica_seen);
        sync_quota_list_free(&replica_quota);
        replica_folders = sync_folder_list_create();
        replica_subs = sync_name_list_create();
        replica_sieve = sync_sieve_list_create();
        replica_seen = sync_seen_list_create();
        replica_quota = sync_quota_list_create();
        goto redo;
    }
    if (r) goto done;
    r = sync_do_user_sub(sync_cs, userid, replica_subs);
    if (r) goto done;
    r = sync_do_user_sieve(sync_cs, userid, replica_sieve);
    if (r) goto done;
    r = sync_do_user_seen(sync_cs, userid, replica_seen);

done:
    sync_folder_list_free(&replica_folders);
    sync_name_list_free(&replica_subs);
    sync_sieve_list_free(&replica_sieve);
    sync_seen_list_free(&replica_seen);
    sync_quota_list_free(&replica_quota);
    mboxname_release(&userlock);

    return r;
}

/* ====================================================================== */

int sync_do_meta(struct sync_client_state *sync_cs, const char *userid)
{
    struct sync_name_list *replica_subs = sync_name_list_create();
    struct sync_sieve_list *replica_sieve = sync_sieve_list_create();
    struct sync_seen_list *replica_seen = sync_seen_list_create();
    struct dlist *kl = NULL;
    int r = 0;

    if (sync_cs->flags & SYNC_FLAG_VERBOSE)
        printf("META %s\n", userid);

    if (sync_cs->flags & SYNC_FLAG_LOGGING)
        syslog(LOG_INFO, "META %s", userid);

    kl = dlist_setatom(NULL, "META", userid);
    sync_send_lookup(kl, sync_cs->backend->out);
    dlist_free(&kl);

    r = sync_response_parse(sync_cs, "META", NULL,
                            replica_subs, replica_sieve, replica_seen, NULL);
    if (!r) r = sync_do_user_seen(sync_cs, userid, replica_seen);
    if (!r) r = sync_do_user_sub(sync_cs, userid, replica_subs);
    if (!r) r = sync_do_user_sieve(sync_cs, userid, replica_sieve);
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
        xsyslog(LOG_ERR, "SYNCERROR: unknown command",
                         "command=<%s>",
                         kin->name);
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
    else if (!strcmp(kin->name, "UNIQUEIDS"))
        r = sync_get_uniqueids(kin, state);
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

EXPORTED const char *sync_restore(struct dlist *kin,
                                  struct sync_reserve_list *reserve_list,
                                  struct sync_state *state)
{
    int r = IMAP_PROTOCOL_ERROR;

    ucase(kin->name);

    if (!strcmp(kin->name, "MAILBOX"))
        r = sync_restore_mailbox(kin, reserve_list, state);
    else if (!strcmp(kin->name, "LOCAL_MAILBOX")) {
        state->local_only = 1;
        r = sync_restore_mailbox(kin, reserve_list, state);
    }
    else {
        xsyslog(LOG_ERR, "SYNCERROR: unknown command",
                         "command=<%s>",
                         kin->name);
        r = IMAP_PROTOCOL_ERROR;
    }

    return sync_response(r);
}

/* ====================================================================== */

static int do_unuser(struct sync_client_state *sync_cs, const char *userid)
{
    const char *cmd = "UNUSER";
    struct mailbox *mailbox = NULL;
    struct dlist *kl;
    int r;

    /* nothing to do if there's no userid */
    if (!userid || !userid[0]) {
        syslog(LOG_WARNING, "ignoring attempt to %s() without userid", __func__);
        return 0;
    }

    /* check local mailbox first */
    char *inbox = mboxname_user_mbox(userid, NULL);
    r = mailbox_open_irl(inbox, &mailbox);

    /* only remove from server if there's no local mailbox */
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        kl = dlist_setatom(NULL, cmd, userid);
        sync_send_apply(kl, sync_cs->backend->out);
        dlist_free(&kl);

        r = sync_parse_response(cmd, sync_cs->backend->in, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    }

    mailbox_close(&mailbox);
    free(inbox);

    return r;
}

/* ====================================================================== */

static int user_sub(struct sync_client_state *sync_cs,
                    const char *userid, const char *mboxname)
{
    int r;

    r = mboxlist_checksub(mboxname, userid);

    switch (r) {
    case CYRUSDB_OK:
        return sync_set_sub(sync_cs, userid, mboxname, 1);
    case CYRUSDB_NOTFOUND:
        return sync_set_sub(sync_cs, userid, mboxname, 0);
    default:
        return r;
    }
}

/* ====================================================================== */

static int do_unmailbox(struct sync_client_state *sync_cs, const char *mboxname)
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* make sure there's an explicit local tombstone */
        mbentry_t *tombstone = NULL;
        r = mboxlist_lookup_allow_all(mboxname, &tombstone, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            // otherwise we don't change anything on the replica
            xsyslog(LOG_NOTICE, "SYNCNOTICE: attempt to UNMAILBOX without a tombstone",
                                "mailbox=<%s>", mboxname);
            r = 0;
            goto skip;
        }
        if (r) {
            syslog(LOG_ERR, "%s: mboxlist_lookup() failed: %s '%s'",
                            __func__, mboxname, error_message(r));
        }
        else if ((tombstone->mbtype & MBTYPE_DELETED) == 0) {
            syslog(LOG_ERR, "attempt to UNMAILBOX non-tombstone: \"%s\"",
                            mboxname);
        }
        else {
            r = sync_do_folder_delete(sync_cs, mboxname);
            if (r) {
                syslog(LOG_ERR, "%s: sync_do_folder_delete(): failed: %s '%s'",
                                __func__, mboxname, error_message(r));
            }
        }
        skip:
        mboxlist_entry_free(&tombstone);
    }
    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

static void remove_meta(char *user, struct sync_action_list *list)
{
    struct sync_action *action;

    for (action = list->head ; action ; action = action->next) {
        if (!strcmp(user, action->user)) {
            action->active = 0;
        }
    }
}

/* ====================================================================== */

#define report_verbose(...) syslog(LOG_INFO, __VA_ARGS__)
#define report_verbose_error(...) syslog(LOG_ERR, __VA_ARGS__)

static int do_mailboxes(struct sync_client_state *sync_cs,
                        struct sync_name_list *mboxname_list,
                        struct sync_action_list *user_list,
                        int flags)
{
    struct sync_name *mbox;
    int r = 0;

    if (mboxname_list->count) {
        r = sync_do_mailboxes(sync_cs, mboxname_list, NULL, flags);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
                if (mbox->mark) continue;
                sync_log_channel_mailbox(sync_cs->channel, mbox->name);
                report_verbose("  Deferred: MAILBOX %s\n", mbox->name);
            }
            r = 0;
        }
        else if (r && r != IMAP_BYE_LOGOUT) {
            /* promote failed personal mailboxes to USER */
            int nonuser = 0;

            for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
                /* done OK?  Good :) */
                if (mbox->mark)
                    continue;

                char *userid = mboxname_to_userid(mbox->name);
                if (userid) {
                    mbox->mark = 1;

                    sync_action_list_add(user_list, NULL, userid);
                    report_verbose("  Promoting: MAILBOX %s -> USER %s\n",
                                   mbox->name, userid);
                    free(userid);
                }
                else
                    nonuser = 1; /* there was a non-user mailbox */
            }
            if (!nonuser) r = 0;
        }
    }

    return r;
}

int sync_do_restart(struct sync_client_state *sync_cs)
{
    sync_send_restart(sync_cs->backend->out);
    return sync_parse_response("RESTART", sync_cs->backend->in, NULL);
}

struct split_user_mailboxes_rock {
    struct sync_client_state *sync_cs;
    struct sync_action_list *user_list;
    int r;
};

static void split_user_mailboxes(const char *key __attribute__((unused)),
                                 void *data,
                                 void *rock)
{
    struct split_user_mailboxes_rock *smrock =
        (struct split_user_mailboxes_rock *) rock;
    struct sync_action_list *mailbox_list = (struct sync_action_list *) data;
    struct sync_name_list *mboxname_list = sync_name_list_create();;
    struct sync_action *action;

    for (action = mailbox_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        sync_name_list_add(mboxname_list, action->name);
    }

    if (mboxname_list->count) {
        syslog(LOG_DEBUG, "sync_mailboxes: doing %lu",
                           mboxname_list->count);
        smrock->r = do_mailboxes(smrock->sync_cs, mboxname_list,
                                 smrock->user_list, smrock->sync_cs->flags);
        if (!smrock->r) smrock->r = sync_do_restart(smrock->sync_cs);
    }

    sync_name_list_free(&mboxname_list);
}

/* need this lil wrapper for free_hash_table callback */
static void sync_action_list_free_wrapper(void *p)
{
    struct sync_action_list *l = (struct sync_action_list *) p;
    sync_action_list_free(&l);
}

int sync_do_reader(struct sync_client_state *sync_cs, sync_log_reader_t *slr)
{
    struct sync_action_list *user_list = sync_action_list_create();
    struct sync_action_list *unuser_list = sync_action_list_create();
    struct sync_action_list *meta_list = sync_action_list_create();
    struct sync_action_list *unmailbox_list = sync_action_list_create();
    struct sync_action_list *quota_list = sync_action_list_create();
    struct sync_action_list *annot_list = sync_action_list_create();
    struct sync_action_list *seen_list = sync_action_list_create();
    struct sync_action_list *sub_list = sync_action_list_create();
    hash_table user_mailboxes = HASH_TABLE_INITIALIZER;
    const char *args[3];
    struct sync_action *action;
    int r = 0;

    construct_hash_table(&user_mailboxes, 1024 /* XXX */, 0);

    while (sync_log_reader_getitem(slr, args) != EOF) {
        if (!strcmp(args[0], "USER"))
            sync_action_list_add(user_list, NULL, args[1]);
        else if (!strcmp(args[0], "UNUSER"))
            sync_action_list_add(unuser_list, NULL, args[1]);
        else if (!strcmp(args[0], "META"))
            sync_action_list_add(meta_list, NULL, args[1]);
        else if (!strcmp(args[0], "SIEVE"))
            sync_action_list_add(meta_list, NULL, args[1]);
        else if ((!strcmp(args[0], "APPEND")) /* just a mailbox event */
                 || (!strcmp(args[0], "MAILBOX"))
                 || (!strcmp(args[0], "DOUBLEMAILBOX"))) {
            char *freeme = NULL;
            const char *userid;
            struct sync_action_list *mailbox_list;

            userid = freeme = mboxname_to_userid(args[1]);
            if (!userid) userid = ""; /* treat non-user mboxes as a single cohort */

            mailbox_list = hash_lookup(userid, &user_mailboxes);
            if (!mailbox_list) {
                mailbox_list = sync_action_list_create();
                hash_insert(userid, mailbox_list, &user_mailboxes);
            }
            sync_action_list_add(mailbox_list, args[1], NULL);

            if (args[2]) {
                /* if there's a second MAILBOX recorded (i.e. a copy or move), add
                 * it to the same user's mailbox_list (even if it's a diff user),
                 * so that the order doesn't get lost.
                 */
                sync_action_list_add(mailbox_list, args[2], NULL);
            }

            free(freeme);
        }
        else if (!strcmp(args[0], "RENAME")) {
            char *freeme1 = NULL, *freeme2 = NULL;
            const char *userid1, *userid2;
            struct sync_action_list *mailbox_list;

            userid1 = freeme1 = mboxname_to_userid(args[1]);
            if (!userid1) userid1 = "";
            userid2 = freeme2 = mboxname_to_userid(args[2]);
            if (!userid2) userid2 = "";

            /* add both mboxnames to the list for the first one's user */
            mailbox_list = hash_lookup(userid1, &user_mailboxes);
            if (!mailbox_list) {
                mailbox_list = sync_action_list_create();
                hash_insert(userid1, mailbox_list, &user_mailboxes);
            }
            sync_action_list_add(mailbox_list, args[1], NULL);
            sync_action_list_add(mailbox_list, args[2], NULL);

            /* if the second mboxname's user is different, add both names there too */
            if (strcmp(userid1, userid2) != 0) {
                mailbox_list = hash_lookup(userid2, &user_mailboxes);
                if (!mailbox_list) {
                    mailbox_list = sync_action_list_create();
                    hash_insert(userid2, mailbox_list, &user_mailboxes);
                }
                sync_action_list_add(mailbox_list, args[1], NULL);
                sync_action_list_add(mailbox_list, args[2], NULL);
            }

            free(freeme1);
            free(freeme2);
        }
        else if (!strcmp(args[0], "UNMAILBOX"))
            sync_action_list_add(unmailbox_list, args[1], NULL);
        else if (!strcmp(args[0], "QUOTA"))
            sync_action_list_add(quota_list, args[1], NULL);
        else if (!strcmp(args[0], "ANNOTATION"))
            sync_action_list_add(annot_list, args[1], NULL);
        else if (!strcmp(args[0], "SEEN"))
            sync_action_list_add(seen_list, args[2], args[1]);
        else if (!strcmp(args[0], "SUB"))
            sync_action_list_add(sub_list, args[2], args[1]);
        else if (!strcmp(args[0], "UNSUB"))
            sync_action_list_add(sub_list, args[2], args[1]);
        else
            syslog(LOG_ERR, "Unknown action type: %s", args[0]);
    }

    /* Optimise out redundant clauses */

    for (action = user_list->head; action; action = action->next) {
        /* remove per-user items */
        remove_meta(action->user, meta_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
    }

    /* duplicate removal for unuser - we also strip all the user events */
    for (action = unuser_list->head; action; action = action->next) {
        /* remove per-user items */
        remove_meta(action->user, meta_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);

        /* unuser trumps user */
        remove_meta(action->user, user_list);
    }

    for (action = meta_list->head; action; action = action->next) {
        /* META action overrides any user SEEN or SUB/UNSUB action
           for same user */
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
    }

    /* And then run tasks. */

    if (hash_numrecords(&user_mailboxes)) {
        struct split_user_mailboxes_rock smrock;
        smrock.sync_cs = sync_cs;
        smrock.user_list = user_list;
        smrock.r = 0;

        /* process user_mailboxes in sets of ~1000, splitting only on
         * user boundaries */
        hash_enumerate(&user_mailboxes, split_user_mailboxes, &smrock);
        r = smrock.r;

        if (r) goto cleanup;
    }

    for (action = quota_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_quota(sync_cs, action->name);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_quota(sync_cs->channel, action->name);
            report_verbose("  Deferred: QUOTA %s\n", action->name);
        }
        else if (r == IMAP_BYE_LOGOUT) {
            goto cleanup;
        }
        else if (r) {
            sync_action_list_add(user_list, action->name, NULL);
            report_verbose("  Promoting: QUOTA %s -> USER %s\n",
                           action->name, action->name);
        }
    }

    for (action = annot_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        /* NOTE: ANNOTATION "" is a special case - it's a server
         * annotation, hence the check for a character at the
         * start of the name */
        r = sync_do_annotation(sync_cs, action->name);
        if (!*action->name) continue;

        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_annotation(sync_cs->channel, action->name);
            report_verbose("  Deferred: ANNOTATION %s\n", action->name);
        }
        else if (r == IMAP_BYE_LOGOUT) {
            goto cleanup;
        }
        else if (r) {
            sync_action_list_add(user_list, action->name, NULL);
            report_verbose("  Promoting: ANNOTATION %s -> USER %s\n",
                           action->name, action->name);
        }
    }

    for (action = seen_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_seen(sync_cs, action->user, action->name);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_seen(sync_cs->channel, action->user, action->name);
            report_verbose("  Deferred: SEEN %s %s\n",
                           action->user, action->name);
        }
        else if (r == IMAP_BYE_LOGOUT) {
            goto cleanup;
        }
        else if (r) {
            char *userid = mboxname_to_userid(action->name);
            if (userid && mboxname_isusermailbox(action->name, 1) && !strcmp(userid, action->user)) {
                sync_action_list_add(user_list, NULL, action->user);
                report_verbose("  Promoting: SEEN %s %s -> USER %s\n",
                               action->user, action->name, action->user);
            } else {
                sync_action_list_add(meta_list, NULL, action->user);
                report_verbose("  Promoting: SEEN %s %s -> META %s\n",
                               action->user, action->name, action->user);
            }
            free(userid);
        }
    }

    for (action = sub_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = user_sub(sync_cs, action->user, action->name);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_subscribe(sync_cs->channel, action->user, action->name);
            report_verbose("  Deferred: SUB %s %s\n",
                           action->user, action->name);
        }
        else if (r == IMAP_BYE_LOGOUT) {
            goto cleanup;
        }
        else if (r) {
            sync_action_list_add(meta_list, NULL, action->user);
            report_verbose("  Promoting: SUB %s %s -> META %s\n",
                           action->user, action->name, action->user);
        }
    }

    /* XXX - is unmailbox used much anyway - we need to see if it's logged for a rename,
     * e.g.
     * RENAME A B:
     *  MAILBOX A
     *  MAILBOX B
     *  UNMAILBOX A
     *
     * suggestion: PROMOTE ALL UNMAILBOX on user accounts to USER foo
     */
    for (action = unmailbox_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = do_unmailbox(sync_cs, action->name);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_unmailbox(sync_cs->channel, action->name);
            report_verbose("  Deferred: UNMAILBOX %s\n", action->name);
        }
        else if (r) goto cleanup;
    }

    for (action = meta_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_meta(sync_cs, action->user);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_sieve(sync_cs->channel, action->user);
            report_verbose("  Deferred: META %s\n", action->user);
        }
        else if (r == IMAP_INVALID_USER || r == IMAP_BYE_LOGOUT) {
            goto cleanup;
        }
        else if (r) {
            sync_action_list_add(user_list, NULL, action->user);
            report_verbose("  Promoting: META %s -> USER %s\n",
                           action->user, action->user);
        }
    }

    for (action = user_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = sync_do_user(sync_cs, action->user, NULL);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_user(sync_cs->channel, action->user);
            report_verbose("  Deferred: USER %s\n", action->user);
        }
        else if (r) goto cleanup;
        r = sync_do_restart(sync_cs);
        if (r) goto cleanup;
    }

    for (action = unuser_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = do_unuser(sync_cs, action->user);
        if (sync_cs->channel && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_unuser(sync_cs->channel, action->user);
            report_verbose("  Deferred: UNUSER %s\n", action->user);
        }
        else if (r) goto cleanup;
    }

  cleanup:
    if (r && r != IMAP_BYE_LOGOUT) {
        report_verbose_error("Error in do_sync(): bailing out! %s", error_message(r));
    }

    sync_action_list_free(&user_list);
    sync_action_list_free(&unuser_list);
    sync_action_list_free(&meta_list);
    sync_action_list_free(&unmailbox_list);
    sync_action_list_free(&quota_list);
    sync_action_list_free(&annot_list);
    sync_action_list_free(&seen_list);
    sync_action_list_free(&sub_list);
    free_hash_table(&user_mailboxes, sync_action_list_free_wrapper);

    return r;
}

EXPORTED int sync_connect(struct sync_client_state *sync_cs)
{
    sasl_callback_t *cb;
    int timeout;
    const char *port, *auth_status = NULL;
    int try_imap;
    struct backend *backend = sync_cs->backend;

    int verbose = (sync_cs->flags & SYNC_FLAG_VERBOSE);

    sync_cs->backend = NULL;
    buf_free(&sync_cs->tagbuf);

    cb = mysasl_callbacks(NULL,
                          sync_get_config(sync_cs->channel, "sync_authname"),
                          sync_get_config(sync_cs->channel, "sync_realm"),
                          sync_get_config(sync_cs->channel, "sync_password"));

    /* get the right port */
    port = sync_get_config(sync_cs->channel, "sync_port");
    if (port) {
        imap_csync_protocol.service = port;
        csync_protocol.service = port;
    }

    try_imap = sync_get_switchconfig(sync_cs->channel, "sync_try_imap");

    if (try_imap) {
        backend = backend_connect(backend, sync_cs->servername,
                                  &imap_csync_protocol, "", cb, &auth_status,
                                  (verbose > 1 ? fileno(stderr) : -1));

        if (backend) {
            if (backend->capability & CAPA_REPLICATION) {
                /* attach our IMAP tag buffer to our protstreams as userdata */
                backend->in->userdata = backend->out->userdata = &sync_cs->tagbuf;
                goto connected;
            }
            else {
                backend_disconnect(backend);
                backend = NULL;
            }
        }
    }

    backend = backend_connect(backend, sync_cs->servername,
                              &csync_protocol, "", cb, NULL,
                              (verbose > 1 ? fileno(stderr) : -1));

    // auth_status means there was an error
    if (!backend) return IMAP_AGAIN;

connected:

    free_callbacks(cb);
    cb = NULL;

    if (sync_cs->servername[0] != '/' && backend->sock >= 0) {
        tcp_disable_nagle(backend->sock);
        tcp_enable_keepalive(backend->sock);
    }

#ifdef HAVE_ZLIB
    /* Does the backend support compression? */
    if (CAPA(backend, CAPA_COMPRESS)) {
        prot_printf(backend->out, "%s\r\n",
                    backend->prot->u.std.compress_cmd.cmd);
        prot_flush(backend->out);

        if (sync_parse_response("COMPRESS", backend->in, NULL)) {
            syslog(LOG_NOTICE, "Failed to enable compression, continuing uncompressed");
        }
        else {
            prot_setcompress(backend->in);
            prot_setcompress(backend->out);
        }
    }
#endif

    /* Set inactivity timer */
    timeout = config_getduration(IMAPOPT_SYNC_TIMEOUT, 's');
    if (timeout < 3) timeout = 3;
    prot_settimeout(backend->in, timeout);

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(backend->in, 1);
    prot_setisclient(backend->out, 1);

    sync_cs->backend = backend;

    return 0;
}

EXPORTED void sync_disconnect(struct sync_client_state *sync_cs)
{
    if (!sync_cs->backend) return;

    if (sync_cs->backend->timeout)
        prot_removewaitevent(sync_cs->clientin, sync_cs->backend->timeout);
    sync_cs->clientin = NULL;
    sync_cs->backend->timeout = NULL;

    backend_disconnect(sync_cs->backend);

    // backend may have put stuff here, free it so we don't leak memory
    buf_free(&sync_cs->tagbuf);

    // drop any cache database too
    if (sync_cs->cachedb) {
        cyrusdb_close(sync_cs->cachedb);
        sync_cs->cachedb = NULL;
    }
}

static struct prot_waitevent *
sync_rightnow_timeout(struct protstream *s __attribute__((unused)),
                      struct prot_waitevent *ev __attribute__((unused)),
                      void *rock __attribute__((unused)))
{
    syslog(LOG_DEBUG, "sync_rightnow_timeout()");

    /* too long since we last used the syncer - disconnect */
    sync_disconnect(&rightnow_sync_cs);
    free(rightnow_sync_cs.backend);
    rightnow_sync_cs.backend = NULL;

    return NULL;
}

EXPORTED int sync_checkpoint(struct protstream *clientin)
{
    struct buf *buf = sync_log_rightnow_buf();
    if (!buf) return 0;

    time_t when = time(NULL) + 30;
    if (rightnow_sync_cs.backend) {
        if (rightnow_sync_cs.backend->timeout->mark) {
            rightnow_sync_cs.backend->timeout->mark = when;
        }
    }
    else {
        const char *conf = config_getstring(IMAPOPT_SYNC_RIGHTNOW_CHANNEL);
        if (conf && strcmp(conf, "\"\""))
            rightnow_sync_cs.channel = conf;
        rightnow_sync_cs.servername = sync_get_config(rightnow_sync_cs.channel, "sync_host");
        rightnow_sync_cs.flags = SYNC_FLAG_LOGGING;
        syslog(LOG_DEBUG, "sync_rightnow_connect(%s)", rightnow_sync_cs.servername);
        sync_connect(&rightnow_sync_cs);
        if (!rightnow_sync_cs.backend) {
            syslog(LOG_ERR, "SYNCERROR sync_rightnow: failed to connect to server: %s",
                   rightnow_sync_cs.servername);
            // dammit, but the show must go on
            buf_reset(buf);
            return 0;
        }
        rightnow_sync_cs.clientin = clientin;
        rightnow_sync_cs.backend->timeout
            = prot_addwaitevent(clientin, when, sync_rightnow_timeout, NULL);
    }

    sync_log_reader_t *slr = sync_log_reader_create_with_content(buf_cstring(buf));

    int r = sync_log_reader_begin(slr);
    if (!r) r = sync_do_reader(&rightnow_sync_cs, slr);
    if (r) {
        syslog(LOG_ERR, "SYNCERROR sync_rightnow: error syncing to: %s (%s)",
               rightnow_sync_cs.servername, error_message(r));
    }

    sync_log_reader_end(slr);
    sync_log_reader_free(slr);

    // mark these items consumed!
    buf_reset(buf);

    return 0;
}
