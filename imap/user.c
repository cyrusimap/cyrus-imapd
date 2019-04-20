/* user.c -- User manipulation routines
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "assert.h"
#include "global.h"
#include "mailbox.h"
#include "mboxkey.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "proc.h"
#include "quota.h"
#include "search_engines.h"
#include "seen.h"
#include "sievedir.h"
#include "sync_log.h"
#include "user.h"
#include "util.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xmalloc.h"
#include "xstrlcat.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#ifdef WITH_DAV
#include "caldav_alarm.h"
#endif

#define FNAME_SUBSSUFFIX "sub"

#if 0
static int user_deleteacl(char *name, int matchlen, int category, void* rock)
{
    /* deleting all references to the user is too slow right now */

    char *ident = (char *) rock;
    int r;
    char *acl;
    char *rights, *nextid;
    char *origacl, *aclalloc;

    r = mboxlist_lookup(name, &origacl, NULL);

    /* setacl re-calls mboxlist_lookup and will stomp on us */
    aclalloc = acl = xstrdup(origacl);

    while (!r && acl) {
        rights = strchr(acl, '\t');
        if (!rights) break;
        *rights++ = '\0';

        nextid = strchr(rights, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        if (!strcmp(acl, ident)) {
            /* delete ACL for ident */
            if (!r) mboxlist_setacl(name, ident, (char *)0,
                                    1, ident, NULL);
        }

        acl = nextid;
    }

    free(aclalloc);

    return 0;
}
#endif

EXPORTED const char *user_sieve_path(const char *inuser)
{
    static char sieve_path[2048];
    char *user = xstrdupnull(inuser);
    char *p;

    /* Make sure it's a real userid, with no ^ escaping!
     * XXX It's kinda bogus to be handling this here; it should be fixed
     * XXX much further up somewhere, but that may require deep surgery.
     */
    for (p = user; p && *p; p++) {
        if (*p == '^')
            *p = '.';
    }

    mbname_t *mbname = mbname_from_userid(user);
    const char *localpart = mbname_localpart(mbname);
    int legacy = 0;

    if (localpart) {
        /* user script */
        char *inboxname = mboxname_user_mbox(user, NULL);
        mbentry_t *mbentry = NULL;

        int r = mboxlist_lookup(inboxname, &mbentry, NULL);
        free(inboxname);

        if (r) sieve_path[0] = '\0';
        else if (mbentry->mbtype & MBTYPE_LEGACY_DIRS) {
            legacy = 1;
        }
        else {
            mboxname_id_hash(sieve_path, sizeof(sieve_path),
                             config_getstring(IMAPOPT_SIEVEDIR),
                             mbentry->uniqueid);
        }
        mboxlist_entry_free(&mbentry);
    }
    else {
        /* global script */
        legacy = 1;
    }

    if (legacy) {
        const char *domain = mbname_domain(mbname);
        size_t len, size = sizeof(sieve_path);

        len = strlcpy(sieve_path, config_getstring(IMAPOPT_SIEVEDIR), size);

        if (config_virtdomains && domain) {
            char d = (char) dir_hash_c(domain, config_fulldirhash);
            len += snprintf(sieve_path + len, size - len, "%s%c/%s",
                            FNAME_DOMAINDIR, d, domain);
        }

        if (localpart) {
            const char *userid = config_virtdomains ? localpart : user;
            char c = (char) dir_hash_c(userid, config_fulldirhash);
            snprintf(sieve_path + len, size - len, "/%c/%s", c, userid);
        }
        else {
            strlcat(sieve_path, "/global", size);
        }
    }

    mbname_free(&mbname);
    free(user);

    return sieve_path;
}

static int delete_cb(const char *sievedir, const char *name,
                     struct stat *sbuf __attribute__((unused)),
                     const char *link_target __attribute__((unused)),
                     void *rock __attribute__((unused)))
{
    char path[2048];

    snprintf(path, sizeof(path), "%s/%s", sievedir, name);

    unlink(path);

    return SIEVEDIR_OK;
}

static int user_deletesieve(const char *user)
{
    const char *sieve_path;

    /* oh well */
    if(config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) return 0;

    sieve_path = user_sieve_path(user);

    /* remove contents of sieve_path */
    sievedir_foreach(sieve_path, 0/*flags*/, &delete_cb, NULL);

    rmdir(sieve_path);

    return 0;
}

EXPORTED int user_deletedata(const char *userid, int wipe_user)
{
    char *fname;

    assert(user_isnamespacelocked(userid));

    /* delete seen state and mbox keys */
    if(wipe_user) {
        seen_delete_user(userid);
        /* XXX  what do we do about multiple backends? */
        mboxkey_delete_user(userid);
    }

    /* delete subscriptions */
    fname = user_hash_subs(userid);
    (void) unlink(fname);
    free(fname);

    /* delete quotas */
    user_deletequotaroots(userid);

    /* delete sieve scripts */
    user_deletesieve(userid);

    /* NOTE: even if conversations aren't enabled, we want to clean up */

    /* delete conversations file */
    fname = conversations_getuserpath(userid);
    (void) unlink(fname);
    free(fname);

    /* XXX: one could make an argument for keeping the counters
     * file forever, so that UIDVALIDITY never gets reused. */
    fname = user_hash_meta(userid, "counters");
    (void) unlink(fname);
    free(fname);

    /* delete dav database (even if DAV is turned off, this is fine) */
    fname = user_hash_meta(userid, "dav");
    (void) unlink(fname);
    free(fname);

    /* delete all the search engine data (if any) */
    search_deluser(userid);

#ifdef WITH_DAV
    /* delete all the calendar alarms for the user */
    caldav_alarm_delete_user(userid);
#endif /* WITH_DAV */

    proc_killuser(userid);

    // make sure it gets removed everywhere else
    sync_log_unuser(userid);

    return 0;
}
#if 0
struct rename_rock {
    const char *olduser;
    const char *newuser;
    const char *oldinbox;
    const char *newinbox;
    int domainchange;
};

static int user_renamesub(const char *name, void* rock)
{
    struct rename_rock *rrock = (struct rename_rock *) rock;
    char newname[MAX_MAILBOX_BUFFER];

    if (!strncasecmp(name, "INBOX", 5) &&
        (name[5] == '\0' || name[5] == '.')) {
        /* generate new name of personal mailbox */
        snprintf(newname, sizeof(newname), "%s%s",
                 rrock->newinbox, name+5);
        name = newname;
    }
    else if (!strncmp(name, rrock->oldinbox, strlen(rrock->oldinbox)) &&
        (name[strlen(rrock->oldinbox)] == '\0' ||
         name[strlen(rrock->oldinbox)] == '.')) {
        /* generate new name of personal mailbox */
        snprintf(newname, sizeof(newname), "%s%s",
                 rrock->newinbox, name+strlen(rrock->oldinbox));
        name = newname;
    }

    return mboxlist_changesub(name, rrock->newuser, NULL, 1, 1, 1);
}

static int user_renamesieve(const char *olduser, const char *newuser)
{
    char hash, *domain;
    char oldpath[2048], newpath[2048];
    int r;

    /* oh well */
    if(config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) return 0;

    if (config_virtdomains && (domain = strchr(olduser, '@'))) {
        char d = (char) dir_hash_c(domain+1, config_fulldirhash);
        *domain = '\0';  /* split user@domain */
        hash = (char) dir_hash_c(olduser, config_fulldirhash);
        snprintf(oldpath, sizeof(oldpath), "%s%s%c/%s/%c/%s",
                 config_getstring(IMAPOPT_SIEVEDIR),
                 FNAME_DOMAINDIR, d, domain+1, hash, olduser);
        *domain = '@';  /* reassemble user@domain */
    }
    else {
        hash = (char) dir_hash_c(olduser, config_fulldirhash);

        snprintf(oldpath, sizeof(oldpath), "%s/%c/%s",
                 config_getstring(IMAPOPT_SIEVEDIR), hash, olduser);
    }

    if (config_virtdomains && (domain = strchr(newuser, '@'))) {
        char d = (char) dir_hash_c(domain+1, config_fulldirhash);
        *domain = '\0';  /* split user@domain */
        hash = (char) dir_hash_c(newuser, config_fulldirhash);
        snprintf(newpath, sizeof(newpath), "%s%s%c/%s/%c/%s",
                 config_getstring(IMAPOPT_SIEVEDIR),
                 FNAME_DOMAINDIR, d, domain+1, hash, newuser);
        *domain = '@';  /* reassemble user@domain */
    }
    else {
        hash = (char) dir_hash_c(newuser, config_fulldirhash);

        snprintf(newpath, sizeof(newpath), "%s/%c/%s",
                 config_getstring(IMAPOPT_SIEVEDIR), hash, newuser);
    }

    /* rename sieve directory
     *
     * XXX this doesn't rename sieve scripts
     */
    r = rename(oldpath, newpath);
    if (r < 0) {
        if (errno == ENOENT) {
            syslog(LOG_WARNING, "error renaming %s to %s: %m",
                   oldpath, newpath);
            /* but maybe the user doesn't have any scripts ? */
            r = 0;
        }
        else if (errno == EXDEV) {
            syslog(LOG_ERR, "error renaming %s to %s: different filesystems",
                   oldpath, newpath);
            /* doh!  need to copy entire directory tree */
        }
        else {
            syslog(LOG_ERR, "error renaming %s to %s: %m", oldpath, newpath);
        }
    }

    return r;
}

EXPORTED int user_renamedata(const char *olduser, const char *newuser)
{
    struct rename_rock rrock;
    int i;

    /* get INBOXes */
    char *oldinbox = mboxname_user_mbox(olduser, NULL);
    char *newinbox = mboxname_user_mbox(newuser, NULL);

    /* copy seen db */
    seen_rename_user(olduser, newuser);

    /* setup rock for find operations */
    rrock.olduser = olduser;
    rrock.newuser = newuser;
    rrock.oldinbox = oldinbox;
    rrock.newinbox = newinbox;

    /* copy/rename subscriptions - we're using the internal names here */
    strarray_t *subs = mboxlist_sublist(olduser);
    for (i = 0; i < strarray_size(subs); i++) {
        user_renamesub(strarray_nth(subs, i), &rrock);
    }
    strarray_free(subs);

    /* move sieve scripts */
    user_renamesieve(olduser, newuser);

    free(oldinbox);
    free(newinbox);

    return 0;
}
#endif
EXPORTED int user_renameacl(const struct namespace *namespace, const char *name,
                            const char *olduser, const char *newuser)
{
    int r = 0;
    char *acl;
    char *rights, *nextid;
    mbentry_t *mbentry = NULL;
    char *aclalloc;

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) return r;

    /* setacl re-calls mboxlist_lookup and will stomp on us */
    aclalloc = acl = xstrdup(mbentry->acl);

    while (!r && acl) {
        rights = strchr(acl, '\t');
        if (!rights) break;
        *rights++ = '\0';

        nextid = strchr(rights, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        if (!strcmp(acl, olduser)) {
            /* copy ACL for olduser to newuser */
            r = mboxlist_setacl(namespace, name, newuser, rights, 1, newuser, NULL);
            /* delete ACL for olduser */
            if (!r)
                r = mboxlist_setacl(namespace, name, olduser, (char *)0, 1, newuser, NULL);
        }

        acl = nextid;
    }

    free(aclalloc);
    mboxlist_entry_free(&mbentry);

    return r;
}

EXPORTED int user_copyquotaroot(const char *oldname, const char *newname)
{
    int r = 0;
    struct quota q;

    quota_init(&q, oldname);
    r = quota_read(&q, NULL, 0);
    if (!r)
        mboxlist_setquotas(newname, q.limits, 0, 0);
    quota_free(&q);

    return r;
}

static int find_p(void *rockp,
                  const char *key, size_t keylen,
                  const char *data __attribute__((unused)),
                  size_t datalen __attribute__((unused)))
{
    char *inboxname = (char *)rockp;
    size_t inboxlen = strlen(inboxname);

    return (!strncmp(key, inboxname, inboxlen) &&
            (keylen == inboxlen || key[inboxlen] == '.'));
}

static int find_cb(void *rockp __attribute__((unused)),
                   const char *key, size_t keylen,
                   const char *data __attribute__((unused)),
                   size_t datalen __attribute__((unused)))
{
    char *root;
    int r;

    root = xstrndup(key, keylen);
    r = quota_deleteroot(root, 0);
    free(root);

    return r;
}

int user_deletequotaroots(const char *userid)
{
    char *inbox = mboxname_user_mbox(userid, NULL);
    int r = quotadb_foreach(inbox, strlen(inbox), &find_p, &find_cb, inbox);
    free(inbox);
    return r;
}

EXPORTED char *user_hash_meta(const char *userid, const char *suffix)
{
    mbname_t *mbname = NULL;
    char *result;

    mbname = mbname_from_userid(userid);
    result = mboxname_conf_getpath(mbname, suffix);

    mbname_free(&mbname);

    return result;
}

HIDDEN char *user_hash_subs(const char *userid)
{
    return user_hash_meta(userid, FNAME_SUBSSUFFIX);
}

static const char *_namelock_name_from_userid(const char *userid)
{
    const char *p;
    static struct buf buf = BUF_INITIALIZER;
    if (!userid) userid = ""; // no userid == global lock

    buf_setcstr(&buf, "*U*");

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

EXPORTED struct mboxlock *user_namespacelock_full(const char *userid, int locktype)
{
    struct mboxlock *namelock;
    const char *name = _namelock_name_from_userid(userid);
    int r = mboxname_lock(name, &namelock, locktype);
    if (r) return NULL;
    return namelock;
}

EXPORTED int user_isnamespacelocked(const char *userid)
{
    const char *name = _namelock_name_from_userid(userid);
    return mboxname_islocked(name);
}
