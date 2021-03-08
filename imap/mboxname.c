/* mboxname.c -- Mailbox list manipulation routines
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "byteorder.h"
#include "crc32.h"
#include "glob.h"
#include "global.h"
#include "mailbox.h"
#include "map.h"
#include "retry.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "mboxname.h"
#include "mboxlist.h"
#include "cyr_lock.h"

struct mboxlocklist {
    struct mboxlocklist *next;
    struct mboxlock l;
    int nopen;
};

static struct mboxlocklist *open_mboxlocks = NULL;

static struct namespace *admin_namespace;

struct mbname_parts {
    /* master data */
    strarray_t *boxes;
    time_t is_deleted;
    char *localpart;
    char *domain;

    /* actual namespace */
    const struct namespace *extns;
    char *extuserid;

    /* cache data */
    char *userid;
    char *intname;
    char *extname;
    char *recipient;
};

#define XX 127
/*
 * Table for decoding modified base64 for IMAP UTF-7 mailbox names
 */
static const char index_mod64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, 63,XX,XX,XX,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHARMOD64(c)  (index_mod64[(unsigned char)(c)])

#define FNAME_SHAREDPREFIX "shared"

EXPORTED int open_mboxlocks_exist(void)
{
    return open_mboxlocks ? 1 : 0;
}

static struct mboxlocklist *create_lockitem(const char *name)
{
    struct mboxlocklist *item = xmalloc(sizeof(struct mboxlocklist));
    item->next = open_mboxlocks;
    open_mboxlocks = item;

    item->nopen = 1;
    item->l.name = xstrdup(name);
    item->l.lock_fd = -1;
    item->l.locktype = 0;

    return item;
}

static struct mboxlocklist *find_lockitem(const char *name)
{
    struct mboxlocklist *item;

    for (item = open_mboxlocks; item; item = item->next) {
        if (!strcmp(name, item->l.name))
            return item;
    }

    return NULL;
}

static void remove_lockitem(struct mboxlocklist *remitem)
{
    struct mboxlocklist *item;
    struct mboxlocklist *previtem = NULL;

    for (item = open_mboxlocks; item; item = item->next) {
        if (item == remitem) {
            if (previtem)
                previtem->next = item->next;
            else
                open_mboxlocks = item->next;
            if (item->l.lock_fd != -1) {
                if (item->l.locktype)
                    lock_unlock(item->l.lock_fd, item->l.name);
                close(item->l.lock_fd);
            }
            free(item->l.name);
            free(item);
            return;
        }
        previtem = item;
    }

    fatal("didn't find item in list", EX_SOFTWARE);
}

/* name locking support */

EXPORTED int mboxname_lock(const char *mboxname, struct mboxlock **mboxlockptr,
                  int locktype_and_flags)
{
    const char *fname;
    int r = 0;
    struct mboxlocklist *lockitem;
    int nonblock;
    int locktype;

    nonblock = !!(locktype_and_flags & LOCK_NONBLOCK);
    locktype = (locktype_and_flags & ~LOCK_NONBLOCK);

    fname = mboxname_lockpath(mboxname);
    if (!fname)
        return IMAP_MAILBOX_BADNAME;

    lockitem = find_lockitem(mboxname);

    /* already open?  just use this one */
    if (lockitem) {
        /* can't change locktype! */
        if (lockitem->l.locktype != locktype)
            return IMAP_MAILBOX_LOCKED;

        lockitem->nopen++;
        goto done;
    }

    lockitem = create_lockitem(mboxname);

    /* assume success, and only create directory on failure.
     * More efficient on a common codepath */
    lockitem->l.lock_fd = open(fname, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (lockitem->l.lock_fd == -1) {
        if (cyrus_mkdir(fname, 0755) == -1) {
            r = IMAP_IOERROR;
            goto done;
        }
        lockitem->l.lock_fd = open(fname, O_CREAT | O_TRUNC | O_RDWR, 0666);
    }
    /* but if it still didn't succeed, we have problems */
    if (lockitem->l.lock_fd == -1) {
        r = IMAP_IOERROR;
        goto done;
    }

    r = lock_setlock(lockitem->l.lock_fd,
                     locktype == LOCK_EXCLUSIVE,
                     nonblock, fname);
    if (!r) lockitem->l.locktype = locktype;
    else if (errno == EWOULDBLOCK) r = IMAP_MAILBOX_LOCKED;
    else r = errno;

done:
    if (r) remove_lockitem(lockitem);
    else *mboxlockptr = &lockitem->l;

    return r;
}

EXPORTED void mboxname_release(struct mboxlock **mboxlockptr)
{
    if (!*mboxlockptr) return;

    struct mboxlocklist *lockitem;
    struct mboxlock *lock = *mboxlockptr;

    lockitem = find_lockitem(lock->name);
    assert(lockitem && &lockitem->l == lock);

    *mboxlockptr = NULL;

    if (lockitem->nopen > 1) {
        lockitem->nopen--;
        return;
    }

    remove_lockitem(lockitem);
}

EXPORTED int mboxname_islocked(const char *mboxname)
{
    struct mboxlocklist *lockitem = find_lockitem(mboxname);
    if (!lockitem) return 0;
    return lockitem->l.locktype;
}

EXPORTED struct mboxlock *mboxname_usernamespacelock(const char *mboxname)
{
    mbname_t *mbname = mbname_from_intname(mboxname);
    struct mboxlock *lock = user_namespacelock(mbname_userid(mbname));
    mbname_free(&mbname);
    return lock;
}

/******************** mbname stuff **********************/

static void _mbdirty(mbname_t *mbname)
{
    free(mbname->userid);
    free(mbname->intname);
    free(mbname->extname);
    free(mbname->recipient);

    mbname->userid = NULL;
    mbname->intname = NULL;
    mbname->extname = NULL;
    mbname->recipient = NULL;
}

EXPORTED void mbname_downcaseuser(mbname_t *mbname)
{
    _mbdirty(mbname);
    if (mbname->localpart) lcase(mbname->localpart);
    if (mbname->domain) lcase(mbname->domain);
}

EXPORTED void mbname_set_localpart(mbname_t *mbname, const char *localpart)
{
    _mbdirty(mbname);
    free(mbname->localpart);
    mbname->localpart = xstrdupnull(localpart);
}

EXPORTED void mbname_set_domain(mbname_t *mbname, const char *domain)
{
    _mbdirty(mbname);
    free(mbname->domain);
    mbname->domain = strcmpsafe(domain, config_defdomain) ? xstrdupnull(domain) : NULL;
}

EXPORTED void mbname_set_boxes(mbname_t *mbname, const strarray_t *boxes)
{
    _mbdirty(mbname);
    strarray_free(mbname->boxes);
    if (boxes)
        mbname->boxes = strarray_dup(boxes);
    else
        mbname->boxes = NULL;
}

EXPORTED void mbname_push_boxes(mbname_t *mbname, const char *item)
{
    _mbdirty(mbname);
    if (!mbname->boxes) mbname->boxes = strarray_new();
    strarray_push(mbname->boxes, item);
}

EXPORTED char *mbname_pop_boxes(mbname_t *mbname)
{
    _mbdirty(mbname);
    if (!mbname->boxes) mbname->boxes = strarray_new();
    return strarray_pop(mbname->boxes);
}

EXPORTED void mbname_truncate_boxes(mbname_t *mbname, size_t len)
{
    _mbdirty(mbname);
    if (!mbname->boxes) mbname->boxes = strarray_new();
    strarray_truncate(mbname->boxes, len);
}

EXPORTED void mbname_set_isdeleted(mbname_t *mbname, time_t isdel)
{
    _mbdirty(mbname);
    mbname->is_deleted = isdel;
}

EXPORTED mbname_t *mbname_from_userid(const char *userid)
{
    mbname_t *mbname = xzmalloc(sizeof(mbname_t));
    const char *p;

    if (!userid)
        return mbname;

    if (!*userid)
        return mbname; // empty string, *sigh*

    mbname->userid = xstrdup(userid); // may as well cache it

    p = strrchr(userid, '@');
    if (p) {
        mbname->localpart = xstrndup(userid, p - userid);
        const char *domain = p+1;
        mbname->domain = strcmpsafe(domain, config_defdomain) ? xstrdupnull(domain) : NULL;
    }
    else {
        mbname->localpart = xstrdup(userid);
    }

    return mbname;
}

EXPORTED mbname_t *mbname_from_recipient(const char *recipient, const struct namespace *ns)
{
    mbname_t *mbname = xzmalloc(sizeof(mbname_t));

    if (!recipient)
        return mbname;

    mbname->recipient = xstrdup(recipient); // may as well cache it
    mbname->extns = ns;

    const char *at = strrchr(recipient, '@');
    if (at) {
        mbname->localpart = xstrndup(recipient, at - recipient);
        const char *domain = at+1;
        if (config_virtdomains && strcmpsafe(domain, config_defdomain))
            mbname->domain = xstrdupnull(domain);
        /* otherwise we ignore domain entirely */
    }
    else {
        mbname->localpart = xstrdup(recipient);
    }

    char *plus = strchr(mbname->localpart, '+');
    if (plus) {
        char sep[2];
        sep[0] = ns->hier_sep;
        sep[1] = '\0';
        *plus = '\0';

        /* Encode mailbox name in IMAP UTF-7 */
        charset_t cs = charset_lookupname("utf-8");
        char *detail =
            charset_to_imaputf7(plus+1, strlen(plus+1), cs, ENCODING_NONE);

        mbname->boxes = strarray_split(detail, sep, /*flags*/0);

        charset_free(&cs);
        free(detail);
    }
    else
        mbname->boxes = strarray_new();

    return mbname;
}

EXPORTED mbname_t *mbname_from_extsub(const char *subfolder, const struct namespace *ns, const char *userid)
{
    mbname_t *mbname = mbname_from_userid(userid);

    if (!subfolder)
        return mbname;

    /* we know boxes isn't set already */
    assert(!mbname->boxes);
    char sep[2];
    sep[0] = ns->hier_sep;
    sep[1] = '\0';
    mbname->boxes = strarray_split(subfolder, sep, /*flags*/0);

    return mbname;
}

EXPORTED mbname_t *mbname_dup(const mbname_t *orig)
{
    mbname_t *mbname = xzmalloc(sizeof(mbname_t));

    mbname->localpart = xstrdupnull(orig->localpart);
    mbname->domain = xstrdupnull(orig->domain);
    mbname->is_deleted = orig->is_deleted;
    if (orig->boxes) mbname->boxes = strarray_dup(orig->boxes);

    return mbname;
}

static void _append_intbuf(struct buf *buf, const char *val)
{
    const char *p;
    for (p = val; *p; p++) {
        switch (*p) {
        case '.':
            buf_putc(buf, '^');
            break;
        default:
            buf_putc(buf, *p);
            break;
        }
    }
}

static strarray_t *_array_from_intname(strarray_t *a)
{
    int i;
    for (i = 0; i < strarray_size(a); i++) {
        char *p;
        for (p = a->data[i]; *p; p++) {
            switch (*p) {
            case '^':
                *p = '.';
                break;
            default:
                break;
            }
        }
    }
    return a;
}

static void _append_extbuf(const struct namespace *ns, struct buf *buf, const char *val)
{
    const char *p;
    int isuhs = (ns->hier_sep == '/');
    for (p = val; *p; p++) {
        switch (*p) {
        case '.':
            if (isuhs) buf_putc(buf, '.');
            else buf_putc(buf, '^');
            break;
        default:
            buf_putc(buf, *p);
            break;
        }
    }
}

static strarray_t *_array_from_extname(const struct namespace *ns, strarray_t *a)
{
    int i;
    int isuhs = (ns->hier_sep == '/');
    for (i = 0; i < strarray_size(a); i++) {
        char *p;
        for (p = a->data[i]; *p; p++) {
            switch (*p) {
            case '^':
                if (isuhs) goto err;
                else *p = '.';
                break;
            case '/':
                goto err;
            default:
                break;
            }
        }
    }
    return a;

err:
    strarray_free(a);
    return NULL;
}


EXPORTED mbname_t *mbname_from_intname(const char *intname)
{
    mbname_t *mbname = xzmalloc(sizeof(mbname_t));
    const char *p;

    if (!intname)
        return mbname;

    if (!*intname)
        return mbname; // empty string, *sigh*

    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);

    mbname->intname = xstrdup(intname); // may as well cache it

    p = strchr(intname, '!');
    if (p) {
        mbname->domain = xstrndup(intname, p - intname);
        if (!strcmpsafe(mbname->domain, config_defdomain)) {
            free(mbname->domain);
            mbname->domain = NULL;
        }
        intname = p+1;
    }

    mbname->boxes = _array_from_intname(strarray_split(intname, ".", 0));

    if (!strarray_size(mbname->boxes))
        return mbname;

    if (strarray_size(mbname->boxes) > 2 && !strcmpsafe(strarray_nth(mbname->boxes, 0), dp)) {
        free(strarray_shift(mbname->boxes));
        char *delval = strarray_pop(mbname->boxes);
        mbname->is_deleted = strtoul(delval, NULL, 16);
        free(delval);
    }

    if (strarray_size(mbname->boxes) > 1 && !strcmpsafe(strarray_nth(mbname->boxes, 0), "user")) {
        free(strarray_shift(mbname->boxes));
        mbname->localpart = strarray_shift(mbname->boxes);
    }

    return mbname;
}

EXPORTED mbname_t *mbname_from_extname(const char *extname, const struct namespace *ns, const char *userid)
{
    int crossdomains = config_getswitch(IMAPOPT_CROSSDOMAINS) && !ns->isadmin;
    int cdother = config_getswitch(IMAPOPT_CROSSDOMAINS_ONLYOTHER);
    /* old-school virtdomains requires admin to be a different domain than the userid */
    int admindomains = config_virtdomains && ns->isadmin;

    /* specialuse magic */
    if (extname && extname[0] == '\\') {
        char *intname = mboxlist_find_specialuse(extname, userid);
        mbname_t *mbname = mbname_from_intname(intname);
        free(intname);
        return mbname;
    }

    mbname_t *mbname = xzmalloc(sizeof(mbname_t));
    char sepstr[2];
    char *p = NULL;

    if (!extname)
        return mbname;

    if (!*extname)
        return mbname; // empty string, *sigh*

    sepstr[0] = ns->hier_sep;
    sepstr[1] = '\0';

    mbname->extname = xstrdup(extname); // may as well cache it

    mbname_t *userparts = mbname_from_userid(userid);

    if (admindomains) {
        p = strrchr(mbname->extname, '@');
        if (p) {
            *p = '\0';
            if (strcmpsafe(p+1, config_defdomain))
                mbname->domain = xstrdup(p+1);
        }
        else {
            // domain admin?
            mbname->domain = xstrdupnull(mbname_domain(userparts));
        }
    }
    else if (!crossdomains) {
        // non-crossdomains, we're always in the user's domain
        mbname->domain = xstrdupnull(mbname_domain(userparts));
    }

    mbname->boxes = _array_from_extname(ns, strarray_split(mbname->extname, sepstr, 0));

    if (p) *p = '@'; // rebuild extname for later use

    if (!mbname->boxes)
        goto done;

    if (!strarray_size(mbname->boxes))
        goto done;

    if (ns->isalt) {
        /* admin can't be in here, so we can ignore that :) - and hence also
         * the DELETED namespace */
        assert(!ns->isadmin);

        const char *toplevel = strarray_nth(mbname->boxes, 0);

        const char *up = config_getstring(IMAPOPT_USERPREFIX);
        const char *sp = config_getstring(IMAPOPT_SHAREDPREFIX);
        const char *ap = config_getstring(IMAPOPT_ALTPREFIX);

        if (!strcmpsafe(toplevel, ap)) {
            free(strarray_shift(mbname->boxes));

            /* everything belongs to the userid */
            mbname->localpart = xstrdupnull(mbname_localpart(userparts));
            /* otherwise it was done above */
            if (crossdomains) mbname->domain = xstrdupnull(mbname_domain(userparts));

            goto done;
        }

        else if (!strcmpsafe(toplevel, up)) {
            /* other user namespace */
            free(strarray_shift(mbname->boxes));
            mbname->localpart = strarray_shift(mbname->boxes);
            if (crossdomains && mbname->localpart) {
                char *p = strrchr(mbname->localpart, '@');
                if (p) {
                    *p = '\0';
                    if (strcmpsafe(p+1, config_defdomain))
                        mbname->domain = xstrdup(p+1);
                }
                else if (cdother) {
                    mbname->domain = xstrdupnull(mbname_domain(userparts));
                }
                /* otherwise it must be in defdomain.  Domains are
                 * always specified in crossdomains */
            }
            goto done;
        }

        else if (!strcmpsafe(toplevel, sp)) {
            /* shared namespace, no user */
            free(strarray_shift(mbname->boxes));
            if (crossdomains) {
                const char *toplevel = strarray_nth(mbname->boxes, 0);
                if (toplevel && strrchr(toplevel, '@')) {
                    char *p = (char *)strrchr(toplevel, '@');
                    *p = '\0';
                    if (strcmpsafe(p+1, config_defdomain))
                        mbname->domain = xstrdup(p+1);
                }
                else if (cdother) {
                    mbname->domain = xstrdupnull(mbname_domain(userparts));
                }
            }
            goto done;
        }

        /* everything else belongs to the userid */
        mbname->localpart = xstrdupnull(mbname_localpart(userparts));
        /* otherwise it was done above */
        if (crossdomains) mbname->domain = xstrdupnull(mbname_domain(userparts));
        /* special case INBOX case, because horrible */
        if (!strcasecmpsafe(toplevel, "INBOX")) {
            if (strarray_size(mbname->boxes) == 1) {
                free(strarray_shift(mbname->boxes));
            }
            else {
                /* force to upper case */
                char *p = (char *)toplevel;
                for (; *p; ++p)
                    *p = toupper(*p);
            }
        }

        goto done;
    }

    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);

    /* special inbox with insensitivity still, because horrible */
    if (!strcasecmpsafe(strarray_nth(mbname->boxes, 0), "INBOX")) {
        free(strarray_shift(mbname->boxes));
        mbname->localpart = xstrdupnull(mbname_localpart(userparts));
        /* otherwise it was done above */
        if (crossdomains) mbname->domain = xstrdupnull(mbname_domain(userparts));
        goto done;
    }

    /* deleted prefix first */
    if (ns->isadmin && !strcmpsafe(strarray_nth(mbname->boxes, 0), dp)) {
        free(strarray_shift(mbname->boxes));
        char *delval = strarray_pop(mbname->boxes);
        if (!delval)
            goto done;
        mbname->is_deleted = strtoul(delval, NULL, 16);
        free(delval);
    }

    if (!strarray_size(mbname->boxes))
        goto done;

    /* now look for user */
    if (!strcmpsafe(strarray_nth(mbname->boxes, 0), "user")) {
        free(strarray_shift(mbname->boxes));
        mbname->localpart = strarray_shift(mbname->boxes);
        if (crossdomains && mbname->localpart) {
            char *p = strrchr(mbname->localpart, '@');
            if (p) {
                *p = '\0';
                if (strcmpsafe(p+1, config_defdomain))
                    mbname->domain = xstrdup(p+1);
            }
            else if (cdother) {
                mbname->domain = xstrdupnull(mbname_domain(userparts));
            }
        }
        goto done;
    }

    /* shared folders: are in user's domain unless admin */
    if ((config_virtdomains && !ns->isadmin) || crossdomains) {
        free(mbname->domain);
        mbname->domain = xstrdupnull(mbname_domain(userparts));
    }

 done:
    mbname_free(&userparts);

    return mbname;
}

EXPORTED mbname_t *mbname_from_path(const char *path)
{
    int absolute = 0, relative = 0, r;
    mbname_t *mbname = NULL;
    mbentry_t *mbentry = NULL;
    const char *uid;

    /* Is the mailbox argument absolute or relative to cwd? */
    if (path[0] == '/') {
        absolute = 1;
    }
    else if (path[0] == '.') {
        relative = 1;
    }

    if (!relative) {
        uid = strrchr(path, '/');
        r = mboxlist_lookup_by_uniqueid(uid+1, &mbentry, NULL);
        if (!r) mbname = mbname_from_intname(mbentry->name);
    }
    if (relative || (!absolute && (r == IMAP_MAILBOX_NONEXISTENT))) {
        char cwd[MAX_MAILBOX_PATH+1];

        mboxlist_entry_free(&mbentry);

        /* Construct a mailbox relative to cwd */
        getcwd(cwd, MAX_MAILBOX_PATH);
        uid = strrchr(cwd, '/');
        if (uid) {
            /* Lookup current mailbox by uniqueid */
            r = mboxlist_lookup_by_uniqueid(uid+1, &mbentry, NULL);

            if (!r) {
                strarray_t *subs = NULL;
                int i;

                /* Build current mailbox name */
                mbname = mbname_from_intname(mbentry->name);

                if (relative) {
                    if (path[1] == '\0') {
                        /* Explicit . */
                        path += 1;
                    }
                    if (path[1] == '/') {
                        /* Explicit ./foo */
                        path += 2;
                    }
                    else {
                        while (path[0] == '.' && path[1] == '.' &&
                               (path[2] == '\0' || path[2] == '/')) {
                            /* Up to parent */
                            free(mbname_pop_boxes(mbname));
                            path += (path[2] == '/') ? 3 : 2;
                        }
                    }
                }

                /* Add submailbox(es) */
                subs = strarray_split(path, "/", 0);
                for (i = 0; i < strarray_size(subs); i++) {
                    mbname_push_boxes(mbname, strarray_nth(subs, i));
                }
                strarray_free(subs);
            }

        }
    }
    mboxlist_entry_free(&mbentry);

    return mbname ? mbname : xzmalloc(sizeof(mbname_t));
}

EXPORTED void mbname_free(mbname_t **mbnamep)
{
    mbname_t *mbname = *mbnamep;
    if (!mbname) return;

    *mbnamep = NULL;

    strarray_free(mbname->boxes);
    free(mbname->localpart);
    free(mbname->domain);

    /* cached values */
    free(mbname->userid);
    free(mbname->intname);
    free(mbname->extname);
    free(mbname->extuserid);
    free(mbname->recipient);

    /* thing itself */
    free(mbname);
}

EXPORTED char *mboxname_to_userid(const char *intname)
{
    mbname_t *mbname = mbname_from_intname(intname);
    char *res = xstrdupnull(mbname_userid(mbname));
    mbname_free(&mbname);
    return res;
}

EXPORTED char *mboxname_from_externalUTF8(const char *extname,
                                          const struct namespace *ns,
                                          const char *userid)
{
    char *intname, *freeme = NULL;

    if (config_getswitch(IMAPOPT_SIEVE_UTF8FILEINTO)) {
        charset_t cs = charset_lookupname("utf-8");
        if (cs == CHARSET_UNKNOWN_CHARSET) {
            /* huh? */
            syslog(LOG_INFO, "charset utf-8 is unknown");
            return NULL;
        }

        /* Encode mailbox name in IMAP UTF-7 */
        freeme = charset_to_imaputf7(extname, strlen(extname), cs, ENCODING_NONE);
        charset_free(&cs);

        if (!freeme) {
            syslog(LOG_ERR, "Could not convert mailbox name to IMAP UTF-7.");
            return NULL;
        }

        extname = freeme;
    }

    intname = mboxname_from_external(extname, ns, userid);
    free(freeme);

    return intname;
}

EXPORTED char *mboxname_from_external(const char *extname, const struct namespace *ns, const char *userid)
{
    mbname_t *mbname = mbname_from_extname(extname, ns, userid);
    char *res = xstrdupnull(mbname_intname(mbname));
    mbname_free(&mbname);
    return res;
}

EXPORTED char *mboxname_to_external(const char *intname, const struct namespace *ns, const char *userid)
{
    mbname_t *mbname = mbname_from_intname(intname);
    char *res = xstrdupnull(mbname_extname(mbname, ns, userid));
    mbname_free(&mbname);
    return res;
}

/* all mailboxes have an internal name representation, so this
 * function should never return a NULL.
 */
EXPORTED const char *mbname_intname(const mbname_t *mbname)
{
    if (mbname->intname)
        return mbname->intname;

    struct buf buf = BUF_INITIALIZER;
    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
    int sep = 0;
    int i;

    strarray_t *boxes = strarray_dup(mbname_boxes(mbname));

    if (mbname->domain) {
        buf_appendcstr(&buf, mbname->domain);
        buf_putc(&buf, '!');
    }

    if (mbname->is_deleted) {
        buf_appendcstr(&buf, dp);
        sep = 1;
    }

    if (mbname->localpart) {
        if (sep) buf_putc(&buf, '.');
        buf_appendcstr(&buf, "user.");
        _append_intbuf(&buf, mbname->localpart);
        sep = 1;
    }

    for (i = 0; i < strarray_size(boxes); i++) {
        if (sep) buf_putc(&buf, '.');
        _append_intbuf(&buf, strarray_nth(boxes, i));
        sep = 1;
    }

    if (mbname->is_deleted) {
        if (sep) buf_putc(&buf, '.');
        buf_printf(&buf, "%X", (unsigned)mbname->is_deleted);
        sep = 1;
    }

    mbname_t *backdoor = (mbname_t *)mbname;
    backdoor->intname = buf_release(&buf);

    strarray_free(boxes);

    return mbname->intname;
}

/* A userid may or may not have a domain - it's just localpart if the
 * domain is unspecified or config_defdomain.  It totally ignores any parts.
 * It's always NULL if there's no localpart
 */
EXPORTED const char *mbname_userid(const mbname_t *mbname)
{
    if (!mbname->localpart)
        return NULL;

    if (mbname->userid)
        return mbname->userid;

    struct buf buf = BUF_INITIALIZER;

    buf_appendcstr(&buf, mbname->localpart);

    if (mbname->domain) {
        buf_putc(&buf, '@');
        buf_appendcstr(&buf, mbname->domain);
    }

    mbname_t *backdoor = (mbname_t *)mbname;
    backdoor->userid = buf_release(&buf);

    return mbname->userid;
}

/* A "recipient" is a full username in external form (including domain) with an optional
 * +addressed mailbox in external form, no INBOX prefix (since they can only be mailboxes
 * owned by the user.
 *
 * shared folders (no user) are prefixed with a +, i.e. +shared@domain.com
 *
 * DELETED folders have no recipient, ever.
 */
EXPORTED const char *mbname_recipient(const mbname_t *mbname, const struct namespace *ns)
{
    if (mbname->is_deleted) return NULL;

    /* gotta match up! */
    if (mbname->recipient && ns == mbname->extns)
        return mbname->recipient;

    struct buf buf = BUF_INITIALIZER;

    if (mbname->localpart) {
        /* user mailbox */
        buf_appendcstr(&buf, mbname->localpart);
    }
    else {
        /* shared mailbox */
        buf_appendcstr(&buf, config_getstring(IMAPOPT_POSTUSER));
    }

    int i;
    for (i = 0; i < strarray_size(mbname->boxes); i++) {
        buf_putc(&buf, i ? ns->hier_sep : '+');
        buf_appendcstr(&buf, strarray_nth(mbname->boxes, i));
    }

    buf_putc(&buf, '@');
    buf_appendcstr(&buf, mbname->domain ? mbname->domain : config_defdomain);

    mbname_t *backdoor = (mbname_t *)mbname;
    free(backdoor->recipient);
    backdoor->recipient = buf_release(&buf);
    backdoor->extns = ns;

    return mbname->recipient;
}

/* This is one of the most complex parts of the code - generating an external
 * name based on the namespace, the 'isadmin' status, and of course the current
 * user.  There are some interesting things to look out for:
 *
 * Due to ambiguity, some names won't be representable in the external namespace,
 * so this function can return a NULL in those cases.
 */
EXPORTED int mbname_category(const mbname_t *mbname, const struct namespace *ns, const char *userid)
{
    if (!mbname_localpart(mbname)) return MBNAME_SHARED;
    if (mbname_isdeleted(mbname)) {
        if (strcmpsafe(mbname_userid(mbname), userid)) return MBNAME_OTHERDELETED;
        return MBNAME_OWNERDELETED;
    }

    if (strcmpsafe(mbname_userid(mbname), userid)) return MBNAME_OTHERUSER;

    const strarray_t *boxes = mbname_boxes(mbname);

    if (!strarray_size(boxes)) return MBNAME_INBOX;

    if (ns->isalt) {
        const char *toplevel = strarray_nth(boxes, 0);

        /* exact "INBOX" */
        if (!strcmpsafe(toplevel, "INBOX")) {
            if (strarray_size(boxes) == 1) return MBNAME_ALTINBOX;
            return MBNAME_INBOXSUB;
        }

        /* other "INBOX" spellings */
        if (!strcasecmpsafe(toplevel, "INBOX")) return MBNAME_ALTPREFIX;

        /* other prefixes that are special */
        if (!strcmpsafe(toplevel, config_getstring(IMAPOPT_USERPREFIX))) return MBNAME_ALTPREFIX;
        if (!strcmpsafe(toplevel, config_getstring(IMAPOPT_SHAREDPREFIX))) return MBNAME_ALTPREFIX;
        if (!strcmpsafe(toplevel, config_getstring(IMAPOPT_ALTPREFIX))) return MBNAME_ALTPREFIX;
    }

    /* everything else is owner */

    return MBNAME_OWNER;
}

EXPORTED const char *mbname_category_prefix(int category, const struct namespace *ns)
{
    if (ns->isalt) {
        switch (category) {
            case MBNAME_ALTINBOX:
                return config_getstring(IMAPOPT_ALTPREFIX);
            case MBNAME_OTHERUSER:
                return config_getstring(IMAPOPT_USERPREFIX);
            case MBNAME_SHARED:
                return config_getstring(IMAPOPT_SHAREDPREFIX);
            default:
                return NULL;
        }
    }
    else {
        if (category == MBNAME_OTHERUSER) return "user";
    }

    return NULL;
}

EXPORTED const char *mbname_extname(const mbname_t *mbname, const struct namespace *ns, const char *userid)
{
    int crossdomains = config_getswitch(IMAPOPT_CROSSDOMAINS) && !ns->isadmin;
    int cdother = config_getswitch(IMAPOPT_CROSSDOMAINS_ONLYOTHER);
    /* old-school virtdomains requires admin to be a different domain than the userid */
    int admindomains = config_virtdomains && ns->isadmin;

    /* gotta match up! */
    if (mbname->extname && ns == mbname->extns && !strcmpsafe(userid, mbname->extuserid))
        return mbname->extname;

    struct buf buf = BUF_INITIALIZER;

    /* have to zero out any existing value just in case we drop through */
    mbname_t *backdoor = (mbname_t *)mbname;
    if (backdoor->extname) {
        free(backdoor->extname);
        backdoor->extname = NULL;
        backdoor->extns = ns;
        free(backdoor->extuserid);
        backdoor->extuserid = xstrdupnull(userid);
    }

    mbname_t *userparts = mbname_from_userid(userid);
    strarray_t *boxes = strarray_dup(mbname_boxes(mbname));

    if (ns->isalt) {
        assert(!ns->isadmin);

        const char *up = config_getstring(IMAPOPT_USERPREFIX);
        const char *sp = config_getstring(IMAPOPT_SHAREDPREFIX);
        const char *ap = config_getstring(IMAPOPT_ALTPREFIX);

        /* DELETED mailboxes have no extname in alt namespace.
         * There's also no need to display domains unless in crossdomains,
         * because admins are never in altnamespace, and only admins can
         * see domains in the admindomains space */
        if (mbname->is_deleted)
            goto done;

        /* shared */
        if (!mbname_localpart(mbname)) {
            /* can't represent an empty mailbox */
            if (!strarray_size(boxes))
                goto done;

            const char *toplevel = strarray_nth(boxes, 0);

            if (strarray_size(boxes) == 1 && !strcmpsafe(toplevel, "user")) {
                /* special case user all by itself */
                buf_appendcstr(&buf, up);
                goto end;
            }
            buf_appendcstr(&buf, sp);
            buf_putc(&buf, ns->hier_sep);
            _append_extbuf(ns, &buf, toplevel);
            /* domains go on the top level folder */
            if (crossdomains) {
                const char *domain = mbname_domain(mbname);
                if (!cdother || strcmpsafe(domain, mbname_domain(userparts))) {
                    if (!domain) domain = config_defdomain;
                    buf_putc(&buf, '@');
                    _append_extbuf(ns, &buf, domain);
                }
            }
            int i;
            for (i = 1; i < strarray_size(boxes); i++) {
                buf_putc(&buf, ns->hier_sep);
                _append_extbuf(ns, &buf, strarray_nth(boxes, i));
            }
            goto end;
        }

        /* other users */
        if (strcmpsafe(mbname_userid(mbname), userid)) {
            buf_appendcstr(&buf, up);
            buf_putc(&buf, ns->hier_sep);
            _append_extbuf(ns, &buf, mbname_localpart(mbname));
            if (crossdomains) {
                const char *domain = mbname_domain(mbname);
                if (!cdother || strcmpsafe(domain, mbname_domain(userparts))) {
                    if (!domain) domain = config_defdomain;
                    buf_putc(&buf, '@');
                    _append_extbuf(ns, &buf, domain);
                }
            }
            int i;
            for (i = 0; i < strarray_size(boxes); i++) {
                buf_putc(&buf, ns->hier_sep);
                _append_extbuf(ns, &buf, strarray_nth(boxes, i));
            }
            goto end;
        }

        /* own user */
        if (!strarray_size(boxes)) {
            buf_appendcstr(&buf, "INBOX");
            goto end;
        }

        const char *toplevel = strarray_nth(boxes, 0);
        /* INBOX is very special, because it can only be represented with exact case,
         * and it skips a level. Everything else including allcaps INBOX goes into
         * the Alt Prefix */
        if (!strcasecmpsafe(toplevel, "INBOX")) {
            if (strarray_size(boxes) == 1 || strcmpsafe(toplevel, "INBOX")) {
                buf_appendcstr(&buf, ap);
                buf_putc(&buf, ns->hier_sep);
            }
        }
        /* likewise anything exactly matching the user, alt or shared prefixes, both top level
         * or with children goes into alt prefix */
        else if (!strcmpsafe(toplevel, up) || !strcmpsafe(toplevel, sp) || !strcmpsafe(toplevel, ap)) {
            buf_appendcstr(&buf, ap);
            buf_putc(&buf, ns->hier_sep);
        }

         _append_extbuf(ns, &buf, toplevel);

        int i;
        for (i = 1; i < strarray_size(boxes); i++) {
           buf_putc(&buf, ns->hier_sep);
            _append_extbuf(ns, &buf, strarray_nth(boxes, i));
        }

        goto end;
    }

    if (mbname->is_deleted) {
        buf_appendcstr(&buf, config_getstring(IMAPOPT_DELETEDPREFIX));
        buf_putc(&buf, ns->hier_sep);
    }

    /* shared */
    if (!mbname_localpart(mbname)) {
        /* invalid names - not sure it's even possible, but hey */
        if (!strarray_size(boxes))
            goto done;
        if (!strcasecmpsafe(strarray_nth(boxes, 0), "INBOX"))
            goto done;

        /* shared folders can ONLY be in the same domain except for admin */
        if (!admindomains && strcmpsafe(mbname_domain(mbname), mbname_domain(userparts)))
            goto done;

        /* note "user" precisely appears here, but no need to special case it
         * since the output is the same */
        int i;
        for (i = 0; i < strarray_size(boxes); i++) {
            if (i) buf_putc(&buf, ns->hier_sep);
            _append_extbuf(ns, &buf, strarray_nth(boxes, i));
        }

        goto end;
    }

    /* other users or DELETED */
    if (mbname->is_deleted || strcmpsafe(mbname_userid(mbname), userid)) {
        buf_appendcstr(&buf, "user");
        buf_putc(&buf, ns->hier_sep);
        _append_extbuf(ns, &buf, mbname_localpart(mbname));
        if (crossdomains) {
            const char *domain = mbname_domain(mbname);
            if (!cdother || strcmpsafe(domain, mbname_domain(userparts))) {
                if (!domain) domain = config_defdomain;
                buf_putc(&buf, '@');
                _append_extbuf(ns, &buf, domain);
            }
        }
        /* shared folders can ONLY be in the same domain except for admin */
        else if (!admindomains && strcmpsafe(mbname_domain(mbname), mbname_domain(userparts)))
            goto done;
        int i;
        for (i = 0; i < strarray_size(boxes); i++) {
            buf_putc(&buf, ns->hier_sep);
            _append_extbuf(ns, &buf, strarray_nth(boxes, i));
        }
        goto end;
    }

    buf_appendcstr(&buf, "INBOX");
    int i;
    for (i = 0; i < strarray_size(boxes); i++) {
       buf_putc(&buf, ns->hier_sep);
       _append_extbuf(ns, &buf, strarray_nth(boxes, i));
    }

 end:

    /* note: kinda bogus in altnamespace, meh */
    if (mbname->is_deleted) {
        buf_putc(&buf, ns->hier_sep);
        buf_printf(&buf, "%X", (unsigned)mbname->is_deleted);
    }

    if (admindomains && mbname_domain(mbname)) {
        buf_putc(&buf, '@');
        buf_appendcstr(&buf, mbname_domain(mbname));
    }

    backdoor->extname = buf_release(&buf);

 done:

    buf_free(&buf);
    mbname_free(&userparts);
    strarray_free(boxes);

    return mbname->extname;
}

EXPORTED const char *mbname_domain(const mbname_t *mbname)
{
    return mbname->domain;
}

EXPORTED const char *mbname_localpart(const mbname_t *mbname)
{
    return mbname->localpart;
}

EXPORTED time_t mbname_isdeleted(const mbname_t *mbname)
{
    return mbname->is_deleted;
}

EXPORTED const strarray_t *mbname_boxes(const mbname_t *mbname)
{
    if (!mbname->boxes) {
        mbname_t *backdoor = (mbname_t *)mbname;
        backdoor->boxes = strarray_new();
    }
    return mbname->boxes;
}

/*
 * Create namespace based on config options.
 */
EXPORTED int mboxname_init_namespace(struct namespace *namespace, int isadmin)
{
    const char *prefix;

    assert(namespace != NULL);

    namespace->isadmin = isadmin;

    namespace->hier_sep =
        config_getswitch(IMAPOPT_UNIXHIERARCHYSEP) ? '/' : '.';
    namespace->isalt = !isadmin && config_getswitch(IMAPOPT_ALTNAMESPACE);

    namespace->accessible[NAMESPACE_INBOX] = 1;
    namespace->accessible[NAMESPACE_USER] = !config_getswitch(IMAPOPT_DISABLE_USER_NAMESPACE);
    namespace->accessible[NAMESPACE_SHARED] = !config_getswitch(IMAPOPT_DISABLE_SHARED_NAMESPACE);

    if (namespace->isalt) {
        /* alternate namespace */
        strcpy(namespace->prefix[NAMESPACE_INBOX], "");

        prefix = config_getstring(IMAPOPT_USERPREFIX);
        if (!prefix || strlen(prefix) == 0 ||
            strlen(prefix) >= MAX_NAMESPACE_PREFIX ||
            strchr(prefix,namespace->hier_sep) != NULL)
            return IMAP_NAMESPACE_BADPREFIX;
        sprintf(namespace->prefix[NAMESPACE_USER], "%.*s%c",
                MAX_NAMESPACE_PREFIX-1, prefix, namespace->hier_sep);

        prefix = config_getstring(IMAPOPT_SHAREDPREFIX);
        if (!prefix || strlen(prefix) == 0 ||
            strlen(prefix) >= MAX_NAMESPACE_PREFIX ||
            strchr(prefix, namespace->hier_sep) != NULL ||
            !strncmp(namespace->prefix[NAMESPACE_USER], prefix, strlen(prefix)))
            return IMAP_NAMESPACE_BADPREFIX;

        if (!isadmin) {
            sprintf(namespace->prefix[NAMESPACE_SHARED], "%.*s%c",
                MAX_NAMESPACE_PREFIX-1, prefix, namespace->hier_sep);
        }
    }

    else {
        /* standard namespace */
        sprintf(namespace->prefix[NAMESPACE_INBOX], "%s%c",
                "INBOX", namespace->hier_sep);
        sprintf(namespace->prefix[NAMESPACE_USER], "%s%c",
                "user", namespace->hier_sep);
        strcpy(namespace->prefix[NAMESPACE_SHARED], "");
    }

    return 0;
}

EXPORTED struct namespace *mboxname_get_adminnamespace()
{
    static struct namespace ns;
    if (!admin_namespace) {
        mboxname_init_namespace(&ns, /*isadmin*/1);
        admin_namespace = &ns;
    }
    return admin_namespace;
}

/*
 * Return nonzero if 'userid' owns the (internal) mailbox 'name'.
 */
EXPORTED int mboxname_userownsmailbox(const char *userid, const char *name)
{
    mbname_t *mbname = mbname_from_intname(name);
    int res = !strcmpsafe(mbname_userid(mbname), userid);
    mbname_free(&mbname);

    return res;
}

/*
 * If (internal) mailbox 'name' is a user's mailbox (optionally INBOX),
 * returns 1, otherwise returns 0.
 */
EXPORTED int mboxname_isusermailbox(const char *name, int isinbox)
{
    mbname_t *mbname = mbname_from_intname(name);
    int res = 0;

    if (mbname_localpart(mbname) && !mbname_isdeleted(mbname)) {
        if (!isinbox || !strarray_size(mbname_boxes(mbname)))
            res = 1;
    }

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a user's Trash folder returns 1,
 * otherwise returns 0
 * XXX: use roles rather than hard coded name?
 */
EXPORTED int mboxname_isusertrash(const char *name)
{
    mbname_t *mbname = mbname_from_intname(name);
    int res = 0;

    if (mbname_localpart(mbname) && !mbname_isdeleted(mbname)) {
        const strarray_t *boxes = mbname_boxes(mbname);
        if (strarray_size(boxes) == 1 && !strcmpsafe(strarray_nth(boxes, 0), "Trash"))
            res = 1;
    }

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a DELETED mailbox
 * returns boolean
 */
EXPORTED int mboxname_isdeletedmailbox(const char *name, time_t *timestampp)
{
    mbname_t *mbname = mbname_from_intname(name);
    time_t res = mbname_isdeleted(mbname);
    mbname_free(&mbname);

    if (timestampp)
        *timestampp = res;

    return res ? 1 : 0;
}

/*
 * If (internal) mailbox 'name' is a CALENDAR mailbox
 * returns boolean
 */
EXPORTED int mboxname_iscalendarmailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_CALENDAR) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a ADDRESSBOOK mailbox
 * returns boolean
 */
EXPORTED int mboxname_isaddressbookmailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_ADDRESSBOOK) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_ADDRESSBOOKPREFIX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a DAVDRIVE mailbox
 * returns boolean
 */
EXPORTED int mboxname_isdavdrivemailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_COLLECTION) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_DAVDRIVEPREFIX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a DAVNOTIFICATIONS mailbox
 * returns boolean
 */
EXPORTED int mboxname_isdavnotificationsmailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_COLLECTION) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a JMAPNOTIFICATIONS mailbox
 * returns boolean
 */
EXPORTED int mboxname_isjmapnotificationsmailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_JMAPNOTIFY) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_JMAPNOTIFICATIONFOLDER);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a user's "Notes" mailbox
 * returns boolean
 */
EXPORTED int mboxname_isnotesmailbox(const char *name, int mbtype __attribute__((unused)))
{
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_NOTESMAILBOX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a user's #jmapsubmission mailbox
 * returns boolean
 */
EXPORTED int mboxname_issubmissionmailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_JMAPSUBMIT) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_JMAPSUBMISSIONFOLDER);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a user's #jmappushsubscription mailbox
 * returns boolean
 */
EXPORTED int mboxname_ispushsubscriptionmailbox(const char *name, int mbtype)
{
    if (mbtype_isa(mbtype) == MBTYPE_JMAPPUSHSUB) return 1;  /* Only works on backends */
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_JMAPPUSHSUBSCRIPTIONFOLDER);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

/*
 * If (internal) mailbox 'name' is a user's #jmap upload mailbox
 * returns boolean
 */
EXPORTED int mboxname_isjmapuploadmailbox(const char *name, int mbtype __attribute__((unused)))
{
    int res = 0;

    mbname_t *mbname = mbname_from_intname(name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_JMAPUPLOADFOLDER);

    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0)))
        res = 1;

    mbname_free(&mbname);
    return res;
}

EXPORTED char *mboxname_user_mbox(const char *userid, const char *subfolder)
{
    if (!userid) return NULL;

    mbname_t *mbname = mbname_from_userid(userid);

    if (subfolder) {
        strarray_t *bits = strarray_split(subfolder, ".", 0);
        mbname_set_boxes(mbname, bits);
        strarray_free(bits);
    }

    char *res = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);

    return res;
}

EXPORTED char *mboxname_abook(const char *userid, const char *collection)
{
    mbname_t *mbname = mbname_from_userid(userid);

    mbname_push_boxes(mbname, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    if (collection) mbname_push_boxes(mbname, collection);

    char *res = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);

    return res;
}

EXPORTED char *mboxname_cal(const char *userid, const char *collection)
{
    mbname_t *mbname = mbname_from_userid(userid);

    mbname_push_boxes(mbname, config_getstring(IMAPOPT_CALENDARPREFIX));
    if (collection) mbname_push_boxes(mbname, collection);

    char *res = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);

    return res;
}

/*
 * Check whether two parts have the same userid.
 * Returns: 1 if the userids are the same, 0 if not.
 */
EXPORTED int mbname_same_userid(const mbname_t *a, const mbname_t *b)
{
    int r;

    r = strcmpsafe(a->domain, b->domain);
    if (!r)
        r = strcmpsafe(a->localpart, b->localpart);
    return !r;
}

/*
 * Check whether two mboxnames have the same userid.
 * Needed for some corner cases in the COPY command.
 * Returns: 1 if the userids are the same, 0 if not,
 *          or negative error.
 */
EXPORTED int mboxname_same_userid(const char *name1, const char *name2)
{
    int r;
    mbname_t *p1 = mbname_from_intname(name1);
    mbname_t *p2 = mbname_from_intname(name2);

    r = mbname_same_userid(p1, p2);

    mbname_free(&p1);
    mbname_free(&p2);

    return r;
}

/*
 * Apply site policy restrictions on mailbox names.
 * Restrictions are hardwired for now.
 * NOTE: '^' is '.' externally in unixhs, and invalid in unixhs
 *
 * The set of printable chars that are not in GOODCHARS are:
 *    !"%&/;<>\`{|}
 */
#define GOODCHARS " #$'()*+,-.0123456789:=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz~"
EXPORTED int mboxname_policycheck(const char *name)
{
    const char *p;
    int sawutf7 = 0;
    unsigned c1, c2, c3, c4, c5, c6, c7, c8;
    int ucs4;
    int namelen = strlen(name);
    int hasdom = 0;

    /* We reserve mailboxes.db keys beginning with $ for internal use
     * (e.g. $RACL), so don't allow a real mailbox to sneak in there.
     *
     * N.B This is only forbidden at the absolute top of the internal
     * namespace: stuff like "user.foo.$bar", "domain!user.foo.$bar",
     * "domain!$bar", and even "user.$bar" are all still valid here,
     * because none of those names start with $, and won't conflict.
     */
    if (name[0] == '$')
        return IMAP_MAILBOX_BADNAME;

    /* Skip policy check on mailbox created in delayed delete namespace
     * assuming the mailbox existed before and was OK then.
     * This should allow mailboxes that are extremely long to be
     * deleted when delayed_delete is enabled.
     * A thorough fix might remove the prefix and timestamp
     * then continue with the check
     */
    if (mboxname_isdeletedmailbox(name, NULL))
        return 0;

    if (namelen > MAX_MAILBOX_NAME)
        return IMAP_MAILBOX_BADNAME;

    /* find the virtual domain, if any.  We don't sanity check domain
       names yet - maybe we should */
    p = strchr(name, '!');
    if (p) {
        if (config_virtdomains) {
            name = p + 1;
            namelen = strlen(name);
            hasdom = 1;
        }
        else
            return IMAP_MAILBOX_BADNAME;
    }

    /* bad mbox patterns */
    // empty name
    if (!name[0]) return IMAP_MAILBOX_BADNAME;
    // leading dot
    if (name[0] == '.') return IMAP_MAILBOX_BADNAME;
    // leading ~
    if (name[0] == '~') return IMAP_MAILBOX_BADNAME;
    // trailing dot
    if (name[namelen-1] == '.') return IMAP_MAILBOX_BADNAME;
    // double dot (zero length path item)
    if (strstr(name, "..")) return IMAP_MAILBOX_BADNAME;
    // non-" " whitespace
    if (strchr(name, '\r')) return IMAP_MAILBOX_BADNAME;
    if (strchr(name, '\n')) return IMAP_MAILBOX_BADNAME;
    if (strchr(name, '\t')) return IMAP_MAILBOX_BADNAME;
    // top level user
    if (!strcmp(name, "user")) return IMAP_MAILBOX_BADNAME;
    // special users
    if (!strcmp(name, "user.anyone")) return IMAP_MAILBOX_BADNAME;
    if (!strcmp(name, "user.anonymous")) return IMAP_MAILBOX_BADNAME;
    // redundant but explicit ban on userids starting with '%'
    // (would conflict with backups of shared mailboxes)
    if (!strncmp(name, "user.%", 6)) return IMAP_MAILBOX_BADNAME;

    while (*name) {
        if (*name == '&') {
            /* Modified UTF-7 */
            name++;
            while (*name != '-') {
                if (sawutf7) {
                    /* Two adjacent utf7 sequences */
                    return IMAP_MAILBOX_BADNAME;
                }

                if ((c1 = CHARMOD64(*name++)) == XX ||
                    (c2 = CHARMOD64(*name++)) == XX ||
                    (c3 = CHARMOD64(*name++)) == XX) {
                    /* Non-base64 character */
                    return IMAP_MAILBOX_BADNAME;
                }
                ucs4 = (c1 << 10) | (c2 << 4) | (c3 >> 2);
                if ((ucs4 & 0xff80) == 0) {
                    /* US-ASCII character */
                    return IMAP_MAILBOX_BADNAME;
                }
                if (*name == '-') {
                    /* Trailing bits not zero */
                    if (c3 & 0x03) return IMAP_MAILBOX_BADNAME;

                    /* End of UTF-7 sequence */
                    break;
                }

                if ((c4 = CHARMOD64(*name++)) == XX ||
                    (c5 = CHARMOD64(*name++)) == XX ||
                    (c6 = CHARMOD64(*name++)) == XX) {
                    /* Non-base64 character */
                    return IMAP_MAILBOX_BADNAME;
                }
                ucs4 = ((c3 & 0x03) << 14) | (c4 << 8) | (c5 << 2) | (c6 >> 4);
                if ((ucs4 & 0xff80) == 0) {
                    /* US-ASCII character */
                    return IMAP_MAILBOX_BADNAME;
                }
                if (*name == '-') {
                    /* Trailing bits not zero */
                    if (c6 & 0x0f) return IMAP_MAILBOX_BADNAME;

                    /* End of UTF-7 sequence */
                    break;
                }

                if ((c7 = CHARMOD64(*name++)) == XX ||
                    (c8 = CHARMOD64(*name++)) == XX) {
                    /* Non-base64 character */
                    return IMAP_MAILBOX_BADNAME;
                }
                ucs4 = ((c6 & 0x0f) << 12) | (c7 << 6) | c8;
                if ((ucs4 & 0xff80) == 0) {
                    /* US-ASCII character */
                    return IMAP_MAILBOX_BADNAME;
                }
            }

            if (name[-1] == '&') sawutf7 = 0; /* '&-' is sequence for '&' */
            else sawutf7 = 1;

            name++;             /* Skip over terminating '-' */
        }
        else {
            if (!(strchr(GOODCHARS, *name) || (hasdom && *name == '!')))
                return IMAP_MAILBOX_BADNAME;
            name++;
            sawutf7 = 0;
        }
    }
    return 0;
}

EXPORTED int mboxname_is_prefix(const char *longstr, const char *shortstr)
{
    int longlen = strlen(longstr);
    int shortlen = strlen(shortstr);

    /* can't be a child */
    if (longlen < shortlen)
        return 0;

    /* don't match along same length */
    if (strncmp(longstr, shortstr, shortlen))
        return 0;

    /* longer, and not a separator */
    if (longlen > shortlen && longstr[shortlen] != '.')
        return 0;

    /* it's a match! */
    return 1;
}


EXPORTED void mboxname_hash(char *dest, size_t destlen,
                            const char *root,
                            const char *name)
{
    mbname_t *mbname = mbname_from_intname(name);
    struct buf buf = BUF_INITIALIZER;

    buf_setcstr(&buf, root);

    const char *domain = mbname_domain(mbname);
    strarray_t *boxes = strarray_dup(mbname_boxes(mbname));

    if (domain) {
        if (config_hashimapspool) {
            char c = dir_hash_c(domain, config_fulldirhash);
            buf_printf(&buf, "%s%c/%s", FNAME_DOMAINDIR, c, domain);
        }
        else {
            buf_printf(&buf, "%s%s", FNAME_DOMAINDIR, domain);
        }
    }

    if (mbname_localpart(mbname)) {
        strarray_unshift(boxes, mbname_localpart(mbname));
        strarray_unshift(boxes, "user");
    }
    if (mbname_isdeleted(mbname)) {
        struct buf dbuf = BUF_INITIALIZER;
        buf_printf(&dbuf, "%X", (unsigned)mbname_isdeleted(mbname));
        strarray_unshift(boxes, config_getstring(IMAPOPT_DELETEDPREFIX));
        strarray_push(boxes, buf_cstring(&dbuf));
        buf_free(&dbuf);
    }

    if (config_hashimapspool && strarray_size(boxes)) {
        const char *idx = strarray_size(boxes) > 1 ? strarray_nth(boxes, 1) : strarray_nth(boxes, 0);
        char c = dir_hash_c(idx, config_fulldirhash);
        buf_printf(&buf, "/%c", c);
    }

    int i;
    for (i = 0; i < strarray_size(boxes); i++) {
        buf_putc(&buf, '/');
        _append_intbuf(&buf, strarray_nth(boxes, i));
    }

    /* for now, keep API even though we're doing a buffer inside here */
    strncpy(dest, buf_cstring(&buf), destlen);

    buf_free(&buf);
    strarray_free(boxes);
    mbname_free(&mbname);
}

EXPORTED void mboxname_id_hash(char *dest, size_t destlen,
                               const char *root,
                               const char *id)
{
    struct buf buf = BUF_INITIALIZER;

    if (root) buf_printf(&buf, "%s/uuid/%c/%c/%s", root, id[0], id[1], id);
    else buf_printf(&buf, "uuid/%c/%c/%s", id[0], id[1], id);

    /* for now, keep API even though we're doing a buffer inside here */
    strncpy(dest, buf_cstring(&buf), destlen);

    buf_free(&buf);
}

/* note: mboxname must be internal */
EXPORTED char *mboxname_datapath(const char *partition,
                                 const char *mboxname,
                                 const char *uniqueid,
                                 unsigned long uid)
{
    static char pathresult[MAX_MAILBOX_PATH+1];
    const char *root;

    if (!partition) return NULL;

    root = config_partitiondir(partition);
    if (!root) return NULL;

    if (!mboxname) {
        xstrncpy(pathresult, root, MAX_MAILBOX_PATH);
        return pathresult;
    }

    if (uniqueid) {
        /* Mailbox dir by uniqueid */
        mboxname_id_hash(pathresult, MAX_MAILBOX_PATH, root, uniqueid);
    }
    else {
        /* Legacy mailbox dir by mboxname */
        mboxname_hash(pathresult, MAX_MAILBOX_PATH, root, mboxname);
    }

    if (uid) {
        int len = strlen(pathresult);
        snprintf(pathresult + len, MAX_MAILBOX_PATH - len, "/%lu.", uid);
    }
    pathresult[MAX_MAILBOX_PATH] = '\0';

    if (strlen(pathresult) == MAX_MAILBOX_PATH)
        return NULL;

    return pathresult;
}

/* note: mboxname must be internal */
EXPORTED char *mboxname_archivepath(const char *partition,
                                    const char *mboxname,
                                    const char *uniqueid,
                                    unsigned long uid)
{
    static char pathresult[MAX_MAILBOX_PATH+1];
    const char *root;

    if (!partition) return NULL;

    root = config_archivepartitiondir(partition);
    if (!root) root = config_partitiondir(partition);
    if (!root) return NULL;

    /* XXX - dedup with datapath above - but make sure to keep the results
     * in separate buffers and/or audit the callers */
    if (!mboxname) {
        xstrncpy(pathresult, root, MAX_MAILBOX_PATH);
        return pathresult;
    }

    if (uniqueid) {
        /* Mailbox dir by uniqueid */
        mboxname_id_hash(pathresult, MAX_MAILBOX_PATH, root, uniqueid);
    }
    else {
        /* Legacy mailbox dir by mboxname */
        mboxname_hash(pathresult, MAX_MAILBOX_PATH, root, mboxname);
    }

    if (uid) {
        int len = strlen(pathresult);
        snprintf(pathresult + len, MAX_MAILBOX_PATH - len, "/%lu.", uid);
    }
    pathresult[MAX_MAILBOX_PATH] = '\0';

    if (strlen(pathresult) == MAX_MAILBOX_PATH)
        return NULL;

    return pathresult;
}

char *mboxname_lockpath(const char *mboxname)
{
    return mboxname_lockpath_suffix(mboxname, ".lock");
}

char *mboxname_lockpath_suffix(const char *mboxname,
                               const char *suffix)
{
    static char lockresult[MAX_MAILBOX_PATH+1];
    char basepath[MAX_MAILBOX_PATH+1];
    const char *root = config_getstring(IMAPOPT_MBOXNAME_LOCKPATH);
    int len;

    if (!root) {
        snprintf(basepath, MAX_MAILBOX_PATH, "%s/lock", config_dir);
        root = basepath;
    }

    mboxname_hash(lockresult, MAX_MAILBOX_PATH, root, mboxname);

    len = strlen(lockresult);
    snprintf(lockresult + len, MAX_MAILBOX_PATH - len, "%s", suffix);
    lockresult[MAX_MAILBOX_PATH] = '\0';

    if (strlen(lockresult) == MAX_MAILBOX_PATH)
        return NULL;

    return lockresult;
}

EXPORTED char *mboxname_metapath(const char *partition,
                                 const char *mboxname,
                                 const char *uniqueid,
                                 int metafile,
                                 int isnew)
{
    static char metaresult[MAX_MAILBOX_PATH];
    int metaflag = 0;
    int archiveflag = 0;
    const char *root = NULL;
    const char *filename = NULL;
    char confkey[256];

    if (!partition) return NULL;

    *confkey = '\0';

    switch (metafile) {
    case META_HEADER:
        snprintf(confkey, 256, "metadir-header-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_HEADER;
        filename = FNAME_HEADER;
        break;
    case META_INDEX:
        snprintf(confkey, 256, "metadir-index-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_INDEX;
        filename = FNAME_INDEX;
        break;
    case META_CACHE:
        snprintf(confkey, 256, "metadir-cache-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_CACHE;
        filename = FNAME_CACHE;
        break;
    case META_EXPUNGE:
        /* not movable, it's only old */
        metaflag = IMAP_ENUM_METAPARTITION_FILES_EXPUNGE;
        filename = FNAME_EXPUNGE;
        break;
    case META_SQUAT:
        snprintf(confkey, 256, "metadir-squat-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_SQUAT;
        filename = FNAME_SQUAT;
        break;
    case META_ANNOTATIONS:
        snprintf(confkey, 256, "metadir-index-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_ANNOTATIONS;
        filename = FNAME_ANNOTATIONS;
        break;
#ifdef WITH_DAV
    case META_DAV:
        snprintf(confkey, 256, "metadir-dav-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_DAV;
        filename = FNAME_DAV;
        break;
#endif
    case META_ARCHIVECACHE:
        snprintf(confkey, 256, "metadir-archivecache-%s", partition);
        metaflag = IMAP_ENUM_METAPARTITION_FILES_ARCHIVECACHE;
        filename = FNAME_CACHE;
        archiveflag = 1;
        break;
    case 0:
        break;
    default:
        fatal("Unknown meta file requested", EX_SOFTWARE);
    }

    if (*confkey)
        root = config_getoverflowstring(confkey, NULL);

    if (!root && (!metaflag || (config_metapartition_files & metaflag)))
        root = config_metapartitiondir(partition);

    if (!root && archiveflag)
        root = config_archivepartitiondir(partition);

    if (!root)
        root = config_partitiondir(partition);

    if (!root)
        return NULL;

    if (!mboxname) {
        xstrncpy(metaresult, root, MAX_MAILBOX_PATH);
        return metaresult;
    }

    if (uniqueid) {
        /* Mailbox dir by uniqueid */
        mboxname_id_hash(metaresult, MAX_MAILBOX_PATH, root, uniqueid);
    }
    else {
        /* Legacy mailbox dir by mboxname */
        mboxname_hash(metaresult, MAX_MAILBOX_PATH, root, mboxname);
    }

    if (filename) {
        int len = strlen(metaresult);
        if (isnew)
            snprintf(metaresult + len, MAX_MAILBOX_PATH - len, "%s.NEW", filename);
        else
            snprintf(metaresult + len, MAX_MAILBOX_PATH - len, "%s", filename);
    }

    if (strlen(metaresult) >= MAX_MAILBOX_PATH)
        return NULL;

    return metaresult;
}

EXPORTED void mboxname_todeleted(const char *name, char *result, int withtime)
{
    int domainlen = 0;
    char *p;
    const char *deletedprefix = config_getstring(IMAPOPT_DELETEDPREFIX);

    xstrncpy(result, name, MAX_MAILBOX_BUFFER);

    if (config_virtdomains && (p = strchr(name, '!')))
        domainlen = p - name + 1;

    if (withtime) {
        struct timeval tv;
        gettimeofday( &tv, NULL );
        snprintf(result+domainlen, MAX_MAILBOX_BUFFER-domainlen, "%s.%s.%X",
                 deletedprefix, name+domainlen, (unsigned) tv.tv_sec);
    } else {
        snprintf(result+domainlen, MAX_MAILBOX_BUFFER-domainlen, "%s.%s",
                 deletedprefix, name+domainlen);
    }
}

EXPORTED int mboxname_make_parent(char *name)
{
    int domainlen = 0;
    char *p;

    if (config_virtdomains && (p = strchr(name, '!')))
        domainlen = p - name + 1;

    if (!name[0] || !strcmp(name+domainlen, "user"))
        return 0;                               /* stop now */

    p = strrchr(name, '.');

    if (p && (p - name > domainlen))            /* don't split subdomain */
        *p = '\0';
    else if (!name[domainlen])                  /* server entry */
        name[0] = '\0';
    else                                        /* domain entry */
        name[domainlen] = '\0';

    return 1;
}

EXPORTED int mboxname_contains_parent(const char *mboxname, const char *prev)
{
    /* no names, definitely can't be parent! */
    if (!mboxname) return 0;
    if (!prev) return 0;

    char *parent = xstrdup(mboxname);

    /* this mailbox is just "user"? prev will always contain that */
    if (!mboxname_make_parent(parent)) {
        free(parent);
        return 1;
    }

    if (mboxname_is_prefix(prev, parent)) {
        /* it's not different?  Great - there's no missing intermediate */
        free(parent);
        return 1;
    }

    /* OK, it doesn't contain the parent for sure */
    free(parent);
    return 0;
}

/* NOTE: caller must free, which is different from almost every
 * other interface in the whole codebase.  Grr */
EXPORTED char *mboxname_conf_getpath(const mbname_t *mbname, const char *suffix)
{
    char *fname = NULL;
    char c[2], d[2];

    if (mbname->localpart) {
        char *mboxname = mboxname_user_mbox(mbname_userid(mbname), NULL);
        mbentry_t *mbentry = NULL;

        int r = mboxlist_lookup_allow_all(mboxname, &mbentry, NULL);
        free(mboxname);

        if (!r && !(mbentry->mbtype & MBTYPE_LEGACY_DIRS)) {
            char path[MAX_MAILBOX_PATH+1];

            mboxname_id_hash(path, MAX_MAILBOX_PATH, NULL, mbentry->uniqueid);

            if (suffix) {
                fname = strconcat(config_dir,
                                  FNAME_USERDIR,
                                  path, "/", suffix, ".db",
                                  (char *)NULL);
            }
            else {
                fname = strconcat(config_dir,
                                  FNAME_USERDIR,
                                  path,
                                  (char *)NULL);
            }
        }
        else if (mbname->domain) {
            if (suffix) {
                fname = strconcat(config_dir,
                                  FNAME_DOMAINDIR,
                                  dir_hash_b(mbname->domain, config_fulldirhash, d),
                                  "/", mbname->domain,
                                  FNAME_USERDIR,
                                  dir_hash_b(mbname->localpart, config_fulldirhash, c),
                                  "/", mbname->localpart, ".", suffix,
                                  (char *)NULL);
            }
            else {
                fname = strconcat(config_dir,
                                  FNAME_DOMAINDIR,
                                  dir_hash_b(mbname->domain, config_fulldirhash, d),
                                  "/", mbname->domain,
                                  FNAME_USERDIR,
                                  dir_hash_b(mbname->localpart, config_fulldirhash, c),
                                  (char *)NULL);
            }
        }
        else {
            if (suffix) {
                fname = strconcat(config_dir,
                                  FNAME_USERDIR,
                                  dir_hash_b(mbname->localpart, config_fulldirhash, c),
                                  "/", mbname->localpart, ".", suffix,
                                  (char *)NULL);
            }
            else {
                fname = strconcat(config_dir,
                                  FNAME_USERDIR,
                                  dir_hash_b(mbname->localpart, config_fulldirhash, c),
                                  (char *)NULL);
            }
        }
        mboxlist_entry_free(&mbentry);
    }
    else if (mbname->domain) {
        if (suffix) {
            fname = strconcat(config_dir,
                              FNAME_DOMAINDIR,
                              dir_hash_b(mbname->domain, config_fulldirhash, d),
                              "/", mbname->domain,
                              "/", FNAME_SHAREDPREFIX, ".", suffix,
                              (char *)NULL);
        }
        else {
            fname = strconcat(config_dir,
                              FNAME_DOMAINDIR,
                              dir_hash_b(mbname->domain, config_fulldirhash, d),
                              "/", mbname->domain,
                              (char *)NULL);
        }
    }
    else {
        if (suffix) {
            fname = strconcat(config_dir,
                              "/", FNAME_SHAREDPREFIX, ".", suffix,
                              (char *)NULL);
        }
        else {
            fname = xstrdup(config_dir);
        }
    }

    return fname;
}

/* ========================= COUNTERS ============================ */

static bit64 mboxname_readval_old(const char *mboxname, const char *metaname)
{
    bit64 fileval = 0;
    mbname_t *mbname = NULL;
    char *fname = NULL;
    const char *base = NULL;
    size_t len = 0;
    int fd = -1;

    mbname = mbname_from_intname(mboxname);

    fname = mboxname_conf_getpath(mbname, metaname);
    if (!fname) goto done;

    fd = open(fname, O_RDONLY);

    /* read the value - note: we don't care if it's being rewritten,
     * we'll still get a consistent read on either the old or new
     * value */
    if (fd != -1) {
        struct stat sbuf;
        if (fstat(fd, &sbuf)) {
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", fname);
            goto done;
        }
        if (sbuf.st_size) {
            map_refresh(fd, 1, &base, &len, sbuf.st_size, metaname, mboxname);
            parsenum(base, NULL, sbuf.st_size, &fileval);
            map_free(&base, &len);
        }
    }

 done:
    if (fd != -1) close(fd);
    mbname_free(&mbname);
    free(fname);
    return fileval;
}

#define MV_VERSION 8

#define MV_OFF_GENERATION 0
#define MV_OFF_VERSION 4
#define MV_OFF_HIGHESTMODSEQ 8
#define MV_OFF_MAILMODSEQ 16
#define MV_OFF_CALDAVMODSEQ 24
#define MV_OFF_CARDDAVMODSEQ 32
#define MV_OFF_NOTESMODSEQ 40
#define MV_OFF_MAILFOLDERSMODSEQ 48
#define MV_OFF_CALDAVFOLDERSMODSEQ 56
#define MV_OFF_CARDDAVFOLDERSMODSEQ 64
#define MV_OFF_NOTESFOLDERSMODSEQ 72
#define MV_OFF_QUOTAMODSEQ 80
#define MV_OFF_RACLMODSEQ 88
#define MV_OFF_SUBMISSIONMODSEQ 96
#define MV_OFF_SUBMISSIONFOLDERSMODSEQ 104
#define MV_OFF_MAILDELETEDMODSEQ 112
#define MV_OFF_CALDAVDELETEDMODSEQ 120
#define MV_OFF_CARDDAVDELETEDMODSEQ 128
#define MV_OFF_NOTESDELETEDMODSEQ 136
#define MV_OFF_SUBMISSIONDELETEDMODSEQ 144
#define MV_OFF_MAILFOLDERSDELETEDMODSEQ 152
#define MV_OFF_CALDAVFOLDERSDELETEDMODSEQ 160
#define MV_OFF_CARDDAVFOLDERSDELETEDMODSEQ 168
#define MV_OFF_NOTESFOLDERSDELETEDMODSEQ 176
#define MV_OFF_SUBMISSIONFOLDERSDELETEDMODSEQ 184
#define MV_OFF_DAVNOTIFICATIONMODSEQ 192
#define MV_OFF_DAVNOTIFICATIONDELETEDMODSEQ 200
#define MV_OFF_DAVNOTIFICATIONFOLDERSMODSEQ 208
#define MV_OFF_DAVNOTIFICATIONFOLDERSDELETEDMODSEQ 216
#define MV_OFF_JMAPNOTIFICATIONMODSEQ 224
#define MV_OFF_JMAPNOTIFICATIONDELETEDMODSEQ 232
#define MV_OFF_JMAPNOTIFICATIONFOLDERSMODSEQ 240
#define MV_OFF_JMAPNOTIFICATIONFOLDERSDELETEDMODSEQ 248
#define MV_OFF_UIDVALIDITY 256
#define MV_OFF_CRC 260
#define MV_LENGTH 264

/* NOTE: you need a MV_LENGTH byte base here */
static int mboxname_buf_to_counters(const char *base, size_t len, struct mboxname_counters *vals)
{
    memset(vals, 0, sizeof(struct mboxname_counters));

    vals->generation = ntohl(*((uint32_t *)(base)));
    vals->version = ntohl(*((uint32_t *)(base+4)));

    /* dodgy broken version storage in v0 code, it could be anything */
    if (len == 48) vals->version = 0;

    switch (vals->version) {
    case 0:
        if (len != 48) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 44) != ntohl(*((uint32_t *)(base+44))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+40)));
        break;

    case 1:
        if (len != 56) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 52) != ntohl(*((uint32_t *)(base+52))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+48)));
        break;

    case 2:
        if (len != 64) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 60) != ntohl(*((uint32_t *)(base+60))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint32_t *)(base+48)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+56)));
        break;

    case 3:
        if (len != 88) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 84) != ntohl(*((uint32_t *)(base+84))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint64_t *)(base+48)));
        vals->caldavfoldersmodseq = ntohll(*((uint64_t *)(base+56)));
        vals->carddavfoldersmodseq = ntohll(*((uint64_t *)(base+64)));
        vals->notesfoldersmodseq = ntohll(*((uint64_t *)(base+72)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+80)));
        break;

    case 4:
        if (len != 104) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 100) != ntohl(*((uint32_t *)(base+100))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint64_t *)(base+48)));
        vals->caldavfoldersmodseq = ntohll(*((uint64_t *)(base+56)));
        vals->carddavfoldersmodseq = ntohll(*((uint64_t *)(base+64)));
        vals->notesfoldersmodseq = ntohll(*((uint64_t *)(base+72)));
        vals->quotamodseq = ntohll(*((uint64_t *)(base+80)));
        vals->raclmodseq = ntohll(*((uint64_t *)(base+88)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+96)));
        break;

    case 5:
        if (len != 120) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 116) != ntohl(*((uint32_t *)(base+116))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint64_t *)(base+48)));
        vals->caldavfoldersmodseq = ntohll(*((uint64_t *)(base+56)));
        vals->carddavfoldersmodseq = ntohll(*((uint64_t *)(base+64)));
        vals->notesfoldersmodseq = ntohll(*((uint64_t *)(base+72)));
        vals->quotamodseq = ntohll(*((uint64_t *)(base+80)));
        vals->raclmodseq = ntohll(*((uint64_t *)(base+88)));
        vals->submissionmodseq = ntohll(*((uint64_t *)(base+96)));
        vals->submissionfoldersmodseq = ntohll(*((uint64_t *)(base+104)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+112)));
        break;

    case 6:
        if (len != 200) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 196) != ntohl(*((uint32_t *)(base+196))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint64_t *)(base+48)));
        vals->caldavfoldersmodseq = ntohll(*((uint64_t *)(base+56)));
        vals->carddavfoldersmodseq = ntohll(*((uint64_t *)(base+64)));
        vals->notesfoldersmodseq = ntohll(*((uint64_t *)(base+72)));
        vals->quotamodseq = ntohll(*((uint64_t *)(base+80)));
        vals->raclmodseq = ntohll(*((uint64_t *)(base+88)));
        vals->submissionmodseq = ntohll(*((uint64_t *)(base+96)));
        vals->submissionfoldersmodseq = ntohll(*((uint64_t *)(base+104)));
        vals->maildeletedmodseq = ntohll(*((uint64_t *)(base+112)));
        vals->caldavdeletedmodseq = ntohll(*((uint64_t *)(base+120)));
        vals->carddavdeletedmodseq = ntohll(*((uint64_t *)(base+128)));
        vals->notesdeletedmodseq = ntohll(*((uint64_t *)(base+136)));
        vals->submissiondeletedmodseq = ntohll(*((uint64_t *)(base+144)));
        vals->mailfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+152)));
        vals->caldavfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+160)));
        vals->carddavfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+168)));
        vals->notesfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+176)));
        vals->submissionfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+184)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+192)));
        break;

    case 7:
        if (len != 232) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 228) != ntohl(*((uint32_t *)(base+228))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint64_t *)(base+48)));
        vals->caldavfoldersmodseq = ntohll(*((uint64_t *)(base+56)));
        vals->carddavfoldersmodseq = ntohll(*((uint64_t *)(base+64)));
        vals->notesfoldersmodseq = ntohll(*((uint64_t *)(base+72)));
        vals->quotamodseq = ntohll(*((uint64_t *)(base+80)));
        vals->raclmodseq = ntohll(*((uint64_t *)(base+88)));
        vals->submissionmodseq = ntohll(*((uint64_t *)(base+96)));
        vals->submissionfoldersmodseq = ntohll(*((uint64_t *)(base+104)));
        vals->maildeletedmodseq = ntohll(*((uint64_t *)(base+112)));
        vals->caldavdeletedmodseq = ntohll(*((uint64_t *)(base+120)));
        vals->carddavdeletedmodseq = ntohll(*((uint64_t *)(base+128)));
        vals->notesdeletedmodseq = ntohll(*((uint64_t *)(base+136)));
        vals->submissiondeletedmodseq = ntohll(*((uint64_t *)(base+144)));
        vals->mailfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+152)));
        vals->caldavfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+160)));
        vals->carddavfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+168)));
        vals->notesfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+176)));
        vals->submissionfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+184)));
        vals->davnotificationmodseq = ntohll(*((uint64_t *)(base+192)));
        vals->davnotificationdeletedmodseq = ntohll(*((uint64_t *)(base+200)));
        vals->davnotificationfoldersmodseq = ntohll(*((uint64_t *)(base+208)));
        vals->davnotificationfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+216)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+224)));
        break;

    case 8:
        if (len != 264) return IMAP_MAILBOX_CHECKSUM;
        if (crc32_map(base, 260) != ntohl(*((uint32_t *)(base+260))))
            return IMAP_MAILBOX_CHECKSUM;

        vals->highestmodseq = ntohll(*((uint64_t *)(base+8)));
        vals->mailmodseq = ntohll(*((uint64_t *)(base+16)));
        vals->caldavmodseq = ntohll(*((uint64_t *)(base+24)));
        vals->carddavmodseq = ntohll(*((uint64_t *)(base+32)));
        vals->notesmodseq = ntohll(*((uint64_t *)(base+40)));
        vals->mailfoldersmodseq = ntohll(*((uint64_t *)(base+48)));
        vals->caldavfoldersmodseq = ntohll(*((uint64_t *)(base+56)));
        vals->carddavfoldersmodseq = ntohll(*((uint64_t *)(base+64)));
        vals->notesfoldersmodseq = ntohll(*((uint64_t *)(base+72)));
        vals->quotamodseq = ntohll(*((uint64_t *)(base+80)));
        vals->raclmodseq = ntohll(*((uint64_t *)(base+88)));
        vals->submissionmodseq = ntohll(*((uint64_t *)(base+96)));
        vals->submissionfoldersmodseq = ntohll(*((uint64_t *)(base+104)));
        vals->maildeletedmodseq = ntohll(*((uint64_t *)(base+112)));
        vals->caldavdeletedmodseq = ntohll(*((uint64_t *)(base+120)));
        vals->carddavdeletedmodseq = ntohll(*((uint64_t *)(base+128)));
        vals->notesdeletedmodseq = ntohll(*((uint64_t *)(base+136)));
        vals->submissiondeletedmodseq = ntohll(*((uint64_t *)(base+144)));
        vals->mailfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+152)));
        vals->caldavfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+160)));
        vals->carddavfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+168)));
        vals->notesfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+176)));
        vals->submissionfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+184)));
        vals->davnotificationmodseq = ntohll(*((uint64_t *)(base+192)));
        vals->davnotificationdeletedmodseq = ntohll(*((uint64_t *)(base+200)));
        vals->davnotificationfoldersmodseq = ntohll(*((uint64_t *)(base+208)));
        vals->davnotificationfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+216)));
        vals->jmapnotificationmodseq = ntohll(*((uint64_t *)(base+224)));
        vals->jmapnotificationdeletedmodseq = ntohll(*((uint64_t *)(base+232)));
        vals->jmapnotificationfoldersmodseq = ntohll(*((uint64_t *)(base+240)));
        vals->jmapnotificationfoldersdeletedmodseq = ntohll(*((uint64_t *)(base+248)));
        vals->uidvalidity = ntohl(*((uint32_t *)(base+256)));
        break;

    default:
        return IMAP_MAILBOX_BADFORMAT;
    }

    return 0;
}

/* NOTE: you need a MV_LENGTH buffer to write into, aligned on 8 byte boundaries */
static void mboxname_counters_to_buf(const struct mboxname_counters *vals, char *base)
{
    *((uint32_t *)(base+MV_OFF_GENERATION)) = htonl(vals->generation);
    *((uint32_t *)(base+MV_OFF_VERSION)) = htonl(MV_VERSION);
    align_htonll(base+MV_OFF_HIGHESTMODSEQ, vals->highestmodseq);
    align_htonll(base+MV_OFF_MAILMODSEQ, vals->mailmodseq);
    align_htonll(base+MV_OFF_CALDAVMODSEQ, vals->caldavmodseq);
    align_htonll(base+MV_OFF_CARDDAVMODSEQ, vals->carddavmodseq);
    align_htonll(base+MV_OFF_NOTESMODSEQ, vals->notesmodseq);
    align_htonll(base+MV_OFF_MAILFOLDERSMODSEQ, vals->mailfoldersmodseq);
    align_htonll(base+MV_OFF_CALDAVFOLDERSMODSEQ, vals->caldavfoldersmodseq);
    align_htonll(base+MV_OFF_CARDDAVFOLDERSMODSEQ, vals->carddavfoldersmodseq);
    align_htonll(base+MV_OFF_NOTESFOLDERSMODSEQ, vals->notesfoldersmodseq);
    align_htonll(base+MV_OFF_QUOTAMODSEQ, vals->quotamodseq);
    align_htonll(base+MV_OFF_RACLMODSEQ, vals->raclmodseq);
    align_htonll(base+MV_OFF_SUBMISSIONMODSEQ, vals->submissionmodseq);
    align_htonll(base+MV_OFF_SUBMISSIONFOLDERSMODSEQ, vals->submissionfoldersmodseq);
    align_htonll(base+MV_OFF_MAILDELETEDMODSEQ, vals->maildeletedmodseq);
    align_htonll(base+MV_OFF_CALDAVDELETEDMODSEQ, vals->caldavdeletedmodseq);
    align_htonll(base+MV_OFF_CARDDAVDELETEDMODSEQ, vals->carddavdeletedmodseq);
    align_htonll(base+MV_OFF_NOTESDELETEDMODSEQ, vals->notesdeletedmodseq);
    align_htonll(base+MV_OFF_SUBMISSIONDELETEDMODSEQ,
                 vals->submissiondeletedmodseq);
    align_htonll(base+MV_OFF_MAILFOLDERSDELETEDMODSEQ,
                 vals->mailfoldersdeletedmodseq);
    align_htonll(base+MV_OFF_CALDAVFOLDERSDELETEDMODSEQ,
                 vals->caldavfoldersdeletedmodseq);
    align_htonll(base+MV_OFF_CARDDAVFOLDERSDELETEDMODSEQ,
                 vals->carddavfoldersdeletedmodseq);
    align_htonll(base+MV_OFF_NOTESFOLDERSDELETEDMODSEQ,
                 vals->notesfoldersdeletedmodseq);
    align_htonll(base+MV_OFF_SUBMISSIONFOLDERSDELETEDMODSEQ,
                 vals->submissionfoldersdeletedmodseq);
    align_htonll(base+MV_OFF_DAVNOTIFICATIONMODSEQ,
                 vals->davnotificationmodseq);
    align_htonll(base+MV_OFF_DAVNOTIFICATIONDELETEDMODSEQ,
                 vals->davnotificationdeletedmodseq);
    align_htonll(base+MV_OFF_DAVNOTIFICATIONFOLDERSMODSEQ,
                 vals->davnotificationfoldersmodseq);
    align_htonll(base+MV_OFF_DAVNOTIFICATIONFOLDERSDELETEDMODSEQ,
                 vals->davnotificationfoldersdeletedmodseq);
    align_htonll(base+MV_OFF_JMAPNOTIFICATIONMODSEQ,
                 vals->jmapnotificationmodseq);
    align_htonll(base+MV_OFF_JMAPNOTIFICATIONDELETEDMODSEQ,
                 vals->jmapnotificationdeletedmodseq);
    align_htonll(base+MV_OFF_JMAPNOTIFICATIONFOLDERSMODSEQ,
                 vals->jmapnotificationfoldersmodseq);
    align_htonll(base+MV_OFF_JMAPNOTIFICATIONFOLDERSDELETEDMODSEQ,
                 vals->jmapnotificationfoldersdeletedmodseq);
    *((uint32_t *)(base+MV_OFF_UIDVALIDITY)) = htonl(vals->uidvalidity);
    *((uint32_t *)(base+MV_OFF_CRC)) = htonl(crc32_map(base, MV_OFF_CRC));
}

/* XXX - inform about errors?  Any error causes the value of at least
   last+1 to be returned.  An error only on writing causes
   max(last, fileval) + 1 to still be returned */
static int mboxname_load_counters(const char *mboxname, struct mboxname_counters *vals, int *fdp)
{
    int fd = -1;
    char *fname = NULL;
    struct stat sbuf, fbuf;
    const char *base = NULL;
    size_t len = 0;
    mbname_t *mbname = NULL;
    int r = 0;

    memset(vals, 0, sizeof(struct mboxname_counters));

    mbname = mbname_from_intname(mboxname);

    fname = mboxname_conf_getpath(mbname, "counters");
    if (!fname) {
        r = IMAP_MAILBOX_BADNAME;
        goto done;
    }

    /* get a blocking lock on fd */
    for (;;) {
        fd = open(fname, O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
            /* OK to not exist - try creating the directory first */
            if (cyrus_mkdir(fname, 0755)) goto done;
            fd = open(fname, O_RDWR | O_CREAT, 0644);
        }
        if (fd == -1) {
            xsyslog(LOG_ERR, "IOERROR: create failed",
                             "filename=<%s>", fname);
            goto done;
        }
        if (lock_blocking(fd, fname)) {
            xsyslog(LOG_ERR, "IOERROR: lock_blocking failed",
                             "filename=<%s>", fname);
            goto done;
        }
        if (fstat(fd, &sbuf)) {
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", fname);
            goto done;
        }
        if (stat(fname, &fbuf)) {
            xsyslog(LOG_ERR, "IOERROR: stat failed",
                             "filename=<%s>", fname);
            goto done;
        }
        if (sbuf.st_ino == fbuf.st_ino) break;
        lock_unlock(fd, fname);
        close(fd);
        fd = -1;
    }

    if (fd < 0) {
        r = IMAP_IOERROR;
        goto done;
    }

    if (sbuf.st_size >= 8) {
        /* read the old value */
        map_refresh(fd, 1, &base, &len, sbuf.st_size, "counters", mboxname);
        if (len >= 8) {
            r = mboxname_buf_to_counters(base, len, vals);
        }
        map_free(&base, &len);
    }
    else {
        /* going to have to read the old files */
        vals->mailmodseq = vals->caldavmodseq = vals->carddavmodseq =
            vals->highestmodseq = mboxname_readval_old(mboxname, "modseq");
        vals->uidvalidity = mboxname_readval_old(mboxname, "uidvalidity");
    }

done:
    if (r) {
        if (fd != -1) {
            lock_unlock(fd, fname);
            close(fd);
        }
    }
    else {
        /* maintain the lock until we're done */
        *fdp = fd;
    }
    mbname_free(&mbname);
    free(fname);
    return r;
}

static int mboxname_set_counters(const char *mboxname, struct mboxname_counters *vals, int fd)
{
    char *fname = NULL;
    mbname_t *mbname = NULL;
    char buf[MV_LENGTH];
    char newfname[MAX_MAILBOX_PATH];
    int newfd = -1;
    int n = 0;
    int r = 0;

    mbname = mbname_from_intname(mboxname);

    fname = mboxname_conf_getpath(mbname, "counters");
    if (!fname) {
        r = IMAP_MAILBOX_BADNAME;
        goto done;
    }

    snprintf(newfname, MAX_MAILBOX_PATH, "%s.NEW", fname);
    newfd = open(newfname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (newfd == -1) {
        r = IMAP_IOERROR;
        xsyslog(LOG_ERR, "IOERROR: open failed",
                         "filename=<%s>", newfname);
        goto done;
    }

    /* it's a new generation! */
    vals->generation++;

    mboxname_counters_to_buf(vals, buf);
    n = retry_write(newfd, buf, MV_LENGTH);
    if (n < 0) {
        r = IMAP_IOERROR;
        xsyslog(LOG_ERR, "IOERROR: retry_write failed",
                         "filename=<%s>", newfname);
        goto done;
    }

    if (fdatasync(newfd)) {
        r = IMAP_IOERROR;
        xsyslog(LOG_ERR, "IOERROR: fdatasync failed",
                         "filename=<%s>", newfname);
        goto done;
    }

    close(newfd);
    newfd = -1;

    if (rename(newfname, fname)) {
        r = IMAP_IOERROR;
        xsyslog(LOG_ERR, "IOERROR: rename failed",
                         "oldfname=<%s> newfname=<%s>",
                         newfname, fname);
        goto done;
    }

 done:
    if (newfd != -1) close(newfd);
    if (fd != -1) {
        lock_unlock(fd, fname);
        close(fd);
    }
    mbname_free(&mbname);
    free(fname);

    return r;
}

static int mboxname_unload_counters(int fd)
{
    lock_unlock(fd, NULL);
    close(fd);
    return 0;
}

EXPORTED int mboxname_read_counters(const char *mboxname, struct mboxname_counters *vals)
{
    int r = 0;
    mbname_t *mbname = NULL;
    struct stat sbuf;
    char *fname = NULL;
    const char *base = NULL;
    size_t len = 0;
    int fd = -1;

    memset(vals, 0, sizeof(struct mboxname_counters));

    mbname = mbname_from_intname(mboxname);

    fname = mboxname_conf_getpath(mbname, "counters");
    if (!fname) {
        r = IMAP_MAILBOX_BADNAME;
        goto done;
    }

    fd = open(fname, O_RDONLY);

    /* if no file, import from the old files potentially, and write a file regardless */
    if (fd < 0) {
        /* race => multiple rewrites, won't hurt too much */
        r = mboxname_load_counters(mboxname, vals, &fd);
        if (r) goto done;
        r = mboxname_set_counters(mboxname, vals, fd);
        fd = -1;
        if (r) goto done;
        free(fname);
        fname = mboxname_conf_getpath(mbname, "modseq");
        if (fname) unlink(fname);
        free(fname);
        fname = mboxname_conf_getpath(mbname, "uidvalidity");
        if (fname) unlink(fname);
        goto done;
    }

    if (fstat(fd, &sbuf)) {
        xsyslog(LOG_ERR, "IOERROR: fstat failed",
                         "filename=<%s>", fname);
        r = IMAP_IOERROR;
        goto done;
    }

    if (sbuf.st_size >= 8) {
        map_refresh(fd, 1, &base, &len, sbuf.st_size, "counters", mboxname);
        if (len >= 8)
            r = mboxname_buf_to_counters(base, len, vals);
        map_free(&base, &len);
    }

 done:
    if (fd != -1) close(fd);
    mbname_free(&mbname);
    free(fname);
    return r;
}

enum domodseq { MBOXMODSEQ, QUOTAMODSEQ, RACLMODSEQ };

static modseq_t mboxname_domodseq(const char *mboxname,
                                  modseq_t last,
                                  enum domodseq domodseq,
                                  int mbtype,   // for MBOXMODSEQ
                                  int flags,    // for MBOXMODSEQ
                                  modseq_t add)
{
    struct mboxname_counters counters;
    struct mboxname_counters oldcounters;
    modseq_t *typemodseqp = NULL;
    modseq_t *foldersmodseqp = NULL;
    int fd = -1;
    int dofolder = flags & MBOXMODSEQ_ISFOLDER;
    int isdelete = flags & MBOXMODSEQ_ISDELETE;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return last + add;

    /* XXX error handling */
    if (mboxname_load_counters(mboxname, &counters, &fd))
        return last + add;

    oldcounters = counters;

    if (domodseq == MBOXMODSEQ) {
        if (mboxname_isaddressbookmailbox(mboxname, mbtype)) {
            typemodseqp = isdelete ?
                &counters.carddavdeletedmodseq :
                &counters.carddavmodseq;
            foldersmodseqp = isdelete ?
                &counters.carddavfoldersdeletedmodseq :
                &counters.carddavfoldersmodseq;
        }
        else if (mboxname_iscalendarmailbox(mboxname, mbtype)) {
            typemodseqp = isdelete ?
                &counters.caldavdeletedmodseq :
                &counters.caldavmodseq;
            foldersmodseqp = isdelete ?
                &counters.caldavfoldersdeletedmodseq :
                &counters.caldavfoldersmodseq;
        }
        else if (mboxname_isnotesmailbox(mboxname, mbtype)) {
            typemodseqp = isdelete ?
                &counters.notesdeletedmodseq :
                &counters.notesmodseq;
            foldersmodseqp = isdelete ?
                &counters.notesfoldersdeletedmodseq :
                &counters.notesfoldersmodseq;
        }
        else if (mboxname_issubmissionmailbox(mboxname, mbtype)) {
            typemodseqp = isdelete ?
                &counters.submissiondeletedmodseq :
                &counters.submissionmodseq;
            foldersmodseqp = isdelete ?
                &counters.submissionfoldersdeletedmodseq :
                &counters.submissionfoldersmodseq;
        }
        else if (mboxname_isdavnotificationsmailbox(mboxname, mbtype)) {
            typemodseqp = isdelete ?
                &counters.davnotificationdeletedmodseq :
                &counters.davnotificationmodseq;
            foldersmodseqp = isdelete ?
                &counters.davnotificationfoldersdeletedmodseq :
                &counters.davnotificationfoldersmodseq;
        }
        else if (mboxname_isjmapnotificationsmailbox(mboxname, mbtype)) {
            typemodseqp = isdelete ?
                &counters.jmapnotificationdeletedmodseq :
                &counters.jmapnotificationmodseq;
            foldersmodseqp = isdelete ?
                &counters.jmapnotificationfoldersdeletedmodseq :
                &counters.jmapnotificationfoldersmodseq;
        }
        else {
            typemodseqp = isdelete ?
                &counters.maildeletedmodseq :
                &counters.mailmodseq;
            foldersmodseqp = isdelete ?
                &counters.mailfoldersdeletedmodseq :
                &counters.mailfoldersmodseq;
        }
    }
    else if (domodseq == QUOTAMODSEQ) {
        typemodseqp = &counters.quotamodseq;
        dofolder = 0;
    }
    else if (domodseq == RACLMODSEQ) {
        typemodseqp = &counters.raclmodseq;
        dofolder = 0;
    }

    /* make sure all counters are at least the old value */
    if (counters.highestmodseq < last)
        counters.highestmodseq = last;
    if (*typemodseqp < last)
        *typemodseqp = last;
    if (dofolder && *foldersmodseqp < last)
        *foldersmodseqp = last;

    /* if adding, bring all counters up to the overall highest modseq */
    if (add) {
        counters.highestmodseq += add;
        *typemodseqp = counters.highestmodseq;
        if (dofolder) *foldersmodseqp = counters.highestmodseq;
    }

    if (memcmp(&counters, &oldcounters, sizeof(struct mboxname_counters)))
        mboxname_set_counters(mboxname, &counters, fd);
    else
        mboxname_unload_counters(fd);

    return counters.highestmodseq;
}

EXPORTED modseq_t mboxname_nextmodseq(const char *mboxname, modseq_t last, int mbtype, int flags)
{
    return mboxname_domodseq(mboxname, last, MBOXMODSEQ, mbtype, flags, 1);
}

EXPORTED modseq_t mboxname_setmodseq(const char *mboxname, modseq_t last, int mbtype, int flags)
{
    return mboxname_domodseq(mboxname, last, MBOXMODSEQ, mbtype, flags, 0);
}

EXPORTED modseq_t mboxname_readquotamodseq(const char *mboxname)
{
    struct mboxname_counters counters;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return 0;

    if (mboxname_read_counters(mboxname, &counters))
        return 0;

    return counters.quotamodseq;
}

EXPORTED modseq_t mboxname_nextquotamodseq(const char *mboxname, modseq_t last)
{
    return mboxname_domodseq(mboxname, last, QUOTAMODSEQ, 0, 0, 1);
}

EXPORTED modseq_t mboxname_setquotamodseq(const char *mboxname, modseq_t last)
{
    return mboxname_domodseq(mboxname, last, QUOTAMODSEQ, 0, 0, 0);
}

EXPORTED modseq_t mboxname_readraclmodseq(const char *mboxname)
{
    struct mboxname_counters counters;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return 0;

    if (!mboxname_isusermailbox(mboxname, /*isinbox*/1))
        return 0;  // raclmodseq is only defined on user inboxes

    if (mboxname_read_counters(mboxname, &counters))
        return 0;

    return counters.raclmodseq;
}

EXPORTED modseq_t mboxname_nextraclmodseq(const char *mboxname, modseq_t last)
{
    return mboxname_domodseq(mboxname, last, RACLMODSEQ, 0, 0, 1);
}

EXPORTED modseq_t mboxname_setraclmodseq(const char *mboxname, modseq_t last)
{
    return mboxname_domodseq(mboxname, last, RACLMODSEQ, 0, 0, 0);
}

EXPORTED uint32_t mboxname_readuidvalidity(const char *mboxname)
{
    struct mboxname_counters counters;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return 0;

    if (mboxname_read_counters(mboxname, &counters))
        return 0;

    return counters.uidvalidity;
}

EXPORTED uint32_t mboxname_nextuidvalidity(const char *mboxname, uint32_t last)
{
    struct mboxname_counters counters;
    int fd = -1;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return last + 1;

    /* XXX error handling */
    if (mboxname_load_counters(mboxname, &counters, &fd))
        return last + 1;

    if (counters.uidvalidity < last)
        counters.uidvalidity = last;

    counters.uidvalidity++;

    /* always set, because we always increased */
    mboxname_set_counters(mboxname, &counters, fd);

    return counters.uidvalidity;
}

EXPORTED uint32_t mboxname_setuidvalidity(const char *mboxname, uint32_t val)
{
    struct mboxname_counters counters;
    int fd = -1;
    int dirty = 0;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return val;

    /* XXX error handling */
    if (mboxname_load_counters(mboxname, &counters, &fd))
        return val;

    if (counters.uidvalidity < val) {
        counters.uidvalidity = val;
        dirty = 1;
    }

    if (dirty)
        mboxname_set_counters(mboxname, &counters, fd);
    else
        mboxname_unload_counters(fd);

    return val;
}

EXPORTED char *mboxname_common_ancestor(const char *mboxname1, const char *mboxname2)
{
    mbname_t *mbname1 = mbname_from_intname(mboxname1);
    mbname_t *mbname2 = mbname_from_intname(mboxname2);
    char *ancestor = NULL;

    if (!mbname_same_userid(mbname1, mbname2))
        goto done;

    const strarray_t *boxes1 = mbname_boxes(mbname1);
    const strarray_t *boxes2 = mbname_boxes(mbname2);
    int len = boxes1->count < boxes2->count ? boxes1->count : boxes2->count;
    int i;
    for (i = 0; i < len - 1; i++) {
        if (strcmp(strarray_nth(boxes1, i), strarray_nth(boxes2, i)))
            break;
    }
    if (i > 0) {
        mbname_truncate_boxes(mbname1, i);
        ancestor = xstrdup(mbname_intname(mbname1));
    }

done:
    mbname_free(&mbname1);
    mbname_free(&mbname2);
    return ancestor;
}
