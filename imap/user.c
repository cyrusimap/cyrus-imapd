/* user.c - User manipulation routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
#include "bsearch.h"
#include "dav_db.h"
#include "global.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "proc.h"
#include "quota.h"
#include "search_engines.h"
#include "seen.h"
#include "sievedir.h"
#include "sqldb.h"
#include "sync_log.h"
#include "user.h"
#include "util.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xmalloc.h"
#include "xunlink.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "caldav_alarm.h"

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

static const char *user_sieve_path_byname(const mbname_t *mbname)
{
    static char sieve_path[2048];
    const char *localpart = mbname_localpart(mbname);
    const char *domain = mbname_domain(mbname);
    size_t len, size = sizeof(sieve_path);

    len = strlcpy(sieve_path, config_getstring(IMAPOPT_SIEVEDIR), size);

    if (config_virtdomains && domain) {
        char d = (char) dir_hash_c(domain, config_fulldirhash);
        len += snprintf(sieve_path + len, size - len, "%s%c/%s",
                        FNAME_DOMAINDIR, d, domain);
    }

    if (localpart) {
        const char *userid = config_virtdomains ? localpart : mbname_userid(mbname);
        char c = (char) dir_hash_c(userid, config_fulldirhash);
        snprintf(sieve_path + len, size - len, "/%c/%s", c, userid);
    }
    else {
        strlcat(sieve_path, "/global", size);
    }

    return sieve_path;
}

static const char *user_sieve_path_byid(const char *mboxid)
{
    static char sieve_path[2048];

    mboxname_id_hash(sieve_path, sizeof(sieve_path),
                     config_getstring(IMAPOPT_SIEVEDIR),
                     mboxid);

    return sieve_path;
}

EXPORTED const char *user_sieve_path(const char *inuser)
{
    const char *sieve_path = NULL;
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

        int r = mboxlist_lookup_allow_all(inboxname, &mbentry, NULL);
        free(inboxname);

        if (r || (mbentry->mbtype & MBTYPE_LEGACY_DIRS) || !mbentry->uniqueid) {
            legacy = 1;
        }
        else {
            sieve_path = user_sieve_path_byid(mbentry->uniqueid);
        }
        mboxlist_entry_free(&mbentry);
    }
    else {
        /* global script */
        legacy = 1;
    }

    if (legacy) {
        sieve_path = user_sieve_path_byname(mbname);
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

    xunlink(path);

    return SIEVEDIR_OK;
}

static int user_deletesieve(const char *sieve_path)
{
    /* remove contents of sieve_path */
    sievedir_foreach(sieve_path, 0/*flags*/, &delete_cb, NULL);

    rmdir(sieve_path);

    return 0;
}

static const char *wipe_user_file_suffixes[] = {
    FNAME_SEENSUFFIX,
    NULL
};

static const char *user_file_suffixes[] = {
    FNAME_DAVSUFFIX,      /* even if DAV is turned off, this is fine */
    FNAME_SUBSSUFFIX,
    FNAME_COUNTERSSUFFIX,

    /* NOTE: even if conversations aren't enabled, we want to clean up */
    FNAME_CONVERSATIONS_SUFFIX,
    NULL
};

EXPORTED int user_deletedata(const mbentry_t *mbentry, int wipe_user)
{
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    const char *userid = mbname_userid(mbname);
    strarray_t paths = STRARRAY_INITIALIZER;
    const char *sieve_path = NULL, **suffixes;
    int i;

    assert(user_nslock_islocked(userid));

    int byid = !(mbentry->mbtype & MBTYPE_LEGACY_DIRS) && mbentry->uniqueid;
    int shared = 0;

    /* the uniqueid survives a rename and a delayed delete, so a tombstone
       can name the very same files as a live user.  Only remove them if we
       still own the uniqueid, e.g. sync_reset of a renamed-away user */
    if (byid) {
        mbentry_t *owner = NULL;
        if (!mboxlist_lookup_by_uniqueid(mbentry->uniqueid, &owner, NULL)
            && strcmpsafe(owner->name, mbentry->name)
            && !mboxname_isdeletedmailbox(owner->name, NULL)) {
            xsyslog(LOG_ERR, "keeping user files still owned by another mailbox",
                             "userid=<%s> mboxname=<%s> uniqueid=<%s> ownername=<%s>",
                             userid, mbentry->name, mbentry->uniqueid,
                             owner->name);
            shared = 1;
        }
        mboxlist_entry_free(&owner);
    }

    if (shared) {
        /* nothing keyed by uniqueid is ours to remove */
    }
    else if (byid) {
        for (suffixes = user_file_suffixes; *suffixes; suffixes++) {
            strarray_appendm(&paths,
                             mboxid_conf_getpath(mbentry->uniqueid, *suffixes));
        }

        if (wipe_user) {
            /* XXX  we could probably just do removedir() for this case
               and not bother populating the list of paths */
            for (suffixes = wipe_user_file_suffixes; *suffixes; suffixes++) {
                strarray_appendm(&paths,
                                 mboxid_conf_getpath(mbentry->uniqueid, *suffixes));
            }

            /* delete entire userdata directory */
            strarray_appendm(&paths,
                             mboxid_conf_getpath(mbentry->uniqueid, NULL));
        }

        if (!config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) {
            sieve_path = user_sieve_path_byid(mbentry->uniqueid);
        }
    }
    else {
        for (suffixes = user_file_suffixes; *suffixes; suffixes++) {
            strarray_appendm(&paths,
                             mboxname_conf_getpath_legacy(mbname, *suffixes));
        }

        if (wipe_user) {
            for (suffixes = wipe_user_file_suffixes; *suffixes; suffixes++) {
                strarray_appendm(&paths,
                                 mboxname_conf_getpath_legacy(mbname, *suffixes));
            }
        }

        if (!config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) {
            sieve_path = user_sieve_path_byname(mbname);
        }
    }

    if (sieve_path) {
        /* delete sieve scripts */
        user_deletesieve(sieve_path);
    }

    /* delete quotas */
    user_deletequotaroots(userid);

    /* delete all the search engine data (if any) - also keyed by uniqueid */
    if (!shared) search_deluser(mbentry);

    /* delete all the calendar alarms for the user */
    caldav_alarm_delete_user(userid);

    /* a handle held over this write keeps writing to an inode which is no
       longer there, and only finds out at SQLDB_ERR_DBMOVED time */
    if (strarray_size(&paths) && sqldb_isopen_forscope(SQLDB_SCOPE_USER, userid)) {
        xsyslog(LOG_ERR, "removing user files with a sqldb still open on them",
                         "userid=<%s>", userid);
    }

    /* delete paths in our list */
    /* XXX  MUST do this last in case one of the functions above
       needs to operate on the userdata directory (e.g. Xapian) */
    for (i = 0; i < strarray_size(&paths); i++) {
        const char *path = strarray_nth(&paths, i);
        struct stat sbuf;

        if (stat(path, &sbuf) < 0) continue;

        /* a database may be a directory of files, not a single file */
        if (S_ISDIR(sbuf.st_mode)) removedir(path);
        else xunlink(path);
    }
    strarray_fini(&paths);

    proc_killuser(userid);

    // make sure it gets removed everywhere else
    sync_log_unuser(userid);

    mbname_free(&mbname);

    return 0;
}

struct rename_rock {
    const struct namespace *namespace;
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

    return mboxlist_changesub(name, rrock->newuser, NULL, 1, 1, 1, /*silent*/1);
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

    /* make sure newpath's directory components exist */
    r = cyrus_mkdir(newpath, 0755 /* unused */);

    /* rename sieve directory
     *
     * XXX this doesn't rename sieve scripts
     */
    if (!r) r = cyrus_rename(oldpath, newpath);
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

static int _user_renameacl(const struct namespace *namespace,
                           const mbentry_t *mbentry,
                           const char *olduser, const char *newuser)
{
    int r = 0;
    char *acl;
    char *rights, *nextid;
    char *aclalloc;

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
            r = mboxlist_setacl(namespace, mbentry->name, newuser, rights, 1, newuser, NULL);
            /* delete ACL for olduser */
            if (!r)
                r = mboxlist_setacl(namespace, mbentry->name, olduser, (char *)0, 1, newuser, NULL);
        }

        acl = nextid;
    }

    free(aclalloc);

    return r;
}

EXPORTED int user_renameacl(const struct namespace *namespace, const char *name,
                            const char *olduser, const char *newuser)
{
    int r = 0;
    mbentry_t *mbentry = NULL;

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) return r;

    r = _user_renameacl(namespace, mbentry, olduser, newuser);

    mboxlist_entry_free(&mbentry);

    return r;
}

static int sharee_rename_cb(const mbentry_t *mbentry, void *rock)
{
    struct rename_rock *rrock = (struct rename_rock *) rock;

    return _user_renameacl(rrock->namespace, mbentry,
                           rrock->olduser, rrock->newuser);
}

EXPORTED int user_sharee_renameacls(const struct namespace *namespace,
                                    const char *olduser, const char *newuser)
{
    struct rename_rock rrock = { namespace, olduser, newuser, NULL, NULL, 0 };

    return mboxlist_usermboxtree(olduser, NULL, &sharee_rename_cb, &rrock,
                                 MBOXTREE_SKIP_ROOT     |
                                 MBOXTREE_SKIP_CHILDREN |
                                 MBOXTREE_SKIP_PERSONAL |
                                 MBOXTREE_PLUS_RACL);
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
    r = quota_deleteroot(root, 1);
    free(root);

    return r;
}

EXPORTED int user_deletequotaroots(const char *userid)
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

EXPORTED char *user_hash_subs(const char *userid)
{
    return user_hash_meta(userid, FNAME_SUBSSUFFIX);
}

EXPORTED char *user_hash_xapian(const char *userid, const char *root)
{
    char *inboxname = mboxname_user_mbox(userid, NULL);
    mbentry_t *mbentry = NULL;
    mbname_t *mbname = NULL;
    char *basedir = NULL;
    int r;

    r = mboxlist_lookup_allow_all(inboxname, &mbentry, NULL);
    if (r) goto out;

    mbname = mbname_from_intname(mbentry->name);
    if (!mbname_userid(mbname)) goto out;

    if (mbentry->mbtype & MBTYPE_LEGACY_DIRS || !mbentry->uniqueid) {
        basedir = user_hash_xapian_byname(mbname, root);
    }
    else {
        basedir = user_hash_xapian_byid(mbentry->uniqueid, root);
    }

 out:
    mboxlist_entry_free(&mbentry);
    mbname_free(&mbname);
    free(inboxname);

    return basedir;
}

EXPORTED char *user_hash_xapian_byname(const mbname_t *mbname, const char *root)
{
    char *basedir = NULL;
    const char *domain = mbname_domain(mbname);
    const char *localpart = mbname_localpart(mbname);
    char c[2], d[2];

    if (domain)
        basedir = strconcat(root,
                            FNAME_DOMAINDIR,
                            dir_hash_b(domain, config_fulldirhash, d),
                            "/", domain,
                            "/", dir_hash_b(localpart, config_fulldirhash, c),
                            FNAME_USERDIR,
                            localpart,
                            (char *)NULL);
    else
        basedir = strconcat(root,
                            "/", dir_hash_b(localpart, config_fulldirhash, c),
                            FNAME_USERDIR,
                            localpart,
                            (char *)NULL);

    return basedir;
}

EXPORTED char *user_hash_xapian_byid(const char *mboxid, const char *root)
{
    char path[MAX_MAILBOX_PATH+1];
    mboxname_id_hash(path, MAX_MAILBOX_PATH, NULL, mboxid);

    return strconcat(root,
                     FNAME_USERDIR,
                     path,
                     (char *)NULL);
}

static const char *_namelock_name_from_userid(const char *userid)
{
    static struct buf buf = BUF_INITIALIZER;

    buf_setcstr(&buf, USER_NAMELOCK_PREFIX);
    if (userid) {
        char *inbox = mboxname_user_mbox(userid, NULL);
        buf_appendcstr(&buf, inbox);
        free(inbox);
    }

    if (config_skip_userlock && !strcmp(config_skip_userlock, userid)) {
        // add a trailing character to avoid clashing with wrapping lock
        buf_putc(&buf, '~');
    }


    return buf_cstring(&buf);
}

EXPORTED int user_run_with_lock(const char *userid, int (*cb)(void *), void *rock)
{
    user_nslock_t *user_nslock = user_nslock_lock(userid, LOCK_EXCLUSIVE);
    int r = cb(rock);
    user_nslock_release(&user_nslock);
    return r;
}

// we don't need two separate APIs for this because a NULL mboxname means a single mailbox, so you
// can pass NULL to the second argument and mean "just lock one mailbox please".
EXPORTED user_nslock_t *user_nslock_bymboxname_full(const char *mboxname1,
                                                   const char *mboxname2,
                                                   int locktype,
                                                   const char *caller)
{
    char *userid1 = mboxname_to_userid(mboxname1);
    if (!mboxname2) {
        user_nslock_t *locks = user_nslock_lock_full(userid1, locktype, caller);
        free(userid1);
        return locks;
    }
    char *userid2 = mboxname_to_userid(mboxname2);
    user_nslock_t *locks = user_nslock_lockdouble(userid1, userid2, locktype);
    free(userid2);
    free(userid1);
    return locks;
}

/* track who took each held user lock, so an out-of-order report can name
   both sides rather than only the caller */
static strarray_t nslock_holders = STRARRAY_INITIALIZER;

static const char *_lockholder(const char *lockname)
{
    int i = strarray_find(&nslock_holders, lockname, 0);
    /* stored as name, caller pairs */
    return i < 0 ? "unknown" : strarray_nth(&nslock_holders, i+1);
}

static int _addlock(user_nslock_t *locks, const char *userid, int locktype,
                    const char *caller)
{
    struct mboxlock *lock = NULL;
    /* n.b. _namelock_name_from_userid() returns a static buffer, so lock
       before working out the next name; mboxname_lock() copies it */
    const char *name = _namelock_name_from_userid(userid);

    if (mboxname_lock(name, &lock, locktype)) {
        assert(locktype == LOCK_NONBLOCKING);
        return IMAP_MAILBOX_LOCKED;
    }

    ptrarray_append(&locks->locks, lock);

    if (strarray_find(&nslock_holders, lock->name, 0) < 0) {
        strarray_append(&nslock_holders, lock->name);
        strarray_append(&nslock_holders, caller);
    }

    return 0;
}

EXPORTED user_nslock_t *user_nslock_lock_full(const char *userid, int locktype,
                                             const char *caller)
{
    int haslock = user_nslock_islocked(userid);

    if (!haslock) {
        assert(!open_mailboxes_namelocked(userid));
        assert(!annotate_anydb_islocked());
    }
    user_nslock_t *locks = xzmalloc(sizeof(struct usernamespacelocks));
    const char *lockname = _namelock_name_from_userid(userid);

    /* taking a second user's lock while holding one deadlocks against the
       same pair taken the other way around.  Use user_nslock_lockmulti() to
       hold more than one, or finish with one user before starting the next.

       Only an acquisition blocks, so re-taking a lock we already hold is just
       a refcount and can't deadlock, e.g. a rename holding both users through
       lockdouble() and mboxlist_setacl() asking for one of them again */
    const char *held = haslock
                     ? NULL
                     : mboxname_findlocked(USER_NAMELOCK_PREFIX, lockname);

    /* holding an earlier-sorting user is the order lockdouble() uses, and a
       consistent order is allowed.  Only the reverse deadlocks */
    if (held && strcmp(held, lockname) > 0) {
        xsyslog(LOG_ERR, "locking a user out of order while another is locked",
                         "userid=<%s> lockname=<%s> caller=<%s>"
                         " heldlock=<%s> heldby=<%s>",
                         userid, lockname, caller, held, _lockholder(held));
    }
    if (_addlock(locks, userid, locktype, caller)) {
        user_nslock_release(&locks);
        return NULL;
    }
    return locks;
}

// we need separate double and single locks because a NULL userid might mean a shared namespace,
// so there's no other way to distinguish between an operation involving a shared mailbox and
// an single mailbox operation

EXPORTED user_nslock_t *user_nslock_lockmulti(const strarray_t *userids,
                                              int locktype)
{
    /* the fixed order must match lockdouble() */
    strarray_t *sorted = strarray_dup(userids);
    strarray_sort(sorted, cmpstringp_raw);
    strarray_uniq(sorted);

    int i;

    /* we may already hold any of these, but never a later one without the
       ones before it, and never a mailbox for an unlocked user */
    for (i = 0; i < strarray_size(sorted); i++) {
        const char *userid = strarray_nth(sorted, i);
        if (user_nslock_islocked(userid)) continue;
        assert(!open_mailboxes_namelocked(userid));
        if (!i) assert(!annotate_anydb_islocked());
    }

    user_nslock_t *locks = xzmalloc(sizeof(struct usernamespacelocks));

    for (i = 0; i < strarray_size(sorted); i++) {
        if (_addlock(locks, strarray_nth(sorted, i), locktype, __func__)) {
            user_nslock_release(&locks);
            break;
        }
    }

    strarray_free(sorted);

    return locks;
}

EXPORTED user_nslock_t *user_nslock_lockdouble(const char *userid1, const char *userid2, int locktype)
{
    strarray_t userids = STRARRAY_INITIALIZER;

    /* both NULL is the shared namespace; lockmulti() collapses duplicates */
    strarray_append(&userids, userid1);
    strarray_append(&userids, userid2);

    user_nslock_t *locks = user_nslock_lockmulti(&userids, locktype);

    strarray_fini(&userids);

    return locks;
}

EXPORTED void user_nslock_release(user_nslock_t **ptr)
{
    user_nslock_t *locks = *ptr;
    if (!locks) return;

    struct mboxlock *lock;
    while ((lock = ptrarray_pop(&locks->locks))) {
        int i = strarray_find(&nslock_holders, lock->name, 0);
        if (i >= 0) {
            free(strarray_remove(&nslock_holders, i));
            free(strarray_remove(&nslock_holders, i));
        }
        mboxname_release(&lock);
    }

    ptrarray_fini(&locks->locks);
    free(locks);
    *ptr = NULL;
}

EXPORTED int user_nslock_islocked(const char *userid)
{
    const char *name = _namelock_name_from_userid(userid);
    return mboxname_islocked(name);
}

EXPORTED int user_nslock_islockedmb(const char *mboxname)
{
    char *userid = mboxname_to_userid(mboxname);
    int r = user_nslock_islocked(userid);
    free(userid);
    return r;
}

EXPORTED int user_isreplicaonly(const char *userid)
{
    int file_exists = 0;
    char *path = strconcat(config_dir, "/replicaonly/", userid, (char *)NULL);
    struct stat sbuf;
    file_exists = !stat(path, &sbuf);
    free(path);
    return file_exists;
}
