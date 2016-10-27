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

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "exitcodes.h"
#include "glob.h"
#include "global.h"
#include "imap/imap_err.h"
#include "mailbox.h"
#include "util.h"
#include "xmalloc.h"

#include "mboxname.h"
#include "mboxlist.h"
#include "cyr_lock.h"

static int mboxname_strip_deletedprefix(char *name, char **ptr);

struct mboxlocklist {
    struct mboxlocklist *next;
    struct mboxlock l;
    int nopen;
};

static struct mboxlocklist *open_mboxlocks = NULL;

static struct namespace *admin_namespace;

/* Mailbox patterns which the design of the server prohibits */
static const char * const badmboxpatterns[] = {
    "",
    "*\t*",
    "*\n*",
    "*/*",
    ".*",
    "*.",
    "*..*",
    "user",
    "user.anyone",
    "user.anonymous",
};
#define NUM_BADMBOXPATTERNS (sizeof(badmboxpatterns)/sizeof(*badmboxpatterns))

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
	    if (item->l.lock_fd != -1)
		close(item->l.lock_fd);
	    free(item->l.name);
	    free(item);
	    return;
	}
	previtem = item;
    }

    fatal("didn't find item in list", EC_SOFTWARE);
}

/* name locking support */

HIDDEN int mboxname_lock(const char *mboxname, struct mboxlock **mboxlockptr,
		  int locktype)
{
    const char *fname;
    int r = 0;
    struct mboxlocklist *lockitem;

    fname = mboxname_lockpath(mboxname);
    if (!fname)
	return IMAP_MAILBOX_BADNAME;

    lockitem = find_lockitem(mboxname);

    /* already open?  just use this one */
    if (lockitem) {
	if (locktype == LOCK_NONBLOCKING)
	    locktype = LOCK_EXCLUSIVE;
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

    switch (locktype) {
    case LOCK_SHARED:
	r = lock_shared(lockitem->l.lock_fd, fname);
	if (!r) lockitem->l.locktype = LOCK_SHARED;
	break;
    case LOCK_EXCLUSIVE:
	r = lock_blocking(lockitem->l.lock_fd, fname);
	if (!r) lockitem->l.locktype = LOCK_EXCLUSIVE;
	break;
    case LOCK_NONBLOCKING:
	r = lock_nonblocking(lockitem->l.lock_fd, fname);
	if (r == -1) r = IMAP_MAILBOX_LOCKED;
	else if (!r) lockitem->l.locktype = LOCK_EXCLUSIVE;
	break;
    default:
	fatal("unknown lock type", EC_SOFTWARE);
    }

done:
    if (r) remove_lockitem(lockitem);
    else *mboxlockptr = &lockitem->l;

    return r;
}

HIDDEN void mboxname_release(struct mboxlock **mboxlockptr)
{
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


/*
 * Convert the external mailbox 'name' to an internal name.
 * If 'userid' is non-null, it is the name of the current user.
 * On success, results are placed in the buffer pointed to by
 * 'result', the buffer must be of size MAX_MAILBOX_BUFFER to
 * allow space for DELETED mailboxes and moving the domain from
 * one end to the other and such.  Yay flexibility.
 */

EXPORTED int mboxname_parts_to_internal(struct mboxname_parts *parts,
					char *result)
{
    char *p = result;
    size_t sz = MAX_MAILBOX_NAME;
    size_t len;
    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
    const char *pf = "";

    if (parts->domain) {
	len = snprintf(p, sz, "%s!", parts->domain);
	p += len;
	sz -= len;
	if (!sz) return IMAP_MAILBOX_BADNAME;
    }

    if (parts->is_deleted) {
	len = snprintf(p, sz, "%s%s", pf, dp);
	p += len;
	sz -= len;
	if (!sz) return IMAP_MAILBOX_BADNAME;
	pf = ".";
    }

    if (parts->userid) {
	len = snprintf(p, sz, "%suser.%s", pf, parts->userid);
	p += len;
	sz -= len;
	if (!sz) return IMAP_MAILBOX_BADNAME;
	pf = ".";
    }

    if (parts->box) {
	len = snprintf(p, sz, "%s%s", pf, parts->box);
	p += len;
	sz -= len;
	if (!sz) return IMAP_MAILBOX_BADNAME;
    }

    return 0;
}

/* Handle conversion from the standard namespace to the internal namespace */
static int mboxname_tointernal(struct namespace *namespace, const char *name,
			       const char *userid, char *result)
{
    char *cp;
    char *atp;
    char *mbresult;
    int userlen, domainlen = 0, namelen;

    /* Blank the result, just in case */
    result[0] = '\0';
    result[MAX_MAILBOX_BUFFER-1] = '\0';

    userlen = userid ? strlen(userid) : 0;
    namelen = strlen(name);

    if (config_virtdomains) {
	if (userid && (cp = strrchr(userid, '@'))) {
	    /* user logged in as user@domain */
	    userlen = cp - userid;
	    /* don't prepend default domain */
	    if (!(config_defdomain && !strcasecmp(config_defdomain, cp+1))) {
		domainlen = strlen(cp+1)+1;
		snprintf(result, MAX_MAILBOX_BUFFER, "%s!", cp+1);
	    }
	}

	if ((cp = strrchr(name, '@'))) {
	    /* mailbox specified as mbox@domain */
	    namelen = cp - name;

	    if (config_defdomain && !strcasecmp(config_defdomain, cp+1)) {
		if (domainlen) {
		    /* don't allow cross-domain access */
		    return IMAP_MAILBOX_BADNAME;
		}
		/* don't prepend default domain */
	    }
	    else {
		if ((!domainlen && !namespace->isadmin) ||
		    (domainlen && strcasecmp(userid+userlen, cp))) {
		    /* don't allow cross-domain access
		       (except for global admin) */
		    return IMAP_MAILBOX_BADNAME;
		}
		domainlen = strlen(cp+1)+1;
		snprintf(result, MAX_MAILBOX_BUFFER, "%s!", cp+1);
	    }

	    atp = strchr(name, '@');
	    if (atp && atp != cp) {
		/* don't allow multiple '@' in name */
		return IMAP_MAILBOX_BADNAME;
	    }
	}

	/* if no domain specified, we're in the default domain */
    }

    mbresult = result + domainlen;

    /* Personal (INBOX) namespace */
    if ((name[0] == 'i' || name[0] == 'I') &&
	!strncasecmp(name, "inbox", 5) &&
	(namelen == 5 || name[5] == namespace->hier_sep)) {

	if (!userid || ((cp = strchr(userid, namespace->hier_sep)) &&
			(cp - userid < userlen))) {
	    return IMAP_MAILBOX_BADNAME;
	}

	snprintf(mbresult, MAX_MAILBOX_BUFFER - domainlen,
		 "user.%.*s%.*s", userlen, userid, namelen-5, name+5);

	/* Translate any separators in userid+mailbox */
	mboxname_hiersep_tointernal(namespace, mbresult+5, 0);
    }

    else {
	/* Other Users & Shared namespace */
	snprintf(mbresult, MAX_MAILBOX_BUFFER - domainlen,
		 "%.*s", namelen, name);

	/* Translate any separators in mailboxname */
	mboxname_hiersep_tointernal(namespace, mbresult, 0);
    }

    if (result[MAX_MAILBOX_BUFFER-1] != '\0') {
	syslog(LOG_ERR, "IOERROR: long mailbox name attempt: %s", name);
	return IMAP_MAILBOX_BADNAME;
    }
    return 0;
}

/* Handle conversion from the alternate namespace to the internal namespace */
static int mboxname_tointernal_alt(struct namespace *namespace,
				   const char *name,
				   const char *userid, char *result)
{
    char *cp;
    int userlen, domainlen = 0, namelen;
    int prefixlen;
    size_t resultlen;

    /* Blank the result, just in case */
    result[0] = '\0';

    userlen = userid ? strlen(userid) : 0;
    namelen = strlen(name);

    if (config_virtdomains) {
	if (userid && (cp = strchr(userid, '@'))) {
	    /* user logged in as user@domain */
	    userlen = cp++ - userid;
	    if (!(config_defdomain && !strcasecmp(config_defdomain, cp))) {
		/* don't prepend default domain */
		domainlen = strlen(cp)+1;
		if (domainlen > MAX_MAILBOX_NAME) 
		    return IMAP_MAILBOX_BADNAME; 
		sprintf(result, "%s!", cp);
	    }
	}
	if ((cp = strrchr(name, '@'))) {
	    /* mailbox specified as mbox@domain */
	    namelen = cp - name;

	    if (config_defdomain && !strcasecmp(config_defdomain, cp+1)) {
		if (domainlen) {
		    /* don't allow cross-domain access */
		    return IMAP_MAILBOX_BADNAME;
		}
		/* don't prepend default domain */
	    }
	    else {
		if ((!domainlen && !namespace->isadmin) ||
		    (domainlen && strcasecmp(userid+userlen, cp))) {
		    /* don't allow cross-domain access 
		       (except for global admin) */
		    return IMAP_MAILBOX_BADNAME;
		}
		domainlen = strlen(cp+1)+1;
		if (domainlen > MAX_MAILBOX_NAME) 
		    return IMAP_MAILBOX_BADNAME; 
		sprintf(result, "%s!", cp+1);
	    }
	}

	/* if no domain specified, we're in the default domain */
    }

    result += domainlen;

    /* Shared namespace */
    prefixlen = strlen(namespace->prefix[NAMESPACE_SHARED]);

    if(prefixlen == 0) return IMAP_MAILBOX_BADNAME;

    if (!strncmp(name, namespace->prefix[NAMESPACE_SHARED], prefixlen-1) &&
	(namelen == prefixlen-1 || name[prefixlen-1] == namespace->hier_sep)) {

	if (namelen ==  prefixlen-1) {
	    /* can't create folders using undelimited prefix */
	    return IMAP_MAILBOX_BADNAME;
	}

	if (domainlen+namelen-prefixlen > MAX_MAILBOX_NAME) {
	    return IMAP_MAILBOX_BADNAME;
	}

	sprintf(result, "%.*s", namelen-prefixlen, name+prefixlen);

	/* Translate any separators in mailboxname */
	mboxname_hiersep_tointernal(namespace, result, 0);

	return 0;
    }

    /* Other Users namespace */
    prefixlen = strlen(namespace->prefix[NAMESPACE_USER]);
    if(prefixlen == 0) return IMAP_MAILBOX_BADNAME;

    if (!strncmp(name, namespace->prefix[NAMESPACE_USER], prefixlen-1) &&
	(namelen == prefixlen-1 || name[prefixlen-1] == namespace->hier_sep)) {

	if (namelen == prefixlen-1) {
	    /* can't create folders using undelimited prefix */
	    return IMAP_MAILBOX_BADNAME;
	}

	if (domainlen+namelen-prefixlen+5 > MAX_MAILBOX_NAME) {
	    return IMAP_MAILBOX_BADNAME;
	}

	sprintf(result, "user.%.*s", namelen-prefixlen, name+prefixlen);

	/* Translate any separators in userid+mailbox */
	mboxname_hiersep_tointernal(namespace, result+5, 0);
	return 0;
    }

    /* Personal (INBOX) namespace */
    if (!userid || ((cp = strchr(userid, namespace->hier_sep)) &&
		    (cp - userid < userlen))) {
	return IMAP_MAILBOX_BADNAME;
    }

    if (domainlen+userlen+5 > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }

    sprintf(result, "user.%.*s", userlen, userid);

    /* INBOX */
    if ((name[0] == 'i' || name[0] == 'I') &&
	!strncasecmp(name, "inbox", 5) && 
	(namelen == 5 || name[5] == namespace->hier_sep)) {

	if (name[5] == namespace->hier_sep) {
	    /* can't create folders under INBOX */
	    return IMAP_MAILBOX_BADNAME;
	}

	return 0;
    }

    resultlen = strlen(result);

    /* other personal folder */
    if (domainlen+resultlen+6+namelen > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }
    snprintf(result+resultlen, MAX_MAILBOX_BUFFER-resultlen, ".%.*s", 
	     namelen, name);

    /* Translate any separators in mailboxname */
    mboxname_hiersep_tointernal(namespace, result+6+userlen, 0);
    return 0;
}

/*
 * Convert the internal mailbox 'name' to an external name.
 * If 'userid' is non-null, it is the name of the current user.
 * On success, results are placed in the buffer pointed to by
 * 'result', the buffer must be of size MAX_MAILBOX_BUFFER.
 */

/* Handle conversion from the internal namespace to the standard namespace */
static int mboxname_toexternal(struct namespace *namespace, const char *mboxname,
			       const char *userid, char *result)
{
    struct mboxname_parts mbparts;
    struct mboxname_parts userparts;

    /* Blank the result, just in case */
    result[0] = '\0';

    if (strlen(mboxname) > MAX_MAILBOX_NAME)
	return IMAP_MAILBOX_BADNAME;

    mboxname_to_parts(mboxname, &mbparts);
    mboxname_userid_to_parts(userid, &userparts);

    if (mbparts.userid) {
	if (!namespace->isadmin && !mbparts.is_deleted &&
	    mboxname_parts_same_userid(&mbparts, &userparts)) {
	    strcpy(result, "INBOX");
	}
	else if (mbparts.is_deleted) {
	    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
	    sprintf(result, "%s.user.%s", dp, mbparts.userid);
	}
	else {
	    sprintf(result, "user.%s", mbparts.userid);
	}

	if (mbparts.box)
	    strcat(result, ".");
    } else {
	/* shared mailbox */
	if (mbparts.is_deleted) {
	    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
	    sprintf(result, "%s.", dp);
	}
    }


    if (mbparts.box)
	strcat(result, mbparts.box);

    /* Translate any separators in mailboxname */
    mboxname_hiersep_toexternal(namespace, result, 0);

    /* Append domain - only if not the same as the user */
    if (mbparts.domain) {
	if (strcmpsafe(userparts.domain, mbparts.domain)) {
	    strcat(result, "@");
	    strcat(result, mbparts.domain);
	} else {
	    if (namespace->isadmin && !userparts.domain) {
		strcat(result, "@");
		strcat(result, mbparts.domain);
	    }
	}
    }

    mboxname_free_parts(&mbparts);
    mboxname_free_parts(&userparts);
    return 0;
}

/* Handle conversion from the internal namespace to the alternate namespace */
static int mboxname_toexternal_alt(struct namespace *namespace, const char *mboxname,
				  const char *userid, char *result)
{
    char iresult[MAX_MAILBOX_NAME];
    int r = 0;

    /* MUST blank the result */
    result[0] = '\0';

    // Make this abundantly simple
    mboxname_toexternal(namespace, mboxname, userid, iresult);

    if (namespace->isadmin) {
	sprintf(result, "%s", iresult);
    }

    // If an administrator view, such as intended with event
    // notifications, then the translation to external is
    // sufficient (omit the "Other Users/" and "Shared Folders/"
    // prefixes for regular users).
    if (namespace->isadmin) {
	sprintf(result, "%s", iresult);
	return 0;
    }

    r = strncasecmp(iresult, "inbox", 5);

    if (!r) {
	if (iresult[5] == '\0') {
	    // Just "INBOX"
	    sprintf(result, "%s", iresult);
	} else if (iresult[5] == namespace->hier_sep) {
	    // INBOX/something
	    sprintf(result, "%s", iresult+6);
	}

	return 0;
    }

    r = strncasecmp(iresult, "user", 4);

    if (!r) {
	if (iresult[4] == namespace->hier_sep) {
	    // The namespace already has a hierarchy separator
	    sprintf(result, "%s%s", namespace->prefix[NAMESPACE_USER], iresult+5);
	/* special case:  LIST/LSUB "" % */
	} else {
	    sprintf(result, "%.*s", (int)strlen(namespace->prefix[NAMESPACE_USER])-1, namespace->prefix[NAMESPACE_USER]);
	}

	return 0;
    }

    /* If not the personal namespace and not the other user namespace, then
     * the shared folder namespace */

    /* special case:  LIST/LSUB "" % */
    if (!strncmp(mboxname, namespace->prefix[NAMESPACE_SHARED],
	strlen(namespace->prefix[NAMESPACE_SHARED])-1)) {
	strcpy(result, mboxname);
    } else {
	strcpy(result, namespace->prefix[NAMESPACE_SHARED]);
	strcat(result, mboxname);
    }

    sprintf(result, "%s%s", namespace->prefix[NAMESPACE_SHARED], iresult);

    return 0;
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

	namespace->mboxname_tointernal = mboxname_tointernal_alt;
	namespace->mboxname_toexternal = mboxname_toexternal_alt;
	namespace->mboxlist_findall = mboxlist_findall_alt;
	namespace->mboxlist_findsub = mboxlist_findsub_alt;
    }

    else {
	/* standard namespace */
	sprintf(namespace->prefix[NAMESPACE_INBOX], "%s%c",
		"INBOX", namespace->hier_sep);
	sprintf(namespace->prefix[NAMESPACE_USER], "%s%c",
		"user", namespace->hier_sep);
	strcpy(namespace->prefix[NAMESPACE_SHARED], "");

	namespace->mboxname_tointernal = mboxname_tointernal;
	namespace->mboxname_toexternal = mboxname_toexternal;
	namespace->mboxlist_findall = mboxlist_findall;
	namespace->mboxlist_findsub = mboxlist_findsub;
    }

    return 0;
}

HIDDEN struct namespace *mboxname_get_adminnamespace()
{
    static struct namespace ns;
    if (!admin_namespace) {
	mboxname_init_namespace(&ns, /*isadmin*/1);
	admin_namespace = &ns;
    }
    return admin_namespace;
}

/*
 * Translate separator charactors in a mailboxname from its external
 * representation to its internal representation '.'.
 * If using the unixhierarchysep '/', all '.'s get translated to DOTCHAR.
 */
EXPORTED char *mboxname_hiersep_tointernal(struct namespace *namespace, char *name,
				  int length)
{
    char *p;

    assert(namespace != NULL);
    assert(namespace->hier_sep == '.' || namespace->hier_sep == '/');

    if (!length) length = strlen(name);

    if (namespace->hier_sep == '/') {
	/* change all '/'s to '.' and all '.'s to DOTCHAR */
	for (p = name; *p && length; p++, length--) {
	    if (*p == '/') *p = '.';
	    else if (*p == '.') *p = DOTCHAR;
	}
    }

    return name;
}

/*
 * Translate separator charactors in a mailboxname from its internal
 * representation '.' to its external representation.
 * If using the unixhierarchysep '/', all DOTCHAR get translated to '.'.
 */
EXPORTED char *mboxname_hiersep_toexternal(struct namespace *namespace, char *name,
                                  int length)
{
    char *p;

    if (name == NULL)
    	return NULL;

    assert(namespace != NULL);
    assert(namespace->hier_sep == '.' || namespace->hier_sep == '/');

    if (!length) length=strlen(name);

    if (namespace->hier_sep == '/') {
	/* change all '.'s to '/' and all DOTCHARs to '.' */
	for (p = name; *p && length; p++, length--) {
	    if (*p == '.') *p = '/';
	    else if (*p == DOTCHAR) *p = '.';
	}
    }

    return name;
}

/*
 * Return nonzero if 'userid' owns the (internal) mailbox 'name'.
 */
EXPORTED int mboxname_userownsmailbox(const char *userid, const char *name)
{
    struct namespace internal = NAMESPACE_INITIALIZER;
    char inboxname[MAX_MAILBOX_BUFFER];

    if (!mboxname_tointernal(&internal, "INBOX", userid, inboxname) &&
	!strncmp(name, inboxname, strlen(inboxname)) &&
	(name[strlen(inboxname)] == '\0' || name[strlen(inboxname)] == '.')) {
	return 1;
    }
    return 0;
}

/*
 * If (internal) mailbox 'name' is a user's mailbox (optionally INBOX),
 * returns a pointer to the userid, otherwise returns NULL.
 */
EXPORTED char *mboxname_isusermailbox(const char *name, int isinbox)
{
    const char *p;
    const char *start = name;

    /* step past the domain part */
    if (config_virtdomains && (p = strchr(start, '!')))
	start = p + 1;

    /* starts with "user." AND
     * we don't care if it's an inbox OR
     * there's no dots after the username 
     */
    if (!strncmp(start, "user.", 5) && (!isinbox || !strchr(start+5, '.')))
	return (char*) start+5;
    else
	return NULL;
}

/* NOTE - name must have had domain removed already */
static int mboxname_strip_deletedprefix(char *name, char **ptr)
{
    static const char *deletedprefix = NULL;
    static int deletedprefix_len = 0;

    /* cache for efficiency, this code can get called 
     * in an inner loop */
    if (!deletedprefix) {
	deletedprefix = config_getstring(IMAPOPT_DELETEDPREFIX);
	deletedprefix_len = strlen(deletedprefix);
    }

    /* if the prefix is blank, then nothing is deleted */
    if (!deletedprefix_len) return 0;

    if (strncmp(name, deletedprefix, deletedprefix_len))
	return IMAP_MAILBOX_BADNAME;

    if (name[deletedprefix_len] != '.')
	return IMAP_MAILBOX_BADNAME;

    *ptr = name + deletedprefix_len + 1;

    return 0;
}

/*
 * If (internal) mailbox 'name' is a DELETED mailbox
 * returns boolean
 */
EXPORTED int mboxname_isdeletedmailbox(const char *name, time_t *timestampp)
{
    int domainlen = 0;
    char *rest = NULL;
    char *p;
    int i;

    if (config_virtdomains && (p = strchr(name, '!')))
	domainlen = p - name + 1;

    if (mboxname_strip_deletedprefix((char *)(name + domainlen), &rest))
	return 0;

    /* Sanity check for 8 hex digits only at the end */
    p = strrchr(rest, '.');
    if (!p)
	return 0;
    p++;

    for (i = 0 ; i < 7; i++) {
        if (!Uisxdigit(p[i]))
	    return 0;
    }
    if (p[8] != '\0')
	return 0;

    if (timestampp)
	*timestampp = (time_t)strtoul(p, NULL, 16);

    return 1;
}

/*
 * If (internal) mailbox 'name' is a CALENDAR mailbox
 * returns boolean
 */
int mboxname_iscalendarmailbox(const char *name, int mbtype)
{
    static const char *calendarprefix = NULL;
    static int calendarprefix_len = 0;
    const char *p;
    const char *start = name;

    if (mbtype & MBTYPE_CALENDAR) return 1;  /* Only works on backends */

    if (!calendarprefix) {
	calendarprefix = config_getstring(IMAPOPT_CALENDARPREFIX);
	if (calendarprefix) calendarprefix_len = strlen(calendarprefix);
    }

    /* if the prefix is blank, then no calendars */
    if (!calendarprefix_len) return 0;

    /* step past the domain part */
    if (config_virtdomains && (p = strchr(start, '!')))
	start = p + 1;

    /* step past the user part */
    if (!strncmp(start, "user.", 5) && (p = strchr(start+5, '.')))
	start = p + 1;

    return ((!strncmp(start, calendarprefix, calendarprefix_len) &&
	     (start[calendarprefix_len] == '\0' ||
	      start[calendarprefix_len] == '.')) ? 1 : 0);
}

/*
 * If (internal) mailbox 'name' is a ADDRESSBOOK mailbox
 * returns boolean
 */
int mboxname_isaddressbookmailbox(const char *name, int mbtype)
{
    static const char *addressbookprefix = NULL;
    static int addressbookprefix_len = 0;
    const char *p;
    const char *start = name;

    if (mbtype & MBTYPE_ADDRESSBOOK) return 1;  /* Only works on backends */

    if (!addressbookprefix) {
	addressbookprefix = config_getstring(IMAPOPT_ADDRESSBOOKPREFIX);
	if (addressbookprefix) addressbookprefix_len = strlen(addressbookprefix);
    }

    /* if the prefix is blank, then no addressbooks */
    if (!addressbookprefix_len) return 0;

    /* step past the domain part */
    if (config_virtdomains && (p = strchr(start, '!')))
	start = p + 1;

    /* step past the user part */
    if (!strncmp(start, "user.", 5) && (p = strchr(start+5, '.')))
	start = p + 1;

    return ((!strncmp(start, addressbookprefix, addressbookprefix_len) &&
	     (start[addressbookprefix_len] == '\0' ||
	      start[addressbookprefix_len] == '.')) ? 1 : 0);
}

/*
 * Translate (internal) inboxname into corresponding userid.
 */
EXPORTED const char *mboxname_to_userid(const char *mboxname)
{
    static char userid[MAX_MAILBOX_BUFFER];
    char *ret;
    struct mboxname_parts parts;
    int unixsep;

    unixsep = config_getswitch(IMAPOPT_UNIXHIERARCHYSEP);

    if (mboxname_to_parts(mboxname, &parts))
	return NULL;

    if (parts.userid == NULL) {
	ret = NULL;
    } else {
	char *p;

	if (unixsep && (p = strchr(parts.userid, DOTCHAR))) {
	    *p = '.';
	}

	if (parts.domain)
	    snprintf(userid, sizeof(userid), "%s@%s", parts.userid, parts.domain);
	else
	    xstrncpy(userid, parts.userid, sizeof(userid));
	ret = userid;
    }

    mboxname_free_parts(&parts);
    return ret;
}

EXPORTED char *mboxname_user_mbox(const char *userid, const char *subfolder)
{
    struct buf mbox = BUF_INITIALIZER;
    char result[MAX_MAILBOX_BUFFER];

    static struct namespace ns;
    mboxname_init_namespace(&ns, /*is_admin*/1);

    if (!userid) return NULL;

    if (config_virtdomains) {
	ns.mboxname_tointernal(&ns, "INBOX", userid, result);
	buf_printf(&mbox, "%s", result);
	goto userdone;
    }

userdone:
    if (subfolder) {
	ns.mboxname_tointernal(&ns, subfolder, NULL, result);
	buf_printf(&mbox, ".%s", result);
    }

    return buf_release(&mbox);
}

/*
 * Check whether two parts have the same userid.
 * Returns: 1 if the userids are the same, 0 if not.
 */
EXPORTED int mboxname_parts_same_userid(struct mboxname_parts *a,
			       struct mboxname_parts *b)
{
    int r;

    r = strcmpsafe(a->domain, b->domain);
    if (!r)
	r = strcmpsafe(a->userid, b->userid);
    return !r;
}

/*
 * Check whether two mboxnames have the same userid.
 * Needed for some corner cases in the COPY command.
 * Returns: 1 if the userids are the same, 0 if not,
 *	    or negative error.
 */
EXPORTED int mboxname_same_userid(const char *name1, const char *name2)
{
    struct mboxname_parts parts1, parts2;
    int r;

    if (mboxname_to_parts(name1, &parts1))
	return IMAP_MAILBOX_BADNAME;
    if (mboxname_to_parts(name2, &parts2)) {
	mboxname_free_parts(&parts1);
	return IMAP_MAILBOX_BADNAME;
    }

    r = mboxname_parts_same_userid(&parts1, &parts2);

    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);

    return r;
}

/*
 * Split an (internal) inboxname into it's constituent
 * parts, filling out and returning a parts structure.
 * The caller must clean up the parts structure by
 * calling mboxname_free_parts().
 * Returns 0 on success, -ve error otherwise.
 */
EXPORTED int mboxname_to_parts(const char *mboxname, struct mboxname_parts *parts)
{
    char *b, *e;    /* beginning and end of string parts */

    mboxname_init_parts(parts);

    if (!mboxname)
	return 0;

    b = parts->freeme = xstrdup(mboxname);

    if (config_virtdomains && (e = strchr(b, '!'))) {
	parts->domain = b;
	*e++ = '\0';
	b = e;
    }

    if (!mboxname_strip_deletedprefix(b, &b)) {
	parts->is_deleted = 1;
    }

    if (!strncmp(b, "user.", 5)) {
	/* user mailbox */
	b += 5;
	parts->userid = b;
	/* find end of userid */
	e = strchr(b, '.');
	if (e) {
	    *e++ = '\0';
	    b = e;
	} else {
	    b += strlen(b);
	}
    } else {
	/* shared mailbox - nothing to strip */
    }

    if (*b) parts->box = b;

    return 0;
}

EXPORTED int mboxname_userid_to_parts(const char *userid, struct mboxname_parts *parts)
{
    char *b, *e;    /* beginning and end of string parts */

    mboxname_init_parts(parts);

    if (!userid)
	return 0;

    b = parts->freeme = xstrdup(userid);

    parts->userid = b;

    if (config_virtdomains && (e = strchr(b, '@'))) {
	*e++ = '\0';
	parts->domain = e;
    }

    return 0;
}

EXPORTED void mboxname_init_parts(struct mboxname_parts *parts)
{
    memset(parts, 0, sizeof(*parts));
}

EXPORTED void mboxname_free_parts(struct mboxname_parts *parts)
{
    if (parts->freeme) {
	free(parts->freeme);
	memset(parts, 0, sizeof(*parts));
    }
}

/*
 * Apply site policy restrictions on mailbox names.
 * Restrictions are hardwired for now.
 */
#define GOODCHARS " #$'+,-.0123456789:=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
HIDDEN int mboxname_policycheck(const char *name)
{
    const char *p;
    unsigned i;
    struct glob *g;
    int sawutf7 = 0;
    unsigned c1, c2, c3, c4, c5, c6, c7, c8;
    int ucs4;
    int unixsep;

    unixsep = config_getswitch(IMAPOPT_UNIXHIERARCHYSEP);

    /* Skip policy check on mailbox created in delayed delete namespace
     * assuming the mailbox existed before and was OK then.
     * This should allow mailboxes that are extremely long to be
     * deleted when delayed_delete is enabled.
     * A thorough fix might remove the prefix and timestamp
     * then continue with the check
     */
    if (mboxname_isdeletedmailbox(name, NULL))
	return 0;

    if (strlen(name) > MAX_MAILBOX_NAME)
	return IMAP_MAILBOX_BADNAME;

    /* find the virtual domain, if any.  We don't sanity check domain
       names yet - maybe we should */
    p = strchr(name, '!');
    if (p) {
	if (config_virtdomains)
	    name = p + 1;
	else
	    return IMAP_MAILBOX_BADNAME;
    }

    for (i = 0; i < NUM_BADMBOXPATTERNS; i++) {
	g = glob_init(badmboxpatterns[i], GLOB_ICASE);
	if (GLOB_TEST(g, name) != -1) {
	    glob_free(&g);
	    return IMAP_MAILBOX_BADNAME;
	}
	glob_free(&g);
    }

    if (*name == '~') return IMAP_MAILBOX_BADNAME;
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
		if ((ucs4 & 0xff80) == 0 || (ucs4 & 0xf800) == 0xd800) {
		    /* US-ASCII or multi-word character */
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
		if ((ucs4 & 0xff80) == 0 || (ucs4 & 0xf800) == 0xd800) {
		    /* US-ASCII or multi-word character */
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
		if ((ucs4 & 0xff80) == 0 || (ucs4 & 0xf800) == 0xd800) {
		    /* US-ASCII or multi-word character */
		    return IMAP_MAILBOX_BADNAME;
		}
	    }

	    if (name[-1] == '&') sawutf7 = 0; /* '&-' is sequence for '&' */
	    else sawutf7 = 1;

	    name++;		/* Skip over terminating '-' */
	}
	else {
	    if (!strchr(GOODCHARS, *name) &&
		/* If we're using unixhierarchysep, DOTCHAR is allowed */
		!(unixsep && *name == DOTCHAR))
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


void mboxname_hash(char *buf, size_t buf_len,
		   const char *root,
		   const char *name)
{
    const char *idx;
    char c, *p;

    snprintf(buf, buf_len, "%s", root);
    buf_len -= strlen(buf);
    buf += strlen(buf);

    if (config_virtdomains && (p = strchr(name, '!'))) {
	*p = '\0';  /* split domain!user */
	if (config_hashimapspool) {
	    c = (char) dir_hash_c(name, config_fulldirhash);
	    snprintf(buf, buf_len, "%s%c/%s", FNAME_DOMAINDIR, c, name);
	}
	else {
	    snprintf(buf, buf_len, "%s%s", FNAME_DOMAINDIR, name);
	}
	*p++ = '!';  /* reassemble domain!user */
	name = p;
	buf_len -= strlen(buf);
	buf += strlen(buf);
    }

    if (config_hashimapspool) {
	idx = strchr(name, '.');
	if (idx == NULL) {
	    idx = name;
	} else {
	    idx++;
	}
	c = (char) dir_hash_c(idx, config_fulldirhash);
	
	snprintf(buf, buf_len, "/%c/%s", c, name);
    } else {
	/* standard mailbox placement */
	snprintf(buf, buf_len, "/%s", name);
    }

    /* change all '.'s to '/' */
    for (p = buf; *p; p++) {
	if (*p == '.') *p = '/';
    }
}

/* note: mboxname must be internal */
EXPORTED char *mboxname_datapath(const char *partition, const char *mboxname, unsigned long uid)
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

    mboxname_hash(pathresult, MAX_MAILBOX_PATH, root, mboxname);

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
    snprintf(lockresult + len, MAX_MAILBOX_PATH - len, "%s", ".lock");
    lockresult[MAX_MAILBOX_PATH] = '\0';

    if (strlen(lockresult) == MAX_MAILBOX_PATH)
	return NULL;

    return lockresult;
}

EXPORTED char *mboxname_metapath(const char *partition, const char *mboxname,
			int metafile, int isnew)
{
    static char metaresult[MAX_MAILBOX_PATH];
    int metaflag = 0;
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
#endif /* WITH_DAV */

    case 0:
	break;
    default:
	fatal("Unknown meta file requested", EC_SOFTWARE);
    }

    if (*confkey)
	root = config_getoverflowstring(confkey, NULL);

    if (!root && (!metaflag || (config_metapartition_files & metaflag)))
	root = config_metapartitiondir(partition);

    if (!root)
	root = config_partitiondir(partition);

    if (!root)
	return NULL;

    if (!mboxname) {
	xstrncpy(metaresult, root, MAX_MAILBOX_PATH);
	return metaresult;
    }

    mboxname_hash(metaresult, MAX_MAILBOX_PATH, root, mboxname);

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
	return 0;				/* stop now */

    p = strrchr(name, '.');

    if (p && (p - name > domainlen))		/* don't split subdomain */
	*p = '\0';
    else if (!name[domainlen])			/* server entry */
	name[0] = '\0';
    else					/* domain entry */
	name[domainlen] = '\0';

    return 1;
}

/* NOTE: caller must free, which is different from almost every
 * other interface in the whole codebase.  Grr */
HIDDEN char *mboxname_conf_getpath(struct mboxname_parts *parts, const char *suffix)
{
    char *fname = NULL;
    char c[2], d[2];
    
    if (parts->domain) {
	if (parts->userid) {
	    fname = strconcat(config_dir,
			      FNAME_DOMAINDIR,
			      dir_hash_b(parts->domain, config_fulldirhash, d),
			      "/", parts->domain,
			      FNAME_USERDIR,
			      dir_hash_b(parts->userid, config_fulldirhash, c),
			      "/", parts->userid, ".", suffix,
			      (char *)NULL);
	}
	else {
	    fname = strconcat(config_dir,
			      FNAME_DOMAINDIR,
			      dir_hash_b(parts->domain, config_fulldirhash, d),
			      "/", parts->domain,
			      "/", FNAME_SHAREDPREFIX, ".", suffix,
			      (char *)NULL);
	}
    }
    else {
	if (parts->userid) {
	    fname = strconcat(config_dir,
			      FNAME_USERDIR,
			      dir_hash_b(parts->userid, config_fulldirhash, c),
			      "/", parts->userid, ".", suffix,
			      (char *)NULL);
	}
	else {
	    fname = strconcat(config_dir,
			      "/", FNAME_SHAREDPREFIX, ".", suffix,
			      (char *)NULL);
	}
    }

    return fname;
}
