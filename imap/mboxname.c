/* mboxname.c -- Mailbox list manipulation routines
 * $Id: mboxname.c,v 1.27 2003/04/25 16:18:58 rjs3 Exp $
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <com_err.h>

#include "assert.h"
#include "glob.h"
#include "imapconf.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"

#include "mboxname.h"
#include "mboxlist.h"

/* Mailbox patterns which the design of the server prohibits */
static char *badmboxpatterns[] = {
    "",
    "*\t*",
    "*\n*",
    "*/*",
    ".*",
    "*.",
    "*..*",
    "user",
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


/*
 * Convert the external mailbox 'name' to an internal name.
 * If 'userid' is non-null, it is the name of the current user.
 * On success, results are placed in the buffer pointed to by
 * 'result', the buffer must be of size MAX_MAILBOX_NAME+1.
 */

/* Handle conversion from the standard namespace to the internal namespace */
static int mboxname_tointernal(struct namespace *namespace, const char *name,
			       const char *userid, char *result)
{
    /* Blank the result, just in case */
    result[0] = '\0';

    /* Personal (INBOX) namespace */
    if ((name[0] == 'i' || name[0] == 'I') &&
	!strncasecmp(name, "inbox", 5) &&
	(name[5] == '\0' || name[5] == namespace->hier_sep)) {

	if (!userid || strchr(userid, namespace->hier_sep)) {
	    return IMAP_MAILBOX_BADNAME;
	}

	if (strlen(name+5)+strlen(userid)+5 > MAX_MAILBOX_NAME) {
	    return IMAP_MAILBOX_BADNAME;
	}

	strcpy(result, "user.");
	strcat(result, userid);
	strcat(result, name+5);

	/* Translate any separators in userid+mailbox */
	mboxname_hiersep_tointernal(namespace, result+5+strlen(userid));
	return 0;
    }

    /* Other Users & Shared namespace */
    if (strlen(name) > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }
    strcpy(result, name);

    /* Translate any separators in mailboxname */
    mboxname_hiersep_tointernal(namespace, result);
    return 0;
}

/* Handle conversion from the alternate namespace to the internal namespace */
static int mboxname_tointernal_alt(struct namespace *namespace,
				   const char *name,
				   const char *userid, char *result)
{
    int prefixlen;

    /* Blank the result, just in case */
    result[0] = '\0';

    /* Shared namespace */
    prefixlen = strlen(namespace->prefix[NAMESPACE_SHARED]);
    if(prefixlen == 0) return IMAP_MAILBOX_BADNAME;

    if (!strncmp(name, namespace->prefix[NAMESPACE_SHARED], prefixlen-1) &&
	(name[prefixlen-1] == '\0' || name[prefixlen-1] == namespace->hier_sep)) {

	if (name[prefixlen-1] == '\0') {
	    /* can't create folders using undelimited prefix */
	    return IMAP_MAILBOX_BADNAME;
	}

	if (strlen(name+prefixlen) > MAX_MAILBOX_NAME) {
	    return IMAP_MAILBOX_BADNAME;
	}

	strcpy(result, name+prefixlen);

	/* Translate any separators in mailboxname */
	mboxname_hiersep_tointernal(namespace, result);
	return 0;
    }

    /* Other Users namespace */
    prefixlen = strlen(namespace->prefix[NAMESPACE_USER]);
    if (!strncmp(name, namespace->prefix[NAMESPACE_USER], prefixlen-1) &&
	(name[prefixlen-1] == '\0' || name[prefixlen-1] == namespace->hier_sep)) {

	if (name[prefixlen-1] == '\0') {
	    /* can't create folders using undelimited prefix */
	    return IMAP_MAILBOX_BADNAME;
	}

	if (strlen(name+prefixlen)+5 > MAX_MAILBOX_NAME) {
	    return IMAP_MAILBOX_BADNAME;
	}

	strcpy(result, "user.");
	strcat(result, name+prefixlen);

	/* Translate any separators in userid+mailbox */
	mboxname_hiersep_tointernal(namespace, result+5);
	return 0;
    }

    /* Personal (INBOX) namespace */
    if (!userid || strchr(userid, namespace->hier_sep)) {
	return IMAP_MAILBOX_BADNAME;
    }

    if (strlen(userid)+5 > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }

    strcpy(result, "user.");
    strcat(result, userid);

    /* INBOX */
    if ((name[0] == 'i' || name[0] == 'I') &&
	!strncasecmp(name, "inbox", 5) &&
	(name[5] == '\0' || name[5] == namespace->hier_sep)) {

	if (name[5] == namespace->hier_sep) {
	    /* can't create folders under INBOX */
	    return IMAP_MAILBOX_BADNAME;
	}

	return 0;
    }

    /* other personal folder */
    if (strlen(result)+6 > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }
    strcat(result, ".");
    strcat(result, name);

    /* Translate any separators in mailboxname */
    mboxname_hiersep_tointernal(namespace, result+6+strlen(userid));
    return 0;
}

/*
 * Convert the internal mailbox 'name' to an external name.
 * If 'userid' is non-null, it is the name of the current user.
 * On success, results are placed in the buffer pointed to by
 * 'result', the buffer must be of size MAX_MAILBOX_NAME+1.
 */

/* Handle conversion from the internal namespace to the standard namespace */
static int mboxname_toexternal(struct namespace *namespace, const char *name,
			       const char *userid, char *result)
{
    /* Blank the result, just in case */
    result[0] = '\0';

    if(strlen(name) > MAX_MAILBOX_NAME) return IMAP_MAILBOX_BADNAME;
    
    strcpy(result, name);

    /* Translate any separators in mailboxname */
    mboxname_hiersep_toexternal(namespace, result);
    return 0;
}

/* Handle conversion from the internal namespace to the alternate namespace */
static int mboxname_toexternal_alt(struct namespace *namespace, const char *name,
				  const char *userid, char *result)
{
    /* Personal (INBOX) namespace */
    if (!strncasecmp(name, "inbox", 5) &&
	(name[5] == '\0' || name[5] == '.')) {
	if (name[5] == '\0')
	    strcpy(result, name);
	else
	    strcpy(result, name+6);
    }
    /* paranoia - this shouldn't be needed */
    else if (!strncmp(name, "user.", 5) &&
	     !strncmp(name+5, userid, strlen(userid)) &&
	     (name[5+strlen(userid)] == '\0' ||
	      name[5+strlen(userid)] == '.')) {
	if (name[5+strlen(userid)] == '\0')
	    strcpy(result, "INBOX");
	else
	    strcpy(result, name+5+strlen(userid)+1);
    }

    /* Other Users namespace */
    else if (!strncmp(name, "user", 4) &&
	     (name[4] == '\0' || name[4] == '.')) {
	sprintf(result, "%.*s",
		(int) strlen(namespace->prefix[NAMESPACE_USER])-1,
		namespace->prefix[NAMESPACE_USER]);
	if (name[4] == '.') {
	    sprintf(result+strlen(result), "%c%s",
		    namespace->hier_sep, name+5);
	}
    }

    /* Shared namespace */
    else {
	/* special case:  LIST/LSUB "" % */
	if (!strncmp(name, namespace->prefix[NAMESPACE_SHARED],
		     strlen(namespace->prefix[NAMESPACE_SHARED])-1)) {
	    strcpy(result, name);
	}
	else {
	    strcpy(result, namespace->prefix[NAMESPACE_SHARED]);
	    strcat(result, name);
	}
    }

    /* Translate any separators in mailboxname */
    mboxname_hiersep_toexternal(namespace, result);
    return 0;
}

/*
 * Create namespace based on config options.
 */
int mboxname_init_namespace(struct namespace *namespace, int force_std)
{
    const char *prefix;

    assert(namespace != NULL);

    namespace->hier_sep = config_getswitch("unixhierarchysep", 0) ? '/' : '.';
    namespace->isalt = !force_std && config_getswitch("altnamespace", 0);

    if (namespace->isalt) {
	/* alternate namespace */
	strcpy(namespace->prefix[NAMESPACE_INBOX], "");

	prefix = config_getstring("userprefix", "Other Users");
	if (!prefix || strlen(prefix) == 0 ||
	    strlen(prefix) >= MAX_NAMESPACE_PREFIX ||
	    strchr(prefix,namespace->hier_sep) != NULL)
	    return IMAP_NAMESPACE_BADPREFIX;
	sprintf(namespace->prefix[NAMESPACE_USER], "%.*s%c",
		MAX_NAMESPACE_PREFIX-1, prefix, namespace->hier_sep);

	prefix = config_getstring("sharedprefix", "Shared Folders");
	if (!prefix || strlen(prefix) == 0 ||
	    strlen(prefix) >= MAX_NAMESPACE_PREFIX ||
	    strchr(prefix, namespace->hier_sep) != NULL ||
	    !strncmp(namespace->prefix[NAMESPACE_USER], prefix, strlen(prefix)))
	    return IMAP_NAMESPACE_BADPREFIX;
	sprintf(namespace->prefix[NAMESPACE_SHARED], "%.*s%c",
		MAX_NAMESPACE_PREFIX-1, prefix, namespace->hier_sep); 

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

/*
 * Translate separator charactors in a mailboxname from its external
 * representation to its internal representation '.'.
 * If using the unixhierarchysep '/', all '.'s get translated to DOTCHAR.
 */
char *mboxname_hiersep_tointernal(struct namespace *namespace, char *name)
{
    char *p;

    assert(namespace != NULL);
    assert(namespace->hier_sep == '.' || namespace->hier_sep == '/');

    if (namespace->hier_sep == '/') {
	/* change all '/'s to '.' and all '.'s to DOTCHAR */
	for (p = name; *p; p++) {
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
char *mboxname_hiersep_toexternal(struct namespace *namespace, char *name)
{
    char *p;

    assert(namespace != NULL);
    assert(namespace->hier_sep == '.' || namespace->hier_sep == '/');

    if (namespace->hier_sep == '/') {
	/* change all '.'s to '/' and all DOTCHARs to '.' */
	for (p = name; *p; p++) {
	    if (*p == '.') *p = '/';
	    else if (*p == DOTCHAR) *p = '.';
	}
    }

    return name;
}

/*
 * Return nonzero if 'userid' owns the (internal) mailbox 'name'.
 */
int mboxname_userownsmailbox(const char *userid, const char *name)
{
    if (!strchr(userid, '.') && !strncmp(name, "user.", 5) &&
	!strncmp(name+5, userid, strlen(userid)) &&
	name[5+strlen(userid)] == '.') {
	return 1;
    }
    return 0;
}

/*
 * Apply additional restrictions on netnews mailbox names.
 * Cannot have all-numeric name components.
 */
int mboxname_netnewscheck(char *name)
{
    int c;
    int sawnonnumeric = 0;

    while ((c = *name++)!=0) {
	switch (c) {
	case '.':
	    if (!sawnonnumeric) return IMAP_MAILBOX_BADNAME;
	    sawnonnumeric = 0;
	    break;

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	    break;

	default:
	    sawnonnumeric = 1;
	    break;
	}
    }
    if (!sawnonnumeric) return IMAP_MAILBOX_BADNAME;
    return 0;
}
	    

/*
 * Apply site policy restrictions on mailbox names.
 * Restrictions are hardwired for now.
 */
#define GOODCHARS " +,-.0123456789:=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
int mboxname_policycheck(char *name)
{
    int i;
    struct glob *g;
    int sawutf7 = 0;
    unsigned c1, c2, c3, c4, c5, c6, c7, c8;
    int ucs4;
    int unixsep;

    unixsep = config_getswitch("unixhierarchysep", 0);

    if (strlen(name) > MAX_MAILBOX_NAME) return IMAP_MAILBOX_BADNAME;
    for (i = 0; i < NUM_BADMBOXPATTERNS; i++) {
	g = glob_init(badmboxpatterns[i], 0);
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

