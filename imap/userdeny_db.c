/* userdeny_db.c -- User deny manipulation routines
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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
 * $Id: userdeny_db.c,v 1.1 2010/04/23 19:48:52 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "cyrusdb.h"
#include "global.h"
#include "userdeny.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#define DENYDB config_userdeny_db

struct db *denydb;

static int deny_dbopen = 0;


/*
 * userdeny() checks to see if 'user' is denied access to 'service'
 * Returns 1 if a matching deny entry exists in DB, otherwise returns 0.
 */
int userdeny(const char *user, const char *service, char *msgbuf, size_t bufsiz)
{
    int r, ret = 0; /* allow access by default */
    const char *data = NULL;
    size_t datalen;

    if (!deny_dbopen) return 0;

    /* fetch entry for user */
    syslog(LOG_DEBUG, "fetching user_deny.db entry for '%s'", user);
    do {
	r = DENYDB->fetch(denydb, user, strlen(user), &data, &datalen, NULL);
    } while (r == CYRUSDB_AGAIN);

    /* XXX  Should we try to reopen the DB if we get IOERROR?
            This might be necessary when using SQL backend
	    and we lose the connection.
    */

    if (r || !data || !datalen) {
	/* ignore non-existent/empty entry, report all other errors */
	if (r != CYRUSDB_NOTFOUND) {
	    syslog(LOG_WARNING,
		   "DENYDB_ERROR: error reading entry '%s': %s",
		   user, cyrusdb_strerror(r));
	}
    } else {
	/* parse the data */
	char *buf, *wild;
	unsigned long version;

	buf = xstrndup(data, datalen);  /* use a working copy */

	/* check version */
	if (((version = strtoul(buf, &wild, 10)) < 1) ||
	    (version > USERDENY_VERSION)) {
	    syslog(LOG_WARNING,
		   "DENYDB_ERROR: invalid version for entry '%s': %lu",
		   user, version);
	} else if (*wild++ != '\t') {
	    syslog(LOG_WARNING,
		   "DENYDB_ERROR: missing wildmat for entry '%s'", user);
	} else {
	    char *pat, *msg = "Access to this service has been blocked";
	    int not;

	    /* check if we have a deny message */
	    switch (version) {
	    case USERDENY_VERSION:
		if ((msg = strchr(wild, '\t'))) *msg++ = '\0';
		break;
	    }

	    /* scan wildmat right to left for a match against our service */
	    syslog(LOG_DEBUG, "wild: '%s'   service: '%s'", wild, service);
	    do {
		/* isolate next pattern */
		if ((pat = strrchr(wild, ','))) {
		    *pat++ = '\0';
		} else {
		    pat = wild;
		}

		/* XXX  trim leading & trailing whitespace? */

		/* is it a negated pattern? */
		not = (*pat == '!');
		if (not) ++pat;

		syslog(LOG_DEBUG, "pat %d:'%s'", not, pat);

		/* see if pattern matches our service */
		if (wildmat(service, pat)) {
		    /* match ==> we're done */
		    ret = !not;
		    if (msgbuf) strlcpy(msgbuf, msg, bufsiz);
		    break;
		}

		/* continue until we reach head of wildmat */
	    } while (pat != wild);
	}

	free(buf);
    }

    return ret;
}

/* must be called after cyrus_init */
void denydb_init(int myflags)
{
    if (myflags & DENYDB_SYNC) {
	DENYDB->sync();
    }
}

void denydb_open(const char *fname)
{
    int ret;
    char *tofree = NULL;

    if (!fname)
	fname = config_getstring(IMAPOPT_USERDENY_DB_PATH);

    /* create db file name */
    if (!fname) {
	tofree =strconcat(config_dir, FNAME_USERDENYDB, (char *)NULL);
	fname = tofree;
    }

    ret = (DENYDB->open)(fname, 0, &denydb);
    if (ret == CYRUSDB_OK) {
	deny_dbopen = 1;
    } else if (errno != ENOENT) {
	/* ignore non-existent DB, report all other errors */
	syslog(LOG_WARNING, "DENYDB_ERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
    }

    free(tofree);
}

void denydb_close(void)
{
    int r;

    if (deny_dbopen) {
	r = (DENYDB->close)(denydb);
	if (r) {
	    syslog(LOG_ERR, "DENYDB_ERROR: error closing: %s",
		   cyrusdb_strerror(r));
	}
	deny_dbopen = 0;
    }
}

void denydb_done(void)
{
    /* DB->done() handled by cyrus_done() */
}
