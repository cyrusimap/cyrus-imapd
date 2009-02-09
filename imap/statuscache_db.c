/* statuscache_db.c -- Status caching routines
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
 * $Id: statuscache_db.c,v 1.5 2009/02/09 05:01:59 brong Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>

#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "imapd.h"
#include "global.h"
#include "imap_err.h"
#include "mboxlist.h"
#include "seen.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

#include "statuscache.h"

#define DB config_statuscache_db

struct db *statuscachedb;
static int statuscache_dbopen = 0;

void statuscache_open(char *fname)
{
    int ret;
    char *tofree = NULL;

    /* create db file name */
    if (!fname) {
	fname = xmalloc(strlen(config_dir)+sizeof(FNAME_STATUSCACHEDB));
	tofree = fname;
	strcpy(fname, config_dir);
	strcat(fname, FNAME_STATUSCACHEDB);
    }

    ret = DB->open(fname, CYRUSDB_CREATE, &statuscachedb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
	fatal("can't read statuscache file", EC_TEMPFAIL);
    }    

    if (tofree) free(tofree);

    statuscache_dbopen = 1;
}

void statuscache_close(void)
{
    int r;

    if (statuscache_dbopen) {
	r = DB->close(statuscachedb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing statuscache: %s",
		   cyrusdb_strerror(r));
	}
	statuscache_dbopen = 0;
    }
}

void statuscache_fill(struct statuscache_data *scdata, struct mailbox *mailbox,
		      int statusitems, int num_recent, int num_unseen)
{
    assert(scdata);
    assert(mailbox);

    scdata->statusitems = statusitems;

    scdata->index_mtime = mailbox->index_mtime;
    scdata->index_ino = mailbox->index_ino;
    scdata->index_size = mailbox->index_size;

    scdata->messages = mailbox->exists;
    scdata->recent = num_recent;
    scdata->uidnext = mailbox->last_uid+1;
    scdata->uidvalidity = mailbox->uidvalidity;
    scdata->unseen = num_unseen;
    scdata->highestmodseq =
	(mailbox->options & OPT_IMAP_CONDSTORE) ? mailbox->highestmodseq : 0;
}

void statuscache_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

static char *statuscache_buildkey(const char *mailboxname, const char *userid,
				  int *keylen)
{
    static char key[MAX_MAILBOX_BUFFER];

    /* Build statuscache key */
    *keylen = strlcpy(key, mailboxname, sizeof(key)) + 1;
    *keylen += strlcpy(key + *keylen, userid, sizeof(key) - *keylen);

    return key;
}

int statuscache_lookup(const char *mboxname, const char *userid,
		       unsigned statusitems,
		       struct statuscache_data *scdata)
{
    int keylen, datalen, r = 0;
    const char *data = NULL, *dend;
    char *p, *key = statuscache_buildkey(mboxname, userid, &keylen);
    unsigned version;
    char *path, *mpath;
    struct stat istat;

    memset(scdata, 0, sizeof(struct statuscache_data));

    /* Check if there is an entry in the database */
    do {
	r = DB->fetch(statuscachedb, key, keylen, &data, &datalen, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (r || !data || ((size_t) datalen < sizeof(unsigned))) {
	return IMAP_NO_NOSUCHMSG;
    }

    dend = data + datalen;

    version = (unsigned) strtoul(data, &p, 10);
    if (version != (unsigned) STATUSCACHE_VERSION) {
	/* Wrong version */
	return IMAP_NO_NOSUCHMSG;
    }

    if (p < dend) scdata->statusitems = (unsigned) strtol(p, &p, 10);
    if (p < dend) scdata->index_mtime = strtol(p, &p, 10);
    if (p < dend) scdata->index_ino = strtoul(p, &p, 10);
    if (p < dend) scdata->index_size = strtoofft(p, &p, 10);
    if (p < dend) scdata->messages = strtoul(p, &p, 10);
    if (p < dend) scdata->recent = (unsigned) strtoul(p, &p, 10);
    if (p < dend) scdata->uidnext = strtoul(p, &p, 10);
    if (p < dend) scdata->uidvalidity = strtoul(p, &p, 10);
    if (p < dend) scdata->unseen = (unsigned) strtoul(p, &p, 10);
#ifdef HAVE_LONG_LONG_INT
    if (p < dend) scdata->highestmodseq = strtoull(p, &p, 10);
#else
    if (p < dend) scdata->highestmodseq = strtoul(p, &p, 10);
#endif

    /* Sanity check the data */
    if (!scdata->statusitems || !scdata->index_mtime || !scdata->index_ino ||
	!scdata->index_size || !scdata->uidnext || !scdata->uidvalidity) {
	return IMAP_NO_NOSUCHMSG;
    }

    if ((scdata->statusitems & statusitems) != statusitems) {
	/* Don't have all of the requested information */
	return IMAP_NO_NOSUCHMSG;
    }

    /* Check status of index file */
    r = mboxlist_detail(mboxname, NULL, &path, &mpath, NULL, NULL, NULL);
    if (!r) r = mailbox_stat(path, mpath, NULL, &istat, NULL);

    if (!r &&
	(istat.st_mtime != scdata->index_mtime ||
	 istat.st_ino   != scdata->index_ino ||
	 istat.st_size  != scdata->index_size)) {
	/* Our information is out of date */
	r = IMAP_NO_NOSUCHMSG;
    }

    return r;
}

int statuscache_update(const char *mboxname, const char *userid,
		       struct statuscache_data *scdata)
{
    char data[250];  /* enough room for 11*(UULONG + SP) */
    int r, keylen, datalen;
    char *key = statuscache_buildkey(mboxname, userid, &keylen);

    datalen = snprintf(data, sizeof(data),
		       "%u %u %ld %lu " OFF_T_FMT " %lu %u %lu %lu %u " MODSEQ_FMT,
		       STATUSCACHE_VERSION, scdata->statusitems,
		       scdata->index_mtime, scdata->index_ino,
		       scdata->index_size, scdata->messages,
		       scdata->recent, scdata->uidnext,
		       scdata->uidvalidity, scdata->unseen,
		       scdata->highestmodseq);

    r = DB->store(statuscachedb, key, keylen, data, datalen, NULL);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error updating database: %s", 
	       cyrusdb_strerror(r));
    }
    return 0; 
}

int statuscache_invalidate(const char *mboxname, const char *userid)
{
    int keylen, r;
    char *key = statuscache_buildkey(mboxname, userid, &keylen);

    /* Don't access DB if it hasn't been opened */
    if (!statuscachedb) return 0;

    /* Delete db entry */
    r = DB->delete(statuscachedb, key, keylen, NULL, 1);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error deleting from database: %s", 
	       cyrusdb_strerror(r));
    }
    return 0; 
}

