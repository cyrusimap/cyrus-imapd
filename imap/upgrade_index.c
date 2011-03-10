/* upgrade_index.c -- Mailbox upgrade routines
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
 * $Id: mailbox.c,v 1.199 2010/01/06 17:01:36 murch Exp $
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
#include <utime.h>

#ifdef HAVE_DIRENT_H
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
#include "crc32.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "cyr_lock.h"
#include "mailbox.h"
#include "message.h"
#include "map.h"
#include "retry.h"
#include "seen.h"
#include "util.h"
#include "sequence.h"
#include "xmalloc.h"

struct expunge_data {
    uint32_t uid;
    const char *base;
};

static int sort_expunge(const void *a, const void *b)
{
    struct expunge_data *ea = (struct expunge_data *)a;
    struct expunge_data *eb = (struct expunge_data *)b;
    return ea->uid - eb->uid;
}

static void upgrade_index_record(struct mailbox *mailbox,
				 const char *buf,
				 struct index_record *record,
				 int record_size,
				 int oldversion)
{
    char recordbuf[INDEX_RECORD_SIZE];
    struct utimbuf settime;
    const char *fname;

    assert(record_size <= INDEX_RECORD_SIZE);

    memset(recordbuf, 0, INDEX_RECORD_SIZE);
    memcpy(recordbuf, buf, record_size);

    /* do the initial parse.  Ignore the result, crc32 will mismatch
     * for sure */
    mailbox_buf_to_index_record(recordbuf, record);

    if (oldversion == 12) {
	/* avoid re-parsing the message by copying the old cache_crc,
	 * but only if the old RECORD_CRC matches */
	if (crc32_map(buf, 92) == ntohl(*((bit32 *)(buf+92)))) { 
	    record->cache_crc = ntohl(*((bit32 *)(buf+88)));
	    /* we need to read the cache record in here, so that repack
	     * will write it out to a new cache file */
	    if (!mailbox_cacherecord(mailbox, record))
		return;
	    /* record failed, drop through */
	    record->cache_offset = 0;
	}
	/* CRC failed, drop through */
    }

    fname = mailbox_message_fname(mailbox, record->uid);

    if (message_parse(fname, record)) {
	/* failed to create, don't try to write */
	record->crec.len = 0;
	/* and the record is expunged too! */
	record->system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
	syslog(LOG_ERR, "IOERROR: FATAL - failed to parse "
			"file %s for upgrade, expunging", fname);
	return;
    }

    /* update the mtime to match the internaldate */
    settime.actime = settime.modtime = record->internaldate;
    utime(fname, &settime);
}

/*
 * Upgrade an index/expunge file for 'mailbox'
 */
int upgrade_index(struct mailbox *mailbox)
{
    uint32_t recno, erecno;
    uint32_t uid, euid;
    unsigned long oldmapnum;
    unsigned long oldnum_records;
    unsigned long expunge_num = 0;
    uint32_t oldminor_version, oldstart_offset, oldrecord_size;
    indexbuffer_t headerbuf;
    const char *bufp = NULL;
    char *hbuf = (char *)headerbuf.buf;
    const char *fname;
    const char *datadirname;
    struct stat sbuf;
    struct seqset *seq = NULL;
    struct index_record record;
    int expunge_fd = -1;
    const char *expunge_base = NULL;
    unsigned long expunge_len = 0;   /* mapped size */
    unsigned long emapnum;
    bit32 eversion = 0, eoffset = 0, expungerecord_size = 0;
    struct expunge_data *expunge_data = NULL;
    struct mailbox_repack *repack = NULL;
    int r;

    if (mailbox->index_size < OFFSET_NUM_RECORDS)
	return IMAP_MAILBOX_BADFORMAT;

    oldminor_version = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_MINOR_VERSION)));
    oldstart_offset = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_START_OFFSET)));
    oldrecord_size = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_RECORD_SIZE)));
    oldnum_records = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_NUM_RECORDS)));

    /* bogus data at the start of the index file? */
    if (!oldstart_offset || !oldrecord_size)
	return IMAP_MAILBOX_BADFORMAT;

    oldmapnum = (mailbox->index_size - oldstart_offset) / oldrecord_size;
    if (oldmapnum < oldnum_records) {
	syslog(LOG_ERR, "upgrade: %s map doesn't fit, shrinking index %lu to %lu",
	       mailbox->name, oldnum_records, oldmapnum);
	oldnum_records = oldmapnum;
    }

    /* check if someone else already upgraded the index! */
    if (oldminor_version == MAILBOX_MINOR_VERSION)
	goto done;

    /* check that the data directory exists.  If not, it may be that
     * something isn't correctly mounted.  We don't want to wipe out
     * all the index records due to IOERRORs just because the admin
     * made a temporary mistake */
    datadirname = mailbox_message_fname(mailbox, 0);
    if (stat(datadirname, &sbuf)) {
	syslog(LOG_ERR, "IOERROR: unable to find data directory %s "
			"for mailbox %s, refusing to upgrade",
			datadirname, mailbox->name);
	return IMAP_IOERROR;
    }

    /* Copy existing header so we can upgrade it */ 
    memset(hbuf, 0, INDEX_HEADER_SIZE);
    if (oldstart_offset > INDEX_HEADER_SIZE)
	memcpy(hbuf, mailbox->index_base, INDEX_HEADER_SIZE);
    else 
	memcpy(hbuf, mailbox->index_base, oldstart_offset);

    /* QUOTA_MAILBOX_USED changed to 64 bit added with minor version 6 */
    if (oldminor_version < 6) {
	/* upgrade quota to 64-bits (bump existing fields) */
	memmove(hbuf+OFFSET_QUOTA_MAILBOX_USED + 4, hbuf+OFFSET_QUOTA_MAILBOX_USED,
		INDEX_HEADER_SIZE - (OFFSET_QUOTA_MAILBOX_USED + 4));
	/* zero the unused 32-bits */
	*((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(0);
    }

    /* ignore the result - we EXPECT a CRC32 mismatch */
    mailbox_buf_to_index_header(hbuf, &mailbox->i);

    /* HIGHESTMODSEQ[_64] added with minor version 8 */
    if (oldminor_version < 8)
	mailbox->i.highestmodseq = 1;

    /* new version fields */
    mailbox->i.minor_version = MAILBOX_MINOR_VERSION;
    mailbox->i.start_offset = INDEX_HEADER_SIZE;
    mailbox->i.record_size = INDEX_RECORD_SIZE;

    /* upgrade other fields as necessary
     *
     * minor version wasn't updated religiously in the early days,
     * so we need to use the old offset instead */
    if (oldstart_offset < OFFSET_POP3_LAST_LOGIN)
	mailbox->i.pop3_last_login = 0;
    if (oldstart_offset < OFFSET_UIDVALIDITY)
	mailbox->i.uidvalidity = 1;
    if (oldstart_offset < OFFSET_MAILBOX_OPTIONS)
	mailbox->i.options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS);

    if (oldminor_version < 12) {
	struct seendata sd;
	const char *owner_userid;

	/* remove the CONDSTORE option - it's implicit now */
	mailbox->i.options &= ~OPT_IMAP_CONDSTORE;

	if (mailbox->i.options & OPT_IMAP_SHAREDSEEN)
	    owner_userid = "anyone";
	else
	    owner_userid = mboxname_to_userid(mailbox->name);

	r = mailbox_read_header(mailbox, NULL);
	if (r) goto fail;

	/* NEW HEADER FIELDS */

	/* we'll set this if there are expunged records */
	mailbox->i.first_expunged = 0;
	/* we can't know about deletions before the current modseq */
	mailbox->i.deletedmodseq = mailbox->i.highestmodseq;
	/* bootstrap CRC matching */
	mailbox->i.header_file_crc = mailbox->header_file_crc;

	/* set up seen tracking for user inside the mailbox */
	if (!owner_userid) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	} else {
	    struct seen *seendb = NULL;
	    r = seen_open(owner_userid, SEEN_SILENT, &seendb);
	    if (!r) r = seen_read(seendb, mailbox->uniqueid, &sd);
	    seen_close(&seendb);
	}
	if (r) { /* no seen data? */
	    mailbox->i.recentuid = 0;
	    mailbox->i.recenttime = 0;
	}
	else {
	    mailbox->i.recentuid = sd.lastuid;
	    mailbox->i.recenttime = sd.lastchange;
	    seq = seqset_parse(sd.seenuids, NULL, sd.lastuid);
	    seen_freedata(&sd);
	}

	/* check for expunge */
	fname = mailbox_meta_fname(mailbox, META_EXPUNGE);
	expunge_fd = open(fname, O_RDWR, 0666);
	if (expunge_fd == -1) goto no_expunge;

	r = fstat(expunge_fd, &sbuf);
	if (r == -1) goto no_expunge;

	if (sbuf.st_size < INDEX_HEADER_SIZE) goto no_expunge;
	map_refresh(expunge_fd, 1, &expunge_base,
		    &expunge_len, sbuf.st_size, "expunge",
		    mailbox->name);

	/* use the expunge file's header information just in case
	 * versions are skewed for some reason */
	eversion = ntohl(*((bit32 *)(expunge_base+OFFSET_MINOR_VERSION)));
	eoffset = ntohl(*((bit32 *)(expunge_base+OFFSET_START_OFFSET)));
	expungerecord_size = ntohl(*((bit32 *)(expunge_base+OFFSET_RECORD_SIZE)));

	/* bogus data at the start of the expunge file? */
	if (!eoffset || !expungerecord_size)
	    goto no_expunge;

	expunge_num = ntohl(*((bit32 *)(expunge_base+OFFSET_NUM_RECORDS)));
	emapnum = (sbuf.st_size - eoffset) / expungerecord_size;
	if (emapnum < expunge_num) {
	    syslog(LOG_ERR, "IOERROR: %s map doesn't fit, shrinking expunge %lu to %lu",
		   mailbox->name, expunge_num, emapnum);
	    expunge_num = emapnum;
	}

	/* make sure there's space for them */
	expunge_data = xmalloc(expunge_num * sizeof(struct expunge_data));

	/* find the start offset for each record, and the UID */
	for (erecno = 1; erecno <= expunge_num; erecno++) {
	    bufp = expunge_base + eoffset + (erecno-1)*expungerecord_size;
	    expunge_data[erecno-1].uid = ntohl(*((bit32 *)(bufp+OFFSET_UID)));
	    expunge_data[erecno-1].base = bufp;
	}

	/* expunge files were not sorted.  So sort them now for easier
	 * interleaving */
	qsort(expunge_data, expunge_num, 
	      sizeof(struct expunge_data), &sort_expunge);
    }
no_expunge:

    mailbox_repack_setup(mailbox, &repack);

    /* Write the rest of new index */
    recno = 1;
    erecno = 1;
    while (recno <= oldnum_records || erecno <= expunge_num) {
	/* read the uid */
	if (recno <= oldnum_records) {
	    bufp = mailbox->index_base + oldstart_offset + (recno-1)*oldrecord_size;
	    uid = ntohl(*((bit32 *)(bufp+OFFSET_UID)));
	}
	else {
	    uid = UINT32_MAX;
	}
	if (erecno <= expunge_num) {
	    euid = expunge_data[erecno-1].uid;
	}
	else {
	    euid = UINT32_MAX;
	}

	/* case: index UID is first, or the same */
	if (uid <= euid) {
	    upgrade_index_record(mailbox, bufp, &record, oldrecord_size,
				 oldminor_version);
	    recno++;
	    if (uid == euid) /* duplicate in both, skip expunged */
		erecno++;
	}
	else {
	    upgrade_index_record(mailbox, expunge_data[erecno-1].base,
				 &record, expungerecord_size, eversion);
	    record.system_flags |= FLAG_EXPUNGED;
	    erecno++;
	}

	/* user seen was merged into the index with version 12 */
	if (oldminor_version < 12 && seqset_ismember(seq, record.uid))
	    record.system_flags |= FLAG_SEEN;

	/* CID was added with version 13 */
	if (oldminor_version < 13)
	    record.cid = 0;

	r = mailbox_repack_add(repack, &record);
	if (r) goto fail;
    }

    r = mailbox_repack_commit(&repack);
    if (r) goto fail;

    /* don't need this file any more! */
    unlink(mailbox_meta_fname(mailbox, META_EXPUNGE));

    /* XXX - remove seen record */

    syslog(LOG_INFO, "Index upgrade: %s (%d -> %d)", mailbox->name, 
	   oldminor_version, MAILBOX_MINOR_VERSION);

done:
    if (expunge_fd != -1) close(expunge_fd);
    if (expunge_base) map_free(&expunge_base, &expunge_len);
    seqset_free(seq);
    free(expunge_data);

    return 0;

fail:
    if (expunge_fd != -1) close(expunge_fd);
    if (expunge_base) map_free(&expunge_base, &expunge_len);
    seqset_free(seq);
    free(expunge_data);

    mailbox_repack_abort(&repack);

    syslog(LOG_ERR, "Index upgrade failed: %s", mailbox->name);

    return IMAP_IOERROR;
}

