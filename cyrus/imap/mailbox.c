/* mailbox.c -- Mailbox manipulation routines
 $Id: mailbox.c,v 1.134.4.11 2002/09/30 19:55:46 ken3 Exp $
 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <com_err.h>

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
#include "imapconf.h"
#include "acl.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "lock.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "seen.h"

static int mailbox_doing_reconstruct = 0;
#define zeromailbox(m) { memset(&m, 0, sizeof(struct mailbox)); \
                         (m).header_fd = -1; \
                         (m).index_fd = -1; \
                         (m).cache_fd = -1; }

static int mailbox_calculate_flagcounts(struct mailbox *mailbox);
static int mailbox_upgrade_index(struct mailbox *mailbox);

/*
 * Names of the headers we cache in the cyrus.cache file.
 * Any changes to this list require corresponding changes to
 * message_parse_headers() in message.c
 */
char *mailbox_cache_header_name[] = {
/*    "in-reply-to", in ENVELOPE */
    "priority",
    "references",
    "resent-from",
    "newsgroups",
    "followup-to",
};
int mailbox_num_cache_header =
  sizeof(mailbox_cache_header_name)/sizeof(char *);

/* function to be used for notification of mailbox changes/updates */
static mailbox_notifyproc_t *updatenotifier = NULL;

/*
 * Set the updatenotifier function
 */
void mailbox_set_updatenotifier(mailbox_notifyproc_t *notifyproc)
{
    updatenotifier = notifyproc;
}

/*
 * Create connection to acappush (obsolete)
 */
int mailbox_initialize(void)
{
    return 0;
}

/* create the unique identifier for a mailbox named 'name' with
 * uidvalidity 'uidvalidity'.  'uniqueid' should be at least 17 bytes
 * long.  the unique identifier is just the mailbox name hashed to 32
 * bits followed by the uid, both converted to hex. 
 */
#define PRIME (2147484043UL)

void mailbox_make_uniqueid(char *name, unsigned long uidvalidity,
			   char *uniqueid)
{
    unsigned long hash = 0;

    while (*name) {
	hash *= 251;
	hash += *name++;
	hash %= PRIME;
    }
    sprintf(uniqueid, "%08lx%08lx", hash, uidvalidity);
}

/*
 * Calculate relative filename for the message with UID 'uid'
 * in 'mailbox'. 'out' must be at least MAILBOX_FNAME_LEN long.
 */
void mailbox_message_get_fname(struct mailbox *mailbox, unsigned long uid,
			       char *out)
{
    assert(mailbox->format != MAILBOX_FORMAT_NETNEWS);

    sprintf(out, "%lu.", uid);
}

/*
 * Maps in the content for the message with UID 'uid' in 'mailbox'.
 * Returns map in 'basep' and 'lenp'
 */
int mailbox_map_message(struct mailbox *mailbox,
			int iscurrentdir,
			unsigned long uid,
			const char **basep,
			unsigned long *lenp)
{
    int msgfd;
    char buf[4096];
    char *p = buf;
    struct stat sbuf;

    if (!iscurrentdir) {
	strcpy(buf, mailbox->path);
	p = buf + strlen(buf);
	*p++ = '/';
    }

    sprintf(p, "%lu.", uid);

    msgfd = open(buf, O_RDONLY, 0666);
    if (msgfd == -1) return errno;
    
    if (fstat(msgfd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", buf);
	fatal("can't fstat message file", EC_OSFILE);
    }
    *basep = 0;
    *lenp = 0;
    map_refresh(msgfd, 1, basep, lenp, sbuf.st_size, buf, mailbox->name);
    close(msgfd);

    return 0;
}

/*
 * Releases the buffer obtained from mailbox_map_message()
 */
void mailbox_unmap_message(struct mailbox *mailbox __attribute__((unused)),
			   unsigned long uid __attribute__((unused)),
			   const char **basep, unsigned long *lenp)
{
    map_free(basep, lenp);
}

/*
 * Set the "reconstruct" mode.  Causes most errors to be ignored.
 */
void
mailbox_reconstructmode()
{
    mailbox_doing_reconstruct = 1;
}

/* stat a mailbox's control files.  returns a bitmask that sets
 * 0x1 if the header fialed, 0x2 if the index failed, and 0x4 if the cache failed */
int mailbox_stat(const char *mbpath,
		 struct stat *header, struct stat *index, struct stat *cache) 
{
    char fnamebuf[MAX_MAILBOX_PATH];
    int r = 0, ret = 0;
    
    assert(mbpath && (header || index));
    
    if(header) {
	snprintf(fnamebuf, sizeof(fnamebuf), "%s/cyrus.header", mbpath);
	r = stat(fnamebuf, header);
	if(r) ret |= 0x1;
    }
    
    if(!r && index) {
	snprintf(fnamebuf, sizeof(fnamebuf), "%s/cyrus.index", mbpath);
	r = stat(fnamebuf, index);
	if(r) ret |= 0x2;
    }

    if(!r && cache) {
	snprintf(fnamebuf, sizeof(fnamebuf), "%s/cyrus.cache", mbpath);
	r = stat(fnamebuf, cache);
	if(r) ret |= 0x4;
    }
    
    return ret;
}


/*
 * Open and read the header of the mailbox with name 'name'
 * The structure pointed to by 'mailbox' is initialized.
 */
int mailbox_open_header(const char *name, 
			struct auth_state *auth_state,
			struct mailbox *mailbox)
{
    char *path, *acl;
    int r;

    r = mboxlist_lookup(name, &path, &acl, NULL);
    if (r) return r;

    return mailbox_open_header_path(name, path, acl, auth_state, mailbox, 0);
}

/*
 * Open and read the header of the mailbox with name 'name'
 * path 'path', and ACL 'acl'.
 * The structure pointed to by 'mailbox' is initialized.
 */
int mailbox_open_header_path(const char *name,
			     const char *path,
			     const char *acl,
			     struct auth_state *auth_state,
			     struct mailbox *mailbox,
			     int suppresslog)
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    int r;

    zeromailbox(*mailbox);
    mailbox->quota.fd = -1;

    strcpy(fnamebuf, path);
    strcat(fnamebuf, FNAME_HEADER);
    mailbox->header_fd = open(fnamebuf, O_RDWR, 0);
    
    if (mailbox->header_fd == -1 && !mailbox_doing_reconstruct) {
	if (!suppresslog) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	}
	return IMAP_IOERROR;
    }

    if (mailbox->header_fd != -1) {
	if (fstat(mailbox->header_fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstating %s: %m", fnamebuf);
	    fatal("can't fstat header file", EC_OSFILE);
	}
	map_refresh(mailbox->header_fd, 1, &mailbox->header_base,
		    &mailbox->header_len, sbuf.st_size, "header", name);
	mailbox->header_ino = sbuf.st_ino;
    }

    mailbox->name = xstrdup(name);
    mailbox->path = xstrdup(path);

    /* Note that the header does have the ACL information, but it is only
     * a backup, and the mboxlist data is considered authoritative, so
     * we will just use what we were passed */
    mailbox->acl = xstrdup(acl);

    mailbox->myrights = cyrus_acl_myrights(auth_state, mailbox->acl);

    if (mailbox->header_fd == -1) return 0;

    r = mailbox_read_header(mailbox);
    if (r && !mailbox_doing_reconstruct) {
	mailbox_close(mailbox);
	return r;
    }

    return 0;
}

int mailbox_open_locked(const char *mbname,
			const char *mbpath,
			const char *mbacl,
			struct auth_state *auth_state,
			struct mailbox *mb,
			int suppresslog) 
{
    int r;
    
    r = mailbox_open_header_path(mbname, mbpath, mbacl, auth_state,
				 mb, suppresslog);
    if(r) return r;

    /* now we have to close the mailbox if we fail */

    r = mailbox_lock_header(mb);
    if(!r)
	r = mailbox_open_index(mb);
    if(!r) 
	r = mailbox_lock_index(mb);

    if(r) mailbox_close(mb);

    return r;
}

#define MAXTRIES 60

/*
 * Open the index and cache files for 'mailbox'.  Also 
 * read the index header.
 */
int mailbox_open_index(struct mailbox *mailbox)
{
    char fnamebuf[MAX_MAILBOX_PATH];
    bit32 index_gen = 0, cache_gen = 0;
    int tries = 0;

    if (mailbox->index_fd != -1) {
	close(mailbox->index_fd);
	map_free(&mailbox->index_base, &mailbox->index_len);
    }
    if (mailbox->cache_fd != -1) {
	close(mailbox->cache_fd);
	map_free(&mailbox->cache_base, &mailbox->cache_len);
    }
    do {
	strcpy(fnamebuf, mailbox->path);
	strcat(fnamebuf, FNAME_INDEX);
	mailbox->index_fd = open(fnamebuf, O_RDWR, 0);
	if (mailbox->index_fd != -1) {
	    map_refresh(mailbox->index_fd, 0, &mailbox->index_base,
			&mailbox->index_len, MAP_UNKNOWN_LEN, "index",
			mailbox->name);
	}
	if (mailbox_doing_reconstruct) break;
	if (mailbox->index_fd == -1) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	    return IMAP_IOERROR;
	}

	strcpy(fnamebuf, mailbox->path);
	strcat(fnamebuf, FNAME_CACHE);
	mailbox->cache_fd = open(fnamebuf, O_RDWR, 0);
	if (mailbox->cache_fd != -1) {
	    struct stat sbuf;

	    if (fstat(mailbox->cache_fd, &sbuf) == -1) {
		syslog(LOG_ERR, "IOERROR: fstating %s: %m", mailbox->name);
		fatal("can't fstat cache file", EC_OSFILE);
	    }
	    mailbox->cache_size = sbuf.st_size;
	    map_refresh(mailbox->cache_fd, 0, &mailbox->cache_base,
			&mailbox->cache_len, mailbox->cache_size, "cache",
			mailbox->name);
	}
	if (mailbox->cache_fd == -1) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	    return IMAP_IOERROR;
	}

	/* Check generation number matches */
	if (mailbox->index_len < 4 || mailbox->cache_len < 4) {
	    return IMAP_MAILBOX_BADFORMAT;
	}
	index_gen = *(bit32 *)mailbox->index_base;
	cache_gen = *(bit32 *)mailbox->cache_base;

	if (index_gen != cache_gen) {
	    close(mailbox->index_fd);
	    map_free(&mailbox->index_base, &mailbox->index_len);
	    close(mailbox->cache_fd);
	    map_free(&mailbox->cache_base, &mailbox->cache_len);
	    sleep(1);
	}
    } while (index_gen != cache_gen && tries++ < MAXTRIES);

    if (index_gen != cache_gen) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    mailbox->generation_no = index_gen;

    return mailbox_read_index_header(mailbox);
}

/*
 * Close the mailbox 'mailbox', freeing all associated resources.
 */
void mailbox_close(struct mailbox *mailbox)
{
    int flag;

    close(mailbox->header_fd);
    map_free(&mailbox->header_base, &mailbox->header_len);

    if (mailbox->index_fd != -1) {
	close(mailbox->index_fd);
	map_free(&mailbox->index_base, &mailbox->index_len);
    }

    if (mailbox->cache_fd != -1) {
	close(mailbox->cache_fd);
	map_free(&mailbox->cache_base, &mailbox->cache_len);
    }

    if (mailbox->quota.fd != -1) {
	close(mailbox->quota.fd);
    }
	
    free(mailbox->name);
    free(mailbox->path);
    free(mailbox->acl);
    free(mailbox->uniqueid);
    if (mailbox->quota.root) free(mailbox->quota.root);

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
    }

    zeromailbox(*mailbox);
    mailbox->quota.fd = -1;
}

/*
 * Read the header of 'mailbox'
 */
int mailbox_read_header(struct mailbox *mailbox)
{
    int flag;
    const char *name, *p, *tab, *eol;
    int oldformat = 0;

    /* Check magic number */
    if (mailbox->header_len < sizeof(MAILBOX_HEADER_MAGIC)-1 ||
	strncmp(mailbox->header_base, MAILBOX_HEADER_MAGIC,
		sizeof(MAILBOX_HEADER_MAGIC)-1)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Read quota file pathname */
    p = mailbox->header_base + sizeof(MAILBOX_HEADER_MAGIC)-1;
    tab = memchr(p, '\t', mailbox->header_len - (p - mailbox->header_base));
    eol = memchr(p, '\n', mailbox->header_len - (p - mailbox->header_base));
    if (!tab || tab > eol || !eol) {
	oldformat = 1;
	if (!eol) return IMAP_MAILBOX_BADFORMAT;
	else {
	    syslog(LOG_DEBUG, "mailbox '%s' has old cyrus.header",
		   mailbox->name);
	}
	tab = eol;
    }
    if (mailbox->quota.root) {
	/* check if this is the same as what's there */
	if (strlen(mailbox->quota.root) != (size_t)(tab-p) ||
	    strncmp(mailbox->quota.root, p, tab-p) != 0) {
	    assert(mailbox->quota.lock_count == 0);
	    if (mailbox->quota.fd != -1) {
		close(mailbox->quota.fd);
	    }
	    mailbox->quota.fd = -1;
	}
	free(mailbox->quota.root);
    }
    if (p < tab) {
	mailbox->quota.root = xstrndup(p, tab - p);
    } else {
	mailbox->quota.root = NULL;
    }

    if (!oldformat) {
	/* read uniqueid */
	p = tab + 1;
	if (p == eol) return IMAP_MAILBOX_BADFORMAT;
	mailbox->uniqueid = xstrndup(p, eol - p);
    } else {
	/* uniqueid needs to be generated when we know the uidvalidity */
	mailbox->uniqueid = NULL;
    }

    /* Read names of user flags */
    p = eol + 1;
    eol = memchr(p, '\n', mailbox->header_len - (p - mailbox->header_base));
    if (!eol) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    name = p;
    flag = 0;
    while (name <= eol && flag < MAX_USER_FLAGS) {
	p = memchr(name, ' ', eol-name);
	if (!p) p = eol;
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
	if (name != p) {
	    mailbox->flagname[flag++] = xstrndup(name, p-name);
	}
	else {
	    mailbox->flagname[flag++] = NULL;
	}

	name = p+1;
    }
    while (flag < MAX_USER_FLAGS) {
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
	mailbox->flagname[flag++] = NULL;
    }

    if (!mailbox->uniqueid) {
	char buf[32];

	/* generate uniqueid */
	mailbox_lock_header(mailbox);
 	mailbox_open_index(mailbox);
 	mailbox_make_uniqueid(mailbox->name, mailbox->uidvalidity, buf);
	mailbox->uniqueid = xstrdup(buf);
	mailbox_write_header(mailbox);
	mailbox_unlock_header(mailbox);
    }

    return 0;
}

/*
 * Read the acl out of the header of 'mailbox'
 */
int mailbox_read_header_acl(struct mailbox *mailbox)
{
    const char *p, *eol;

    /* Check magic number */
    if (mailbox->header_len < sizeof(MAILBOX_HEADER_MAGIC)-1 ||
	strncmp(mailbox->header_base, MAILBOX_HEADER_MAGIC,
		sizeof(MAILBOX_HEADER_MAGIC)-1)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Skip quota file pathname */
    p = mailbox->header_base + sizeof(MAILBOX_HEADER_MAGIC)-1;
    eol = memchr(p, '\n', mailbox->header_len - (p - mailbox->header_base));
    if (!eol) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Skip names of user flags */
    p = eol + 1;
    eol = memchr(p, '\n', mailbox->header_len - (p - mailbox->header_base));
    if (!eol) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Read ACL */
    p = eol + 1;
    eol = memchr(p, '\n', mailbox->header_len - (p - mailbox->header_base));
    if (!eol) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    
    free(mailbox->acl);
    mailbox->acl = xstrndup(p, eol-p);

    return 0;
}

/*
 * Read the the ACL for 'mailbox'.
 */
int mailbox_read_acl(struct mailbox *mailbox,
		     struct auth_state *auth_state)
{
    int r;
    char *acl;

    r = mboxlist_lookup(mailbox->name, (char **)0, &acl, NULL);
    if (r) return r;

    free(mailbox->acl);
    mailbox->acl = xstrdup(acl);
    mailbox->myrights = cyrus_acl_myrights(auth_state, mailbox->acl);

    return 0;
}

/*
 * Read the header of the index file for mailbox
 */
int mailbox_read_index_header(struct mailbox *mailbox)
{
    struct stat sbuf;
    int upgrade = 0;

    if (mailbox->index_fd == -1) return IMAP_MAILBOX_BADFORMAT;

    fstat(mailbox->index_fd, &sbuf);
    mailbox->index_ino = sbuf.st_ino;
    mailbox->index_mtime = sbuf.st_mtime;
    mailbox->index_size = sbuf.st_size;
    map_refresh(mailbox->index_fd, 0, &mailbox->index_base,
		&mailbox->index_len, sbuf.st_size, "index",
		mailbox->name);

    if (mailbox->index_len < OFFSET_POP3_LAST_LOGIN ||
	(mailbox->index_len <
	 ntohl(*((bit32 *)(mailbox->index_base+OFFSET_START_OFFSET))))) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    if (mailbox_doing_reconstruct) {
	mailbox->generation_no =
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_GENERATION_NO)));
    }
    mailbox->format =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_FORMAT)));
    mailbox->minor_version =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_MINOR_VERSION)));
    mailbox->start_offset =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_START_OFFSET)));
    mailbox->record_size =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_RECORD_SIZE)));
    mailbox->exists =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_EXISTS)));
    mailbox->last_appenddate =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_LAST_APPENDDATE)));
    mailbox->last_uid =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_LAST_UID)));
    mailbox->quota_mailbox_used =
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_QUOTA_MAILBOX_USED)));

    if (mailbox->start_offset < OFFSET_POP3_LAST_LOGIN+sizeof(bit32)) {
	mailbox->pop3_last_login = 0;
    }
    else {
	mailbox->pop3_last_login =
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_POP3_LAST_LOGIN)));
    }

    if (mailbox->start_offset < OFFSET_UIDVALIDITY+sizeof(bit32)) {
	mailbox->uidvalidity = 1;
    }
    else {
	mailbox->uidvalidity =
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_UIDVALIDITY)));
    }

    if (mailbox->start_offset < OFFSET_FLAGGED+sizeof(bit32)) {
	/* calculate them now */
	if (mailbox_calculate_flagcounts(mailbox))
	    return IMAP_IOERROR;
	
	upgrade = 1;
    } else {
	mailbox->deleted = 
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_DELETED)));
	mailbox->answered = 
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_ANSWERED)));
	mailbox->flagged = 
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_FLAGGED)));
	mailbox->dirty = 0;
    }

    if (mailbox->start_offset < OFFSET_POP3_NEW_UIDL+sizeof(bit32)) {
	mailbox->pop3_new_uidl = !mailbox->exists;
	upgrade = 1;
    }
    else {
	mailbox->pop3_new_uidl = !mailbox->exists ||
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_POP3_NEW_UIDL)));
    }

    if (upgrade) {
	if (mailbox_upgrade_index(mailbox))
	    return IMAP_IOERROR;

	/* things might have been changed out from under us. reread */
	return mailbox_open_index(mailbox); 
    }

    if (!mailbox_doing_reconstruct &&
	(mailbox->minor_version < MAILBOX_MINOR_VERSION)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    return 0;
}

/*
 * Read an index record from a mailbox
 */
int
mailbox_read_index_record(mailbox, msgno, record)
struct mailbox *mailbox;
unsigned msgno;
struct index_record *record;
{
    unsigned long offset;
    unsigned const char *buf;
    int n;

    offset = mailbox->start_offset + (msgno-1) * mailbox->record_size;
    if (offset + INDEX_RECORD_SIZE > mailbox->index_len) {
	syslog(LOG_ERR,
	       "IOERROR: index record %u for %s past end of file",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    buf = (unsigned char*) mailbox->index_base + offset;

    record->uid = htonl(*((bit32 *)(buf+OFFSET_UID)));
    record->internaldate = htonl(*((bit32 *)(buf+OFFSET_INTERNALDATE)));
    record->sentdate = htonl(*((bit32 *)(buf+OFFSET_SENTDATE)));
    record->size = htonl(*((bit32 *)(buf+OFFSET_SIZE)));
    record->header_size = htonl(*((bit32 *)(buf+OFFSET_HEADER_SIZE)));
    record->content_offset = htonl(*((bit32 *)(buf+OFFSET_CONTENT_OFFSET)));
    record->cache_offset = htonl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));
    record->last_updated = htonl(*((bit32 *)(buf+OFFSET_LAST_UPDATED)));
    record->system_flags = htonl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));
    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
	record->user_flags[n] = htonl(*((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)));
    }
    return 0;
}

/*
 * Open and read the quota file 'quota'
 */
int
mailbox_read_quota(quota)
struct quota *quota;
{
    const char *p, *eol;
    char buf[4096];
    const char *quota_base = 0;
    unsigned long quota_len = 0;


    if (!quota->root) {
	quota->used = 0;
	quota->limit = -1;
	return 0;
    }

    if (quota->fd == -1) {
	mailbox_hash_quota(buf, quota->root);
	quota->fd = open(buf, O_RDWR, 0);
	if (quota->fd == -1) {
	    syslog(LOG_ERR, "IOERROR: opening quota file %s: %m", buf);
	    return IMAP_IOERROR;
	}
    }
    
    map_refresh(quota->fd, 1, &quota_base, &quota_len,
		MAP_UNKNOWN_LEN, buf, 0);

    p = quota_base;
    eol = memchr(p, '\n', quota_len - (p - quota_base));
    if (!eol) {
	map_free(&quota_base, &quota_len);
	return IMAP_MAILBOX_BADFORMAT;
    }
    quota->used = atol(p);

    p = eol + 1;
    eol = memchr(p, '\n', quota_len - (p - quota_base));
    if (!eol) {
	map_free(&quota_base, &quota_len);
	return IMAP_MAILBOX_BADFORMAT;
    }
    quota->limit = atoi(p);

    map_free(&quota_base, &quota_len);
    return 0;
}

/*
 * Lock the header for 'mailbox'.  Reread header if necessary.
 */
int
mailbox_lock_header(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    const char *lockfailaction;
    int r;

    if (mailbox->header_lock_count++) return 0;

    assert(mailbox->index_lock_count == 0);
    assert(mailbox->quota.lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_HEADER);

    r = lock_reopen(mailbox->header_fd, fnamebuf, &sbuf, &lockfailaction);
    if (r) {
	mailbox->header_lock_count--;
	syslog(LOG_ERR, "IOERROR: %s header for %s: %m",
	       lockfailaction, mailbox->name);
	return IMAP_IOERROR;
    }

    if (sbuf.st_ino != mailbox->header_ino) {
	map_free(&mailbox->header_base, &mailbox->header_len);
	map_refresh(mailbox->header_fd, 1, &mailbox->header_base,
		    &mailbox->header_len, sbuf.st_size, "header",
		    mailbox->name);
	mailbox->header_ino = sbuf.st_ino;
	r = mailbox_read_header(mailbox);
	if (r && !mailbox_doing_reconstruct) {
	    mailbox_unlock_header(mailbox);
	    return r;
	}
    }

    return 0;
}

/*
 * Lock the index file for 'mailbox'.  Reread index file header if necessary.
 */
int
mailbox_lock_index(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->index_lock_count++) return 0;

    assert(mailbox->quota.lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);

    /* xxx why is this not a lock_reopen() ? */
    for (;;) {
	r = lock_blocking(mailbox->index_fd);
	if (r == -1) {
	    mailbox->index_lock_count--;
	    syslog(LOG_ERR, "IOERROR: locking index for %s: %m",
		   mailbox->name);
	    return IMAP_IOERROR;
	}

	fstat(mailbox->index_fd, &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating index for %s: %m",
		   mailbox->name);
	    mailbox_unlock_index(mailbox);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	if ((r = mailbox_open_index(mailbox))) {
	    return r;
	}
    }

    r = mailbox_read_index_header(mailbox);
    if (r && !mailbox_doing_reconstruct) {
	mailbox_unlock_index(mailbox);
	return r;
    }

    return 0;
}

/*
 * Place a POP lock on 'mailbox'.
 */
int
mailbox_lock_pop(mailbox)
struct mailbox *mailbox;
{
    int r = -1;

    if (mailbox->pop_lock_count++) return 0;

    r = lock_nonblocking(mailbox->cache_fd);
    if (r == -1) {
	mailbox->pop_lock_count--;
	if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EACCES) {
	    return IMAP_MAILBOX_POPLOCKED;
	}
	syslog(LOG_ERR, "IOERROR: locking cache for %s: %m", mailbox->name);
	return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Lock the quota file 'quota'.  Reread quota file if necessary.
 */
int
mailbox_lock_quota(quota)
struct quota *quota;
{
    char quota_path[MAX_MAILBOX_PATH];
    struct stat sbuf;
    const char *lockfailaction;
    int r;

    /* assert(mailbox->header_lock_count != 0); */

    if (quota->lock_count++) return 0;

    /* assert(mailbox->seen_lock_count == 0); */

    if (!quota->root) {
	quota->used = 0;
	quota->limit = -1;
	return 0;
    }
    mailbox_hash_quota(quota_path, quota->root);
    if (quota->fd == -1) {
	quota->fd = open(quota_path, O_RDWR, 0);
	if (quota->fd == -1) {
	    syslog(LOG_ERR, "IOERROR: opening quota file %s: %m",
		   quota_path);
	    return IMAP_IOERROR;
	}
    }

    r = lock_reopen(quota->fd, quota_path, &sbuf, &lockfailaction);
    if (r == -1) {
	quota->lock_count--;
	syslog(LOG_ERR, "IOERROR: %s quota %s: %m", lockfailaction,
	       quota->root);
	return IMAP_IOERROR;
    }

    return mailbox_read_quota(quota);
}

/*
 * Release lock on the header for 'mailbox'
 */
void mailbox_unlock_header(struct mailbox *mailbox)
{
    assert(mailbox->header_lock_count != 0);

    if (--mailbox->header_lock_count == 0) {
	lock_unlock(mailbox->header_fd);
    }
}

/*
 * Release lock on the index file for 'mailbox'
 */
void
mailbox_unlock_index(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->index_lock_count != 0);

    if (--mailbox->index_lock_count == 0) {
	lock_unlock(mailbox->index_fd);
    }
}

/*
 * Release POP lock for 'mailbox'
 */
void
mailbox_unlock_pop(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->pop_lock_count != 0);

    if (--mailbox->pop_lock_count == 0) {
	lock_unlock(mailbox->cache_fd);
    }
}

/*
 * Release lock on the quota file 'quota'
 */
void
mailbox_unlock_quota(quota)
struct quota *quota;
{
    assert(quota->lock_count != 0);

    if (--quota->lock_count == 0 && quota->root) {
	lock_unlock(quota->fd);
    }
}

/*
 * Write the header file for 'mailbox'
 */
int mailbox_write_header(struct mailbox *mailbox)
{
    int flag;
    int newheader_fd;
    int r = 0;
    const char *quota_root;
    char fnamebuf[MAX_MAILBOX_PATH];
    char newfnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    struct iovec iov[10];
    int niov;

    assert(mailbox->header_lock_count != 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_HEADER);
    strcpy(newfnamebuf, fnamebuf);
    strcat(newfnamebuf, ".NEW");

    newheader_fd = open(newfnamebuf, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (newheader_fd == -1) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	return IMAP_IOERROR;
    }

    /* Write magic header, do NOT write the trailing NUL */
    r = write(newheader_fd, MAILBOX_HEADER_MAGIC,
	      sizeof(MAILBOX_HEADER_MAGIC) - 1);

    if(r != -1) {
	niov = 0;
	quota_root = mailbox->quota.root ? mailbox->quota.root : "";
	WRITEV_ADDSTR_TO_IOVEC(iov,niov,(char *)quota_root);
	WRITEV_ADD_TO_IOVEC(iov,niov,"\t",1);
	WRITEV_ADDSTR_TO_IOVEC(iov,niov,mailbox->uniqueid);
	WRITEV_ADD_TO_IOVEC(iov,niov,"\n",1);
	r = retry_writev(newheader_fd, iov, niov);
    }

    if(r != -1) {
	for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	    if (mailbox->flagname[flag]) {
		niov = 0;
		WRITEV_ADDSTR_TO_IOVEC(iov,niov,mailbox->flagname[flag]);
		WRITEV_ADD_TO_IOVEC(iov,niov," ",1);
		r = retry_writev(newheader_fd, iov, niov);
		if(r == -1) break;
	    }
	}
    }
    
    if(r != -1) {
	niov = 0;
	WRITEV_ADD_TO_IOVEC(iov,niov,"\n",1);
	WRITEV_ADDSTR_TO_IOVEC(iov,niov,mailbox->acl);
	WRITEV_ADD_TO_IOVEC(iov,niov,"\n",1);
	r = retry_writev(newheader_fd, iov, niov);
    }
    
    if (r == -1 || fsync(newheader_fd) ||
	lock_blocking(newheader_fd) == -1 ||
	rename(newfnamebuf, fnamebuf) == -1) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	close(newheader_fd);
	unlink(newfnamebuf);
	return IMAP_IOERROR;
    }

    if (mailbox->header_fd != -1) {
	close(mailbox->header_fd);
	map_free(&mailbox->header_base, &mailbox->header_len);
    }
    mailbox->header_fd = newheader_fd;

    if (fstat(mailbox->header_fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstating %s: %m", fnamebuf);
	fatal("can't fstat header file", EC_OSFILE);
    }

    map_refresh(mailbox->header_fd, 1, &mailbox->header_base,
		&mailbox->header_len, sbuf.st_size, "header", mailbox->name);
    mailbox->header_ino = sbuf.st_ino;

    return 0;
}

/*
 * Write the index header for 'mailbox'
 */
int mailbox_write_index_header(struct mailbox *mailbox)
{
    char buf[INDEX_HEADER_SIZE];
    unsigned long header_size = INDEX_HEADER_SIZE;
    int n;
    
    assert(mailbox->index_lock_count != 0);

    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = mailbox->generation_no;
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(mailbox->exists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox->last_uid);
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(mailbox->quota_mailbox_used);
    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(mailbox->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(mailbox->deleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(mailbox->answered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(mailbox->flagged);
    *((bit32 *)(buf+OFFSET_POP3_NEW_UIDL)) = htonl(mailbox->pop3_new_uidl);

    if (mailbox->start_offset < header_size)
	header_size = mailbox->start_offset;

    lseek(mailbox->index_fd, 0, SEEK_SET);
    n = retry_write(mailbox->index_fd, buf, header_size);
    if ((unsigned long)n != header_size || fsync(mailbox->index_fd)) {
	syslog(LOG_ERR, "IOERROR: writing index header for %s: %m",
	       mailbox->name);
	return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Write an index record to a mailbox
 * call fsync() on index_fd if 'sync' is true
 */
int
mailbox_write_index_record(struct mailbox *mailbox,
			   unsigned msgno,
			   struct index_record *record,
			   int sync)
{
    int n;
    char buf[INDEX_RECORD_SIZE];

    *((bit32 *)(buf+OFFSET_UID)) = htonl(record->uid);
    *((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(record->internaldate);
    *((bit32 *)(buf+OFFSET_SENTDATE)) = htonl(record->sentdate);
    *((bit32 *)(buf+OFFSET_SIZE)) = htonl(record->size);
    *((bit32 *)(buf+OFFSET_HEADER_SIZE)) = htonl(record->header_size);
    *((bit32 *)(buf+OFFSET_CONTENT_OFFSET)) = htonl(record->content_offset);
    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(record->cache_offset);
    *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(record->last_updated);
    *((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)) = htonl(record->system_flags);
    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
	*((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)) = htonl(record->user_flags[n]);
    }

    n = lseek(mailbox->index_fd,
	      mailbox->start_offset + (msgno-1) * mailbox->record_size,
	      SEEK_SET);
    if (n == -1) {
	syslog(LOG_ERR, "IOERROR: seeking index record %u for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    n = retry_write(mailbox->index_fd, buf, INDEX_RECORD_SIZE);
    if (n != INDEX_RECORD_SIZE || (sync && fsync(mailbox->index_fd))) {
	syslog(LOG_ERR, "IOERROR: writing index record %u for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    if (updatenotifier) updatenotifier(mailbox);

    return 0;
}

/*
 * Append a new record to the index file
 * call fsync() on index_fd if 'sync' is true
 */
int mailbox_append_index(struct mailbox *mailbox,
			 struct index_record *record,
			 unsigned start,
			 unsigned num,
			 int sync)
{
    unsigned i;
    int j, len, n;
    char *buf, *p;
    long last_offset;

    assert(mailbox->index_lock_count != 0);

    if (mailbox->record_size < INDEX_RECORD_SIZE) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    len = num * mailbox->record_size;
    buf = xmalloc(len);
    memset(buf, 0, len);

    for (i = 0; i < num; i++) {
	p = buf + i*mailbox->record_size;
	*((bit32 *)(p+OFFSET_UID)) = htonl(record[i].uid);
	*((bit32 *)(p+OFFSET_INTERNALDATE)) = htonl(record[i].internaldate);
	*((bit32 *)(p+OFFSET_SENTDATE)) = htonl(record[i].sentdate);
	*((bit32 *)(p+OFFSET_SIZE)) = htonl(record[i].size);
	*((bit32 *)(p+OFFSET_HEADER_SIZE)) = htonl(record[i].header_size);
	*((bit32 *)(p+OFFSET_CONTENT_OFFSET)) = htonl(record[i].content_offset);
	*((bit32 *)(p+OFFSET_CACHE_OFFSET)) = htonl(record[i].cache_offset);
	*((bit32 *)(p+OFFSET_LAST_UPDATED)) = htonl(record[i].last_updated);
	*((bit32 *)(p+OFFSET_SYSTEM_FLAGS)) = htonl(record[i].system_flags);
	p += OFFSET_USER_FLAGS;
	for (j = 0; j < MAX_USER_FLAGS/32; j++, p += 4) {
	    *((bit32 *)p) = htonl(record[i].user_flags[j]);
	}
    }

    last_offset = mailbox->start_offset + start * mailbox->record_size;
    lseek(mailbox->index_fd, last_offset, SEEK_SET);
    n = retry_write(mailbox->index_fd, buf, len);
    free(buf);
    if (n != len || (sync && fsync(mailbox->index_fd))) {
	syslog(LOG_ERR, "IOERROR: appending index records for %s: %m",
	       mailbox->name);
	ftruncate(mailbox->index_fd, last_offset);
	return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Write out the quota 'quota'
 */
int mailbox_write_quota(struct quota *quota)
{
    int r;
    int len;
    char buf[1024];
    char quota_path[MAX_MAILBOX_PATH];
    char new_quota_path[MAX_MAILBOX_PATH];
    int newfd;

    assert(quota->lock_count != 0);

    if (!quota->root) return 0;

    mailbox_hash_quota(quota_path, quota->root);
    strcpy(new_quota_path, quota_path);
    strcat(new_quota_path, ".NEW");

    newfd = open(new_quota_path, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (newfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating quota file %s: %m", new_quota_path);
	return IMAP_IOERROR;
    }

    r = lock_blocking(newfd);
    if (r) {
	syslog(LOG_ERR, "IOERROR: locking quota file %s: %m",
	       new_quota_path);
	close(newfd);
	return IMAP_IOERROR;
    }

    len = snprintf(buf, sizeof(buf) - 1,
		   "%lu\n%d\n", quota->used, quota->limit);
    r = write(newfd, buf, len);
    
    if (r == -1 || fsync(newfd)) {
	syslog(LOG_ERR, "IOERROR: writing quota file %s: %m",
	       new_quota_path);
	close(newfd);
	return IMAP_IOERROR;
    }

    if (rename(new_quota_path, quota_path)) {
	syslog(LOG_ERR, "IOERROR: renaming quota file %s: %m",
	       quota_path);
	close(newfd);
	return IMAP_IOERROR;
    }

    if (quota->fd != -1) {
	close(quota->fd);
	quota->fd = -1;
    }

    quota->fd = newfd;

    return 0;
}

/*
 * Remove the quota root 'quota'
 */
int
mailbox_delete_quota(quota)
struct quota *quota;
{
    char quota_path[MAX_MAILBOX_PATH];

    assert(quota->lock_count != 0);

    if (!quota->root) return 0;

    mailbox_hash_quota(quota_path, quota->root);

    unlink(quota_path);

    if (quota->fd != -1) {
	close(quota->fd);
	quota->fd = -1;
    }

    free(quota->root);
    quota->root = 0;

    return 0;
}

/*
 * Lock the index file for 'mailbox'.
 * DON'T Reread index file header if necessary.
 */
static int mailbox_lock_index_for_upgrade(struct mailbox *mailbox)
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->index_lock_count++) return 0;

    assert(mailbox->quota.lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);

    for (;;) {
	r = lock_blocking(mailbox->index_fd);
	if (r == -1) {
	    mailbox->index_lock_count--;
	    syslog(LOG_ERR, "IOERROR: locking index for %s: %m",
		   mailbox->name);
	    return IMAP_IOERROR;
	}

	fstat(mailbox->index_fd, &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating index for %s: %m",
		   mailbox->name);
	    mailbox_unlock_index(mailbox);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	if ((r = mailbox_open_index(mailbox))) {
	    return r;
	}
    }

    return 0;
}

/*
 * Upgrade the index header for 'mailbox'
 */
static int mailbox_upgrade_index(struct mailbox *mailbox)
{
    int r;
    unsigned msgno;
    bit32 oldstart_offset;
    char buf[INDEX_HEADER_SIZE];
    char fnamebuf[MAX_MAILBOX_PATH], fnamebufnew[MAX_MAILBOX_PATH];
    FILE *newindex;
    char *fnametail;
    char *bufp;

    /* Lock files and open new index file */
    r = mailbox_lock_header(mailbox);
    if (r) return r;
    r = mailbox_lock_index_for_upgrade(mailbox);
    if (r) {
	mailbox_unlock_header(mailbox);
	return r;
    }

    r = mailbox_lock_pop(mailbox);
    if (r) {
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return r;
    }

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);
    strcat(fnamebuf, ".NEW");
    newindex = fopen(fnamebuf, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	goto fail;
    }

    /* change version number */
    mailbox->minor_version = MAILBOX_MINOR_VERSION;

    /* save old start_offset; change start_offset */
    oldstart_offset = mailbox->start_offset;
    mailbox->start_offset = INDEX_HEADER_SIZE;

    /* Write the new index header */ 
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = mailbox->generation_no;
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(mailbox->exists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox->last_uid);
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(mailbox->quota_mailbox_used);
    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(mailbox->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(mailbox->deleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(mailbox->answered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(mailbox->flagged);
    *((bit32 *)(buf+OFFSET_POP3_NEW_UIDL)) = htonl(mailbox->pop3_new_uidl);

    fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);

    /* Write the rest of new index same as old */
    for (msgno = 1; msgno <= mailbox->exists; msgno++) {
	bufp = (char *) (mailbox->index_base + oldstart_offset +
			(msgno - 1)*mailbox->record_size);

	fwrite(bufp, mailbox->record_size, 1, newindex);
    }

    /* Ensure everything made it to disk */
    fflush(newindex);
    if (ferror(newindex) ||
	fsync(fileno(newindex))) {
	syslog(LOG_ERR, "IOERROR: writing index for %s: %m",
	       mailbox->name);
	goto fail;
    }

    strcpy(fnamebuf, mailbox->path);
    fnametail = fnamebuf + strlen(fnamebuf);
    strcpy(fnametail, FNAME_INDEX);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_ERR, "IOERROR: renaming index file for %s: %m",
	       mailbox->name);
	goto fail;
    }

    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    fclose(newindex);

    return 0;

 fail:
    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);

    return IMAP_IOERROR;
}

/*
 * Calculate the number of messages in the mailbox with
 * answered/deleted/flagged system flags
 */

static int mailbox_calculate_flagcounts(struct mailbox *mailbox)
{
    int r;
    unsigned msgno;
    bit32 numansweredflag = 0;
    bit32 numdeletedflag = 0;
    bit32 numflaggedflag = 0;
    struct stat sbuf;
    char *bufp;

    /* Lock files */
    r = mailbox_lock_header(mailbox);
    if (r) return r;
    r = mailbox_lock_index_for_upgrade(mailbox);
    if (r) {
	mailbox_unlock_header(mailbox);
	return r;
    }

    r = mailbox_lock_pop(mailbox);
    if (r) {
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return r;
    }

    if (fstat(mailbox->cache_fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstating %s: %m", mailbox->name);
	fatal("can't fstat cache file", EC_OSFILE);
    }
    mailbox->cache_size = sbuf.st_size;
    map_refresh(mailbox->cache_fd, 0, &mailbox->cache_base,
		&mailbox->cache_len, mailbox->cache_size, 
		"cache", mailbox->name);

    /* for each message look at the system flags */
    for (msgno = 1; msgno <= mailbox->exists; msgno++) {
	bit32 sysflags;
	
	bufp = (char *) (mailbox->index_base + mailbox->start_offset +
			(msgno - 1)*mailbox->record_size);

	/* Sanity check */
	if (*((bit32 *)(bufp+OFFSET_UID)) == 0) {
	    syslog(LOG_ERR, "IOERROR: %s zero index record %u/%lu",
		   mailbox->name, msgno, mailbox->exists);
	    mailbox_unlock_pop(mailbox);
	    mailbox_unlock_index(mailbox);
	    mailbox_unlock_header(mailbox);
	    return IMAP_IOERROR;
	}

	sysflags = ntohl(*((bit32 *)(bufp+OFFSET_SYSTEM_FLAGS)));
	if (sysflags & FLAG_ANSWERED)
	    numansweredflag++;
	if (sysflags & FLAG_DELETED)
	    numdeletedflag++;
	if (sysflags & FLAG_FLAGGED)
	    numflaggedflag++;
    }

    mailbox->answered = numansweredflag;
    mailbox->deleted = numdeletedflag;
    mailbox->flagged = numflaggedflag;

    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);

    return 0;
}

/*
 * Perform an expunge operation on 'mailbox'.  If 'iscurrentdir' is nonzero,
 * the current directory is set to the mailbox directory.  If nonzero, the
 * function pointed to by 'decideproc' is called (with 'deciderock') to
 * determine which messages to expunge.  If 'decideproc' is a null pointer,
 * then messages with the \Deleted flag are expunged.
 */
int
mailbox_expunge(mailbox, iscurrentdir, decideproc, deciderock)
struct mailbox *mailbox;
int iscurrentdir;
mailbox_decideproc_t *decideproc;
void *deciderock;
{
    int r, n;
    char fnamebuf[MAX_MAILBOX_PATH], fnamebufnew[MAX_MAILBOX_PATH];
    FILE *newindex, *newcache;
    unsigned long *deleted;
    unsigned numdeleted = 0, quotadeleted = 0;
    unsigned numansweredflag = 0;
    unsigned numdeletedflag = 0;
    unsigned numflaggedflag = 0;
    unsigned newexists;
    unsigned newdeleted;
    unsigned newanswered;
    unsigned newflagged; 
    char *buf;
    unsigned msgno;
    int lastmsgdeleted = 1;
    unsigned long cachediff = 0;
    unsigned long cachestart = sizeof(bit32);
    unsigned long cache_offset;
    struct stat sbuf;
    char *fnametail;

    /* Lock files and open new index/cache files */
    r = mailbox_lock_header(mailbox);
    if (r) return r;
    r = mailbox_lock_index(mailbox);
    if (r) {
	mailbox_unlock_header(mailbox);
	return r;
    }

    r = mailbox_lock_pop(mailbox);
    if (r) {
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return r;
    }

    if (fstat(mailbox->cache_fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstating %s: %m", fnamebuf); /* xxx is fnamebuf initialized??? */
	fatal("can't fstat cache file", EC_OSFILE);
    }
    mailbox->cache_size = sbuf.st_size;
    map_refresh(mailbox->cache_fd, 0, &mailbox->cache_base,
		&mailbox->cache_len, mailbox->cache_size,
		"cache", mailbox->name);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);
    strcat(fnamebuf, ".NEW");
    newindex = fopen(fnamebuf, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	mailbox_unlock_pop(mailbox);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_CACHE);
    strcat(fnamebuf, ".NEW");
    newcache = fopen(fnamebuf, "w+");
    if (!newcache) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	fclose(newindex);
	mailbox_unlock_pop(mailbox);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    /* Allocate temporary buffers */
    if (mailbox->exists > 0) {
        /* XXX kludge: not all mallocs return a valid pointer to 0 bytes;
           some have the good sense to return 0 */
        deleted = (unsigned long *)
            xmalloc(mailbox->exists*sizeof(unsigned long));
    } else {
        deleted = 0;
    }
    buf = xmalloc(mailbox->start_offset > mailbox->record_size ?
		  mailbox->start_offset : mailbox->record_size);

    /* Copy over headers */
    memcpy(buf, mailbox->index_base, mailbox->start_offset);
    (*(bit32 *)buf)++;    /* Increment generation number */
    fwrite(buf, 1, mailbox->start_offset, newindex);
    /* Grow the index header if necessary */
    for (n = mailbox->start_offset; n < INDEX_HEADER_SIZE; n++) {
	if (n == OFFSET_UIDVALIDITY+3) {
	    putc(1, newindex);
	}
	else {
	    putc(0, newindex);
	}
    }
    fwrite(buf, 1, sizeof(bit32), newcache);

    /* Copy over records for nondeleted messages */
    for (msgno = 1; msgno <= mailbox->exists; msgno++) {
	memcpy(buf,
	       mailbox->index_base + mailbox->start_offset +
	       (msgno - 1)*mailbox->record_size, mailbox->record_size);

	/* Sanity check */
	if (*((bit32 *)(buf+OFFSET_UID)) == 0) {
	    syslog(LOG_ERR, "IOERROR: %s zero index record %u/%lu",
		   mailbox->name, msgno, mailbox->exists);
	    goto fail;
	}

	if (decideproc ? decideproc(mailbox, deciderock, buf) :
	    (ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS))) & FLAG_DELETED)) {
	    bit32 sysflags;

	    /* Remember UID and size */
	    deleted[numdeleted++] = ntohl(*((bit32 *)(buf+OFFSET_UID)));
	    quotadeleted += ntohl(*((bit32 *)(buf+OFFSET_SIZE)));

	    /* figure out if deleted msg has system flags. update counts accordingly */
	    sysflags = ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));
	    if (sysflags & FLAG_ANSWERED)
		numansweredflag++;
	    if (sysflags & FLAG_DELETED)
		numdeletedflag++;
	    if (sysflags & FLAG_FLAGGED)
		numflaggedflag++;

	    /* Copy over cache file data */
	    if (!lastmsgdeleted) {
		cache_offset = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));
		
		fwrite(mailbox->cache_base + cachestart,
		       1, cache_offset - cachestart, newcache);
		cachestart = cache_offset;
		lastmsgdeleted = 1;
	    }
	}
	else {
	    cache_offset = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));

	    /* Set up for copying cache file data */
	    if (lastmsgdeleted) {
		cachediff += cache_offset - cachestart;
		cachestart = cache_offset;
		lastmsgdeleted = 0;
	    }

	    /* Fix up cache file offset */
	    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(cache_offset - cachediff);

	    fwrite(buf, 1, mailbox->record_size, newindex);
	}
    }

    /* Copy over any remaining cache file data */
    if (!lastmsgdeleted) {
	fwrite(mailbox->cache_base + cachestart, 1,
	       mailbox->cache_size - cachestart, newcache);
    }

    /* Fix up information in index header */
    rewind(newindex);
    n = fread(buf, 1, mailbox->start_offset, newindex);
    if ((unsigned long)n != mailbox->start_offset) {
	syslog(LOG_ERR, "IOERROR: reading index header for %s: got %d of %ld",
	       mailbox->name, n, mailbox->start_offset);
	goto fail;
    }
    /* Fix up exists */
    newexists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS)))-numdeleted;
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);
    /* fix up other counts */
    newanswered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED)))-numansweredflag;
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(newanswered);
    newdeleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED)))-numdeletedflag;
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(newdeleted);
    newflagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED)))-numflaggedflag;
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(newflagged);

    /* Fix up quota_mailbox_used */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
      htonl(ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)))-quotadeleted);
    /* Fix up start offset if necessary */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
	*((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }
	
    rewind(newindex);
    fwrite(buf, 1, mailbox->start_offset, newindex);
    
    /* Ensure everything made it to disk */
    fflush(newindex);
    fflush(newcache);
    if (ferror(newindex) || ferror(newcache) ||
	fsync(fileno(newindex)) || fsync(fileno(newcache))) {
	syslog(LOG_ERR, "IOERROR: writing index/cache for %s: %m",
	       mailbox->name);
	goto fail;
    }

    /* Record quota release */
    r = mailbox_lock_quota(&mailbox->quota);
    if (r) goto fail;
    if (mailbox->quota.used >= quotadeleted) {
	mailbox->quota.used -= quotadeleted;
    }
    else {
	mailbox->quota.used = 0;
    }
    r = mailbox_write_quota(&mailbox->quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record free of %u bytes in quota %s",
	       quotadeleted, mailbox->quota.root);
    }
    mailbox_unlock_quota(&mailbox->quota);

    strcpy(fnamebuf, mailbox->path);
    fnametail = fnamebuf + strlen(fnamebuf);
    strcpy(fnametail, FNAME_INDEX);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_ERR, "IOERROR: renaming index file for %s: %m",
	       mailbox->name);
	goto fail;
    }

    strcpy(fnametail, FNAME_CACHE);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_CRIT,
	       "CRITICAL IOERROR: renaming cache file for %s, need to reconstruct: %m",
	       mailbox->name);
	/* Fall through and delete message files anyway */
    }

    if (numdeleted) {
	if (updatenotifier) updatenotifier(mailbox);
    }

    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    fclose(newindex);
    fclose(newcache);

    /* Delete message files */
    *fnametail++ = '/';
    for (msgno = 0; msgno < numdeleted; msgno++) {
	if (iscurrentdir) {
	    char shortfnamebuf[MAILBOX_FNAME_LEN];
	    mailbox_message_get_fname(mailbox, deleted[msgno], shortfnamebuf);
	    unlink(shortfnamebuf);
	}
	else {
	    mailbox_message_get_fname(mailbox, deleted[msgno], fnametail);
	    unlink(fnamebuf);
	}
    }

    free(buf);
    if (deleted) free(deleted);

    return 0;

 fail:
    free(buf);
    free(deleted);
    fclose(newindex);
    fclose(newcache);
    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    return IMAP_IOERROR;
}

/* find the mailbox 'name' 's quotaroot, and return it in 'start'.
   'start' must be at least MAX_MAILBOX_PATH. 

   returns true if a quotaroot is found, 0 otherwise. 
*/
int mailbox_findquota(char *start, const char *name)
{
    char quota_path[MAX_MAILBOX_PATH];
    char *tail;
    struct stat sbuf;

    strcpy(start, name);

    mailbox_hash_quota(quota_path, start);
    while (stat(quota_path, &sbuf) == -1) {
	tail = strrchr(start, '.');
	if (!tail) return 0;
	*tail = '\0';
	mailbox_hash_quota(quota_path, start);
    }
    return 1;
}


int mailbox_create(const char *name,
		   char *path,
		   const char *acl,
		   const char *uniqueid,
		   int format,
		   struct mailbox *mailboxp)
{
    int r;
    char *p=path;
    char quota_root[MAX_MAILBOX_PATH];
    int hasquota;
    char fnamebuf[MAX_MAILBOX_PATH];
    struct mailbox mailbox;
    int save_errno;
    int n;
    const char *lockfailaction;
    struct stat sbuf;

    while ((p = strchr(p+1, '/'))) {
	*p = '\0';
	if (mkdir(path, 0755) == -1 && errno != EEXIST) {
	    save_errno = errno;
	    if (stat(path, &sbuf) == -1) {
		errno = save_errno;
		syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
		return IMAP_IOERROR;
	    }
	}
	*p = '/';
    }
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
	save_errno = errno;
	if (stat(path, &sbuf) == -1) {
	    errno = save_errno;
	    syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
	    return IMAP_IOERROR;
	}
    }

    zeromailbox(mailbox);
    mailbox.quota.fd = -1;

    hasquota = mailbox_findquota(quota_root, name);

    strcpy(fnamebuf, path);
    p = fnamebuf + strlen(fnamebuf);
    strcpy(p, FNAME_HEADER);
    mailbox.header_fd = open(fnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox.header_fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	return IMAP_IOERROR;
    }

    /* Note that we are locking the mailbox here.  Technically, this function
     * can be called with a lock on the mailbox list.  This would otherwise
     * violate the locking semantics, but it is okay since the mailbox list
     * changes have not been committed, and the mailbox we create here *can't*
     * be opened by anyone else */

    r = lock_reopen(mailbox.header_fd, fnamebuf, NULL, &lockfailaction);
    if(r) {
	syslog(LOG_ERR, "IOERROR: %s header for new mailbox %s: %m",
	       lockfailaction, mailbox.name);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    mailbox.header_lock_count++;

    mailbox.name = xstrdup(name);
    mailbox.path = xstrdup(path);
    mailbox.acl = xstrdup(acl);

    strcpy(p, FNAME_INDEX);
    mailbox.index_fd = open(fnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox.index_fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    r = lock_reopen(mailbox.index_fd, fnamebuf, NULL, &lockfailaction);
    if(r) {
	syslog(LOG_ERR, "IOERROR: %s index for new mailbox %s: %m",
	       lockfailaction, mailbox.name);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    mailbox.index_lock_count++;

    strcpy(p, FNAME_CACHE);
    mailbox.cache_fd = open(fnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox.cache_fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
        
    if (hasquota) mailbox.quota.root = xstrdup(quota_root);
    mailbox.generation_no = 0;
    mailbox.format = format;
    mailbox.minor_version = MAILBOX_MINOR_VERSION;
    mailbox.start_offset = INDEX_HEADER_SIZE;
    mailbox.record_size = INDEX_RECORD_SIZE;
    mailbox.exists = 0;
    mailbox.last_appenddate = 0;
    mailbox.last_uid = 0;
    mailbox.quota_mailbox_used = 0;
    mailbox.pop3_last_login = 0;
    mailbox.uidvalidity = time(0);
    mailbox.deleted = 0;
    mailbox.answered = 0;
    mailbox.flagged = 0;
    mailbox.pop3_new_uidl = 1;

    if (!uniqueid) {
	mailbox.uniqueid = xmalloc(sizeof(char) * 32);
	mailbox_make_uniqueid(mailbox.name, mailbox.uidvalidity, 
			      mailbox.uniqueid);
    } else {
	mailbox.uniqueid = xstrdup(uniqueid);
    }

    r = mailbox_write_header(&mailbox);
    if (!r) r = mailbox_write_index_header(&mailbox);
    if (!r) {
	n = retry_write(mailbox.cache_fd, (char *)&mailbox.generation_no, 4);
	if (n != 4 || fsync(mailbox.cache_fd)) {
	    syslog(LOG_ERR, "IOERROR: writing initial cache for %s: %m",
		   mailbox.name);
	    r = IMAP_IOERROR;
	}
    }
    if (!r) r = seen_create_mailbox(&mailbox);

    if (mailboxp) {
	*mailboxp = mailbox;
    }
    else {
	mailbox_close(&mailbox);
    }
    return r;
}

/*
 * Delete and close the mailbox 'mailbox'.  Closes 'mailbox' whether
 * or not the deletion was successful.  Requires a locked mailbox.
 */
int mailbox_delete(struct mailbox *mailbox, int delete_quota_root)
{
    int r, rquota = 0;
    DIR *dirp;
    struct dirent *f;
    char buf[MAX_MAILBOX_PATH];
    char *tail;
    
    /* Ensure that we are locked */
    if(!mailbox->header_lock_count) return IMAP_INTERNAL;

    rquota = mailbox_lock_quota(&mailbox->quota);

    seen_delete_mailbox(mailbox);

    if (delete_quota_root && !rquota) {
	mailbox_delete_quota(&mailbox->quota);
    } else if (!rquota) {
	/* Free any quota being used by this mailbox */
	if (mailbox->quota.used >= mailbox->quota_mailbox_used) {
	    mailbox->quota.used -= mailbox->quota_mailbox_used;
	}
	else {
	    mailbox->quota.used = 0;
	}
	r = mailbox_write_quota(&mailbox->quota);
	if (r) {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record free of %lu bytes in quota %s",
		   mailbox->quota_mailbox_used, mailbox->quota.root);
	}
	mailbox_unlock_quota(&mailbox->quota);
    }

    /* remove all files in directory */
    strcpy(buf, mailbox->path);
    tail = buf + strlen(buf);
    *tail++ = '/';
    dirp = opendir(mailbox->path);
    if (dirp) {
	while ((f = readdir(dirp))!=NULL) {
	    if (f->d_name[0] == '.'
		&& (f->d_name[1] == '\0'
		    || (f->d_name[1] == '.' &&
			f->d_name[2] == '\0'))) {
		/* readdir() can return "." or "..", and I got a bug report
		   that SCO might blow the file system to smithereens if we
		   unlink("..").  Let's not do that. */
		continue;
	    }
	    strcpy(tail, f->d_name);
	    (void) unlink(buf);
	}
	closedir(dirp);
    }

    /* Remove empty directories, going up path */
    tail--;
    do {
	*tail = '\0';
    } while (rmdir(buf) == 0 && (tail = strrchr(buf, '/')));

    mailbox_close(mailbox);
    return 0;
}

/*
 * Expunge decision proc used by mailbox_rename() to expunge all messages
 * in INBOX
 */
static int expungeall(struct mailbox *mailbox __attribute__((unused)),
		      void *rock __attribute__((unused)),
		      char *indexbuf __attribute__((unused)))
{
    return 1;
}

/* if 'isinbox' is set, we perform the funky RENAME INBOX INBOX.old
   semantics, regardless of whether or not the name of the mailbox is
   'user.foo'.*/
/* requires a LOCKED oldmailbox pointer */
int mailbox_rename_copy(struct mailbox *oldmailbox, 
			const char *newname, char *newpath,
			bit32 *olduidvalidityp, bit32 *newuidvalidityp,
			struct mailbox *newmailbox)
{
    int r;
    unsigned int flag, msgno;
    struct index_record record;
    char oldfname[MAX_MAILBOX_PATH], newfname[MAX_MAILBOX_PATH];
    char *oldfnametail, *newfnametail;

    assert(oldmailbox->header_lock_count > 0
	   && oldmailbox->index_lock_count > 0);
    

    /* Create new mailbox */
    r = mailbox_create(newname, newpath, 
		       oldmailbox->acl, oldmailbox->uniqueid,
		       oldmailbox->format, newmailbox);

    if (r) return r;

    if (strcmp(oldmailbox->name, newname) == 0) {
	/* Just moving mailboxes between partitions */
	newmailbox->uidvalidity = oldmailbox->uidvalidity;
    }

    if (olduidvalidityp) *olduidvalidityp = oldmailbox->uidvalidity;
    if (newuidvalidityp) *newuidvalidityp = newmailbox->uidvalidity;

    /* Copy flag names */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (oldmailbox->flagname[flag]) {
	    newmailbox->flagname[flag] = xstrdup(oldmailbox->flagname[flag]);
	}
    }
    r = mailbox_write_header(newmailbox);
    if (r) {
	mailbox_close(newmailbox);
	return r;
    }

    /* Check quota if necessary */
    if (newmailbox->quota.root) {
	r = mailbox_lock_quota(&(newmailbox->quota));
	if (!oldmailbox->quota.root ||
	    strcmp(oldmailbox->quota.root, newmailbox->quota.root) != 0) {
	    if (!r && newmailbox->quota.limit >= 0 &&
		newmailbox->quota.used + oldmailbox->quota_mailbox_used >
		((unsigned) newmailbox->quota.limit * QUOTA_UNITS)) {
		r = IMAP_QUOTA_EXCEEDED;
	    }
	}
	if (r) {
	    mailbox_close(newmailbox);
	    return r;
	}
    }

    strcpy(oldfname, oldmailbox->path);
    oldfnametail = oldfname + strlen(oldfname);
    strcpy(newfname, newmailbox->path);
    newfnametail = newfname + strlen(newfname);

    /* Copy over index/cache files */
    strcpy(oldfnametail, FNAME_INDEX);
    strcpy(newfnametail, FNAME_INDEX);
    unlink(newfname);		/* Make link() possible */
    r = mailbox_copyfile(oldfname, newfname);
    strcpy(oldfnametail, FNAME_CACHE);
    strcpy(newfnametail, FNAME_CACHE);
    unlink(newfname);
    if (!r) r = mailbox_copyfile(oldfname, newfname);
    if (r) {
	mailbox_close(newmailbox);
	return r;
    }

    /* Re-open index file and store new uidvalidity  */
    close(newmailbox->index_fd);
    newmailbox->index_fd = dup(oldmailbox->index_fd);
    (void) mailbox_read_index_header(newmailbox);
    newmailbox->generation_no = oldmailbox->generation_no;
    (void) mailbox_write_index_header(newmailbox);

    /* Copy over message files */
    oldfnametail++;
    newfnametail++;
    for (msgno = 1; msgno <= oldmailbox->exists; msgno++) {
	r = mailbox_read_index_record(oldmailbox, msgno, &record);
	if (r) break;
	mailbox_message_get_fname(oldmailbox, record.uid, oldfnametail);
	strcpy(newfnametail, oldfnametail);
	r = mailbox_copyfile(oldfname, newfname);
	if (r) break;
    }
    if (!r) r = seen_copy(oldmailbox, newmailbox);

    /* Record new quota usage */
    if (!r && newmailbox->quota.root) {
	newmailbox->quota.used += oldmailbox->quota_mailbox_used;
	r = mailbox_write_quota(&(newmailbox->quota));
	mailbox_unlock_quota(&(newmailbox->quota));
    }
    if (r) {
	/* failure and back out */
	for (msgno = 1; msgno <= oldmailbox->exists; msgno++) {
	    if (mailbox_read_index_record(oldmailbox, msgno, &record))
		continue;
	    mailbox_message_get_fname(oldmailbox, record.uid, newfnametail);
	    (void) unlink(newfname);
	}
    }

    return r;
}

int mailbox_rename_cleanup(struct mailbox *oldmailbox, int isinbox) 
{
    int r = 0;
    
    if (isinbox) {
	/* Expunge old mailbox */
	r = mailbox_expunge(oldmailbox, 0, expungeall, (char *)0);
    } else {
	r = mailbox_delete(oldmailbox, 0);
    }

    if(r) {
	syslog(LOG_CRIT,
	       "Rename Failure during mailbox_rename_cleanup (%s), " \
	       "potential leaked space (%s)", oldmailbox->name,
	       error_message(r));
    }

    return r;
}


/*
 * Synchronize 'new' mailbox to 'old' mailbox.
 */
int
mailbox_sync(const char *oldname, const char *oldpath, const char *oldacl, 
	     const char *newname, char *newpath, int docreate, 
	     bit32 *olduidvalidityp, bit32 *newuidvalidityp,
	     struct mailbox *mailboxp)
{
    int r, r2;
    struct mailbox oldmailbox, newmailbox;
    unsigned int flag, oldmsgno, newmsgno;
    struct index_record oldrecord, newrecord;
    char oldfname[MAX_MAILBOX_PATH], newfname[MAX_MAILBOX_PATH];
    char *oldfnametail, *newfnametail;

    /* Open old mailbox and lock */
    mailbox_open_header_path(oldname, oldpath, oldacl, 0, &oldmailbox, 0);

    if (oldmailbox.format == MAILBOX_FORMAT_NETNEWS) {
	mailbox_close(&oldmailbox);
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    r =  mailbox_lock_header(&oldmailbox);
    if (!r) r = mailbox_open_index(&oldmailbox);
    if (!r) r = mailbox_lock_index(&oldmailbox);
    if (r) {
	mailbox_close(&oldmailbox);
	return r;
    }

    if (docreate) {
	/* Create new mailbox */
	r = mailbox_create(newname, newpath, 
			   oldmailbox.acl, oldmailbox.uniqueid, oldmailbox.format,
			   &newmailbox);
    }
    else {
	/* Open new mailbox and lock */
	r = mailbox_open_header_path(newname, newpath, oldacl, 0, &newmailbox, 0);
	r =  mailbox_lock_header(&newmailbox);
	if (!r) r = mailbox_open_index(&newmailbox);
	if (!r) r = mailbox_lock_index(&newmailbox);
	if (r) {
	    mailbox_close(&newmailbox);
	}
    }
    if (r) {
	mailbox_close(&oldmailbox);
	return r;
    }

    newmailbox.uidvalidity = oldmailbox.uidvalidity;
    if (olduidvalidityp) *olduidvalidityp = oldmailbox.uidvalidity;
    if (newuidvalidityp) *newuidvalidityp = newmailbox.uidvalidity;

    /* Copy flag names */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (oldmailbox.flagname[flag]) {
	    newmailbox.flagname[flag] = xstrdup(oldmailbox.flagname[flag]);
	}
    }
    r = mailbox_write_header(&newmailbox);
    if (r) {
	mailbox_close(&newmailbox);
	mailbox_close(&oldmailbox);
	return r;
    }

    /* Check quota if necessary */
    if (newmailbox.quota.root) {
	r = mailbox_lock_quota(&newmailbox.quota);
	if (!oldmailbox.quota.root ||
	    strcmp(oldmailbox.quota.root, newmailbox.quota.root) != 0) {
	    if (!r && newmailbox.quota.limit >= 0 &&
		newmailbox.quota.used + oldmailbox.quota_mailbox_used >
		((unsigned) newmailbox.quota.limit * QUOTA_UNITS)) {
		r = IMAP_QUOTA_EXCEEDED;
	    }
	}
	if (r) {
	    mailbox_close(&newmailbox);
	    mailbox_close(&oldmailbox);
	    return r;
	}
    }

    strcpy(oldfname, oldmailbox.path);
    strcat(oldfname, "/");
    oldfnametail = oldfname + strlen(oldfname);
    strcpy(newfname, newmailbox.path);
    strcat(newfname, "/");
    newfnametail = newfname + strlen(newfname);

    /*
     * Copy over new message files and delete expunged ones.
     *
     * We use the fact that UIDs are monotonically increasing to our
     * advantage; we compare the UIDs from each mailbox in order, and:
     *
     *  - if UID in "slave" mailbox < UID in "master" mailbox,
     *    then the message has been deleted from "master" since last sync,
     *    so delete it from "slave" and move on to next "slave" UID
     *  - if UID in "slave" mailbox == UID in "master" mailbox,
     *    then message is still current and we already have a copy,
     *    so move on to next UID in each mailbox
     *  - if UID in "master" mailbox > last UID in "slave" mailbox, 
     *    then this is a new arrival in "master" since last sync,
     *    so copy it to "slave" and move on to next "master" UID
     */
    newmsgno = 1;
    for (oldmsgno = 1; oldmsgno <= oldmailbox.exists; oldmsgno++) {
	r = mailbox_read_index_record(&oldmailbox, oldmsgno, &oldrecord);
	if (r) break;
	if (newmsgno <= newmailbox.exists) {
	    do {
		r = mailbox_read_index_record(&newmailbox, newmsgno,
					      &newrecord);
		if (r) goto fail;
		newmsgno++;

		if (newrecord.uid < oldrecord.uid) {
		    /* message expunged since last sync - delete message file */
		    mailbox_message_get_fname(&newmailbox, newrecord.uid,
					      newfnametail);
		    unlink(newfname);
		}
	    } while ((newrecord.uid < oldrecord.uid) &&
		     (newmsgno <= newmailbox.exists));
	}
	/* we check 'exists' instead of last UID in case of empty mailbox */
	if (newmsgno > newmailbox.exists) {
	    /* message arrived since last sync - copy message file */
	    mailbox_message_get_fname(&oldmailbox, oldrecord.uid, oldfnametail);
	    strcpy(newfnametail, oldfnametail);
	    r = mailbox_copyfile(oldfname, newfname);
	    if (r) break;
	}
    }
    if (!r) r = seen_copy(&oldmailbox, &newmailbox);

    if (!r) {
	/* Copy over index/cache files */
	oldfnametail--;
	newfnametail--;
	strcpy(oldfnametail, FNAME_INDEX);
	strcpy(newfnametail, FNAME_INDEX);
	unlink(newfname);		/* Make link() possible */
	r = mailbox_copyfile(oldfname, newfname);
	strcpy(oldfnametail, FNAME_CACHE);
	strcpy(newfnametail, FNAME_CACHE);
	unlink(newfname);
	if (!r) r = mailbox_copyfile(oldfname, newfname);
	if (r) {
	    mailbox_close(&newmailbox);
	    mailbox_close(&oldmailbox);
	    return r;
	}

	/* Re-open index file and store new uidvalidity  */
	close(newmailbox.index_fd);
	newmailbox.index_fd = dup(oldmailbox.index_fd);
	(void) mailbox_read_index_header(&newmailbox);
	newmailbox.generation_no = oldmailbox.generation_no;
	(void) mailbox_write_index_header(&newmailbox);
    }

    /* Record new quota usage */
    if (!r && newmailbox.quota.root) {
	newmailbox.quota.used += oldmailbox.quota_mailbox_used;
	r = mailbox_write_quota(&newmailbox.quota);
	mailbox_unlock_quota(&newmailbox.quota);
    }
    if (r) goto fail;

    if (r && newmailbox.quota.root) {
	r2 = mailbox_lock_quota(&newmailbox.quota);
	newmailbox.quota.used += newmailbox.quota_mailbox_used;
	if (!r2) {
	    r2 = mailbox_write_quota(&newmailbox.quota);
	    mailbox_unlock_quota(&newmailbox.quota);
	}
	if (r2) {
	    syslog(LOG_ERR,
	      "LOSTQUOTA: unable to record use of %lu bytes in quota %s",
		   newmailbox.quota_mailbox_used, newmailbox.quota.root);
	}
    }
    if (r) goto fail;

    mailbox_close(&oldmailbox);
    if (mailboxp) {
	*mailboxp = newmailbox;
    } else {
	mailbox_close(&newmailbox);
    }
    return 0;

 fail:
#if 0
    for (msgno = 1; msgno <= oldmailbox.exists; msgno++) {
	if (mailbox_read_index_record(&oldmailbox, msgno, &record)) continue;
	mailbox_message_get_fname(&oldmailbox, record.uid, newfnametail);
	(void) unlink(newfname);
    }
#endif
    mailbox_close(&newmailbox);
    mailbox_close(&oldmailbox);
    return r;
}

    
/*
 * Copy (or link) the file 'from' to the file 'to'
 */
int mailbox_copyfile(from, to)
const char *from;
const char *to;
{
    int srcfd, destfd;
    struct stat sbuf;
    const char *src_base = 0;
    unsigned long src_size = 0;
    int n;

    if (link(from, to) == 0) return 0;
    if (errno == EEXIST) {
	if (unlink(to) == -1) {
	    syslog(LOG_ERR, "IOERROR: unlinking to recreate %s: %m", to);
	    return IMAP_IOERROR;
	}
	if (link(from, to) == 0) return 0;
    }
    
    destfd = open(to, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (destfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", to);
	return IMAP_IOERROR;
    }

    srcfd = open(from, O_RDONLY, 0666);
    if (srcfd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", from);
	close(destfd);
	return IMAP_IOERROR;
    }


    if (fstat(srcfd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", from);
	close(srcfd);
	close(destfd);
	return IMAP_IOERROR;
    }
    map_refresh(srcfd, 1, &src_base, &src_size, sbuf.st_size, from, 0);
    
    n = retry_write(destfd, src_base, src_size);

    if (n == -1 || fsync(destfd)) {
	map_free(&src_base, &src_size);
	close(srcfd);
	close(destfd);
	syslog(LOG_ERR, "IOERROR: writing %s: %m", to);
	return IMAP_IOERROR;
    }
    map_free(&src_base, &src_size);
    close(srcfd);
    close(destfd);
    return 0;
}

void mailbox_hash_mbox(char *buf, 
		       const char *root,
		       const char *name)
{
    const char *idx;
    char c, *p;

    sprintf(buf, "%s", root);
    buf += strlen(buf);

    if (config_virtdomains && (p = strchr(name, '!'))) {
	*p = '\0';  /* split domain!user */
	if (config_hashimapspool) {
	    c = (char) dir_hash_c(name);
	    sprintf(buf, "%s%c/%s", FNAME_DOMAINDIR, c, name);
	}
	else {
	    sprintf(buf, "%s%s", FNAME_DOMAINDIR, name);
	}
	*p++ = '!';  /* reassemble domain!user */
	name = p;
	buf += strlen(buf);
    }

    if (config_hashimapspool) {
	idx = strchr(name, '.');
	if (idx == NULL) {
	    idx = name;
	} else {
	    idx++;
	}
	c = (char) dir_hash_c(idx);
	
	sprintf(buf, "/%c/%s", c, name);
    } else {
	/* standard mailbox placement */
	sprintf(buf, "/%s", name);
    }

    /* change all '.'s to '/' */
    for (p = buf; *p; p++) {
	if (*p == '.') *p = '/';
    }
}

/* simple hash so it's easy to find these things in the filesystem;
   our human time is worth more than efficiency */
void mailbox_hash_quota(char *buf, const char *qr)
{
    const char *idx;
    char c, *p;

    sprintf(buf, "%s", config_dir);
    buf += strlen(buf);

    if (config_virtdomains && (p = strchr(qr, '!'))) {
	*p = '\0';  /* split domain!qr */
	c = (char) dir_hash_c(qr);
	sprintf(buf, "%s%c/%s", FNAME_DOMAINDIR, c, qr);
	*p++ = '!';  /* reassemble domain!qr */
	qr = p;
	buf += strlen(buf);
    }

    idx = strchr(qr, '.'); /* skip past user. */
    if (idx == NULL) {
	idx = qr;
    } else {
	idx++;
    }
    c = (char) dir_hash_c(idx);

    sprintf(buf, "%s%c/%s", FNAME_QUOTADIR, c, qr);
}
