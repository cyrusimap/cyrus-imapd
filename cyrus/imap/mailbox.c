/* mailbox.c -- Mailbox manipulation routines
 *
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
 * $Id: mailbox.c,v 1.147.2.16 2004/08/05 16:23:44 ken3 Exp $
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

#include "acl.h"
#include "assert.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "index.h"
#include "lock.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "retry.h"
#include "seen.h"
#include "util.h"
#include "xmalloc.h"

static int mailbox_doing_reconstruct = 0;
#define zeromailbox(m) { memset(&m, 0, sizeof(struct mailbox)); \
                         (m).header_fd = -1; \
                         (m).index_fd = -1; \
                         (m).cache_fd = -1; }

static int mailbox_calculate_flagcounts(struct mailbox *mailbox);
static int mailbox_upgrade_index(struct mailbox *mailbox);

struct fnamebuf {
    char buf[MAX_MAILBOX_PATH+1];
    char *tail;
    size_t len;
};

struct fnamepath {
    struct fnamebuf data;
    struct fnamebuf meta;
};

/*
 * Build the filename of the given metadata file specified by 'metaflag'.
 *
 * On success, returns a pointer to the correct fnamebuf.
 * On failure (buffer overflow), returns NULL.
 *
 * A metaflag of 0 (zero) initializes the buffers.
 */
static struct fnamebuf *mailbox_meta_get_fname(struct fnamepath *fpath,
					       struct mailbox *mailbox,
					       unsigned long metaflag)
{
    const char *filename = NULL;
    struct fnamebuf *fname;
    char *path;
    size_t n;

    /* select the filename, based on the metadata flag */
    switch (metaflag) {
    case 0: /* initialize */
	fpath->data.len = fpath->meta.len = 0;
	return NULL;
    case IMAP_ENUM_METAPARTITION_FILES_HEADER:
	filename = FNAME_HEADER;
	break;
    case IMAP_ENUM_METAPARTITION_FILES_INDEX:
	filename = FNAME_INDEX;
	break;
    case IMAP_ENUM_METAPARTITION_FILES_CACHE:
	filename = FNAME_CACHE;
	break;
    case IMAP_ENUM_METAPARTITION_FILES_EXPUNGE:
	filename = FNAME_EXPUNGE_INDEX;
	break;
    case IMAP_ENUM_METAPARTITION_FILES_SQUAT:
	filename = FNAME_SQUAT_INDEX;
	break;
    }

    /* select the path and buffer, based on the metadata flag */
    if (mailbox->mpath && (config_metapartition_files & metaflag)) {
	fname = &fpath->meta;
	path = mailbox->mpath;
    }
    else {
	fname = &fpath->data;
	path = mailbox->path;
    }

    if (!fname->len) {
	/* first time using the buffer, add the path */
	n = strlcpy(fname->buf, path, sizeof(fname->buf));
	if (n >= sizeof(fname->buf)) return NULL; /* overflow */

	fname->len = strlen(fname->buf);
	fname->tail = fname->buf + fname->len;
    }

    /* append the filename to the path */
    n = strlcpy(fname->tail, filename, sizeof(fname->buf) - fname->len);
    if (n >= (sizeof(fname->buf) - fname->len)) return NULL; /* overflow */

    return fname;
}

/*
 * Names of the headers we cache in the cyrus.cache file.
 *
 * Changes to this list probably require bumping the cache version
 * number (obviously)
 *
 * note that header names longer than MAX_CACHED_HEADER_SIZE
 * won't be cached regardless
 *
 * xxx can we get benefits by requireing this list to be sorted?
 * (see is_cached_header())
 *
 */
const struct mailbox_header_cache mailbox_cache_headers[] = {
    /* things we have always cached */
    { "priority", 0 },
    { "references", 0 },
    { "resent-from", 0 },
    { "newsgroups", 0 },
    { "followup-to", 0 },

    /* x headers that we may want to cache anyway */
    { "x-mailer", 1 },
    { "x-trace", 1 },

    /* outlook express seems to want these */
    { "x-ref", 2  },
    { "x-priority", 2 },
    { "x-msmail-priority", 2 },
    { "x-msoesrec", 2 },

    /* things to never cache */
    { "bcc", BIT32_MAX },
    { "cc", BIT32_MAX },
    { "date", BIT32_MAX },
    { "delivery-date", BIT32_MAX },
    { "envelope-to", BIT32_MAX },
    { "from", BIT32_MAX },
    { "in-reply-to", BIT32_MAX },
    { "mime-version", BIT32_MAX },
    { "reply-to", BIT32_MAX },
    { "received", BIT32_MAX },
    { "return-path", BIT32_MAX },
    { "sender", BIT32_MAX },
    { "subject", BIT32_MAX },
    { "to", BIT32_MAX },

    /* older versions of PINE (before 4.56) need message-id in the cache too
     * though technically it is a waste of space because it is in
     * ENVELOPE.  We should probably uncomment the following at some
     * future point [ken3 notes this may also be useful to have here for
     * threading so we can avoid parsing the envelope] */
    /* { "message-id", BIT32_MAX }, */
};
const int MAILBOX_NUM_CACHE_HEADERS =
  sizeof(mailbox_cache_headers)/sizeof(struct mailbox_header_cache);

/*
 *  Function to test if a header is in the cache
 *
 *  Assume cache entry version 1, unless other data is found
 *  in the table.
 */
static inline int is_cached_header(const char *hdr) 
{
    int i;
    
    /* xxx if we can sort the header list we can do better here */
    for (i=0; i<MAILBOX_NUM_CACHE_HEADERS; i++) {
	if (!strcmp(mailbox_cache_headers[i].name, hdr))
	    return mailbox_cache_headers[i].min_cache_version;
    }

    /* Don't Cache X- headers unless explicitly configured to*/
    if ((hdr[0] == 'x') && (hdr[1] == '-')) return BIT32_MAX;

    /* Everything else we cache in version 1 */
    return 1;
}

/*  External API to is_cached_header that prepares the string
 *
 *   Returns minimum version required for lookup to succeed
 *   or BIT32_MAX if header not cached
 */
int mailbox_cached_header(const char *s) 
{
    char hdr[MAX_CACHED_HEADER_SIZE];
    int i;
 
    /* Generate lower case copy of string */
    /* xxx sometimes the caller has already generated this .. 
     * maybe we can just require callers to do it? */
    for (i=0 ; *s && (i < MAX_CACHED_HEADER_SIZE) ; i++)
	hdr[i] = tolower(*s++);
    
    if (*s) return BIT32_MAX;   /* Input too long for match */
    hdr[i] = '\0';
    
    return is_cached_header(hdr);
}

/* Same as mailbox_cached_header, but for use on a header
 * as it appears in the message (i.e. :-terminated, not NUL-terminated)
 */
int mailbox_cached_header_inline(const char *text)
{
    char buf[MAX_CACHED_HEADER_SIZE];
    int i;
    
    /* Scan for header */
    for (i=0; i < MAX_CACHED_HEADER_SIZE; i++) {
	if (!text[i] || text[i] == '\r' || text[i] == '\n') break;
	
	if (text[i] == ':') {
	    buf[i] = '\0';
	    return is_cached_header(buf);
	} else {
	    buf[i] = tolower(text[i]);
	}
    }
    return BIT32_MAX;
}

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
			   char *uniqueid, size_t outlen)
{
    unsigned long hash = 0;

    while (*name) {
	hash *= 251;
	hash += *name++;
	hash %= PRIME;
    }
    snprintf(uniqueid, outlen, "%08lx%08lx", hash, uidvalidity);
}

/*
 * Calculate relative filename for the message with UID 'uid'
 * in 'mailbox'. 'out' must be at least MAILBOX_FNAME_LEN long.
 */
void mailbox_message_get_fname(struct mailbox *mailbox, unsigned long uid,
			       char *out, size_t size)
{
    char buf[MAILBOX_FNAME_LEN];
	     
    assert(mailbox->format != MAILBOX_FORMAT_NETNEWS);

    snprintf(buf, sizeof(buf), "%lu.", uid);

    assert(strlen(buf) < size);

    strlcpy(out,buf,size);
}

/*
 * Maps in the content for the message with UID 'uid' in 'mailbox'.
 * Returns map in 'basep' and 'lenp'
 */
int mailbox_map_message(struct mailbox *mailbox, unsigned long uid,
			const char **basep, unsigned long *lenp)
{
    int msgfd;
    char buf[4096];
    struct stat sbuf;

    snprintf(buf, sizeof(buf), "%s/%lu.", mailbox->path,uid);

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
int mailbox_stat(const char *mbpath, const char *metapath,
		 struct stat *header, struct stat *index, struct stat *cache) 
{
    char fnamebuf[MAX_MAILBOX_PATH+1];
    const char *path;
    int r = 0, ret = 0;
    
    assert(mbpath && (header || index));
    
    if(header) {
	path = (metapath &&
		(config_metapartition_files &
		 IMAP_ENUM_METAPARTITION_FILES_HEADER)) ?
	    metapath : mbpath;
	strlcpy(fnamebuf, path, sizeof(fnamebuf));
	strlcat(fnamebuf, FNAME_HEADER, sizeof(fnamebuf));
	r = stat(fnamebuf, header);
	if(r) ret |= 0x1;
    }
    
    if(!r && index) {
	path = (metapath &&
		(config_metapartition_files &
		 IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	    metapath : mbpath;
	strlcpy(fnamebuf, path, sizeof(fnamebuf));
	strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));
	r = stat(fnamebuf, index);
	if(r) ret |= 0x2;
    }

    if(!r && cache) {
	path = (metapath &&
		(config_metapartition_files &
		 IMAP_ENUM_METAPARTITION_FILES_CACHE)) ?
	    metapath : mbpath;
	strlcpy(fnamebuf, path, sizeof(fnamebuf));
	strlcat(fnamebuf, FNAME_CACHE, sizeof(fnamebuf));
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
    char *path, *mpath, *acl;
    int r;

    r = mboxlist_detail(name, NULL, &path, &mpath, NULL, &acl, NULL);
    if (r) return r;

    return mailbox_open_header_path(name, path, mpath,
				    acl, auth_state, mailbox, 0);
}

/*
 * Open and read the header of the mailbox with name 'name'
 * path 'path', and ACL 'acl'.
 * The structure pointed to by 'mailbox' is initialized.
 */
int mailbox_open_header_path(const char *name,
			     const char *path,
			     const char *mpath,
			     const char *acl,
			     struct auth_state *auth_state,
			     struct mailbox *mailbox,
			     int suppresslog)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    int r;

    zeromailbox(*mailbox);

    if (mpath &&
	(config_metapartition_files & IMAP_ENUM_METAPARTITION_FILES_HEADER)) {
	strlcpy(fnamebuf, mpath, sizeof(fnamebuf));
    }
    else
	strlcpy(fnamebuf, path, sizeof(fnamebuf));

    strlcat(fnamebuf, FNAME_HEADER, sizeof(fnamebuf));
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
    if (mpath) mailbox->mpath = xstrdup(mpath);

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
			const char *metapath,
			const char *mbacl,
			struct auth_state *auth_state,
			struct mailbox *mb,
			int suppresslog) 
{
    int r;
    
    r = mailbox_open_header_path(mbname, mbpath, metapath, mbacl, auth_state,
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
    struct fnamepath fpath;
    struct fnamebuf *fname;
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

    /* initialize the paths */
    mailbox_meta_get_fname(&fpath, mailbox, 0);

    do {
	fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_INDEX);
	mailbox->index_fd = open(fname->buf, O_RDWR, 0);
	if (mailbox->index_fd != -1) {
	    map_refresh(mailbox->index_fd, 0, &mailbox->index_base,
			&mailbox->index_len, MAP_UNKNOWN_LEN, "index",
			mailbox->name);
	}
	if (mailbox_doing_reconstruct) break;
	if (mailbox->index_fd == -1) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fname->buf);
	    return IMAP_IOERROR;
	}

	fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_CACHE);
	mailbox->cache_fd = open(fname->buf, O_RDWR, 0);
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
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fname->buf);
	    return IMAP_IOERROR;
	}

	/* Check generation number matches */
	if (mailbox->index_len < 4 || mailbox->cache_len < 4) {
	    return IMAP_MAILBOX_BADFORMAT;
	}
	index_gen = ntohl(*(bit32 *)(mailbox->index_base+OFFSET_GENERATION_NO));
	cache_gen = ntohl(*(bit32 *)(mailbox->cache_base+OFFSET_GENERATION_NO));

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

    free(mailbox->name);
    free(mailbox->path);
    if (mailbox->mpath) free(mailbox->mpath);
    free(mailbox->acl);
    free(mailbox->uniqueid);
    if (mailbox->quota.root) free(mailbox->quota.root);

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
    }

    zeromailbox(*mailbox);
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
 	mailbox_make_uniqueid(mailbox->name, mailbox->uidvalidity,
			      buf, sizeof(buf));
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

    r = mboxlist_lookup(mailbox->name, &acl, NULL);
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
    int quota_upgrade_offset = 0;

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

    if(mailbox->minor_version <= 5) {
	/* Upgrade Quota, Add Cache Version Field */
	quota_upgrade_offset = sizeof(bit32);
    }

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
	ntohl(*((bit32 *)(mailbox->index_base+OFFSET_QUOTA_MAILBOX_USED-quota_upgrade_offset)));

    if (mailbox->start_offset < OFFSET_POP3_LAST_LOGIN-quota_upgrade_offset+sizeof(bit32)) {
	mailbox->pop3_last_login = 0;
    }
    else {
	mailbox->pop3_last_login =
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_POP3_LAST_LOGIN-quota_upgrade_offset)));
    }

    if (mailbox->start_offset < OFFSET_UIDVALIDITY-quota_upgrade_offset+sizeof(bit32)) {
	mailbox->uidvalidity = 1;
    }
    else {
	mailbox->uidvalidity =
	    ntohl(*((bit32 *)(mailbox->index_base-quota_upgrade_offset+OFFSET_UIDVALIDITY)));
    }

    if (mailbox->start_offset < OFFSET_FLAGGED-quota_upgrade_offset+sizeof(bit32)) {
	/* calculate them now */
	if (mailbox_calculate_flagcounts(mailbox))
	    return IMAP_IOERROR;
	
	upgrade = 1;
    } else {
	mailbox->deleted = 
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_DELETED-quota_upgrade_offset)));
	mailbox->answered = 
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_ANSWERED-quota_upgrade_offset)));
	mailbox->flagged = 
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_FLAGGED-quota_upgrade_offset)));
	mailbox->dirty = 0;
    }

    if (mailbox->start_offset < OFFSET_POP3_NEW_UIDL-quota_upgrade_offset+sizeof(bit32)) {
	mailbox->pop3_new_uidl = !mailbox->exists;
	upgrade = 1;
    }
    else {
	mailbox->pop3_new_uidl = !mailbox->exists ||
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_POP3_NEW_UIDL-quota_upgrade_offset)));
    }

    if (mailbox->start_offset < OFFSET_LEAKED_CACHE-quota_upgrade_offset+sizeof(bit32)) {
	mailbox->leaked_cache_records = 0;
	upgrade = 1;
    }
    else {
	mailbox->leaked_cache_records =
	    ntohl(*((bit32 *)(mailbox->index_base+OFFSET_LEAKED_CACHE-quota_upgrade_offset)));
    }

    if (mailbox->record_size < INDEX_RECORD_SIZE) {
	upgrade = 1;
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
    record->content_lines = htonl(*((bit32 *)(buf+OFFSET_CONTENT_LINES)));
    record->cache_version = htonl(*((bit32 *)(buf+OFFSET_CACHE_VERSION)));
    return 0;
}

/*
 * Lock the header for 'mailbox'.  Reread header if necessary.
 */
int mailbox_lock_header(struct mailbox *mailbox)
{
    char fnamebuf[MAX_MAILBOX_PATH+1], *path;
    struct stat sbuf;
    const char *lockfailaction;
    int r;

    if (mailbox->header_lock_count++) return 0;

    assert(mailbox->index_lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_HEADER)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_HEADER, sizeof(fnamebuf));

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
int mailbox_lock_index(struct mailbox *mailbox)
{
    char fnamebuf[MAX_MAILBOX_PATH+1], *path;
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->index_lock_count++) return 0;

    assert(mailbox->seen_lock_count == 0);

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));

    /* why is this not a lock_reopen()? -leg
     *
     * this is not a lock_reopen() because we need to do all of the
     * work of mailbox_open_index, not just opening the file -- 
     * presumably we could extend the api of lock_reopen to tell us if
     * it had to reopen the file or not, then this could be a bit smarter --
     * but we'd still have to deal with the fact that mailbox_open_index
     * does its own open() call. -rjs3 */
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
 * Release lock on the header for 'mailbox'
 */
void mailbox_unlock_header(struct mailbox *mailbox)
{
    assert(mailbox->header_lock_count != 0);

    if (--mailbox->header_lock_count == 0) {
	if (lock_unlock(mailbox->header_fd))
	    syslog(LOG_ERR, "IOERROR: unlocking header of %s: %m", 
		mailbox->name);
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
	if (lock_unlock(mailbox->index_fd))
	    syslog(LOG_ERR, "IOERROR: unlocking index of %s: %m", 
		mailbox->name);
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
	if (lock_unlock(mailbox->cache_fd))
	    syslog(LOG_ERR, "IOERROR: unlocking POP lock of %s: %m", 
		mailbox->name);
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
    char fnamebuf[MAX_MAILBOX_PATH+1], *path;
    char newfnamebuf[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    struct iovec iov[10];
    int niov;

    assert(mailbox->header_lock_count != 0);

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_HEADER)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_HEADER, sizeof(fnamebuf));
    strlcpy(newfnamebuf, fnamebuf, sizeof(newfnamebuf));
    strlcat(newfnamebuf, ".NEW", sizeof(newfnamebuf));

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
    unsigned long header_size = sizeof(buf);
    int n;
    
    assert(mailbox->index_lock_count != 0);

    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = htonl(mailbox->generation_no);
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(mailbox->exists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox->last_uid);
    *((bit32 *)(buf+OFFSET_QUOTA_RESERVED_FIELD)) = htonl(0); /* RESERVED */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
	htonl(mailbox->quota_mailbox_used);
    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(mailbox->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(mailbox->deleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(mailbox->answered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(mailbox->flagged);
    *((bit32 *)(buf+OFFSET_POP3_NEW_UIDL)) = htonl(mailbox->pop3_new_uidl);
    *((bit32 *)(buf+OFFSET_LEAKED_CACHE)) =
	htonl(mailbox->leaked_cache_records);
    *((bit32 *)(buf+OFFSET_SPARE1)) = htonl(0); /* RESERVED */
    *((bit32 *)(buf+OFFSET_SPARE2)) = htonl(0); /* RESERVED */

    if (mailbox->start_offset < header_size)
	header_size = mailbox->start_offset;

    lseek(mailbox->index_fd, 0, SEEK_SET);
    n = retry_write(mailbox->index_fd, buf, header_size);
    if ((unsigned long)n != header_size || fsync(mailbox->index_fd)) {
	syslog(LOG_ERR, "IOERROR: writing index header for %s: %m",
	       mailbox->name);
	return IMAP_IOERROR;
    }

    if (updatenotifier) updatenotifier(mailbox);

    return 0;
}

/*
 * Put an index record into a buffer suitable for writing to a file.
 */
void mailbox_index_record_to_buf(struct index_record *record, char *buf)
{
    int n;

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
    *((bit32 *)(buf+OFFSET_CONTENT_LINES)) = htonl(record->content_lines);
    *((bit32 *)(buf+OFFSET_CACHE_VERSION)) = htonl(record->cache_version);
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

    mailbox_index_record_to_buf(record, buf);

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
    int len, n;
    char *buf, *p;
    long last_offset;
    time_t now = time(NULL);

    assert(mailbox->index_lock_count != 0);

    if (mailbox->record_size < INDEX_RECORD_SIZE) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    len = num * mailbox->record_size;
    buf = xmalloc(len);
    memset(buf, 0, len);

    for (i = 0; i < num; i++) {
	/* Sanity check the timestamps so index_fetchreply() won't abort() */
        if (record[i].internaldate <= 0) record[i].internaldate = now;
        if (record[i].sentdate <= 0) record[i].sentdate = now;
        if (record[i].last_updated <= 0) record[i].internaldate = now;

	p = buf + i*mailbox->record_size;

	mailbox_index_record_to_buf(&record[i], p);
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
 * Lock the index file for 'mailbox'.
 * DON'T Reread index file header if necessary.
 */
static int mailbox_lock_index_for_upgrade(struct mailbox *mailbox)
{
    char fnamebuf[MAX_MAILBOX_PATH+1], *path;
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->index_lock_count++) return 0;

    assert(mailbox->seen_lock_count == 0);

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));

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
    bit32 oldstart_offset, oldrecord_size, recsize_diff;
    char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
	     INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
    char fnamebuf[MAX_MAILBOX_PATH+1], fnamebufnew[MAX_MAILBOX_PATH+1], *path;
    FILE *newindex;
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

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));

    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    newindex = fopen(fnamebufnew, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebufnew);
	goto fail;
    }

    /* change version number */
    mailbox->minor_version = MAILBOX_MINOR_VERSION;

    /* save old start_offset; change start_offset */
    oldstart_offset = mailbox->start_offset;
    mailbox->start_offset = INDEX_HEADER_SIZE;

    /* save old record_size; change record_size */
    oldrecord_size = mailbox->record_size;
    mailbox->record_size = INDEX_RECORD_SIZE;
    recsize_diff = INDEX_RECORD_SIZE - oldrecord_size;

    /* Write the new index header */ 
    memset(buf, 0, INDEX_HEADER_SIZE);
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = htonl(mailbox->generation_no);
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(mailbox->exists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox->last_uid);
    /* OFFSET_QUOTA_RESERVED_FIELD left as zero */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
	htonl(mailbox->quota_mailbox_used);
    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(mailbox->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(mailbox->deleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(mailbox->answered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(mailbox->flagged);
    *((bit32 *)(buf+OFFSET_POP3_NEW_UIDL)) = htonl(mailbox->pop3_new_uidl);
    *((bit32 *)(buf+OFFSET_LEAKED_CACHE)) =
	htonl(mailbox->leaked_cache_records);

    fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);

    /* Write the rest of new index */
    memset(buf, 0, INDEX_RECORD_SIZE);
    for (msgno = 1; msgno <= mailbox->exists; msgno++) {
	/* Write the existing (old) part of the index record */
	bufp = (char *) (mailbox->index_base + oldstart_offset +
			 (msgno - 1)*oldrecord_size);
	
	fwrite(bufp, oldrecord_size, 1, newindex);

	if (recsize_diff) {
	    /* We need to upgrade the index record to include new fields. */

	    /* Currently, this means adding a content_lines placeholder.
	     * We use BIT32_MAX rather than 0, since a message body can
	     * be empty.  We'll calculate the actual value on demand.
	     */
	    if (oldrecord_size < OFFSET_CONTENT_LINES+sizeof(bit32)) {
		*((bit32 *)(buf+OFFSET_CONTENT_LINES)) = htonl(BIT32_MAX);
	    }

	    /* Set the initial cache version to 0, that is, with the old
	     * format of the cached headers */
	    if (oldrecord_size < OFFSET_CACHE_VERSION+sizeof(bit32)) {
		*((bit32 *)(buf+OFFSET_CACHE_VERSION)) = htonl(0);
	    }

	    fwrite(buf+oldrecord_size, recsize_diff, 1, newindex);
	}
    }

    /* Ensure everything made it to disk */
    fflush(newindex);
    if (ferror(newindex) ||
	fsync(fileno(newindex))) {
	syslog(LOG_ERR, "IOERROR: writing index for %s: %m",
	       mailbox->name);
	goto fail;
    }

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
 * Expunge decision proc used by mailbox_expunge() (in cleanup mode) 
 * to avoid expunging any messages from cyrus.index
 */
static int expungenone(struct mailbox *mailbox __attribute__((unused)),
		       void *rock __attribute__((unused)),
		       char *index __attribute__((unused)),
		       int expunge_flags __attribute__((unused)))
{
    return 0;
}

/*
 * Expunge decision proc used by mailbox_expunge() (in cleanup mode) 
 * to expunge all messages in cyrus.expunge
 * Also used by mailbox_rename() to expunge all messages in INBOX
 */
static int expungeall(struct mailbox *mailbox __attribute__((unused)),
		      void *rock __attribute__((unused)),
		      char *indexbuf __attribute__((unused)),
		      int expunge_flags __attribute__((unused)))
{
    return 1;
}

static int process_records(struct mailbox *mailbox, FILE *newindex,
			   const char *index_base, unsigned long exists,
			   unsigned long *deleted, unsigned *numdeleted,
			   unsigned *quotadeleted, unsigned *numansweredflag,
			   unsigned *numdeletedflag, unsigned *numflaggedflag,
			   FILE *newcache, size_t *new_cache_total_size,
			   int expunge_fd, long last_offset,
			   mailbox_decideproc_t *decideproc, void *deciderock,
			   int expunge_flags)
{
    char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
	     INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
    unsigned msgno;
    unsigned newexpunged;
    unsigned newexists;
    unsigned newdeleted;
    unsigned newanswered;
    unsigned newflagged; 
    time_t now = time(NULL);
    int n;

    /* Copy over records for nondeleted messages */
    for (msgno = 1; msgno <= exists; msgno++) {
	/* Copy index record for this message */
	memcpy(buf,
	       index_base + mailbox->start_offset +
	       (msgno - 1) * mailbox->record_size, mailbox->record_size);

	/* Sanity check */
	if (*((bit32 *)(buf+OFFSET_UID)) == 0) {
	    syslog(LOG_ERR, "IOERROR: %s zero index/expunge record %u/%lu",
		   mailbox->name, msgno, exists);
	    return IMAP_IOERROR;
	}

	/* Should we delete the message from the index file? */
	if (decideproc ? decideproc(mailbox, deciderock, buf, expunge_flags) :
	    (ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS))) & FLAG_DELETED)) {

	    bit32 sysflags = ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));

	    /* Remember UID and size */
	    deleted[(*numdeleted)++] = ntohl(*((bit32 *)(buf+OFFSET_UID)));
	    *quotadeleted += ntohl(*((bit32 *)(buf+OFFSET_SIZE)));

	    /* Update system flag counts accordingly */
	    if (sysflags & FLAG_ANSWERED) (*numansweredflag)++;
	    if (sysflags & FLAG_DELETED) (*numdeletedflag)++;
	    if (sysflags & FLAG_FLAGGED) (*numflaggedflag)++;

	    if (expunge_fd != -1) {
		/* Copy the index record to cyrus.expunge */
		/* XXX  For now, we just append to the end of the file.
		 * For two-phase, we should sort by UID.
		 */
		*((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(now);
		n = retry_write(expunge_fd, buf, mailbox->record_size);
		if (n != mailbox->record_size) {
		    syslog(LOG_ERR,
			   "IOERROR: writing expunge index record %u for %s: %m",
			   msgno, mailbox->name);
		    ftruncate(expunge_fd, last_offset);
		    return IMAP_IOERROR;
		}
	    }
	} else if (newcache) {
	    /* Keep this message and update the index/cache record */
	    size_t cache_record_size;
	    unsigned long cache_offset;
	    unsigned int cache_ent;
	    const char *cacheitem, *cacheitembegin;
	    
	    cache_offset = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));

	    /* Fix up cache file offset */
	    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) =
		htonl(*new_cache_total_size);
	    if (newindex) fwrite(buf, 1, mailbox->record_size, newindex);

	    /* Compute size of this record */
	    cacheitembegin = cacheitem = mailbox->cache_base + cache_offset;
	    for (cache_ent = 0; cache_ent < NUM_CACHE_FIELDS; cache_ent++) {
		cacheitem = CACHE_ITEM_NEXT(cacheitem);
	    }
	    cache_record_size = (cacheitem - cacheitembegin);
	    *new_cache_total_size += cache_record_size;

	    /* fwrite will automatically call write() in a sane way */
	    fwrite(cacheitembegin, 1, cache_record_size, newcache);

	} else if (newindex) {
	    /* Keep this message, but just update the index record */
	    fwrite(buf, 1, mailbox->record_size, newindex);
	}
    }

    if (!newindex) return 0;

    /* Fix up information in index header */
    rewind(newindex);
    n = fread(buf, 1, mailbox->start_offset, newindex);
    if ((unsigned long) n != mailbox->start_offset) {
	syslog(LOG_ERR,
	       "IOERROR: reading index header for %s: got %d of %ld",
	       mailbox->name, n, mailbox->start_offset);
	return IMAP_IOERROR;
    }

    /* Fix up exists */
    newexists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS))) - *numdeleted;
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);

    /* Fix up expunged count */
    if (newcache) {
	*((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(0);
    } else {
	newexpunged = ntohl(*((bit32 *)(buf+OFFSET_LEAKED_CACHE))) + *numdeleted;
	*((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(newexpunged);
    }
	    
    /* Fix up other counts */
    newanswered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED))) - *numansweredflag;
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(newanswered);
    newdeleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED))) - *numdeletedflag;
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(newdeleted);
    newflagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED))) - *numflaggedflag;
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(newflagged);

    /* Fix up quota_mailbox_used */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
	htonl(ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED))) - *quotadeleted);

    /* Fix up start offset if necessary */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
	*((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }
	
    /* Write out new index header */
    rewind(newindex);
    fwrite(buf, 1, mailbox->start_offset, newindex);

    return 0;
}

/*
 * Perform an expunge operation on 'mailbox'.  If nonzero, the
 * function pointed to by 'decideproc' is called (with 'deciderock') to
 * determine which messages to expunge.  If 'decideproc' is a null pointer,
 * then messages with the \Deleted flag are expunged.  If 'flags' includes
 * EXPUNGE_FORCE, then messages will be expunged immediately, regardless of
 * expunge_mode.  If 'flags' includes EXPUNGE_CLEANUP, then any previously
 * delayed expunges will be completed (remove leaked cache entries
 * and delete messages files).
 *
 * The following files are updated for the various modes:
 * - immediate mode: cyrus.index, cyrus.cache, quota.db, messages
 * - delayed mode: cyrus.index, cyrus.expunge, quota.db
 * - cleanup mode: cyrus.index, cyrus.cache, cyrus.expunge, messages
 */
int mailbox_expunge(struct mailbox *mailbox,
		    mailbox_decideproc_t *decideproc, void *deciderock,
		    int flags)
{
    enum enum_value config_expunge_mode = config_getenum(IMAPOPT_EXPUNGE_MODE);
    int r, n;
    struct fnamepath fpath;
    struct fnamebuf *fname;
    char fnamebufnew[MAX_MAILBOX_PATH+1];
    FILE *newindex = NULL, *newcache = NULL, *newexpungeindex = NULL;
    unsigned long *deleted = 0;
    unsigned numdeleted = 0, quotadeleted = 0;
    unsigned numansweredflag = 0;
    unsigned numdeletedflag = 0;
    unsigned numflaggedflag = 0;
    unsigned newexists;
    unsigned newdeleted;
    unsigned newanswered;
    unsigned newflagged; 
    
    char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
	     INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
    unsigned msgno;
    struct stat sbuf;
    struct txn *tid = NULL;

    /* Offset into the new cache file for use when updating the index record */
    size_t new_cache_total_size = sizeof(bit32);

    /* delayed expunge related stuff */
    int expunge_fd = -1;
    long last_offset = 0;
    const char *expunge_index_base = NULL;
    unsigned long expunge_index_len = 0;	/* mapped size */
    time_t now = time(NULL);
    unsigned long expunge_exists = 0;

    /* EXPUNGE_FORCE means immediate mode */
    if (flags == EXPUNGE_FORCE)
	config_expunge_mode = IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE;

    /* initialize the paths */
    mailbox_meta_get_fname(&fpath, mailbox, 0);

    /* If we're in delayed or cleanup mode, open the expunge index */
    if ((config_expunge_mode != IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE) ||
	(flags & EXPUNGE_CLEANUP)) {
	fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_EXPUNGE);

	expunge_fd = open(fname->buf, O_RDWR, 0666);
	if (expunge_fd == -1 && errno == ENOENT &&
	    !(flags & EXPUNGE_CLEANUP)) {
	    /* we're not in cleanup mode, try creating one */
	    expunge_fd = open(fname->buf, O_RDWR|O_CREAT, 0666);
	}
	if (expunge_fd == -1) {
	    if (errno == ENOENT && (flags & EXPUNGE_CLEANUP)) {
		/* we're doing cleanup and no cyrus.expunge */
		if (flags == EXPUNGE_CLEANUP) {
		    /* we're ONLY doing cleanup, so we're done */
		    return 0;
		}
	    } else {
		syslog(LOG_ERR, "IOERROR: opening %s: %m", fname->buf);
		return IMAP_IOERROR;
	    }
	}
    }

    /* Lock files and open new index file */
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

    fname = mailbox_meta_get_fname(&fpath, mailbox,
				   IMAP_ENUM_METAPARTITION_FILES_INDEX);
    strlcat(fname->buf, ".NEW", sizeof(fname->buf));

    newindex = fopen(fname->buf, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fname->buf);
	mailbox_unlock_pop(mailbox);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    /* If we're in immediate or cleanup mode, open cache files */
    if ((config_expunge_mode == IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE) ||
	(flags & EXPUNGE_CLEANUP)) {
        fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_CACHE);

	if (fstat(mailbox->cache_fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstating %s: %m", fname->buf);
	    fatal("can't fstat cache file", EC_OSFILE);
	}
	mailbox->cache_size = sbuf.st_size;
	map_refresh(mailbox->cache_fd, 0, &mailbox->cache_base,
		    &mailbox->cache_len, mailbox->cache_size,
		    "cache", mailbox->name);

	strlcat(fname->buf, ".NEW", sizeof(fname->buf));
	
	newcache = fopen(fname->buf, "w+");
	if (!newcache) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", fname->buf);
	    fclose(newindex);
	    mailbox_unlock_pop(mailbox);
	    mailbox_unlock_index(mailbox);
	    mailbox_unlock_header(mailbox);
	    return IMAP_IOERROR;
	}
    }

    /* Copy over index header */
    memcpy(buf, mailbox->index_base, mailbox->start_offset);

    /* Update Generation Number */
    if (newcache) {
	*((bit32 *)buf+OFFSET_GENERATION_NO) = htonl(mailbox->generation_no+1);

	/* Write generation number to cache file */
	fwrite(buf, 1, sizeof(bit32), newcache);
    }

    /* Write out new index header */
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

    /* If we're using cyrus.expunge, lock it */
    if (expunge_fd != -1) {
	const char *lockfailaction;

	fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_EXPUNGE);

	if ((r = lock_reopen(expunge_fd, fname->buf, &sbuf, &lockfailaction))) {
	    syslog(LOG_ERR, "IOERROR: %s expunge index for %s: %m",
		   lockfailaction, mailbox->name);
	    close(expunge_fd);
	}
	else {
	    /* Read the expunge index */
	    if (!sbuf.st_size) {
		/* Empty cyrus.expunge, create a header */
		*((bit32 *)(buf+OFFSET_EXISTS)) = htonl(0);
		*((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(0);
		*((bit32 *)(buf+OFFSET_DELETED)) = htonl(0);
		*((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(0);
		*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(0);
		*((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(0);

		n = retry_write(expunge_fd, buf, mailbox->start_offset);
    
		/* Ensure everything made it to disk */
		if (n != mailbox->start_offset || fsync(expunge_fd)) {
		    syslog(LOG_ERR, "IOERROR: writing expunge index for %s: %m",
			   mailbox->name);
		    goto fail;
		}

		sbuf.st_size = mailbox->start_offset;
	    }

	    map_refresh(expunge_fd, 1, &expunge_index_base,
			&expunge_index_len, sbuf.st_size, "expunge",
			mailbox->name);

	    expunge_exists = ntohl(*((bit32 *)(expunge_index_base+OFFSET_EXISTS)));

	    /* Skip to end of file, so we can append new records */
	    last_offset = mailbox->start_offset +
		expunge_exists * mailbox->record_size;
	    lseek(expunge_fd, last_offset, SEEK_SET);

	    if ((flags & EXPUNGE_CLEANUP) && expunge_exists && decideproc) {
		/* If we're doing a cleanup and there's a chance that we'll
		 * leave expunged messages behind, open a new expunge file.
		 */
		strlcat(fname->buf, ".NEW", sizeof(fname->buf));

		newexpungeindex = fopen(fname->buf, "w+");
		if (!newexpungeindex) {
		    syslog(LOG_ERR, "IOERROR: creating %s: %m", fname->buf);
		    map_free(&expunge_index_base, &expunge_index_len);
		    if (lock_unlock(expunge_fd))
			syslog(LOG_ERR,
			       "IOERROR: unlocking expunge index of %s: %m", 
			       mailbox->name);
		    r = IMAP_IOERROR;
		}
	    }
	}

	if (r) {
	    mailbox_unlock_pop(mailbox);
	    mailbox_unlock_index(mailbox);
	    mailbox_unlock_header(mailbox);
	    return IMAP_IOERROR;
	}
    }
	
    /* Allocate array for deleted msgnos */
    if (mailbox->exists || expunge_exists) {
        /* XXX kludge: not all mallocs return a valid pointer to 0 bytes;
           some have the good sense to return 0 */
        deleted = (unsigned long *)
            xmalloc((mailbox->exists + expunge_exists) * sizeof(unsigned long));
    }

    /* If we're doing a cleanup w/o a decideproc, use expungenone()
       so we don't delete any records from cyrus.index. */
    if ((flags & EXPUNGE_CLEANUP) && !decideproc) decideproc = expungenone;

    /* Copy over records for nondeleted messages */
    r = process_records(mailbox, newindex, mailbox->index_base,
			mailbox->exists, deleted, &numdeleted,
			&quotadeleted, &numansweredflag, &numdeletedflag,
			&numflaggedflag, newcache, &new_cache_total_size,
			expunge_fd, last_offset, decideproc, deciderock, 0);
    if (r) goto fail;

    /* Record quota release */
    r = quota_read(&mailbox->quota, &tid, 1);
    if (!r) {
	if (mailbox->quota.used >= quotadeleted) {
	    mailbox->quota.used -= quotadeleted;
	}
	else {
	    mailbox->quota.used = 0;
	}
	r = quota_write(&mailbox->quota, &tid);
	if (!r) quota_commit(&tid);
	else {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record free of %u bytes in quota %s",
		   quotadeleted, mailbox->quota.root);
	}
    }
    else if (r != IMAP_QUOTAROOT_NONEXISTENT) goto fail;

    if (flags & EXPUNGE_CLEANUP) {
	unsigned new_deleted = numdeleted;

	if (newexpungeindex) {
	    /* Copy over expunge index header */
	    memcpy(buf, expunge_index_base, mailbox->start_offset);

	    /* Update Generation Number */
	    *((bit32 *)buf+OFFSET_GENERATION_NO) = htonl(mailbox->generation_no+1);

	    /* Write out new expunge index header */
	    fwrite(buf, 1, mailbox->start_offset, newexpungeindex);
	}

	/* If we're doing a cleanup w/o a decideproc, use expungeall()
	   so we delete all records from cyrus.expunge. */
	if (decideproc == expungenone) decideproc = expungeall;

	/* Copy over records for nonpurged messages */
	r = process_records(mailbox, newexpungeindex, expunge_index_base,
			    expunge_exists, deleted, &numdeleted,
			    &quotadeleted, &numansweredflag, &numdeletedflag,
			    &numflaggedflag, newcache, &new_cache_total_size,
			    -1, 0, decideproc, deciderock, EXPUNGE_CLEANUP);
	if (r) goto fail;
	expunge_exists -= (numdeleted - new_deleted);
    }
    else if (config_expunge_mode != IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE) {
	/* Fix up information in expunge index header */
	lseek(expunge_fd, 0, SEEK_SET);
	n = read(expunge_fd, buf, mailbox->start_offset);
	if ((unsigned long)n != mailbox->start_offset) {
	    syslog(LOG_ERR,
		   "IOERROR: reading expunge index header for %s: got %d of %ld",
		   mailbox->name, n, mailbox->start_offset);
	    ftruncate(expunge_fd, last_offset);
	    goto fail;
	}

	/* Update appenddate */
	*((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(now);

	/* Fix up exists */
	newexists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS)))+numdeleted;
	*((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);

	/* Fix up other counts */
	newanswered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED)))+numansweredflag;
	*((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(newanswered);
	newdeleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED)))+numdeletedflag;
	*((bit32 *)(buf+OFFSET_DELETED)) = htonl(newdeleted);
	newflagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED)))+numflaggedflag;
	*((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(newflagged);

	/* Fix up quota_mailbox_used */
	*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
	    htonl(ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)))+quotadeleted);
	/* Fix up start offset if necessary */
	if (mailbox->start_offset < INDEX_HEADER_SIZE) {
	    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
	}

	/* Write out new cyrus.expunge header */
	lseek(expunge_fd, 0, SEEK_SET);
	n = retry_write(expunge_fd, buf, mailbox->start_offset);

	/* Ensure everything made it to disk */
	if (n != mailbox->start_offset || fsync(expunge_fd)) {
	    syslog(LOG_ERR, "IOERROR: writing index/cache for %s: %m",
		   mailbox->name);
	    ftruncate(expunge_fd, last_offset);
	    goto fail;
	}
    }

    /* Ensure everything made it to disk */
    fflush(newindex);
    if (newcache) fflush(newcache);
    if (newexpungeindex) fflush(newexpungeindex);
    if (ferror(newindex) || fsync(fileno(newindex)) ||
	(newcache && (ferror(newcache) || fsync(fileno(newcache)))) ||
	(newexpungeindex &&
	 (ferror(newexpungeindex) || fsync(fileno(newexpungeindex))))) {
	syslog(LOG_ERR, "IOERROR: writing index/cache/expunge for %s: %m",
	       mailbox->name);
	goto fail;
    }

    /* Rename/close our files */
    fname = mailbox_meta_get_fname(&fpath, mailbox,
				   IMAP_ENUM_METAPARTITION_FILES_INDEX);

    strlcpy(fnamebufnew, fname->buf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    if (rename(fnamebufnew, fname->buf)) {
	syslog(LOG_ERR, "IOERROR: renaming index file for %s: %m",
	       mailbox->name);
	goto fail;
    }

    if (newcache) {
        fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_CACHE);

	strlcpy(fnamebufnew, fname->buf, sizeof(fnamebufnew));
	strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));
	
	if (rename(fnamebufnew, fname->buf)) {
	    syslog(LOG_CRIT,
		   "CRITICAL IOERROR: renaming cache file for %s, need to reconstruct: %m",
		   mailbox->name);
	    /* Fall through and delete message files anyway */
	}
    }

    if (flags & EXPUNGE_CLEANUP) {
        fname = mailbox_meta_get_fname(&fpath, mailbox,
				       IMAP_ENUM_METAPARTITION_FILES_EXPUNGE);

	if (newexpungeindex) {
	    strlcpy(fnamebufnew, fname->buf, sizeof(fnamebufnew));
	    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));
	
	    if (rename(fnamebufnew, fname->buf)) {
		syslog(LOG_CRIT,
		       "CRITICAL IOERROR: renaming cache file for %s, need to reconstruct: %m",
		       mailbox->name);
		/* Fall through and delete message files anyway */
	    }

	    fclose(newexpungeindex);
	}

	if (!expunge_exists) {
	    /* We deleted all cyrus.expunge records, so delete the file */
	    unlink(fname->buf);
	}
    }
    else if (numdeleted) {
	if (updatenotifier) updatenotifier(mailbox);
    }

    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    if (expunge_fd != -1) {
	if (lock_unlock(expunge_fd))
	    syslog(LOG_ERR, "IOERROR: unlocking expunge index of %s: %m", 
		   mailbox->name);
	close(expunge_fd);
    }
    if (expunge_index_base) map_free(&expunge_index_base, &expunge_index_len);
    fclose(newindex);

    if (newcache) {
	fclose(newcache);

	/* Delete message files */
	fname = &fpath.data;
	*(fname->tail)++ = '/';
	fname->len++;
	for (msgno = 0; msgno < numdeleted; msgno++) {
	    mailbox_message_get_fname(mailbox, deleted[msgno],
				      fname->tail,
				      sizeof(fname->buf) - fname->len);
	    unlink(fname->buf);
	}
    }

    if (deleted) free(deleted);

    return 0;

 fail:
    if (deleted) free(deleted);
    if (newindex) fclose(newindex);
    if (newcache) fclose(newcache);
    if (expunge_fd != -1) {
	if (lock_unlock(expunge_fd))
	    syslog(LOG_ERR, "IOERROR: unlocking expunge index of %s: %m", 
		   mailbox->name);
	close(expunge_fd);
    }
    if (expunge_index_base) map_free(&expunge_index_base, &expunge_index_len);
    if (newexpungeindex) fclose(newexpungeindex);
    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    return IMAP_IOERROR;
}

int mailbox_create(const char *name,
		   char *partition,
		   const char *acl,
		   const char *uniqueid,
		   int format,
		   struct mailbox *mailboxp)
{
    int r;
    char quota_root[MAX_MAILBOX_PATH+1];
    int hasquota;
    char *path, *mpath;
    struct fnamepath fpath;
    struct fnamebuf *fname;
    struct mailbox mailbox;
    int save_errno;
    int n;
    const char *lockfailaction;
    struct stat sbuf;

    r = mboxlist_getpath(partition, name, &path, &mpath);
    if (r) return r;

    if (cyrus_mkdir(path, 0755) == -1) return IMAP_IOERROR;
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
	save_errno = errno;
	if (stat(path, &sbuf) == -1) {
	    errno = save_errno;
	    syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
	    return IMAP_IOERROR;
	}
    }

    if (mpath && config_metapartition_files) {
	if (cyrus_mkdir(mpath, 0755) == -1) return IMAP_IOERROR;
	if (mkdir(mpath, 0755) == -1 && errno != EEXIST) {
	    save_errno = errno;
	    if (stat(mpath, &sbuf) == -1) {
		errno = save_errno;
		syslog(LOG_ERR, "IOERROR: creating directory %s: %m", mpath);
		return IMAP_IOERROR;
	    }
	}
    }

    zeromailbox(mailbox);

    mailbox.name = xstrdup(name);
    mailbox.path = xstrdup(path);
    if (mpath) mailbox.mpath = xstrdup(mpath);
    mailbox.acl = xstrdup(acl);

    hasquota = quota_findroot(quota_root, sizeof(quota_root), name);

    /* Initialize the paths */
    mailbox_meta_get_fname(&fpath, &mailbox, 0);
    
    fname = mailbox_meta_get_fname(&fpath, &mailbox,
				   IMAP_ENUM_METAPARTITION_FILES_HEADER);
    /* Bounds Check */
    if(!fname) {
	syslog(LOG_ERR, "IOERROR: Mailbox name too long (%s + %s)",
	       fname->buf, FNAME_HEADER);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    mailbox.header_fd = open(fname->buf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox.header_fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fname->buf);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    /* Note that we are locking the mailbox here.  Technically, this function
     * can be called with a lock on the mailbox list.  This would otherwise
     * violate the locking semantics, but it is okay since the mailbox list
     * changes have not been committed, and the mailbox we create here *can't*
     * be opened by anyone else */

    r = lock_reopen(mailbox.header_fd, fname->buf, NULL, &lockfailaction);
    if(r) {
	syslog(LOG_ERR, "IOERROR: %s header for new mailbox %s: %m",
	       lockfailaction, mailbox.name);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    mailbox.header_lock_count++;

    fname = mailbox_meta_get_fname(&fpath, &mailbox,
				   IMAP_ENUM_METAPARTITION_FILES_INDEX);
    /* Bounds Check */
    if(!fname) {
	syslog(LOG_ERR, "IOERROR: Mailbox name too long (%s + %s)",
	       fname->buf, FNAME_INDEX);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    mailbox.index_fd = open(fname->buf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox.index_fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fname->buf);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    r = lock_reopen(mailbox.index_fd, fname->buf, NULL, &lockfailaction);
    if(r) {
	syslog(LOG_ERR, "IOERROR: %s index for new mailbox %s: %m",
	       lockfailaction, mailbox.name);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    mailbox.index_lock_count++;

    fname = mailbox_meta_get_fname(&fpath, &mailbox,
				   IMAP_ENUM_METAPARTITION_FILES_CACHE);
    /* Bounds Check */
    if(!fname) {
	syslog(LOG_ERR, "IOERROR: Mailbox name too long (%s + %s)",
	       fname->buf, FNAME_CACHE);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    mailbox.cache_fd = open(fname->buf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox.cache_fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fname->buf);
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
	size_t unique_size = sizeof(char) * 32;
	mailbox.uniqueid = xmalloc(unique_size);
	mailbox_make_uniqueid(mailbox.name, mailbox.uidvalidity, 
			      mailbox.uniqueid, unique_size);
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
    char buf[MAX_MAILBOX_PATH+1], *path;
    char *tail;
    struct txn *tid = NULL;
    
    /* Ensure that we are locked */
    if(!mailbox->header_lock_count) return IMAP_INTERNAL;

    rquota = quota_read(&mailbox->quota, &tid, 1);

    seen_delete_mailbox(mailbox);

    if (delete_quota_root && !rquota) {
	quota_delete(&mailbox->quota, &tid);
	free(mailbox->quota.root);
	mailbox->quota.root = NULL;
    } else if (!rquota) {
	/* Free any quota being used by this mailbox */
	if (mailbox->quota.used >= mailbox->quota_mailbox_used) {
	    mailbox->quota.used -= mailbox->quota_mailbox_used;
	}
	else {
	    mailbox->quota.used = 0;
	}
	r = quota_write(&mailbox->quota, &tid);
	if (r) {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record free of %lu bytes in quota %s",
		   mailbox->quota_mailbox_used, mailbox->quota.root);
	}
	else
	    quota_commit(&tid);
    }

    /* remove data (message file) directory */
    path = mailbox->path;

    do {
	/* remove all files in directory */
	strlcpy(buf, path, sizeof(buf));

	if(strlen(buf) >= sizeof(buf) - 2) {
	    syslog(LOG_ERR, "IOERROR: Path too long (%s)", buf);
	    fatal("path too long", EC_OSFILE);
	}

	tail = buf + strlen(buf);
	*tail++ = '/';
	*tail = '\0';
	dirp = opendir(path);
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

		if(strlen(buf) + strlen(f->d_name) >= sizeof(buf)) {
		    syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
			   buf, f->d_name);
		    fatal("Path too long", EC_OSFILE);
		}
		strcpy(tail, f->d_name);
		unlink(buf);
		*tail = '\0';
	    }
	    closedir(dirp);
	}

	/* Remove empty directories, going up path */
	tail--;
	do {
	    *tail = '\0';
	} while (rmdir(buf) == 0 && (tail = strrchr(buf, '/')));

	/* remove metadata directory (if exists) */
    } while (mailbox->mpath && (path != mailbox->mpath) &&
	     (path = mailbox->mpath));

    mailbox_close(mailbox);
    return 0;
}

/* if 'isinbox' is set, we perform the funky RENAME INBOX INBOX.old
   semantics, regardless of whether or not the name of the mailbox is
   'user.foo'.*/
/* requires a LOCKED oldmailbox pointer */
int mailbox_rename_copy(struct mailbox *oldmailbox, 
			const char *newname,
			char *newpartition,
			bit32 *olduidvalidityp, bit32 *newuidvalidityp,
			struct mailbox *newmailbox)
{
    int r;
    unsigned int flag, msgno;
    struct index_record record;
    struct fnamepath oldfpath, newfpath;
    struct fnamebuf *oldfname, *newfname;
    struct txn *tid = NULL;

    assert(oldmailbox->header_lock_count > 0
	   && oldmailbox->index_lock_count > 0);

    /* Create new mailbox */
    r = mailbox_create(newname, newpartition,
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
	r = quota_read(&(newmailbox->quota), &tid, 1);
	if (!oldmailbox->quota.root ||
	    strcmp(oldmailbox->quota.root, newmailbox->quota.root) != 0) {
	    if (!r && newmailbox->quota.limit >= 0 &&
		newmailbox->quota.used + oldmailbox->quota_mailbox_used >
		((unsigned) newmailbox->quota.limit * QUOTA_UNITS)) {
		r = IMAP_QUOTA_EXCEEDED;
	    }
	}
	if (r && r != IMAP_QUOTAROOT_NONEXISTENT) {
	    mailbox_close(newmailbox);
	    return r;
	}
    }

    /* Initialize the paths */
    mailbox_meta_get_fname(&oldfpath, oldmailbox, 0);
    mailbox_meta_get_fname(&newfpath, newmailbox, 0);

    /* Copy over index/cache files */
    oldfname = mailbox_meta_get_fname(&oldfpath, oldmailbox,
				      IMAP_ENUM_METAPARTITION_FILES_INDEX);
    newfname = mailbox_meta_get_fname(&newfpath, newmailbox,
				      IMAP_ENUM_METAPARTITION_FILES_INDEX);

    /* Check to see if we're going to be over-long */
    if (!oldfname) {
	syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
	       oldfname->buf, FNAME_INDEX);
	fatal("Path Too Long", EC_OSFILE);
    }
    if (!newfname) {
	syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
	       newfname->buf, FNAME_INDEX);
	fatal("Path Too Long", EC_OSFILE);
    }

    unlink(newfname->buf);		/* Make link() possible */

    r = mailbox_copyfile(oldfname->buf, newfname->buf, 0);

    oldfname = mailbox_meta_get_fname(&oldfpath, oldmailbox,
				      IMAP_ENUM_METAPARTITION_FILES_CACHE);
    newfname = mailbox_meta_get_fname(&newfpath, newmailbox,
				      IMAP_ENUM_METAPARTITION_FILES_CACHE);

    /* Check to see if we're going to be over-long */
    if (!oldfname) {
	syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
	       oldfname->buf, FNAME_CACHE);
	fatal("Path Too Long", EC_OSFILE);
    }
    if (!newfname) {
	syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
	       newfname->buf, FNAME_CACHE);
	fatal("Path Too Long", EC_OSFILE);
    }

    unlink(newfname->buf);

    if (!r) r = mailbox_copyfile(oldfname->buf, newfname->buf, 0);
    if (r) {
	mailbox_close(newmailbox);
	return r;
    }

    /* XXX For two-phase expunge, we also need to copy cyrus.expunge */

    /* Re-open index file and store new uidvalidity  */
    close(newmailbox->index_fd);
    newmailbox->index_fd = dup(oldmailbox->index_fd);
    (void) mailbox_read_index_header(newmailbox);
    newmailbox->generation_no = oldmailbox->generation_no;
    (void) mailbox_write_index_header(newmailbox);

    /* Copy over message files */
    oldfname = &oldfpath.data;
    *(oldfname->tail)++;
    oldfname->len++;
    newfname = &newfpath.data;
    *(newfname->tail)++;
    newfname->len++;

    for (msgno = 1; msgno <= oldmailbox->exists; msgno++) {
	r = mailbox_read_index_record(oldmailbox, msgno, &record);
	if (r) break;
	mailbox_message_get_fname(oldmailbox, record.uid, oldfname->tail,
				  sizeof(oldfname->buf) - oldfname->len);

	if(newfname->len + strlen(oldfname->tail) >= sizeof(newfname->buf)) {
	    syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
		   newfname->buf, oldfname->tail);
	    fatal("Path too long", EC_OSFILE);
	}

	strcpy(newfname->tail, oldfname->tail);

	r = mailbox_copyfile(oldfname->buf, newfname->buf, 0);
	if (r) break;
    }
    if (!r) r = seen_copy(oldmailbox, newmailbox);

    /* XXX For two-phase expunge, we also need to copy message files
       referenced by cyrus.expunge */

    /* Record new quota usage */
    if (!r && newmailbox->quota.root) {
	newmailbox->quota.used += oldmailbox->quota_mailbox_used;
	r = quota_write(&(newmailbox->quota), &tid);
	if (!r) quota_commit(&tid);
    }
    if (r) {
	/* failure and back out */
	for (msgno = 1; msgno <= oldmailbox->exists; msgno++) {
	    if (mailbox_read_index_record(oldmailbox, msgno, &record))
		continue;
	    mailbox_message_get_fname(oldmailbox, record.uid, newfname->tail,
				      sizeof(newfname->buf) - newfname->len);
	    (void) unlink(newfname->buf);
	}
    }

    return r;
}

int mailbox_rename_cleanup(struct mailbox *oldmailbox, int isinbox) 
{
    int r = 0;
    
    if (isinbox) {
	/* Expunge old mailbox */
	r = mailbox_expunge(oldmailbox, expungeall, (char *)0, EXPUNGE_FORCE);
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
mailbox_sync(const char *oldname, const char *oldpath,
	     const char *oldmpath, const char *oldacl, 
	     const char *newname, char *newpath, char *newmpath, int docreate, 
	     bit32 *olduidvalidityp, bit32 *newuidvalidityp,
	     struct mailbox *mailboxp)
{
    int r, r2;
    struct mailbox oldmailbox, newmailbox;
    unsigned int flag, oldmsgno, newmsgno;
    struct index_record oldrecord, newrecord;
    char oldfname[MAX_MAILBOX_PATH+1], newfname[MAX_MAILBOX_PATH+1];
    size_t oldfname_len, newfname_len, fn_len;
    char *oldfnametail, *newfnametail;
    struct txn *tid = NULL;

    /* Open old mailbox and lock */
    mailbox_open_header_path(oldname, oldpath, oldmpath,
			     oldacl, 0, &oldmailbox, 0);

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
	r = mailbox_open_header_path(newname, newpath, newmpath,
				     oldacl, 0, &newmailbox, 0);
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
	r = quota_read(&newmailbox.quota, &tid, 1);
	if (!oldmailbox.quota.root ||
	    strcmp(oldmailbox.quota.root, newmailbox.quota.root) != 0) {
	    if (!r && newmailbox.quota.limit >= 0 &&
		newmailbox.quota.used + oldmailbox.quota_mailbox_used >
		((unsigned) newmailbox.quota.limit * QUOTA_UNITS)) {
		r = IMAP_QUOTA_EXCEEDED;
	    }
	}
	if (r && r != IMAP_QUOTAROOT_NONEXISTENT) {
	    mailbox_close(&newmailbox);
	    mailbox_close(&oldmailbox);
	    return r;
	}
    }

    strlcpy(oldfname, oldmailbox.path, sizeof(oldfname));
    strlcat(oldfname, "/", sizeof(oldfname));
    oldfname_len = strlen(oldfname);
    oldfnametail = oldfname + oldfname_len;

    strlcpy(newfname, newmailbox.path, sizeof(newfname));
    strlcat(newfname, "/", sizeof(newfname));
    newfname_len = strlen(newfname);
    newfnametail = newfname + newfname_len;

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
					      newfnametail,
					      sizeof(newfname) - strlen(newfname));
		    unlink(newfname);
		}
	    } while ((newrecord.uid < oldrecord.uid) &&
		     (newmsgno <= newmailbox.exists));
	}
	/* we check 'exists' instead of last UID in case of empty mailbox */
	if (newmsgno > newmailbox.exists) {
	    /* message arrived since last sync - copy message file */
	    mailbox_message_get_fname(&oldmailbox, oldrecord.uid,
				      oldfnametail,
				      sizeof(oldfname) - strlen(oldfname));
	    strcpy(newfnametail, oldfnametail);
	    r = mailbox_copyfile(oldfname, newfname, 0);
	    if (r) break;
	}
    }
    if (!r) r = seen_copy(&oldmailbox, &newmailbox);

    if (!r) {
	/* Copy over index/cache files */
	oldfnametail--;
	newfnametail--;

	fn_len = strlen(FNAME_INDEX);
	if((oldfname_len - 1) + fn_len > sizeof(oldfname))
	{
	    syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
		   oldfname, FNAME_INDEX);
	    fatal("Path too long", EC_OSFILE);
	}
	if((newfname_len - 1) + fn_len > sizeof(oldfname))
	{
	    syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
		   newfname, FNAME_INDEX);
	    fatal("Path too long", EC_OSFILE);
	}

	strlcpy(oldfnametail, FNAME_INDEX,
		sizeof(oldfname) - (oldfname_len - 1));
	strlcpy(newfnametail, FNAME_INDEX,
	        sizeof(newfname) - (newfname_len - 1));

	unlink(newfname);		/* Make link() possible */
	r = mailbox_copyfile(oldfname, newfname, 0);

	fn_len = strlen(FNAME_CACHE);
	if((oldfname_len - 1) + fn_len > sizeof(oldfname))
	{
	    syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
		   oldfname, FNAME_CACHE);
	    fatal("Path too long", EC_OSFILE);
	}
	if((newfname_len - 1) + fn_len > sizeof(oldfname))
	{
	    syslog(LOG_ERR, "IOERROR: Path too long (%s + %s)",
		   newfname, FNAME_CACHE);
	    fatal("Path too long", EC_OSFILE);
	}

	strlcpy(oldfnametail, FNAME_CACHE,
		sizeof(oldfname) - (oldfname_len - 1));
	strlcpy(newfnametail, FNAME_CACHE,
	        sizeof(newfname) - (newfname_len - 1));

	unlink(newfname);
	if (!r) r = mailbox_copyfile(oldfname, newfname, 0);

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
	r = quota_write(&newmailbox.quota, &tid);
	if (!r) quota_commit(&tid);
	tid = NULL;
    }
    if (r) goto fail;

    if (r && newmailbox.quota.root) {
	r2 = quota_read(&newmailbox.quota, &tid, 1);
	newmailbox.quota.used += newmailbox.quota_mailbox_used;
	if (!r2) {
	    r2 = quota_write(&newmailbox.quota, &tid);
	    if (!r2) quota_commit(&tid);
	}
	else if (r2 == IMAP_QUOTAROOT_NONEXISTENT) r2 = 0;
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
	mailbox_message_get_fname(&oldmailbox, record.uid, newfnametail,
				  sizeof(newfname) - strlen(newfname));
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
int mailbox_copyfile(const char *from, const char *to, int nolink)
{
    int srcfd, destfd;
    struct stat sbuf;
    const char *src_base = 0;
    unsigned long src_size = 0;
    int n;

    if (!nolink) {
	if (link(from, to) == 0) return 0;
	if (errno == EEXIST) {
	    if (unlink(to) == -1) {
		syslog(LOG_ERR, "IOERROR: unlinking to recreate %s: %m", to);
		return IMAP_IOERROR;
	    }
	    if (link(from, to) == 0) return 0;
	}
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

void mailbox_hash_mbox(char *buf, size_t buf_len,
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
	    c = (char) dir_hash_c(name);
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
	c = (char) dir_hash_c(idx);
	
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
