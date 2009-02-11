/* reconstruct.c -- program to reconstruct a mailbox 
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
 * $Id: reconstruct.c,v 1.109 2009/02/11 18:53:04 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>

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

#include "acl.h"
#include "assert.h"
#include "bsearch.h"
#include "imparse.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "map.h"
#include "message.h"
#include "message_guid.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "global.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "quota.h"
#include "seen.h"
#include "retry.h"
#include "convert_code.h"
#include "util.h"
#include "sync_log.h"
#include "lock.h"

extern int optind;
extern char *optarg;

struct discovered {
    char *name;
    struct discovered *next;
};       
struct uniqmailid {
    char * uniqmbxid;
    char *uniqname;
    struct uniqmailid *uniqnext;
};

struct uniqmailid *uniqmid_head;

/* current namespace */
static struct namespace recon_namespace;

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* forward declarations */
void do_mboxlist(void);
int do_reconstruct(char *name, int matchlen, int maycreate, void *rock);
int reconstruct(char *name, struct discovered *l);
void usage(void);
char * getmailname (char * mailboxname);
struct uniqmailid * add_uniqid (char * mailboxname, char * mailboxid);
struct uniqmailid * find_uniqid (char * mailboxname, char * mailboxid);

extern cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

int code = 0;
int keepflag = 0;
int syncflag = 0;
int guid_clear = 0;
int guid_set   = 0;

int main(int argc, char **argv)
{
    int opt, i, r;
    int rflag = 0;
    int mflag = 0;
    int fflag = 0;
    int xflag = 0;
    char buf[MAX_MAILBOX_PATH+1];
    char mbbuf[MAX_MAILBOX_PATH+1];
    struct discovered head;
    char *alt_config = NULL;
    char *start_part = NULL;
    const char *start_part_path = NULL, *start_part_mpath = NULL, *path;

    memset(&head, 0, sizeof(head));

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_SPARE4+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_MODSEQ+4));

    while ((opt = getopt(argc, argv, "C:kp:rmfsxgG")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'k':
	    keepflag = 1;
	    break;

	case 'p':
	    start_part = optarg;
	    break;

	case 'r':
	    rflag = 1;
	    break;

	case 'm':
	    mflag = 1;
	    break;

	case 'f':
	    fflag = 1;
	    break;

	case 's':
	    syncflag = 1;
	    break;
	    
	case 'x':
	    xflag = 1;
	    break;
	    
	case 'g':
	    guid_clear = 1;
	    break;
	    
	case 'G':
	    guid_set = 1;
	    break;
	    
	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "reconstruct", 0);
    global_sasl_init(1,0,NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }
    if (syncflag)
	sync_log_init();

    if(start_part) {
    	/* Get partition's path */
	start_part_path = config_partitiondir(start_part);
	if (!start_part_path) {
	    fatal(error_message(IMAP_PARTITION_UNKNOWN), EC_USAGE);
	}
	start_part_mpath = config_metapartitiondir(start_part);
    }

    if (mflag) {
	if (rflag || fflag || optind != argc) {
	    cyrus_done();
	    usage();
	}
	do_mboxlist();
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    mailbox_reconstructmode();

    /* Deal with nonexistent mailboxes */
    if (start_part) {
	/* We were handed a mailbox that does not exist currently */
	if(optind == argc) {
	    fprintf(stderr,
		    "When using -p, you must specify a mailbox to attempt to reconstruct.");
	    exit(EC_USAGE);
	}

	/* do any of the mailboxes exist in mboxlist already? */
	/* Do they look like mailboxes? */
	for (i = optind; i < argc; i++) {
	    struct stat sbuf;

	    if(strchr(argv[i],'%') || strchr(argv[i],'*')) {
		fprintf(stderr, "Using wildcards with -p is not supported.\n");
		exit(EC_USAGE);
	    }

	    /* Translate mailboxname */
	    (*recon_namespace.mboxname_tointernal)(&recon_namespace, argv[i],
						   NULL, buf);

	    /* Does it exist */
	    do {
		r = mboxlist_lookup(buf, NULL, NULL);
	    } while (r == IMAP_AGAIN);

	    if(r != IMAP_MAILBOX_NONEXISTENT) {
		fprintf(stderr,
			"Mailbox %s already exists.  Cannot specify -p.\n",
			argv[i]);
		exit(EC_USAGE);
	    }

	    /* Does the suspected path *look* like a mailbox? */
	    path = (start_part_mpath &&
		    (config_metapartition_files &
		     IMAP_ENUM_METAPARTITION_FILES_HEADER)) ?
		start_part_mpath : start_part_path;
	    mailbox_hash_mbox(mbbuf, sizeof(mbbuf), path, buf);
	    strlcat(mbbuf, FNAME_HEADER, sizeof(mbbuf));
	    if(stat(mbbuf, &sbuf) < 0) {
		fprintf(stderr,
			"%s does not appear to be a mailbox (no %s).\n",
			argv[i], mbbuf);
		exit(EC_USAGE);
	    }
	}
	
	/* None of them exist.  Create them. */
	for (i = optind; i < argc; i++) {
	    /* Translate mailboxname */
	    (*recon_namespace.mboxname_tointernal)(&recon_namespace, argv[i],
						   NULL, buf);

	    r = mboxlist_createmailbox(buf, 0, start_part, 1,
				       "cyrus", NULL, 0, 0, !xflag);
	    if(r) {
		fprintf(stderr, "could not create %s\n", argv[i]);
	    }
	}
    }

    /* Normal Operation */
    if (optind == argc) {
	if (rflag) {
	    fprintf(stderr, "please specify a mailbox to recurse from\n");
	    cyrus_done();
	    exit(EC_USAGE);
	}
	assert(!rflag);
	strlcpy(buf, "*", sizeof(buf));
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0, 0,
					    do_reconstruct, NULL);
    }

    for (i = optind; i < argc; i++) {
	char *domain = NULL;

	/* save domain */
	if (config_virtdomains) domain = strchr(argv[i], '@');

	strlcpy(buf, argv[i], sizeof(buf));
	/* Translate any separators in mailboxname */
	mboxname_hiersep_tointernal(&recon_namespace, buf,
				    config_virtdomains ?
				    strcspn(buf, "@") : 0);

	/* reconstruct the first mailbox/pattern */
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0,
					    0, do_reconstruct, 
					    fflag ? &head : NULL);
	if (rflag) {
	    /* build a pattern for submailboxes */
	    char *p = strchr(buf, '@');
	    if (p) *p = '\0';
	    strlcat(buf, ".*", sizeof(buf));

	    /* append the domain */
	    if (domain) strlcat(buf, domain, sizeof(buf));

	    /* reconstruct the submailboxes */
	    (*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0,
						0, do_reconstruct, 
						fflag ? &head : NULL);
	}
    }

    /* examine our list to see if we discovered anything */
    while (head.next) {
	struct discovered *p;
	int r = 0;

	p = head.next;
	head.next = p->next;

	/* create p (database only) and reconstruct it */
	/* partition is defined by the parent mailbox */
	r = mboxlist_createmailbox(p->name, 0, NULL, 1,
				   "cyrus", NULL, 0, 0, !xflag);
	if (!r) {
	    do_reconstruct(p->name, strlen(p->name), 0, &head);
	} else {
	    fprintf(stderr, "createmailbox %s: %s\n",
		    p->name, error_message(r));
	}
	/* may have added more things into our list */

	free(p->name);
	free(p);
    }

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    cyrus_done();

    return code;
}

void usage(void)
{
    fprintf(stderr,
	    "usage: reconstruct [-C <alt_config>] [-p partition] [-ksrfx] mailbox...\n");
    fprintf(stderr, "       reconstruct [-C <alt_config>] -m\n");
    exit(EC_USAGE);
}    

int compare_uid(const void *a, const void *b)
{
    return *(unsigned long *)a - *(unsigned long *)b;
}

#define UIDGROW 300


/*
 * mboxlist_findall() callback function to reconstruct a mailbox
 */
int
do_reconstruct(char *name,
	       int matchlen,
	       int maycreate __attribute__((unused)),
	       void *rock)
{
    int r;
    char buf[MAX_MAILBOX_PATH+1];
    static char lastname[MAX_MAILBOX_PATH+1] = "";

    signals_poll();

    /* don't repeat */
    if (matchlen == (int) strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    if(matchlen >= (int) sizeof(lastname))
	matchlen = sizeof(lastname) - 1;
    
    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    r = reconstruct(lastname, rock);
    if (r) {
	com_err(lastname, r,
		(r == IMAP_IOERROR) ? error_message(errno) : NULL);
	code = convert_code(r);
    } else {
	/* Convert internal name to external */
	(*recon_namespace.mboxname_toexternal)(&recon_namespace, lastname,
					       NULL, buf);
	printf("%s\n", buf);
    }

    return 0;
}

char * 
getmailname (char * mailboxname) 
{
    static char   namebuf[MAX_MAILBOX_PATH + 1];

    char * pname;

    strlcpy (namebuf, mailboxname, sizeof (namebuf));
    pname = strchr (namebuf, '.');
    if (pname) {
	pname = strchr(pname + 1, '.');
	if (pname)
	    *pname = '\0';
    }
    return (namebuf);
}

struct uniqmailid * 
find_uniqid ( char * mailboxname, char * mailboxid) 
{
    struct uniqmailid *puniq;
    char * nameptr;
    
    nameptr = getmailname (mailboxname);
    for (puniq = uniqmid_head; puniq != NULL; puniq = puniq->uniqnext) {
	if  (strcmp (puniq->uniqmbxid, mailboxid) == 0) {
	    if (strcmp (puniq->uniqname, nameptr) == 0) {
		return (puniq);
	    }
	}
    }
    return NULL;
}
struct uniqmailid * 
add_uniqid ( char * mailboxname, char * mailboxid)
{
    struct uniqmailid *puniq;
    char *pboxname;

    pboxname = getmailname (mailboxname);

    puniq = xmalloc (sizeof (struct uniqmailid));
    puniq->uniqmbxid = xstrdup(mailboxid);
    puniq->uniqname = xstrdup(pboxname);
    
    puniq->uniqnext = uniqmid_head;
    uniqmid_head = puniq;

    return (puniq);
}

/* ---------------------------------------------------------------------- */

/* Code which is typically reused for index,expunge and cache files */

static void reconstruct_make_path(char *buf, int size,
                                  struct mailbox *mailbox,
                                  int mask, char *name, char *suffix)
{
    char *path = (mailbox->mpath && (config_metapartition_files & mask))
	? mailbox->mpath : mailbox->path;

    strlcpy(buf, path, size);
    strlcat(buf, name, size);

    if (suffix && suffix[0])
        strlcat(buf, suffix, size);
}

static int reconstruct_open_expunge(struct mailbox *mailbox, int *fdp,
                                    unsigned long *lenp)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    const char *lockfailaction;
    int r;

    reconstruct_make_path(fnamebuf, sizeof(fnamebuf), mailbox,
                          IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                          FNAME_EXPUNGE_INDEX, NULL);
    *fdp = -1;
    if ((stat(fnamebuf, &sbuf) < 0) ||
        (sbuf.st_size < (int) INDEX_HEADER_SIZE) ||
        ((*fdp = open(fnamebuf, O_RDWR, 0666)) < 0)) {
	unlink(fnamebuf);
        return(0);
    }
    *lenp = sbuf.st_size;

    if ((r = lock_reopen(*fdp, fnamebuf, &sbuf, &lockfailaction)))
         syslog(LOG_ERR, "IOERROR: %s expunge index for %s: %m",
                lockfailaction, mailbox->name);
    return(r);
}

/* Commit a single index/expunge/cache file */
static int reconstruct_rename_single(struct mailbox *mailbox,
                                     int mask, char *filename)
{
    char fnamebuf[MAX_MAILBOX_PATH+1], fnamebufnew[MAX_MAILBOX_PATH+1];

    reconstruct_make_path(fnamebuf, sizeof(fnamebuf),
                          mailbox, mask, filename, NULL);
    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    if (rename(fnamebufnew, fnamebuf)) {
        syslog(LOG_ERR, "IOERROR: renaming %s for %s: %m",
               filename, mailbox->name);
        return(IMAP_IOERROR);
    }
    return(0);
}

/* Delete a single index/expunge/cache file */
static int reconstruct_delete_single(struct mailbox *mailbox, int mask,
                                     char *filename, char *suffix)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];

    reconstruct_make_path(fnamebuf, sizeof(fnamebuf), mailbox, mask,
                          filename, suffix);
    return ((unlink(fnamebuf) < 0) ? IMAP_IOERROR : 0);
}

/* ---------------------------------------------------------------------- */

/* uiditem used to generate list of msgnos sorted by ascending UID */
struct uiditem {
    unsigned long msgno;
    unsigned long uid;
};

static int compare_uiditem(const void *a0, const void *b0)
{
    struct uiditem *a = (struct uiditem *) a0;
    struct uiditem *b = (struct uiditem *) b0;

    /* If duplicate UIDs appear list lowest msgnos first */
    if (a->uid == b->uid)
        return((a->msgno) - (b->msgno));

    return ((a->uid) - (b->uid));
}

/* ---------------------------------------------------------------------- */

/* Running counts which will go into the index and expunge headers */
struct reconstruct_counts {
    unsigned long newexists;
    unsigned long newanswered;
    unsigned long newflagged;
    unsigned long newdeleted;
    uquota_t      newquota_used;
};

static void reconstruct_counts_clear(struct reconstruct_counts *c)
{
    memset(c, 0, sizeof(struct reconstruct_counts));
}


static void reconstruct_counts_update(struct reconstruct_counts *c,
                                      struct index_record *p)
{
    c->newexists++;
    c->newquota_used += p->size;

    if (p->system_flags & FLAG_ANSWERED) c->newanswered++;
    if (p->system_flags & FLAG_DELETED)  c->newdeleted++;
    if (p->system_flags & FLAG_FLAGGED)  c->newflagged++;
}

static void reconstruct_counts_tobuf(unsigned char *buf,
                                     struct mailbox *mailbox,
                                     struct reconstruct_counts *c)
{
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = htonl(mailbox->generation_no + 1);
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(MAILBOX_MINOR_VERSION);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(INDEX_RECORD_SIZE);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(c->newexists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox->last_uid);

    /* quotas may be 64bit now */
#ifdef HAVE_LONG_LONG_INT
    *((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonll(c->newquota_used);
#else
    /* zero the unused 32bits */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonl(0);
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(c->newquota_used);
#endif

    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(mailbox->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(c->newdeleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(c->newanswered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(c->newflagged);
    *((bit32 *)(buf+OFFSET_MAILBOX_OPTIONS)) = htonl(mailbox->options);
    *((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(0);
#ifdef HAVE_LONG_LONG_INT
    align_htonll(buf+OFFSET_HIGHESTMODSEQ_64, mailbox->highestmodseq);
#else
    /* zero the unused 32bits */
    *((bit32 *)(buf+OFFSET_HIGHESTMODSEQ_64)) = htonl(0);
    *((bit32 *)(buf+OFFSET_HIGHESTMODSEQ)) = htonl(mailbox->highestmodseq);
#endif
    *((bit32 *)(buf+OFFSET_SPARE0)) = htonl(0); /* RESERVED */
    *((bit32 *)(buf+OFFSET_SPARE1)) = htonl(0); /* RESERVED */
    *((bit32 *)(buf+OFFSET_SPARE2)) = htonl(0); /* RESERVED */
    *((bit32 *)(buf+OFFSET_SPARE3)) = htonl(0); /* RESERVED */
    *((bit32 *)(buf+OFFSET_SPARE4)) = htonl(0); /* RESERVED */
}

/* ---------------------------------------------------------------------- */

static int reconstruct_header_isvalid(const char *index_base,
                                      unsigned long index_len)
{
    int format;
    int  minor_version;
    unsigned long start_offset;
    unsigned long record_size;
    unsigned long  exists;

    if ((index_base == NULL) || (index_len < INDEX_HEADER_SIZE))
        return(0);

    format        = ntohl(*((bit32 *)(index_base+OFFSET_FORMAT)));
    minor_version = ntohl(*((bit32 *)(index_base+OFFSET_MINOR_VERSION)));
    start_offset  = ntohl(*((bit32 *)(index_base+OFFSET_START_OFFSET)));
    record_size   = ntohl(*((bit32 *)(index_base+OFFSET_RECORD_SIZE)));
    exists        = ntohl(*((bit32 *)(index_base+OFFSET_EXISTS)));

    if ((format != 0)        ||
        (minor_version == 0) || (minor_version > MAILBOX_MINOR_VERSION) || 
        (start_offset == 0)  || (start_offset > INDEX_HEADER_SIZE) ||
        (record_size  == 0)  || (record_size > INDEX_RECORD_SIZE) ||
        ((unsigned) index_len < (start_offset + exists * record_size)))
        return(0);

    return(1);
}

static void reconstruct_clear_expunged(struct mailbox *mailbox,
                                       struct uiditem *expunge_uidmap,
                                       unsigned expunge_exists)
{
    char msgfname[MAILBOX_FNAME_LEN+1];
    unsigned long uid;
    unsigned msgno;

    for (msgno = 1; msgno <= expunge_exists; msgno++) {
        if ((uid = expunge_uidmap[msgno-1].uid) > 0) {
            mailbox_message_get_fname(mailbox, uid, msgfname, sizeof(msgfname));
            unlink(msgfname);
        }
    }
}

/*  Read an index record from a mapped index file without struct mailbox */
int reconstruct_read_index_record(const char *name,
                                  const char *index_base,
                                  unsigned long index_len,
                                  unsigned msgno,
                                  struct index_record *record)
{
    unsigned long start_offset;
    unsigned long record_size;
    unsigned long exists;
    unsigned long offset;
    unsigned const char *buf;
    int n;

    /* Following would normally come from struct mailbox */
    start_offset = ntohl(*((bit32 *)(index_base+OFFSET_START_OFFSET)));
    record_size  = ntohl(*((bit32 *)(index_base+OFFSET_RECORD_SIZE)));
    exists       = ntohl(*((bit32 *)(index_base+OFFSET_EXISTS)));

    offset = start_offset + (msgno-1) * record_size;
    if (offset + INDEX_RECORD_SIZE > index_len) {
	syslog(LOG_ERR,
	       "IOERROR: index record %u for %s past end of file",
	       msgno, name);
	return IMAP_IOERROR;
    }

    buf = (unsigned char*) index_base + offset;

    record->uid = ntohl(*((bit32 *)(buf+OFFSET_UID)));
    record->internaldate = ntohl(*((bit32 *)(buf+OFFSET_INTERNALDATE)));
    record->sentdate = ntohl(*((bit32 *)(buf+OFFSET_SENTDATE)));
    record->size = ntohl(*((bit32 *)(buf+OFFSET_SIZE)));
    record->header_size = ntohl(*((bit32 *)(buf+OFFSET_HEADER_SIZE)));
    record->content_offset = ntohl(*((bit32 *)(buf+OFFSET_CONTENT_OFFSET)));
    record->cache_offset = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));
    record->last_updated = ntohl(*((bit32 *)(buf+OFFSET_LAST_UPDATED)));
    record->system_flags = ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));
    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
	record->user_flags[n] = ntohl(*((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)));
    }
    record->content_lines = ntohl(*((bit32 *)(buf+OFFSET_CONTENT_LINES)));
    record->cache_version = ntohl(*((bit32 *)(buf+OFFSET_CACHE_VERSION)));
    message_guid_import(&record->guid, buf+OFFSET_MESSAGE_GUID);
#ifdef HAVE_LONG_LONG_INT
    record->modseq = ntohll(*((bit64 *)(buf+OFFSET_MODSEQ_64)));
#else
    record->modseq = ntohl(*((bit32 *)(buf+OFFSET_MODSEQ)));
#endif
    return 0;
}

/* ---------------------------------------------------------------------- */

/*
 * Reconstruct the single mailbox named 'name'
 */
int reconstruct(char *name, struct discovered *found)
{
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    char quota_root[MAX_MAILBOX_BUFFER];
    bit32 valid_user_flags[MAX_USER_FLAGS/32];

    struct mailbox mailbox;

    int expunge_fd = -1;
    const char *expunge_base = NULL;
    unsigned long expunge_len = 0;
    unsigned long expunge_exists = 0;
    struct uiditem *expunge_uidmap = NULL;
    unsigned long expunge_size = 0;
    unsigned expmsg;
    
    int r = 0;
    int i, n, hasquota, flag;
    int format = MAILBOX_FORMAT_NORMAL;

    char *p;

    char fnamebuf[MAX_MAILBOX_PATH+1];
    FILE *newindex = NULL, *newexpunge = NULL, *msgfile = NULL;
    DIR *dirp;
    struct dirent *dirent;
    struct stat sbuf;
    int newcache_fd = -1;

    unsigned long *uid = NULL;
    unsigned uid_num, uid_alloc;
    unsigned msg, oldmsg;

    struct reconstruct_counts index_counts;
    struct reconstruct_counts expunge_counts;

    char *list_acl, *list_part;
    int list_type;

    struct index_record message_index, tmp_index, old_index;
    struct body *body = NULL;

    char *mypath, *mympath, *mypart, *myacl;
    int mytype;
    char mbpath[MAX_MAILBOX_PATH+1], *path;
    
    int expunge_found, index_found;
    char unique_buf[32];

    time_t now = time(0);
    modseq_t highestmodseq = 0;

    /* Start by looking up current data in mailbox list */
    r = mboxlist_detail(name, &mytype, &mypath, &mympath,
			&mypart, &myacl, NULL);
    if(r) return r;
    
    /* stat for header, if it is not there, we need to create it
     * note that we do not want to wind up with a fully-open mailbox,
     * so we will re-open. */
    path = (mympath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_HEADER)) ?
	mympath : mypath;
    snprintf(mbpath, sizeof(mbpath), "%s%s", path, FNAME_HEADER);
    if(stat(mbpath, &sbuf) == -1) {
	/* Header doesn't exist, create it! */
	r = mailbox_create(name, mypart, myacl, NULL,
			   ((mytype & MBTYPE_NETNEWS) ?
			    MAILBOX_FORMAT_NETNEWS :
			    MAILBOX_FORMAT_NORMAL), NULL);
	if(r) return r;
    }
    
    /* Now open just the header (it will hopefully be valid) */
    r = mailbox_open_header(name, 0, &mailbox);
    if (r) return r;
    
    if (mailbox.header_fd != -1) {
	(void) mailbox_lock_header(&mailbox);
    }
    mailbox.header_lock_count = 1;
    
    if (chdir(mailbox.path) == -1) {
        mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    
    /* Fix quota root */
    hasquota = quota_findroot(quota_root, sizeof(quota_root), mailbox.name);
    if (mailbox.quota.root) free(mailbox.quota.root);
    if (hasquota) {
	mailbox.quota.root = xstrdup(quota_root);
    }
    else {
	mailbox.quota.root = 0;
    }

    /* Validate user flags */
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	valid_user_flags[i] = 0;
    }
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox.flagname[flag]) continue;
	if ((flag && !mailbox.flagname[flag-1]) ||
	    !imparse_isatom(mailbox.flagname[flag])) {
	    free(mailbox.flagname[flag]);
	    mailbox.flagname[flag] = 0;
	}
	valid_user_flags[flag/32] |= 1<<(flag&31);
    }

    /* Verify ACL and update mboxlist if needed */
    r = mailbox_read_header_acl(&mailbox);
    if (r) {
        mailbox_close(&mailbox);
        return r;
    }

    r = mboxlist_detail(name, &list_type, NULL, NULL,
			&list_part, &list_acl, NULL);
    if (r) {
        mailbox_close(&mailbox);
        return r;
    }

    if(strcmp(list_acl, mailbox.acl)) {
	r = mboxlist_update(name, list_type, list_part, mailbox.acl, 0);
    }
    if (r) {
        mailbox_close(&mailbox);
        return r;
    }

    /* Attempt to open/lock index */
    r = mailbox_open_index(&mailbox);
    if (r) {
	mailbox.exists = 0;
	mailbox.last_uid = 0;
	mailbox.last_appenddate = 0;
	mailbox.uidvalidity = now;
	/* If we can't read the index, assume new UIDL so that stupid clients
	   will retrieve all of the messages in the mailbox. */
	mailbox.options = OPT_POP3_NEW_UIDL;
	mailbox.highestmodseq = 1;
    }
    else {
	(void) mailbox_lock_index(&mailbox);
    }
    mailbox.index_lock_count = 1;
    mailbox.pop3_last_login = 0;

    /* Open, lock and then map cyrus.expunge file if it exists */
    r = reconstruct_open_expunge(&mailbox, &expunge_fd, &expunge_size);
    if (r) {
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    if (expunge_fd != -1) {
        map_refresh(expunge_fd, 1, &expunge_base, &expunge_len, expunge_size,
                    "expunge", mailbox.name);
        if (!reconstruct_header_isvalid(expunge_base, expunge_len)) {
            map_free(&expunge_base, &expunge_len);
            close(expunge_fd);
            expunge_fd = -1;
            syslog(LOG_ERR, "Unable to verify expunge header - deleting: %s",
                   mailbox.name);
            reconstruct_delete_single(&mailbox,
                                      IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                                      FNAME_EXPUNGE_INDEX, NULL);
        }
    }
    if (expunge_base && (expunge_len >= INDEX_HEADER_SIZE))
        expunge_exists = ntohl(*((bit32 *)(expunge_base+OFFSET_EXISTS)));

    /* expunge_uidmap is list of msgnos sorted in ascending UID */
    if (expunge_exists > 0) {
        unsigned msgno;

        expunge_uidmap = xmalloc(expunge_exists * sizeof(struct uiditem));
        
        for (msgno = 1 ; msgno <= expunge_exists; msgno++) {
            /* Can't use mailbox_read_index_record_from_mapped() safely */
            r = reconstruct_read_index_record(mailbox.name,
                                              expunge_base, expunge_len,
                                              msgno, &message_index);
            if (r) {
                r = IMAP_IOERROR;
                goto bail;
            }
            expunge_uidmap[msgno-1].msgno = msgno;
            expunge_uidmap[msgno-1].uid   = message_index.uid;
        }
        qsort(expunge_uidmap, expunge_exists,
              sizeof(struct uiditem), compare_uiditem);
    }

    if (!keepflag && (expunge_exists > 0))
        reconstruct_clear_expunged(&mailbox, expunge_uidmap, expunge_exists);

    /* Create new index/cache/expunge files */
    reconstruct_make_path(fnamebuf, sizeof(fnamebuf), &mailbox,
                          IMAP_ENUM_METAPARTITION_FILES_INDEX,
                          FNAME_INDEX, ".NEW");
    if ((newindex = fopen(fnamebuf, "w+")) == NULL) {
        r = IMAP_IOERROR;
        goto bail;
    }
    reconstruct_make_path(fnamebuf, sizeof(fnamebuf), &mailbox,
                          IMAP_ENUM_METAPARTITION_FILES_CACHE,
                          FNAME_CACHE, ".NEW");
    if ((newcache_fd = open(fnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666)) == -1) {
        r = IMAP_IOERROR;
        goto bail;
    }
    reconstruct_make_path(fnamebuf, sizeof(fnamebuf), &mailbox,
                          IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                          FNAME_EXPUNGE_INDEX, ".NEW");
    if ((newexpunge = fopen(fnamebuf, "w+")) == NULL) {
        r = IMAP_IOERROR;
        goto bail;
    }

    /* Create placeholder space for index/cache/expunge headers */
    memset(buf, 0, sizeof(buf));
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = htonl(mailbox.generation_no + 1);
    fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);
    fwrite(buf, 1, INDEX_HEADER_SIZE, newexpunge);
    retry_write(newcache_fd, buf, sizeof(bit32));

    /* Find all message files in directory */
    uid = (unsigned long *) xmalloc(UIDGROW * sizeof(unsigned long));
    uid_num = 0;
    uid_alloc = UIDGROW;
    dirp = opendir(".");
    if (!dirp) {
        r = IMAP_IOERROR;
        goto bail;
    }
    while ((dirent = readdir(dirp))!=NULL) {
	if (!isdigit((int) (dirent->d_name[0])) || dirent->d_name[0] == '0')
            continue;
        p = dirent->d_name;
	msg = 0;
        while (isdigit((int) *p)) {
	    msg = msg * 10 + *p++ - '0';
        }
        if (*p++ != '.') continue;
        if (*p) continue;
	    
	if (uid_num == uid_alloc) {
	    uid_alloc += UIDGROW;
	    uid = (unsigned long *)
                xrealloc((char *)uid, uid_alloc * sizeof(unsigned long));
	}
	uid[uid_num] = msg;
        uid_num++;
    }
    closedir(dirp);

    qsort((char *)uid, uid_num, sizeof(*uid), compare_uid);

    /* Put each message file in new index/cache or expunge/cache */
    mailbox.format = format;
    reconstruct_counts_clear(&index_counts);
    reconstruct_counts_clear(&expunge_counts);

    memset(&tmp_index, 0, sizeof(struct index_record));
    memset(&old_index, 0, sizeof(struct index_record));

    old_index.uid  = 0;      /* Only valid after mailbox_read_index_record() */

    oldmsg = 0;
    expmsg = 0;
    for (msg = 0; msg < uid_num; msg++) {
	char msgfname[MAILBOX_FNAME_LEN+1];

        memset(&message_index, 0, sizeof(struct index_record));
	message_index.uid = uid[msg];
	
	mailbox_message_get_fname(&mailbox, uid[msg],
                                  msgfname, sizeof(msgfname));
	msgfile = fopen(msgfname, "r");
	if (!msgfile) {
	    fprintf(stderr,
                    ("reconstruct: fopen() failed for '%s' "
                     "[error=%d] -- skipping.\n"), msgfname, errno);
	    continue;
	}

	if (fstat(fileno(msgfile), &sbuf)) {
	    fclose(msgfile);
	    continue;
	}
	if (sbuf.st_size == 0) {
	    /* Zero-length message file--blow it away */
	    fclose(msgfile);
	    unlink(msgfname);
	    continue;
	}

        /* Was this message expunged? */
        while ((expmsg < expunge_exists) &&
               (expunge_uidmap[expmsg].uid < uid[msg]))
            expmsg++;

        expunge_found = 0;
        if ((expmsg < expunge_exists) &&
            (expunge_uidmap[expmsg].uid == uid[msg])) {
            expunge_found = 1;
        }

        /* Does this message have index record in cyrus.index or expunge? */
        index_found = 0;
	if (expunge_found) {
            unsigned msgno = expunge_uidmap[expmsg].msgno;
            
            if ((msgno > 0) && !reconstruct_read_index_record
                (mailbox.name, expunge_base, expunge_len, msgno, &tmp_index))
                index_found = 1;
            expmsg++;
        } else {
	    while (oldmsg < mailbox.exists && old_index.uid < uid[msg]) {
		if (mailbox_read_index_record(&mailbox, ++oldmsg,
                                              &old_index)) {
		    old_index.uid = 0;
		}
	    }
            if (old_index.uid == uid[msg]) {
                memcpy(&tmp_index, &old_index, sizeof(struct index_record));
                index_found = 1;
            }
        }

        if (index_found) {
            /* Use data in old index file, subject to validity checks */
            message_index.internaldate = tmp_index.internaldate;
            message_index.last_updated = tmp_index.last_updated;

            message_index.modseq = tmp_index.modseq;
            /* This should never happen, but bugs in 2.3.4 and 2.3.5
             * could have left modseq blank.  If so, update it */
            if (!message_index.modseq) message_index.modseq = 1;
            message_index.system_flags = tmp_index.system_flags &
                (FLAG_ANSWERED|FLAG_FLAGGED|FLAG_DELETED|FLAG_DRAFT);
            for (i = 0; i < MAX_USER_FLAGS/32; i++) {
                message_index.user_flags[i] =
                    tmp_index.user_flags[i] & valid_user_flags[i];
            }
            /* Copy across MessageGUID if confident that data on disk */
            message_guid_copy(&message_index.guid, &tmp_index.guid);
        } else {
            /* Message file write time is good estimate of internaldate */
            message_index.internaldate = sbuf.st_mtime;
            message_index.last_updated = time(0);
            /* If we are recovering a message, assume new UIDL
               so that stupid clients will retrieve this message */
            mailbox.options |= OPT_POP3_NEW_UIDL;
            /* Wipe the Message GUID */
            message_guid_set_null(&message_index.guid);
            /* If we are recovering a message, reset MODSEQ */
            message_index.modseq = 1;
        }

        if (message_index.modseq > highestmodseq) {
            highestmodseq = message_index.modseq;
        }

	/* Force rebuild from message_create_record() */
	if (guid_set) message_guid_set_null(&message_index.guid);

	/* NB: message_create_record() will reconstruct GUID if NULL */
	if (((r = message_parse_file(msgfile, NULL, NULL, &body)) != 0) ||
	    ((r = message_create_record(mailbox.name, newcache_fd,
					&message_index, body)) != 0)) {
            r = IMAP_IOERROR;
            goto bail;
	}
	fclose(msgfile);
	if (body) message_free_body(body);
	
        /* Clear out existing or regenerated GUID */
        if (guid_clear) message_guid_set_null(&message_index.guid);

	if (expunge_found && keepflag) {
            /* Write out new entry in expunge file */
            reconstruct_counts_update(&expunge_counts, &message_index);
            mailbox_index_record_to_buf(&message_index, buf);
            n = fwrite(buf, 1, INDEX_RECORD_SIZE, newexpunge);
        } else {
            /* Write out new entry in index file */
            reconstruct_counts_update(&index_counts, &message_index);
            mailbox_index_record_to_buf(&message_index, buf);
            n = fwrite(buf, 1, INDEX_RECORD_SIZE, newindex);
        }

        if (n != INDEX_RECORD_SIZE) {
            r = IMAP_IOERROR;
            goto bail;
        }
    }

    /* Write out new index and expunge file headers */
    if (uid_num && mailbox.last_uid < uid[uid_num-1]) {
	syslog (LOG_ERR, "Updating last_uid for %s: %lu => %lu",
		mailbox.name, mailbox.last_uid, uid[uid_num-1] + 100);
	mailbox.last_uid = uid[uid_num-1] + 100;
    }

    if (mailbox.last_appenddate == 0 || mailbox.last_appenddate > now) {
	syslog (LOG_ERR, "Updating last_appenddate for %s: %lu => %lu",
		mailbox.name, mailbox.last_appenddate, now);
	mailbox.last_appenddate = now;
    }

    if (mailbox.uidvalidity == 0 || mailbox.uidvalidity > (unsigned)now) {
	syslog (LOG_ERR, "Updating uidvalidity for %s: %lu => %lu",
		mailbox.name, mailbox.uidvalidity, now);
	mailbox.uidvalidity = (unsigned)now;
    }

    if (mailbox.highestmodseq < highestmodseq) {
	syslog (LOG_ERR, "Updating highestmodseq for %s: "
		MODSEQ_FMT " => " MODSEQ_FMT,
		mailbox.name, mailbox.highestmodseq, highestmodseq);
	mailbox.highestmodseq = highestmodseq;
    }

    if (mailbox.quota_mailbox_used != index_counts.newquota_used) {
	syslog (LOG_ERR, "Updating quota_mailbox_used for %s: "
                QUOTA_T_FMT " => " QUOTA_T_FMT,
		mailbox.name, mailbox.quota_mailbox_used, index_counts.newquota_used);
	/* updated by the counts_tobuf below, different in each file */
    }

    rewind(newindex);
    reconstruct_counts_tobuf(buf, &mailbox, &index_counts);
    n = fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);
    if (n != INDEX_HEADER_SIZE) {
        r = IMAP_IOERROR;
        goto bail;
    }
    rewind(newexpunge);
    reconstruct_counts_tobuf(buf, &mailbox, &expunge_counts);
    n = fwrite(buf, 1, INDEX_HEADER_SIZE, newexpunge);
    if (n != INDEX_HEADER_SIZE) {
        r = IMAP_IOERROR;
        goto bail;
    }

    fflush(newindex);
    fflush(newexpunge);
    if (ferror(newindex) || ferror(newexpunge) || fsync(newcache_fd) ||
        fsync(fileno(newindex)) || fsync(fileno(newexpunge))) {
        r = IMAP_IOERROR;
        goto bail;
    }

    /* Free temporary resources now that the index/expunge update is done */
    close(newcache_fd);
    fclose(newexpunge);
    fclose(newindex);

    if (expunge_base)    map_free(&expunge_base, &expunge_len);
    if (expunge_fd >= 0) close(expunge_fd);
    if (expunge_uidmap)  free(expunge_uidmap);
    if (uid)  free(uid);
    if (body) free(body);

    expunge_base = NULL;
    expunge_len = 0;
    newexpunge = newindex = NULL;
    uid = NULL;
    body = NULL;
    expunge_uidmap = NULL;
    expunge_fd = -1;
    newcache_fd = -1;
    
    /* validate uniqueid */
    if (!mailbox.uniqueid) {

	/* this may change uniqueid, but if it does, nothing we can do
           about it */
	mailbox_make_uniqueid(mailbox.name, mailbox.uidvalidity, unique_buf,
			      sizeof(unique_buf));
	mailbox.uniqueid = xstrdup(unique_buf);
    } else {
	if (find_uniqid (mailbox.name, mailbox.uniqueid) != NULL ) {
    
	    mailbox_make_uniqueid(mailbox.name, mailbox.uidvalidity,
                                  unique_buf, sizeof(unique_buf));
	    free (mailbox.uniqueid);
	    mailbox.uniqueid = xstrdup(unique_buf);
	}
    }
    if (add_uniqid (mailbox.name,  mailbox.uniqueid) == NULL) {
	syslog (LOG_ERR, "Failed adding mailbox: %s unique id: %s\n",
                mailbox.name, mailbox.uniqueid );
    }
    
    /* Write header and commit replacement index/cache files.
     *
     * Do cyrus.index last as this blows away the index lock. In contrast
     * mailbox_write_header() locks the new header file before it commits.
     * That lock is only released on mailbox_close().
     */
    r = mailbox_write_header(&mailbox);
    if (!r)
        r = reconstruct_rename_single(&mailbox,
                                      IMAP_ENUM_METAPARTITION_FILES_CACHE,
                                      FNAME_CACHE);
    if (!r)
        r = reconstruct_rename_single(&mailbox,
                                      IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                                      FNAME_EXPUNGE_INDEX);
    if (expunge_counts.newexists == 0) {
        reconstruct_delete_single(&mailbox,
                                  IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                                  FNAME_EXPUNGE_INDEX, NULL);
    }
    if (!r)
        r = reconstruct_rename_single(&mailbox,
                                      IMAP_ENUM_METAPARTITION_FILES_INDEX,
                                      FNAME_INDEX);
    if (r) {
	mailbox_close(&mailbox);
	return (r);
    }
    
    r = seen_reconstruct(&mailbox,
                         (time_t)0, (time_t)0, (int (*)())0, (void *)0);
    if (syncflag) {
	sync_log_mailbox(mailbox.name);
    }
    mailbox_close(&mailbox);

    if (found) {
	if (mympath &&
	    (config_metapartition_files &
             IMAP_ENUM_METAPARTITION_FILES_HEADER) &&
	    chdir(mympath) == -1) {
	    return IMAP_IOERROR;
	}

	/* we recurse down this directory to see if there's any mailboxes
	   under this not in the mailboxes database */
	dirp = opendir(".");

	while ((dirent = readdir(dirp)) != NULL) {
	    struct discovered *new;

	    /* mailbox directories never have a dot in them */
	    if (strchr(dirent->d_name, '.')) continue;
	    if (stat(dirent->d_name, &sbuf) < 0) continue;
	    if (!S_ISDIR(sbuf.st_mode)) continue;

	    /* ok, we found a directory that doesn't have a dot in it;
               is there a cyrus.header file? */
	    snprintf(fnamebuf, sizeof(fnamebuf), "%s%s",
		     dirent->d_name, FNAME_HEADER);
	    if (stat(fnamebuf, &sbuf) < 0) continue;

	    /* ok, we have a real mailbox directory */
	    snprintf(fnamebuf, sizeof(fnamebuf), "%s.%s", 
		     name, dirent->d_name);

	    /* does fnamebuf exist as a mailbox in mboxlist? */
	    do {
		r = mboxlist_lookup(fnamebuf, NULL, NULL);
	    } while (r == IMAP_AGAIN);
	    if (!r) continue; /* mailbox exists; it'll be reconstructed
			         with a -r */

	    if (r != IMAP_MAILBOX_NONEXISTENT) break; /* erg? */
	    else r = 0; /* reset error condition */

	    printf("discovered %s\n", fnamebuf);
	    new = (struct discovered *) xmalloc(sizeof(struct discovered));
	    new->name = strdup(fnamebuf);
	    new->next = found->next;
	    found->next = new;
	}
	closedir(dirp);
    }

    return r;

 bail:
    if (msgfile)          fclose(msgfile);
    if (newindex)         fclose(newindex);
    if (newexpunge)       fclose(newexpunge);
    if (expunge_fd >= 0)  close(expunge_fd);
    if (newcache_fd >= 0) close(newcache_fd);
    if (uid)              free(uid);
    if (expunge_uidmap)   free(expunge_uidmap);
    if (expunge_base)     map_free(&expunge_base, &expunge_len);

    mailbox_close(&mailbox);
    return r;
}

/*
 * Reconstruct the mailboxes list.
 */
void do_mboxlist(void)
{
    fprintf(stderr, "reconstructing mailboxes.db currently not supported\n");
    exit(EC_USAGE);
}
