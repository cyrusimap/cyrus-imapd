/* squatter.c -- SQUAT-based message indexing tool
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
 * $Id: squatter.c,v 1.21 2008/03/24 17:09:19 murch Exp $
 */

/*
  This is the tool that creates SQUAT indexes for Cyrus mailboxes.

  SQUAT index files are organised as follows:

  There is (at most) one index file for each Cyrus mailbox, named
  "cyrus.squat", stored in the mailbox directory.

  Source documents are named 'xUID' where UID is the numeric UID of a
  message and x is a character denoting a part of the message: 'f' ==
  FROM, 't' == TO, 'b' == BCC, 'c' == CC, 's' == SUBJECT, 'h' == other
  headers, 'm' == the body. So, a messge with UID 331 could give rise
  to several source documents named "f331", "t331", "b331", "c331",
  "s331", "h331"  and "m331".

  There is also a special source document named "validity.N" where N
  is the validitity nonce for the mailbox. We use this to detect when
  the UIDs have been renumbered since we created the index (in which
  case the index is useless and is ignored).

  This tool creates new indexes for one or more mailboxes. (We do not
  support incremental updates to an index yet.) The index is created
  in "cyrus.squat.tmp" and then, if creation was successful, it is
  atomically renamed to "cyrus.squat". This guarantees that we don't
  interfere with anyone who has the old index open.
*/

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>

#include "annotate.h"
#include "assert.h"
#include "mboxlist.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "squat.h"
#include "imapd.h"
#include "util.h"

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

extern char *optarg;
extern int optind;

/* current namespace */
static struct namespace squat_namespace;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;
int imapd_condstore_client = 0;
void printastring(const char *s __attribute__((unused)))
{
    fatal("not implemented", EC_SOFTWARE);
}
/* end stuff to make index.c link */

/* These stats are gathered 1) per mailbox and 2) for the whole operation. */
typedef struct {
  int indexed_bytes;    /* How many bytes of processed message text
			   have we indexed? */
  int indexed_messages; /* How many messages have we indexed? */
  int index_size;       /* How many bytes is the index using? */
  time_t start_time;    /* When did this operation start? */
  time_t end_time;      /* When did it end? */
} SquatStats;

const int SKIP_FUZZ = 60;

static int verbose = 0;
static int mailbox_count = 0;
static int skip_unmodified = 0;
static int incremental_mode = 0;
static SquatStats total_stats;

static void start_stats(SquatStats* stats) {
  stats->index_size = 0;
  stats->indexed_bytes = 0;
  stats->indexed_messages = 0;
  stats->start_time = time(NULL);
}

static void stop_stats(SquatStats* stats) {
  stats->end_time = time(NULL);
}

static void print_stats(FILE* out, SquatStats* stats) {
  fprintf(out, "Indexed %d messages (%d bytes) "
          "into %d index bytes in %d seconds\n",
          stats->indexed_messages, stats->indexed_bytes,
          stats->index_size, (int) (stats->end_time - stats->start_time));
}

static int usage(const char *name)
{
    fprintf(stderr,
	    "usage: %s [-C <alt_config>] [-r] [-s] [-a] [-v] [mailbox...]\n",
	    name);
 
    exit(EC_USAGE);
}

static void fatal_syserror(const char* s)
{
  perror(s);
  exit(99);
}

static void fatal_squat_error(const char* s)
{
  int err = squat_get_last_error();

  switch (err) {
  case SQUAT_ERR_OUT_OF_MEMORY:
    fprintf(stderr, "SQUAT: Out of memory (%s)\n", s);
    break;
  case SQUAT_ERR_SYSERR:
    perror(s);
    break;
  default:
    /* There are other error codes, but they only apply for searching,
       not index construction */
    fprintf(stderr, "SQUAT: Unknown error %d (%s)\n", err, s);
  }

  exit(98);
}

/* ====================================================================== */

/* uid_info is used to track which messages exist in old squat index, by
 * parsing document names (e.g: m456. is part of message UID 456).
 */

struct uid_item {
  unsigned long uid;
  int flagged;
};

struct uid_info {
  struct uid_item *list;
  unsigned long len;
  unsigned long uidvalidity;
  int valid;
};

static void uid_info_init(struct uid_info *uid_info, unsigned long exists)
{
  uid_info->list = xmalloc((exists+1)*sizeof(struct uid_item));
  uid_info->len  = exists;
  uid_info->uidvalidity = 0L;
  uid_info->valid = 1;
}

static void uid_info_free(struct uid_info *uid_info)
{
  if (uid_info->list != NULL)
    free(uid_info->list);

  uid_info->list = NULL;
}

static void uid_item_init(struct uid_item *uid_item, unsigned long uid)
{
  uid_item->uid = uid;
  uid_item->flagged = 0;
}

static struct uid_item *find_uid_item(struct uid_info *uid_info,
                                      unsigned long uid)
{
  struct uid_item *list = uid_info->list;
  unsigned long first = 0;
  unsigned long last  = uid_info->len;

  /* Binary chop on sorted array */
  while (first < last) {
    unsigned long middle = (first + last) / 2;

    if (list[middle].uid == uid)
      return(&list[middle]);
    if (list[middle].uid < uid)
      first = middle + 1;
    else
      last = middle;
  }
  return(NULL);
}

/* Populate uid_info map using document names from SquatSearchIndex backend */
static int doc_check(void *closure, SquatListDoc const* doc)
{
  struct uid_info *uid_info = (struct uid_info *)closure;
  struct uid_item *uid_item;
  unsigned long uid;

  /* validity will be replaced with new value in same slot */
  if  (!strncmp(doc->doc_name, "validity.", 9)) {
    uid_info->uidvalidity = strtoul(doc->doc_name+9, NULL, 10);
    return(1);
  }

  if (!strchr("tfcbsmh", doc->doc_name[0])) {
    syslog(LOG_ERR, "Invalid document name: %s", doc->doc_name);
    uid_info->valid = 0;
    return(1);
  }

  uid = strtoul(doc->doc_name+1, NULL, 10);
  if ((uid > 0) && (uid_item=find_uid_item(uid_info, uid))) {
    uid_item->flagged = 1;
    return(1);
  }

  /* Remove this UID from the index */
  return(0);
}

/* ====================================================================== */


typedef struct {
  SquatStats* mailbox_stats;
  SquatIndex* index;
  struct mailbox* mailbox;
} SquatReceiverData;

/* Cyrus passes the text to index in here, after it has canonicalized
   the text. We figure out what source document the text belongs to,
   and update the index. */
static void search_text_receiver(int uid, int part, int cmd,
                                 char const* text, int text_len, void* rock) {
  SquatReceiverData* d = (SquatReceiverData*)rock;

  if ((cmd & SEARCHINDEX_CMD_BEGINPART) != 0) {
    char buf[100];
    char part_char;
    
    /* Figure out what the name of the source document is going to be. */
    switch (part) {
    case SEARCHINDEX_PART_FROM: part_char = 'f'; break;
    case SEARCHINDEX_PART_TO:   part_char = 't'; break;
    case SEARCHINDEX_PART_CC:   part_char = 'c'; break;
    case SEARCHINDEX_PART_BCC:  part_char = 'b'; break;
    case SEARCHINDEX_PART_SUBJECT: part_char = 's'; break;
    case SEARCHINDEX_PART_HEADERS: part_char = 'h'; break;
    default:
      assert(0);
    case SEARCHINDEX_PART_BODY:
      part_char = 'm';
      d->mailbox_stats->indexed_messages++;
      total_stats.indexed_messages++;
      break;
    }

    snprintf(buf, sizeof(buf), "%c%d", part_char, uid);

    /* don't index document parts that are going to be empty (or too
       short to search) */
    if ((cmd & SEARCHINDEX_CMD_ENDPART) != 0
        && ((cmd & SEARCHINDEX_CMD_APPENDPART) == 0
            || text_len < SQUAT_WORD_SIZE)) {
      if (verbose > 2) {
        printf("Skipping tiny document part '%s' (size %d)\n", buf,
               (cmd & SEARCHINDEX_CMD_APPENDPART) == 0 ? 0 : text_len);
      }
      return;
    }

    if (verbose > 2) {
      printf("Opening document part '%s'\n", buf);
    }

    if (squat_index_open_document(d->index, buf) != SQUAT_OK) {
      fatal_squat_error("Writing index");
    }
  }

  if ((cmd & SEARCHINDEX_CMD_APPENDPART) != 0) {
    if (verbose > 3) {
      printf("Writing %d bytes into message %d\n", text_len, uid);
    }

    if (squat_index_append_document(d->index, text, text_len) != SQUAT_OK) {
      fatal_squat_error("Writing index data");
    }
    d->mailbox_stats->indexed_bytes += text_len;
    total_stats.indexed_bytes += text_len;
  }

  if ((cmd & SEARCHINDEX_CMD_ENDPART) != 0) {
    if (squat_index_close_document(d->index) != SQUAT_OK) {
      fatal_squat_error("Writing index update");
    }
  }
}

/* Let SQUAT tell us what's going on in the expensive
   squat_index_finish function. */
static void stats_callback(void* closure __attribute__((unused)),
			   SquatStatsEvent* params) {
  switch (params->generic.type) {
  case SQUAT_STATS_COMPLETED_INITIAL_CHAR:
    if (verbose > 1) {
      if (params->completed_initial_char.num_words > 0) {
        printf("Processing index character %d, %d total words, "
               "temp file size is %d\n",
               params->completed_initial_char.completed_char,
               params->completed_initial_char.num_words,
               params->completed_initial_char.temp_file_size);
      }
    }
    break;

  default:
    ; /* do nothing */
  }
}

/* Squat a single open mailbox */
static int squat_single(struct mailbox *mailbox, int incremental,
                        char *squat_file_name)
{
    char new_file_name[MAX_MAILBOX_PATH+1];
    SquatStats stats;
    SquatOptions options;
    SquatReceiverData data;
    SquatSearchIndex *old_index = NULL;
    char uid_validity_buf[30];
    struct index_record record;
    struct uid_info  uid_info;
    struct uid_item *uid_item;
    struct stat index_file_info;
    unsigned long lastuid;
    unsigned msgno;
    int new_index_fd = -1;
    int old_index_fd = -1;
    int r = 0;               /* Using IMAP_* not SQUAT_* return codes here */

    uid_info_init(&uid_info, mailbox->exists);

    strlcpy(new_file_name, squat_file_name, sizeof(new_file_name));
    strlcat(new_file_name, ".NEW", sizeof(new_file_name));

    if ((new_index_fd = open(new_file_name,
                             O_CREAT|O_TRUNC|O_WRONLY, 0666)) < 0) {
      fatal_syserror("Unable to create temporary index file");
    }

    options.option_mask = SQUAT_OPTION_TMP_PATH | SQUAT_OPTION_STATISTICS;
    options.tmp_path = mailbox->path;
    options.stats_callback = stats_callback;
    options.stats_callback_closure = NULL;
    data.index = squat_index_init(new_index_fd, &options);
    if (data.index == NULL) {
      fatal_squat_error("Initializing index");
    }

    if (mailbox_read_index_header(mailbox) != 0) {
      r = IMAP_IOERROR;
      goto bail;
    }

    lastuid  = 0;
    uid_item = uid_info.list;
    for (msgno = 1; msgno <= mailbox->exists ; msgno++) {
      if ((r=mailbox_read_index_record(mailbox, msgno, &record)))
        goto bail;
      if (record.uid == 0) {
        syslog(LOG_ERR, "Invalid UID 0 in index for %s: try reconstruct",
               mailbox->name);
        r = IMAP_IOERROR;
        goto bail;
      }
      if ((msgno > 1) && (record.uid <= lastuid)) {
        syslog(LOG_ERR,
               "UID %lu out of order in index for %s: try reconstruct",
               record.uid, mailbox->name);
        r = IMAP_IOERROR;
        goto bail;
      }
      uid_item_init(&uid_item[msgno-1], record.uid);
      lastuid = record.uid;
    }
    /* Add zero UID as an end of list marker: uid_info_init() assigned space */
    uid_item_init(&uid_item[mailbox->exists], 0);

    /* Open existing index if it exists */
    old_index_fd   = -1;
    old_index = NULL;
    if (incremental &&
        ((old_index_fd = open(squat_file_name, O_RDONLY)) >= 0) &&
        (old_index = squat_search_open(old_index_fd)) == NULL) {
      close(old_index_fd);
      old_index_fd = -1;
    }

    /* Fall back to full update if open() or squat_search_open() failed */
    if (!old_index) incremental = 0;

    if (incremental) {
      /* Copy existing document names verbatim. They end up with the same
       * doc_IDs as in the old index, which makes trie copying much simpler.
       */
      uid_info.valid       = 1;
      uid_info.uidvalidity = 0L;
      squat_index_add_existing(data.index, old_index, doc_check, &uid_info);

      if (!uid_info.valid) {
        syslog(LOG_ERR,
               "Corrupt squat index for %s, retrying without incremental",
               mailbox->name);
        r = IMAP_IOERROR;
        goto bail;
      }

      if (uid_info.uidvalidity != mailbox->uidvalidity) {
        /* Squat file refers to old mailbox: force full rebuild */
        r = IMAP_IOERROR;
        goto bail;
      }
    } else {
      /* write an empty document at the beginning to record the validity
         nonce */
      snprintf(uid_validity_buf, sizeof(uid_validity_buf), 
               "validity.%ld", mailbox->uidvalidity);
      if (squat_index_open_document(data.index, uid_validity_buf) != SQUAT_OK
          || squat_index_close_document(data.index) != SQUAT_OK) {
        fatal_squat_error("Writing index");
      }
    }

    data.mailbox       = mailbox;
    data.mailbox_stats = &stats;
    start_stats(&stats);

    uid_item =  uid_info.list;
    index_operatemailbox(mailbox);
    for (msgno = 1; msgno <= mailbox->exists ; msgno++) {
      if ((r=mailbox_read_index_record(mailbox, msgno, &record))) {
        index_closemailbox(mailbox);
        goto bail;
      }

      /* Scan uid_item list for matching UID (ascending order, 0 termination) */
      while (uid_item->uid && (uid_item->uid < record.uid))
        uid_item++;

      if ((uid_item->uid == record.uid) && uid_item->flagged)
        continue;

      /* This UID didn't appear in the old index file */
      index_getsearchtext_single(mailbox, msgno, search_text_receiver, &data);
      uid_item->flagged = 1;
    }
    index_closemailbox(mailbox);

    if (squat_index_finish(data.index) != SQUAT_OK) {
      if (incremental) {
        syslog(LOG_ERR,
               "Corrupt squat index %s, retrying without incremental update",
               squat_file_name);
        r = IMAP_IOERROR;
        goto bail;
      }
      /* Just give up if not incremental */
      fatal_squat_error("Closing index");
    }

    /* Check how big the resulting file is */
    if (fstat(new_index_fd, &index_file_info) < 0) {
      fatal_syserror("Unable to stat temporary index file");
    }
    stats.index_size        = index_file_info.st_size;
    total_stats.index_size += index_file_info.st_size;

    if (close(new_index_fd) < 0) {
      fatal_syserror("Unable to complete writing temporary index file");
    }
    new_index_fd = -1;

    /* OK, we successfully created the index under the temporary file name.
       Let's rename it to make it the real index. */
    if (rename(new_file_name, squat_file_name) < 0) {
      fatal_syserror("Unable to rename temporary index file");
    }

    stop_stats(&stats);
    if (verbose > 0) {
      print_stats(stdout, &stats);
    }

 bail:
    if (old_index)             squat_search_close(old_index);
    if (old_index_fd >= 0)     close(old_index_fd);
    if (new_index_fd >= 0)     close(new_index_fd);
    uid_info_free(&uid_info);

    return(r);
}

/* This is called once for each mailbox we're told to index. */
static int index_me(char *name, int matchlen __attribute__((unused)),
		    int maycreate __attribute__((unused)),
		    void *rock) {
    struct mailbox m;
    int r;
    char squat_file_name[MAX_MAILBOX_PATH+1], *path;
    struct stat squat_file_info;
    struct stat index_file_info;
    char extname[MAX_MAILBOX_NAME+1];
    int use_annot = *((int *) rock);
    int mbtype;

    /* Convert internal name to external */
    (*squat_namespace.mboxname_toexternal)(&squat_namespace, name,
					   NULL, extname);

    /* Skip remote mailboxes */
    r = mboxlist_detail(name, &mbtype, NULL, NULL, NULL, NULL, NULL);
    if (r) {
        if (verbose) {
            printf("error opening looking up %s: %s\n",
		   extname, error_message(r));
        }
        return 1;
    }
    if (mbtype & MBTYPE_REMOTE) return 0;

    /* make sure the mailbox (or an ancestor) has
       /vendor/cmu/cyrus-imapd/squat set to "true" */
    if (use_annot) {
	char buf[MAX_MAILBOX_NAME+1] = "", *p;
	struct annotation_data attrib;
	int domainlen = 0;

	if (config_virtdomains && (p = strchr(name, '!')))
	    domainlen = p - name + 1;

	strlcpy(buf, name, sizeof(buf));

	/* since mailboxes inherit /vendor/cmu/cyrus-imapd/squat,
	   we need to iterate all the way up to "" (server entry) */
	while (1) {
	    r = annotatemore_lookup(buf, "/vendor/cmu/cyrus-imapd/squat", "",
				    &attrib);

	    if (r ||				/* error */
		attrib.value ||			/* found an entry */
		!buf[0]) {			/* done recursing */
		break;
	    }

	    p = strrchr(buf, '.');		/* find parent mailbox */

	    if (p && (p - buf > domainlen))	/* don't split subdomain */
		*p = '\0';
	    else if (!buf[domainlen])		/* server entry */
		buf[0] = '\0';
	    else				/* domain entry */
		buf[domainlen] = '\0';
	}

	if (r || !attrib.value || strcasecmp(attrib.value, "true"))
	    return 0;
    }

    /* First we have to jump through hoops to open the mailbox and its
       Cyrus index. */
    memset(&m, 0, sizeof(struct mailbox));
    r = mailbox_open_header(name, 0, &m);
    if (r) {
        if (verbose) {
            printf("error opening %s: %s\n", extname, error_message(r));
        }
        return 1;
    }

    r = mailbox_open_index(&m);
    if (!r) r = mailbox_lock_pop(&m);
    if (r) {
        if (verbose) {
            printf("error locking index %s: %s\n", extname, error_message(r));
        }
        mailbox_close(&m);
        return 1;
    }

    path = (m.mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_SQUAT)) ?
	m.mpath : m.path;
    snprintf(squat_file_name, sizeof(squat_file_name),
             "%s%s", path, FNAME_SQUAT_INDEX);

    /* process only changed mailboxes if skip option delected. */
    if (skip_unmodified &&
        !fstat(m.index_fd, &index_file_info) &&
        !stat(squat_file_name, &squat_file_info)) {
        if (SKIP_FUZZ + index_file_info.st_mtime <
            squat_file_info.st_mtime) {
            syslog(LOG_DEBUG, "skipping mailbox %s", extname);
            if (verbose > 0) {
                printf("Skipping mailbox %s\n", extname);
            }
            mailbox_close(&m);
            return 0;
        }
    }

    syslog(LOG_INFO, "indexing mailbox %s... ", extname);
    if (verbose > 0) {
      printf("Indexing mailbox %s... ", extname);
    }

    if (!incremental_mode || (squat_single(&m, 1, squat_file_name) != 0)) {
      /* Fall back to complete squat */
      squat_single(&m, 0, squat_file_name);
    }

    mailbox_close(&m);
    mailbox_count++;

    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;
    int rflag = 0, use_annot = 0;
    int i;
    char buf[MAX_MAILBOX_PATH+1];
    int r;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:rsiav")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
          alt_config = optarg;
          break;

        case 'v': /* verbose */
          verbose++;
          break;

	case 'r': /* recurse */
	  rflag = 1;
	  break;

	case 's': /* skip unmodifed */
	  skip_unmodified = 1;
          break;

	case 'i': /* incremental mode */
	  incremental_mode = 1;
          break;

	case 'a': /* use /squat annotation */
	  use_annot = 1;
	  break;

	default:
	    usage("squatter");
	}
    }

    cyrus_init(alt_config, "squatter", 0);

    syslog(LOG_NOTICE, "indexing mailboxes");

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&squat_namespace, 1)) != 0) {
	fatal(error_message(r), EC_CONFIG);
    }

    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    mboxlist_init(0);
    mboxlist_open(NULL);
    mailbox_initialize();

    start_stats(&total_stats);

    if (optind == argc) {
	if (rflag) {
	    fprintf(stderr, "please specify a mailbox to recurse from\n");
	    exit(EC_USAGE);
	}
	assert(!rflag);
	strlcpy(buf, "*", sizeof(buf));
	(*squat_namespace.mboxlist_findall)(&squat_namespace, buf, 1,
					    0, 0, index_me, &use_annot);
    }

    for (i = optind; i < argc; i++) {
	/* Translate any separators in mailboxname */
	(*squat_namespace.mboxname_tointernal)(&squat_namespace, argv[i],
					       NULL, buf);
	index_me(buf, 0, 0, &use_annot);
	if (rflag) {
	    strlcat(buf, ".*", sizeof(buf));
	    (*squat_namespace.mboxlist_findall)(&squat_namespace, buf, 1,
						0, 0, index_me, &use_annot);
	}
    }

    if (verbose > 0 && mailbox_count > 1) {
      stop_stats(&total_stats);
      printf("Total over all mailboxes: ");
      print_stats(stdout, &total_stats);
    }

    syslog(LOG_NOTICE, "done indexing mailboxes");

    seen_done();
    mboxlist_close();
    mboxlist_done();
    annotatemore_close();
    annotatemore_done();

    cyrus_done();
    
    return 0;
}
