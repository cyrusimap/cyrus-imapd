/* cyr_virusscan.c - scan mailboxes for infected messages and remove them
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
 * $Id: cyr_virusscan.c,v 1.5 2008/09/23 16:17:09 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

/* cyrus includes */
#include "global.h"
#include "sysexits.h"
#include "exitcodes.h"
#include "append.h"
#include "imap_err.h"
#include "index.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "prot.h"
#include "util.h"
#include "sync_log.h"
#include "rfc822date.h"

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

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

struct infected_msg {
    char *mboxname;
    char *virname;
    char *msgid;
    char *date;
    char *from;
    char *subj;
    unsigned long uid;
    struct infected_msg *next;
};

struct infected_mbox {
    char *owner;
    unsigned msgno; /* running count of which message we're scanning */
    struct infected_msg *msgs;
    struct infected_mbox *next;
};

/* globals for getopt routines */
extern char *optarg;
extern int  optind;
extern int  opterr;
extern int  optopt;

/* globals for callback functions */
int disinfect = 0;
int notify = 0;
struct infected_mbox *public = NULL;
struct infected_mbox *user = NULL;

/* current namespace */
static struct namespace scan_namespace;

int verbose = 1;

/* abstract definition of a virus scan engine */
struct scan_engine {
    const char *name;
    void *state;
    void *(*init)(void);  /* initialize state */
    int (*scanfile)(void *state,  /* scan fname & return non-zero if infected */
		    const char *fname, const char **virname);
    void (*destroy)(void *state);  /* destroy state */
};


#define HAVE_CLAMAV
#ifdef HAVE_CLAMAV
/* ClamAV implementation */
#include <clamav.h>

struct clamav_state {
    struct cl_engine *av_engine;
    struct cl_limits av_limits;
};

void *clamav_init()
{
    unsigned int sigs = 0;
    int r;

    struct clamav_state *st = xzmalloc(sizeof(struct clamav_state));

    /* load all available databases from default directory */
    if ((r = cl_load(cl_retdbdir(), &st->av_engine, &sigs, CL_DB_STDOPT))) {
	syslog(LOG_ERR, "cl_load: %s", cl_strerror(r));
	fatal(cl_strerror(r), EC_SOFTWARE);
    }

    if (verbose) printf("Loaded %d virus signatures.\n", sigs);

    /* build av_engine */
    if((r = cl_build(st->av_engine))) {
	syslog(LOG_ERR,
	       "Database initialization error: %s", cl_strerror(r));
	cl_free(st->av_engine);
	fatal(cl_strerror(r), EC_SOFTWARE);
    }

    /* set up archive av_limits */
    st->av_limits.maxfiles = 10000; /* max files */
    st->av_limits.maxscansize = 100 * 1048576; /* during the scanning of
						* archives
						* this size (100 MB) will never
						* be exceeded
						*/
    st->av_limits.maxfilesize = 10 * 1048576; /* compressed files will only be
					       * decompressed and scanned up to
					       * this size (10 MB)
					       */
    st->av_limits.maxreclevel = 16; /* maximum recursion level for archives */

    return (void *) st;
}


int clamav_scanfile(void *state, const char *fname,
		    const char **virname)
{
    struct clamav_state *st = (struct clamav_state *) state;
    int r;

    /* scan file */
    r = cl_scanfile(fname, virname, NULL, st->av_engine, &st->av_limits,
		    CL_SCAN_STDOPT);

    switch (r) {
    case CL_CLEAN:
	/* do nothing */
	break;
    case CL_VIRUS:
	return 1;
	break;

    default:
	printf("cl_scanfile error: %s\n", cl_strerror(r));
	syslog(LOG_ERR, "cl_scanfile error: %s\n", cl_strerror(r));
	break;
    }

    return 0;
}

void clamav_destroy(void *state)
{
    struct clamav_state *st = (struct clamav_state *) state;

    if (st->av_engine) {
	/* free memory */
	cl_free(st->av_engine);
    }
    free(st);
}

struct scan_engine engine =
{ "ClamAV", NULL, &clamav_init, &clamav_scanfile, &clamav_destroy };

#elif defined(HAVE_SOME_UNKNOWN_VIRUS_SCANNER)
/* XXX  Add other implementations here */

#else
/* NO configured virus scanner */
struct scan_engine engine = { NULL, NULL, NULL, NULL, NULL };
#endif


/* forward declarations */
int usage(char *name);
int scan_me(char *, int, int, void *);
unsigned virus_check(struct mailbox *, void *, unsigned char *, int);
void append_notifications();


int main (int argc, char *argv[]) {
    int option;		/* getopt() returns an int */
    char buf[MAX_MAILBOX_PATH+1];
    char *alt_config = NULL;
    int r;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((option = getopt(argc, argv, "C:rn")) != EOF) {
	switch (option) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'r':
	    disinfect = 1;
	    break;

	case 'n':
	    notify = 1;
	    break;

	case 'h':
	default: usage(argv[0]);
	}
    }

    cyrus_init(alt_config, "cyr_virusscan", 0);

    if (!engine.name) {
	fatal("no virus scanner configured", EC_SOFTWARE);
    } else {
	if (verbose) printf("Using %s virus scanner\n", engine.name);
    }

    engine.state = engine.init();

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&scan_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    sync_log_init();

    if (optind == argc) { /* do the whole partition */
	strcpy(buf, "*");
	(*scan_namespace.mboxlist_findall)(&scan_namespace, buf, 1, 0, 0,
					   scan_me, NULL);
    } else {
	for (; optind < argc; optind++) {
	    strncpy(buf, argv[optind], MAX_MAILBOX_NAME);
	    /* Translate any separators in mailboxname */
	    mboxname_hiersep_tointernal(&scan_namespace, buf,
					config_virtdomains ?
					strcspn(buf, "@") : 0);
	    (*scan_namespace.mboxlist_findall)(&scan_namespace, buf, 1, 0, 0,
					       scan_me, NULL);
	}
    }

    if (notify) append_notifications();

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

    engine.destroy(engine.state);

    cyrus_done();

    return 0;
}

int usage(char *name)
{
    printf("usage: %s [-C <alt_config>] [ -r [-n] ]\n"
	   "\t[mboxpattern1 ... [mboxpatternN]]\n", name);
    printf("\tif no mboxpattern is given %s works on all mailboxes\n", name);
    printf("\t -r remove infected messages\n");
    printf("\t -n notify mailbox owner of deleted messages via email\n");
    exit(0);
}

/* we don't check what comes in on matchlen and maycreate, should we? */
int scan_me(char *name,
	    int matchlen __attribute__((unused)),
	    int maycreate __attribute__((unused)),
	    void *rock __attribute__((unused)))
{
    struct mailbox the_box;
    int            error;
    struct infected_mbox *i_mbox = NULL;

    if (verbose) {
	char mboxname[MAX_MAILBOX_NAME+1];

	/* Convert internal name to external */
	(*scan_namespace.mboxname_toexternal)(&scan_namespace, name,
					     "cyrus", mboxname);
	printf("Working on %s...\n", mboxname);
    }

    error = mailbox_open_header(name, 0, &the_box);
    if (error != 0) { /* did we find it? */
	syslog(LOG_ERR, "Couldn't find %s, check spelling", name);
	return 0;
    }
    if (the_box.header_fd != -1) {
	(void) mailbox_lock_header(&the_box);
    }
    the_box.header_lock_count = 1;

    error = mailbox_open_index(&the_box);
    if (error != 0) {
	mailbox_close(&the_box);
	syslog(LOG_ERR, "Couldn't open mailbox index for %s", name);
	return 0;
    }
    (void) mailbox_lock_index(&the_box);
    the_box.index_lock_count = 1;

    if (notify) {
	/* XXX  Need to handle virtdomains */
	if (!strncmp(name, "user.", 5)) {
	    size_t ownerlen;

	    if (user && (ownerlen = strlen(user->owner)) &&
		!strncmp(name, user->owner, ownerlen) &&
		(name[ownerlen] == '.' || name[ownerlen] =='\0')) {
		/* mailbox belongs to current owner */
		i_mbox = user;
	    } else {
		/* new owner (Inbox) */
		struct infected_mbox *new = xzmalloc(sizeof(struct infected_mbox));
		new->owner = xstrdup(name);
		new->next = user;
		i_mbox = user = new;
	    }
	}
#if 0  /* XXX what to do with public mailboxes (bboards)? */
	else {
	    if (!public) {
		public = xzmalloc(sizeof(struct infected_mbox));
		public->owner = xstrdup("");
	    }

	    i_mbox = public;
	}
#endif

	if (i_mbox) i_mbox->msgno = 1;
    }

    mailbox_expunge(&the_box, virus_check, i_mbox, EXPUNGE_FORCE);

    sync_log_mailbox(the_box.name);
    mailbox_close(&the_box);

    return 0;
}

void create_digest(struct infected_mbox *i_mbox, struct mailbox *mbox,
		   unsigned msgno, unsigned long uid, const char *virname)
{
    struct infected_msg *i_msg = xmalloc(sizeof(struct infected_msg));
    struct nntp_overview *over;

    i_msg->mboxname = xstrdup(mbox->name);
    i_msg->virname = xstrdup(virname);
    i_msg->uid= uid;

    index_operatemailbox(mbox);
    over = index_overview(mbox, msgno);
    i_msg->msgid = strdup(over->msgid);
    i_msg->date = strdup(over->date);
    i_msg->from = strdup(over->from);
    i_msg->subj = strdup(over->subj);

    i_msg->next = i_mbox->msgs;
    i_mbox->msgs = i_msg;
}

/* thumbs up routine, checks for virus and returns yes or no for deletion */
/* 0 = no, 1 = yes */
unsigned virus_check(struct mailbox *mailbox,
		     void *deciderock,
		     unsigned char *buf,
		     int expunge_flags __attribute__((unused)))
{
    struct infected_mbox *i_mbox = (struct infected_mbox *) deciderock;
    unsigned long uid;
    char fname[4096];
    const char *virname;
    int r = 0;

    uid = ntohl(*((bit32 *)(buf+OFFSET_UID)));

    snprintf(fname, sizeof(fname), "%s/%lu.", mailbox->path, uid);

    if ((r = engine.scanfile(engine.state, fname, &virname))) {
	if (verbose) {
	    printf("Virus detected in message %lu: %s\n", uid, virname);
	}
	if (disinfect) {
	    if (notify && i_mbox) {
		create_digest(i_mbox, mailbox, i_mbox->msgno, uid, virname);
	    }
	}
    }

    if (i_mbox) i_mbox->msgno++;

    return r;
}

void append_notifications()
{
    struct infected_mbox *i_mbox;
    int outgoing_count = 0;
    pid_t p = getpid();;
    int fd = create_tempfile(config_getstring(IMAPOPT_TEMP_PATH));

    while ((i_mbox = user)) {
	if (i_mbox->msgs) {
	    FILE *f = fdopen(fd, "w+");
	    size_t ownerlen;
	    struct infected_msg *msg;
	    char buf[8192], datestr[80];
	    time_t t;
	    struct protstream *pout;
	    struct appendstate as;
	    struct body *body = NULL;
	    long msgsize;

	    fprintf(f, "Return-Path: <>\r\n");
	    t = time(NULL);
	    snprintf(buf, sizeof(buf), "<cmu-cyrus-%d-%d-%d@%s>",
		     (int) p, (int) t, 
		     outgoing_count++, config_servername);
	    fprintf(f, "Message-ID: %s\r\n", buf);
	    rfc822date_gen(datestr, sizeof(datestr), t);
	    fprintf(f, "Date: %s\r\n", datestr);
	    fprintf(f, "From: Mail System Administrator <%s>\r\n",
		    config_getstring(IMAPOPT_POSTMASTER));
	    /* XXX  Need to handle virtdomains */
	    fprintf(f, "To: <%s>\r\n", i_mbox->owner+5);
	    fprintf(f, "MIME-Version: 1.0\r\n");
	    fprintf(f, "Subject: Automatically deleted mail\r\n");

	    ownerlen = strlen(i_mbox->owner);

	    while ((msg = i_mbox->msgs)) {
		fprintf(f, "\r\n\r\nThe following message was deleted from mailbox "
			"'Inbox%s'\r\n", msg->mboxname+ownerlen);
		fprintf(f, "because it was infected with virus '%s'\r\n\r\n",
			msg->virname);
		fprintf(f, "\tMessage-ID: %s\r\n", msg->msgid);
		fprintf(f, "\tDate: %s\r\n", msg->date);
		fprintf(f, "\tFrom: %s\r\n", msg->from);
		fprintf(f, "\tSubject: %s\r\n", msg->subj);
		fprintf(f, "\tIMAP UID: %lu\r\n", msg->uid);

		i_mbox->msgs = msg->next;

		/* free msg digest */
		free(msg->mboxname);
		free(msg->msgid);
		free(msg->date);
		free(msg->from);
		free(msg->subj);
		free(msg->virname);
		free(msg);
	    }

	    fflush(f);
	    msgsize = ftell(f);

	    append_setup(&as, i_mbox->owner, MAILBOX_FORMAT_NORMAL,
			 NULL, NULL, 0, -1);
	    pout = prot_new(fd, 0);
	    prot_rewind(pout);
	    append_fromstream(&as, &body, pout, msgsize, t, NULL, 0);
	    append_commit(&as, -1, NULL, NULL, NULL);

	    if (body) {
		message_free_body(body);
		free(body);
	    }
	    prot_free(pout);
	    fclose(f);
	}
	
	user = i_mbox->next;

	/* free owner info */
	free(i_mbox->owner);
	free(i_mbox);
    }
}
