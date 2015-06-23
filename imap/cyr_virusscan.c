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
#include "exitcodes.h"
#include "append.h"
#include "imap/imap_err.h"
#include "index.h"
#include "mailbox.h"
#include "message.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "prot.h"
#include "util.h"
#include "sync_log.h"
#include "times.h"

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
};

void *clamav_init()
{
    unsigned int sigs = 0;
    int r;

    struct clamav_state *st = xzmalloc(sizeof(struct clamav_state));
    if (st == NULL) {
      fatal("memory allocation failed", EC_SOFTWARE);
    }

    st->av_engine = cl_engine_new();
    if ( ! st->av_engine ) {
      fatal("Failed to initialize AV engine", EC_SOFTWARE);
    }
    
    /* load all available databases from default directory */
    if ((r = cl_load(cl_retdbdir(), st->av_engine, &sigs, CL_DB_STDOPT))) {
	syslog(LOG_ERR, "cl_load: %s", cl_strerror(r));
	fatal(cl_strerror(r), EC_SOFTWARE);
    }

    if (verbose) printf("Loaded %d virus signatures.\n", sigs);

    /* build av_engine */
    if((r = cl_engine_compile(st->av_engine))) {
	syslog(LOG_ERR,
	       "Database initialization error: %s", cl_strerror(r));
	cl_engine_free(st->av_engine);
	fatal(cl_strerror(r), EC_SOFTWARE);
    }

    /* set up archive av_limits */
    /* max files */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_FILES, 10000);
    /* during the scanning of archives, this size (100 MB) will
     * never be exceeded
     */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_SCANSIZE, 100 * 1048576);
    /* compressed files will only be decompressed and scanned up to 
     * this size (10 MB)
     */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_FILESIZE, 10 * 1048576);
    /* maximum recursion level for archives */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_RECURSION, 16);

    return (void *) st;
}


int clamav_scanfile(void *state, const char *fname,
		    const char **virname)
{
    struct clamav_state *st = (struct clamav_state *) state;
    int r;

    /* scan file */
    r = cl_scanfile(fname, virname, NULL, st->av_engine,
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
	cl_engine_free(st->av_engine);
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
int scan_me(const char *, int, int, void *);
unsigned virus_check(struct mailbox *mailbox,
                     struct index_record *record,
		     void *rock);
void append_notifications();


int main (int argc, char *argv[]) {
    int option;		/* getopt() returns an int */
    char *alt_config = NULL;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
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

    cyrus_init(alt_config, "cyr_virusscan", 0, CONFIG_NEED_PARTITION_DATA);

    if (!engine.name) {
	fatal("no virus scanner configured", EC_SOFTWARE);
    } else {
	if (verbose) printf("Using %s virus scanner\n", engine.name);
    }

    engine.state = engine.init();

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    sync_log_init();

    /* setup for mailbox event notifications */
    mboxevent_init();

    if (optind == argc) { /* do the whole partition */
        mboxlist_findall(NULL, "*", 1, 0, 0, scan_me, NULL);
    } else {
	for (; optind < argc; optind++) {
	    mboxlist_findall(NULL, argv[optind], 1, 0, 0, scan_me, NULL);
	}
    }

    if (notify) append_notifications();

    sync_log_done();

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

int scan_me(const char *name,
	    int matchlen __attribute__((unused)),
	    int maycreate __attribute__((unused)),
	    void *rock __attribute__((unused)))
{
    struct mailbox *mailbox;
    int r;
    struct infected_mbox *i_mbox = NULL;

    if (verbose) {
        printf("Working on %s...\n", name);
    }

    r = mailbox_open_iwl(name, &mailbox);
    if (r) {
        printf("failed to open %s (%s)\n", name, error_message(r));
	return 0;
    }

    if (notify) {
        const char *owner = mboxname_to_userid(name);
        if (owner) {
            if (!strcmp(owner, user->owner)) {
		i_mbox = user;
	    } else {
		/* new owner (Inbox) */
		struct infected_mbox *new = xzmalloc(sizeof(struct infected_mbox));
                new->owner = xstrdup(owner);
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
    }

    mailbox_expunge(mailbox, virus_check, i_mbox, NULL, EVENT_MESSAGE_EXPUNGE);
    mailbox_close(&mailbox);

    return 0;
}

void create_digest(struct infected_mbox *i_mbox, struct mailbox *mailbox,
                   struct index_record *record, const char *virname)
{
    struct infected_msg *i_msg = xzmalloc(sizeof(struct infected_msg));

    i_msg->mboxname = xstrdup(mailbox->name);
    i_msg->virname = xstrdup(virname);
    i_msg->uid = record->uid;

    i_msg->msgid = mailbox_cache_get_env(mailbox, record, ENV_MSGID);
    i_msg->date = mailbox_cache_get_env(mailbox, record, ENV_DATE);
    i_msg->from = mailbox_cache_get_env(mailbox, record, ENV_FROM);
    i_msg->subj = mailbox_cache_get_env(mailbox, record, ENV_SUBJECT);

    i_msg->next = i_mbox->msgs;
    i_mbox->msgs = i_msg;
}

/* thumbs up routine, checks for virus and returns yes or no for deletion */
/* 0 = no, 1 = yes */
unsigned virus_check(struct mailbox *mailbox,
                     struct index_record *record,
		     void *deciderock)
{
    struct infected_mbox *i_mbox = (struct infected_mbox *) deciderock;
    char *fname;
    const char *virname;
    int r = 0;

    fname = mailbox_message_fname(mailbox, record->uid);

    if ((r = engine.scanfile(engine.state, fname, &virname))) {
	if (verbose) {
            printf("Virus detected in message %u: %s\n", record->uid, virname);
	}
	if (disinfect) {
	    if (notify && i_mbox) {
                create_digest(i_mbox, mailbox, record, virname);
	    }
	}
    }

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
	    char buf[8192], datestr[RFC822_DATETIME_MAX+1];
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
	    time_to_rfc822(t, datestr, sizeof(datestr));
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

	    /* send MessageAppend event notification */
	    append_setup(&as, i_mbox->owner, NULL, NULL, 0, NULL, NULL, 0,
			 EVENT_MESSAGE_APPEND);

	    pout = prot_new(fd, 0);
	    prot_rewind(pout);
	    append_fromstream(&as, &body, pout, msgsize, t, NULL);
	    append_commit(&as);

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
