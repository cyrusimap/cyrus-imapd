/* sync_client.c -- Cyrus synchonization client
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
 * $Id: sync_client.c,v 1.51 2010/06/28 12:04:20 brong Exp $
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <utime.h>

#include <netinet/tcp.h>

#include "global.h"
#include "assert.h"
#include "append.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imap_proxy.h"
#include "imparse.h"
#include "util.h"
#include "prot.h"
#include "message_guid.h"
#include "sync_log.h"
#include "sync_support.h"
#include "cyr_lock.h"
#include "backend.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "signals.h"
#include "cyrusdb.h"

/* signal to config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* ====================================================================== */

/* Static global variables and support routines for sync_client */

extern char *optarg;
extern int optind;

static const char *servername = NULL;
static struct backend *sync_backend = NULL;
static struct protstream *sync_out = NULL;
static struct protstream *sync_in = NULL;
static struct buf tagbuf = BUF_INITIALIZER;

static struct namespace   sync_namespace;

static unsigned flags      = 0;
static int verbose         = 0;
static int verbose_logging = 0;
static int connect_once    = 0;
static int background      = 0;
static int do_compress     = 0;

static char *imap_parsemechlist(const char *str, struct stdprot_t *std)
{
    char *ret = xzmalloc(strlen(str)+1);
    char *tmp;
    int num = 0;
    
    if (strstr(str, " SASL-IR")) {
	/* server supports initial response in AUTHENTICATE command */
	std->sasl_cmd.maxlen = USHRT_MAX;
    }
    
    while ((tmp = strstr(str, " AUTH="))) {
	char *end = (tmp += 6);
	
	while((*end != ' ') && (*end != '\0')) end++;
	
	/* add entry to list */
	if (num++ > 0) strcat(ret, " ");
	strlcat(ret, tmp, strlen(ret) + (end - tmp) + 1);
	
	/* reset the string */
	str = end;
    }
    
    return ret;
}

struct protocol_t imap_csync_protocol =
{ "imap", "imap", TYPE_STD,
  { { { 1, NULL },
      { "C01 CAPABILITY", NULL, "C01 ", &imap_parsemechlist,
	{ { " AUTH=", CAPA_AUTH },
	  { " STARTTLS", CAPA_STARTTLS },
	  { " COMPRESS=DEFLATE", CAPA_COMPRESS },
	  { " X-REPLICATION", CAPA_REPLICATION },
	  { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*",
	NULL, AUTO_CAPA_AUTH_OK },
      { "Z01 COMPRESS DEFLATE", "* ", "Z01 OK" },
      { "N01 NOOP", "* ", "N01 OK" },
      { "Q01 LOGOUT", "* ", "Q01 " } } }
};

static struct protocol_t csync_protocol =
{ "csync", "csync", TYPE_STD,
  { { { 1, "* OK" },
      { NULL, NULL, "* OK", NULL,
	{ { "* SASL ", CAPA_AUTH },
	  { "* STARTTLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", USHRT_MAX, 0, "OK", "NO", "+ ", "*", NULL, 0 },
      { "COMPRESS DEFLATE", NULL, "OK" },
      { "NOOP", NULL, "OK" },
      { "EXIT", NULL, "OK" } } }
};

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    seen_done();
    annotatemore_close();
    annotatemore_done();
    quotadb_close();
    quotadb_done();
    mboxlist_close();
    mboxlist_done();
    cyrus_done();
    exit(code);
}

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s -S <servername> [-C <alt_config>] [-r] [-v] mailbox...\n", name);
 
    exit(EC_USAGE);
}

void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    exit(code);
}

/* ====================================================================== */

static int user_sub(const char *userid, const char *mboxname)
{
    int r;

    r = mboxlist_checksub(mboxname, userid);

    switch (r) {
    case CYRUSDB_OK:
	return sync_set_sub(userid, mboxname, 1, sync_backend, flags);
    case CYRUSDB_NOTFOUND:
	return sync_set_sub(userid, mboxname, 0, sync_backend, flags);
    default:
	return r;
    }
}

/* ====================================================================== */

static void remove_meta(char *user, struct sync_action_list *list)
{
    struct sync_action *action;

    for (action = list->head ; action ; action = action->next) {
	if (!strcmp(user, action->user)) {
	    action->active = 0;
	}
    }
}

static void remove_folder(char *name, struct sync_action_list *list,
			  int chk_child)
{
    struct sync_action *action;
    size_t len = strlen(name);

    for (action = list->head ; action ; action = action->next) {
	if (!strncmp(name, action->name, len) &&
	    ((action->name[len] == '\0') ||
	     (chk_child && (action->name[len] == '.')))) {
            action->active = 0;
        }
    }
}

/* ====================================================================== */

static int do_sync(const char *filename)
{
    struct sync_action_list *user_list = sync_action_list_create();
    struct sync_action_list *meta_list = sync_action_list_create();
    struct sync_action_list *mailbox_list = sync_action_list_create();
    struct sync_action_list *quota_list = sync_action_list_create();
    struct sync_action_list *annot_list = sync_action_list_create();
    struct sync_action_list *seen_list = sync_action_list_create();
    struct sync_action_list *sub_list = sync_action_list_create();
    struct sync_name_list *mboxname_list = sync_name_list_create();
    static struct buf type, arg1, arg2;
    char *arg1s, *arg2s;
    struct sync_action *action;
    int c;
    int fd = -1;
    int doclose = 0;
    struct protstream *input;
    int r = 0;

    if ((filename == NULL) || !strcmp(filename, "-"))
	fd = 0; /* STDIN */
    else {
	fd = open(filename, O_RDWR);
	if (fd < 0) {
	    syslog(LOG_ERR, "Failed to open %s: %m", filename);
	    r = IMAP_IOERROR;
	    goto cleanup;
	}

	doclose = 1;

	if (lock_blocking(fd) < 0) {
	    syslog(LOG_ERR, "Failed to lock %s: %m", filename);
	    r = IMAP_IOERROR;
	    goto cleanup;
	}
    }

    input = prot_new(fd, 0);

    while (1) {
	if ((c = getword(input, &type)) == EOF)
	    break;

	/* Ignore blank lines */
	if (c == '\r') c = prot_getc(input);
	if (c == '\n')
	    continue;

	if (c != ' ') {
	    syslog(LOG_ERR, "Invalid input");
	    eatline(input, c);
	    continue;
	}

	if ((c = getastring(input, 0, &arg1)) == EOF) break;
	arg1s = arg1.s;

	if (c == ' ') {
	    if ((c = getastring(input, 0, &arg2)) == EOF) break;
	    arg2s = arg2.s;

	} else 
	    arg2s = NULL;
	
	if (c == '\r') c = prot_getc(input);
	if (c != '\n') {
	    syslog(LOG_ERR, "Garbage at end of input line");
	    eatline(input, c);
	    continue;
	}

	ucase(type.s);

	if (!strcmp(type.s, "USER"))
	    sync_action_list_add(user_list, NULL, arg1s);
	else if (!strcmp(type.s, "META"))
	    sync_action_list_add(meta_list, NULL, arg1s);
	else if (!strcmp(type.s, "SIEVE"))
	    sync_action_list_add(meta_list, NULL, arg1s);
	else if (!strcmp(type.s, "MAILBOX"))
	    sync_action_list_add(mailbox_list, arg1s, NULL);
	else if (!strcmp(type.s, "QUOTA"))
	    sync_action_list_add(quota_list, arg1s, NULL);
	else if (!strcmp(type.s, "ANNOTATION"))
	    sync_action_list_add(annot_list, arg1s, NULL);
	else if (!strcmp(type.s, "SEEN"))
	    sync_action_list_add(seen_list, arg2s, arg1s);
	else if (!strcmp(type.s, "SUB"))
	    sync_action_list_add(sub_list, arg2s, arg1s);
	else if (!strcmp(type.s, "UNSUB"))
	    sync_action_list_add(sub_list, arg2s, arg1s);
	else
	    syslog(LOG_ERR, "Unknown action type: %s", type.s);
    }

    prot_free(input);
    if (doclose) {
	close(fd);
	doclose = 0;
    }

    /* Optimise out redundant clauses */

    for (action = user_list->head; action; action = action->next) {
	char inboxname[MAX_MAILBOX_BUFFER];
	char deletedname[MAX_MAILBOX_BUFFER];

	/* USER action overrides any MAILBOX action on any of the 
	 * user's mailboxes or any META, SEEN or SUB/UNSUB
	 * action for same user */
	(sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					      action->user, inboxname);
	remove_folder(inboxname, mailbox_list, 1);

	/* remove deleted namespace items as well */
	if (mboxlist_delayed_delete_isenabled()) {
	    mboxname_todeleted(inboxname, deletedname, 0);
	    remove_folder(deletedname, mailbox_list, 1);
	}

	/* remove per-user items */
	remove_meta(action->user, meta_list);
	remove_meta(action->user, seen_list);
	remove_meta(action->user, sub_list);
    }
    
    for (action = meta_list->head; action; action = action->next) {
	/* META action overrides any user SEEN or SUB/UNSUB action
	   for same user */
	remove_meta(action->user, seen_list);
	remove_meta(action->user, sub_list);
    }

    /* And then run tasks. */
    for (action = quota_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	if (sync_do_quota(action->name, sync_backend, flags)) {
	    /* XXX - bogus handling, should be user */
	    sync_action_list_add(mailbox_list, action->name, NULL);
	    if (verbose) {
		printf("  Promoting: QUOTA %s -> MAILBOX %s\n",
		       action->name, action->name);
	    }
	    if (verbose_logging) {
		syslog(LOG_INFO, "  Promoting: QUOTA %s -> MAILBOX %s",
		       action->name, action->name);
	    }
	}
    }

    for (action = annot_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	/* NOTE: ANNOTATION "" is a special case - it's a server
	 * annotation, hence the check for a character at the
	 * start of the name */
	if (sync_do_annotation(action->name, sync_backend,
			       flags) && *action->name) {
	    /* XXX - bogus handling, should be ... er, something */
	    sync_action_list_add(mailbox_list, action->name, NULL);
	    if (verbose) {
		printf("  Promoting: ANNOTATION %s -> MAILBOX %s\n",
		       action->name, action->name);
	    }
	    if (verbose_logging) {
		syslog(LOG_INFO, "  Promoting: ANNOTATION %s -> MAILBOX %s",
		       action->name, action->name);
	    }
	}
    }

    for (action = seen_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

        if (sync_do_seen(action->user, action->name, sync_backend, flags)) {
	    char *userid = mboxname_isusermailbox(action->name, 1);
	    if (userid && !strcmp(userid, action->user)) {
		sync_action_list_add(user_list, NULL, action->user);
		if (verbose) {
		    printf("  Promoting: SEEN %s %s -> USER %s\n",
			   action->user, action->name, action->user);
		}
		if (verbose_logging) {
		    syslog(LOG_INFO, "  Promoting: SEEN %s %s -> USER %s",
			   action->user, action->name, action->user);
		}
	    } else {
		sync_action_list_add(meta_list, NULL, action->user);
		if (verbose) {
		    printf("  Promoting: SEEN %s %s -> META %s\n",
			   action->user, action->name, action->user);
		}
		if (verbose_logging) {
		    syslog(LOG_INFO, "  Promoting: SEEN %s %s -> META %s",
			   action->user, action->name, action->user);
		}
	    }
	}
    }

    for (action = sub_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

        if (user_sub(action->user, action->name)) {
            sync_action_list_add(meta_list, NULL, action->user);
            if (verbose) {
                printf("  Promoting: SUB %s %s -> META %s\n",
                       action->user, action->name, action->user);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: SUB %s %s -> META %s",
                       action->user, action->name, action->name);
            }
        }
    }

    for (action = mailbox_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	sync_name_list_add(mboxname_list, action->name);
    }

    if (mboxname_list->count) {
	int nonuser = 0;
	r = sync_do_mailboxes(mboxname_list, NULL, sync_backend, flags);
	if (r) {
	    /* promote failed personal mailboxes to USER */
	    struct sync_name *mbox;
	    char *userid, *p, *useridp;

	    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
		/* done OK?  Good :) */
		if (mbox->mark)
		    continue;

		useridp = mboxname_isusermailbox(mbox->name, 0);
		if (useridp) {
		    userid = xstrdup(useridp);
		    if ((p = strchr(userid, '.'))) *p = '\0';
		    mbox->mark = 1;

		    sync_action_list_add(user_list, NULL, userid);
		    if (verbose) {
			printf("  Promoting: MAILBOX %s -> USER %s\n",
			       mbox->name, userid);
		    }
		    if (verbose_logging) {
			syslog(LOG_INFO, "  Promoting: MAILBOX %s -> USER %s",
			       mbox->name, userid);
		    }
		    free(userid);
		}
		else
		    nonuser = 1;
	    }
	}

	if (r && nonuser) goto cleanup;
    }

    for (action = meta_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	r = sync_do_meta(action->user, sync_backend, flags);
	if (r) {
	    if (r == IMAP_INVALID_USER) goto cleanup;

	    sync_action_list_add(user_list, NULL, action->user);
	    if (verbose) {
		printf("  Promoting: META %s -> USER %s\n",
		       action->user, action->user);
	    }
	    if (verbose_logging) {
		syslog(LOG_INFO, "  Promoting: META %s -> USER %s",
		       action->user, action->user);
	    }
	}
    }

    for (action = user_list->head; action; action = action->next) {
	r = sync_do_user(action->user, NULL, sync_backend, flags);
	if (r) goto cleanup;
    }

  cleanup:
    if (doclose) close(fd);

    if (r) {
	if (verbose)
	    fprintf(stderr, "Error in do_sync(): bailing out! %s\n", error_message(r));

	syslog(LOG_ERR, "Error in do_sync(): bailing out! %s", error_message(r));
    }

    sync_action_list_free(&user_list);
    sync_action_list_free(&meta_list);
    sync_action_list_free(&mailbox_list);
    sync_action_list_free(&quota_list);
    sync_action_list_free(&annot_list);
    sync_action_list_free(&seen_list);
    sync_action_list_free(&sub_list);
    sync_name_list_free(&mboxname_list);

    return r;
}

/* ====================================================================== */

enum {
    RESTART_NONE = 0,
    RESTART_NORMAL,
    RESTART_RECONNECT
};

int do_daemon_work(const char *sync_log_file, const char *sync_shutdown_file,
		   unsigned long timeout, unsigned long min_delta,
		   int *restartp)
{
    int r = 0;
    char *work_file_name;
    time_t session_start;
    time_t single_start;
    int    delta;
    struct stat sbuf;
    int restartcnt = 0;

    *restartp = RESTART_NONE;

    /* Create a work log filename.  Use the PID so we can
     * try to reprocess it if the sync fails */
    work_file_name = xmalloc(strlen(sync_log_file)+20);
    snprintf(work_file_name, strlen(sync_log_file)+20,
             "%s-%d", sync_log_file, getpid());

    session_start = time(NULL);

    while (1) {
        single_start = time(NULL);

        signals_poll();

	/* Check for shutdown file */
        if (sync_shutdown_file && !stat(sync_shutdown_file, &sbuf)) {
            unlink(sync_shutdown_file);
            break;
        }

	/* See if its time to RESTART */
        if ((timeout > 0) &&
	    ((single_start - session_start) > (time_t) timeout)) {
            *restartp = RESTART_NORMAL;
            break;
        }

        if (stat(work_file_name, &sbuf) == 0) {
	    /* Existing work log file from our parent < 1 hour old */
	    /* XXX  Is 60 minutes a resonable timeframe? */
	    syslog(LOG_NOTICE,
		   "Reprocessing sync log file %s", work_file_name);
	}
	else {
	    /* Check for sync_log file */
	    if (stat(sync_log_file, &sbuf) < 0) {
		if (min_delta > 0) {
		    sleep(min_delta);
		} else {
		    usleep(100000);    /* 1/10th second */
		}
		continue;
	    }

	    /* Move sync_log to our work file */
	    if (rename(sync_log_file, work_file_name) < 0) {
		syslog(LOG_ERR, "Rename %s -> %s failed: %m",
		       sync_log_file, work_file_name);
		r = IMAP_IOERROR;
		break;
	    }
	}

	/* Process the work log */
        if ((r=do_sync(work_file_name))) {
	    syslog(LOG_ERR,
		   "Processing sync log file %s failed: %s",
		   work_file_name, error_message(r));
	    break;
	}

	/* Remove the work log */
        if (unlink(work_file_name) < 0) {
            syslog(LOG_ERR, "Unlink %s failed: %m", work_file_name);
	    r = IMAP_IOERROR;
	    break;
        }
        delta = time(NULL) - single_start;

        if (((unsigned) delta < min_delta) && ((min_delta-delta) > 0))
            sleep(min_delta-delta);
    }
    free(work_file_name);

    if (*restartp == RESTART_NORMAL) {
	if (sync_out->userdata) {
	    /* IMAP flavor (w/ tag) */
	    prot_printf(sync_out, "R%d SYNC", restartcnt++);
	}
	prot_printf(sync_out, "RESTART\r\n"); 
	prot_flush(sync_out);

	r = sync_parse_response("RESTART", sync_in, NULL);

	if (r) {
	    syslog(LOG_ERR, "sync_client RESTART failed: %s",
		   error_message(r));
	} else {
	    syslog(LOG_INFO, "sync_client RESTART succeeded");
	}
	r = 0;
    }

    return(r);
}

static int get_intconfig(const char *channel, const char *val)
{
    int response = -1;

    if (channel) {
	const char *result = NULL;
	char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
	snprintf(name, MAX_MAILBOX_NAME, "%s_%s", channel, val);
	result = config_getoverflowstring(name, NULL);
	if (result) response = atoi(result);
    }

    if (response == -1) {
	if (!strcmp(val, "sync_repeat_interval"))
	    response = config_getint(IMAPOPT_SYNC_REPEAT_INTERVAL);
    }

    return response;
}

static const char *get_config(const char *channel, const char *val)
{
    const char *response = NULL;

    if (channel) {
	char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
	snprintf(name, MAX_MAILBOX_NAME, "%s_%s", channel, val);
	response = config_getoverflowstring(name, NULL);
    }

    if (!response) {
	/* get the core value */
	if (!strcmp(val, "sync_host"))
	    response = config_getstring(IMAPOPT_SYNC_HOST);
	else if (!strcmp(val, "sync_authname"))
	    response = config_getstring(IMAPOPT_SYNC_AUTHNAME);
	else if (!strcmp(val, "sync_password"))
	    response = config_getstring(IMAPOPT_SYNC_PASSWORD);
	else if (!strcmp(val, "sync_realm"))
	    response = config_getstring(IMAPOPT_SYNC_REALM);
	else if (!strcmp(val, "sync_port"))
	    response = config_getstring(IMAPOPT_SYNC_PORT);
	else if (!strcmp(val, "sync_shutdown_file"))
	    response = config_getstring(IMAPOPT_SYNC_SHUTDOWN_FILE);
	else
	    fatal("unknown config variable requested", EC_SOFTWARE);
    }

    return response;
}

void replica_connect(const char *channel)
{
    int wait;
    struct protoent *proto;
    sasl_callback_t *cb;
    const char *port, *auth_status = NULL;

    cb = mysasl_callbacks(NULL,
			  get_config(channel, "sync_authname"),
			  get_config(channel, "sync_realm"),
			  get_config(channel, "sync_password"));

    /* get the right port */
    port = get_config(channel, "sync_port");
    if (port) imap_csync_protocol.service = port;

    for (wait = 15;; wait *= 2) {
	sync_backend = backend_connect(sync_backend, servername,
				       &imap_csync_protocol, "", cb,
				       &auth_status);

	if (sync_backend || auth_status || connect_once || wait > 1000) break;

	fprintf(stderr,
		"Can not connect to server '%s', retrying in %d seconds\n",
		servername, wait);
	sleep(wait);
    }

    if (sync_backend) {
	if (sync_backend->capability & CAPA_REPLICATION) {
	    /* attach our IMAP tag buffer to our protstreams as userdata */
	    sync_backend->in->userdata = sync_backend->out->userdata = &tagbuf;
	}
	else {
	    backend_disconnect(sync_backend);
	    sync_backend = NULL;
	}
    }

    if (!sync_backend) {
	if (port) csync_protocol.service = port;

	for (wait = 15;; wait *= 2) {
	    sync_backend = backend_connect(sync_backend, servername,
					   &csync_protocol, "", cb, NULL);

	    if (sync_backend || connect_once || wait > 1000) break;

	    fprintf(stderr,
		    "Can not connect to server '%s', retrying in %d seconds\n",
		    servername, wait);
	    sleep(wait);
	}
    }

    if (!sync_backend) {
	fprintf(stderr, "Can not connect to server '%s'\n",
		servername);
	syslog(LOG_ERR, "Can not connect to server '%s'", servername);
	_exit(1);
    }

    /* Disable Nagle's Algorithm => increase throughput
     *
     * http://en.wikipedia.org/wiki/Nagle's_algorithm
     */ 
    if (servername[0] != '/') {
	if (sync_backend->sock >= 0 && (proto = getprotobyname("tcp")) != NULL) {
	    int on = 1;

	    if (setsockopt(sync_backend->sock, proto->p_proto, TCP_NODELAY,
			   (void *) &on, sizeof(on)) != 0) {
		syslog(LOG_ERR, "unable to setsocketopt(TCP_NODELAY): %m");
	    }

	    /* turn on TCP keepalive if set */
	    if (config_getswitch(IMAPOPT_TCP_KEEPALIVE)) {
		int r;
		int optval = 1;
		socklen_t optlen = sizeof(optval);
		struct protoent *proto = getprotobyname("TCP");

		r = setsockopt(sync_backend->sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
		if (r < 0) {
		    syslog(LOG_ERR, "unable to setsocketopt(SO_KEEPALIVE): %m");
		}
#ifdef TCP_KEEPCNT
		optval = config_getint(IMAPOPT_TCP_KEEPALIVE_CNT);
		if (optval) {
		    r = setsockopt(sync_backend->sock, proto->p_proto, TCP_KEEPCNT, &optval, optlen);
		    if (r < 0) {
			syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPCNT): %m");
		    }
		}
#endif
#ifdef TCP_KEEPIDLE
		optval = config_getint(IMAPOPT_TCP_KEEPALIVE_IDLE);
		if (optval) {
		    r = setsockopt(sync_backend->sock, proto->p_proto, TCP_KEEPIDLE, &optval, optlen);
		    if (r < 0) {
			syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPIDLE): %m");
		    }
		}
#endif
#ifdef TCP_KEEPINTVL
		optval = config_getint(IMAPOPT_TCP_KEEPALIVE_INTVL);
		if (optval) {
		    r = setsockopt(sync_backend->sock, proto->p_proto, TCP_KEEPINTVL, &optval, optlen);
		    if (r < 0) {
			syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPINTVL): %m");
		    }
		}
#endif
	    }
	} else {
	    syslog(LOG_ERR, "unable to getprotobyname(\"tcp\"): %m");
	}
    }

#ifdef HAVE_ZLIB
    /* check if we should compress */
    if (do_compress || config_getswitch(IMAPOPT_SYNC_COMPRESS)) {
	prot_printf(sync_backend->out, "%s\r\n",
		    sync_backend->prot->u.std.compress_cmd.cmd);
        prot_flush(sync_backend->out);

        if (sync_parse_response("COMPRESS", sync_backend->in, NULL)) {
	    syslog(LOG_ERR, "Failed to enable compression, continuing uncompressed");
	}
	else {
	    prot_setcompress(sync_backend->in);
	    prot_setcompress(sync_backend->out);
        }
    }
#endif

    /* links to sockets */
    sync_in = sync_backend->in;
    sync_out = sync_backend->out;

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(sync_in, 1);
    prot_setisclient(sync_out, 1);

}

static void replica_disconnect()
{
    backend_disconnect(sync_backend);
}

void do_daemon(const char *sync_log_file, const char *sync_shutdown_file,
	       const char *channel, unsigned long timeout, unsigned long min_delta)
{
    int r = 0;
    int restart = 1;

    signal(SIGPIPE, SIG_IGN); /* don't fail on server disconnects */

    while (restart) {
	replica_connect(channel);
	r = do_daemon_work(sync_log_file, sync_shutdown_file,
			   timeout, min_delta, &restart);
	if (r) {
	    /* See if we're still connected to the server.
	     * If we are, we had some type of error, so we exit.
	     * Otherwise, try reconnecting.
	     */
	    if (!backend_ping(sync_backend, NULL)) restart = 1;
	}
	replica_disconnect();
    }
}

/* ====================================================================== */

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

enum {
    MODE_UNKNOWN = -1,
    MODE_REPEAT,
    MODE_USER,
    MODE_MAILBOX,
    MODE_META
};

int main(int argc, char **argv)
{
    int   opt, i = 0;
    char *alt_config     = NULL;
    char *input_filename = NULL;
    int   r = 0;
    int   exit_rc = 0;
    int   mode = MODE_UNKNOWN;
    int   wait     = 0;
    int   timeout  = 600;
    int   min_delta = 0;
    const char *sync_log_file;
    const char *channel = NULL;
    const char *sync_shutdown_file = NULL;
    const char *partition = NULL;
    char buf[512];
    FILE *file;
    int len;
    int config_virtdomains;
    struct sync_name_list *mboxname_list;
    char mailboxname[MAX_MAILBOX_BUFFER];

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vlLS:F:f:w:t:d:n:rRumsozp:")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'o': /* only try to connect once */
            connect_once = 1;
            break;

        case 'v': /* verbose */
            verbose++;
            break;

        case 'l': /* verbose Logging */
            verbose_logging++;
            break;

	case 'L': /* local mailbox operations only */
	    flags |= SYNC_FLAG_LOCALONLY;
	    break;

	case 'S': /* Socket descriptor for server */
	    servername = optarg;
	    break;

        case 'F': /* Shutdown file */
            sync_shutdown_file = optarg;
            break;

        case 'f': /* input_filename used by user and mailbox modes; OR
		     alternate sync_log_file used by single-run repeat mode */
            input_filename = optarg;
            break;

        case 'n':
	    channel = optarg;
	    break;

        case 'w':
            wait = atoi(optarg);
            break;

        case 't':
            timeout = atoi(optarg);
            break;

        case 'd':
            min_delta = atoi(optarg);
            break;

        case 'r':
	    background = 1;
	    /* fallthrough */

        case 'R':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_REPEAT;
            break;

        case 'u':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_USER;
            break;

        case 'm':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_MAILBOX;
            break;

        case 's':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_META;
            break;

	case 'z':
#ifdef HAVE_ZLIB
	    do_compress = 1;
#else
	    fatal("Compress not available without zlib compiled in", EC_SOFTWARE);
#endif
	    break;

        case 'p':
	    partition = optarg;
	    break;

        default:
            usage("sync_client");
        }
    }

    if (mode == MODE_UNKNOWN)
        fatal("No replication mode specified", EC_USAGE);

    if (verbose) flags |= SYNC_FLAG_VERBOSE;
    if (verbose_logging) flags |= SYNC_FLAG_LOGGING;

    /* fork if required */
    if (background && !input_filename) {
	int pid = fork();

	if (pid == -1) {
	    perror("fork");
	    exit(1);
	}

	if (pid != 0) { /* parent */
	    exit(0);
	}
    }

    cyrus_init(alt_config, "sync_client", 0);

    /* get the server name if not specified */
    if (!servername)
	servername = get_config(channel, "sync_host");

    if (!servername)
        fatal("sync_host not defined", EC_SOFTWARE);

    /* Just to help with debugging, so we have time to attach debugger */
    if (wait > 0) {
        fprintf(stderr, "Waiting for %d seconds for gdb attach...\n", wait);
        sleep(wait);
    }

    /* Set namespace -- force standard (internal) */
    config_virtdomains = config_getenum(IMAPOPT_VIRTDOMAINS);
    if ((r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for real work */
    quotadb_init(0);
    quotadb_open(NULL);

    /* open the annotation db */
    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    /* load the SASL plugins */
    global_sasl_init(1, 0, mysasl_cb);

    switch (mode) {
    case MODE_USER:
	/* Open up connection to server */
	replica_connect(channel);

	if (input_filename) {
	    if ((file=fopen(input_filename, "r")) == NULL) {
		syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
		shut_down(1);
	    }
	    while (fgets(buf, sizeof(buf), file)) {
		/* Chomp, then ignore empty/comment lines. */
		if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
		    buf[--len] = '\0';

		if ((len == 0) || (buf[0] == '#'))
		    continue;

		mboxname_hiersep_tointernal(&sync_namespace, buf,
					    config_virtdomains ?
					    strcspn(buf, "@") : 0);
		if (sync_do_user(buf, partition, sync_backend, flags)) {
		    if (verbose)
			fprintf(stderr,
				"Error from do_user(%s): bailing out!\n",
				buf);
		    syslog(LOG_ERR, "Error in do_user(%s): bailing out!",
			   buf);
		    exit_rc = 1;
		}
	    }
	    fclose(file);
	} else for (i = optind; !r && i < argc; i++) {
	    mboxname_hiersep_tointernal(&sync_namespace, argv[i],
					config_virtdomains ?
					strcspn(argv[i], "@") : 0);
	    if (sync_do_user(argv[i], partition, sync_backend, flags)) {
		if (verbose)
		    fprintf(stderr, "Error from do_user(%s): bailing out!\n",
			    argv[i]);
		syslog(LOG_ERR, "Error in do_user(%s): bailing out!", argv[i]);
		exit_rc = 1;
	    }
	}

	replica_disconnect();
	break;

    case MODE_MAILBOX:
	/* Open up connection to server */
	replica_connect(channel);

	mboxname_list = sync_name_list_create();
	if (input_filename) {
	    if ((file=fopen(input_filename, "r")) == NULL) {
		syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
		shut_down(1);
	    }
	    while (fgets(buf, sizeof(buf), file)) {
		/* Chomp, then ignore empty/comment lines. */
		if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
		    buf[--len] = '\0';

		if ((len == 0) || (buf[0] == '#'))
		    continue;

		(*sync_namespace.mboxname_tointernal)(&sync_namespace, buf,
						      NULL, mailboxname);
		if (!sync_name_lookup(mboxname_list, mailboxname))
		    sync_name_list_add(mboxname_list, mailboxname);
	    }
	    fclose(file);
	} else for (i = optind; i < argc; i++) {
	    (*sync_namespace.mboxname_tointernal)(&sync_namespace, argv[i],
						   NULL, mailboxname);
	    if (!sync_name_lookup(mboxname_list, mailboxname))
		sync_name_list_add(mboxname_list, mailboxname);
	}

	if (sync_do_mailboxes(mboxname_list, partition, sync_backend, flags)) {
	    if (verbose) {
		fprintf(stderr,
			"Error from do_mailboxes(): bailing out!\n");
	    }
	    syslog(LOG_ERR, "Error in do_mailboxes(): bailing out!");
	    exit_rc = 1;
	}

	sync_name_list_free(&mboxname_list);
	replica_disconnect();
	break;

    case MODE_META:
	/* Open up connection to server */
	replica_connect(channel);

        for (i = optind; i < argc; i++) {
	    mboxname_hiersep_tointernal(&sync_namespace, argv[i],
					config_virtdomains ?
					strcspn(argv[i], "@") : 0);
	    if (sync_do_meta(argv[i], sync_backend, flags)) {
		if (verbose) {
		    fprintf(stderr,
			    "Error from do_meta(%s): bailing out!\n",
			    argv[i]);
		}
		syslog(LOG_ERR, "Error in do_meta(%s): bailing out!",
		       argv[i]);
		exit_rc = 1;
	    }
	}

	replica_disconnect();

	break;

    case MODE_REPEAT:
	if (input_filename) {
	    /* Open up connection to server */
	    replica_connect(channel);

	    exit_rc = do_sync(input_filename);

	    replica_disconnect();
	}
	else {
	    /* rolling replication */
	    sync_log_file = sync_log_fname(channel);

	    if (!sync_shutdown_file)
		sync_shutdown_file = get_config(channel, "sync_shutdown_file");

	    if (!min_delta)
		min_delta = get_intconfig(channel, "sync_repeat_interval");

	    do_daemon(sync_log_file, sync_shutdown_file, channel, timeout, min_delta);
	}

	break;

    default:
	if (verbose) fprintf(stderr, "Nothing to do!\n");
	break;
    }

    buf_free(&tagbuf);

    shut_down(exit_rc);
}
