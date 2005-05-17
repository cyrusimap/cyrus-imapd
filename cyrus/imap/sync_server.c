/* sync_server.c -- Cyrus synchonization server
 *
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 *
 * $Id: sync_server.c,v 1.1.2.15 2005/05/17 18:29:46 ken3 Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "imap_err.h"
#include "imparse.h"
#include "iptostring.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "prot.h"
#include "quota.h"
#include "retry.h"
#include "seen.h"
#include "spool.h"
#include "telemetry.h"
#include "tls.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"

#include "sync_support.h"
#include "sync_commit.h"
/*#include "cdb.h"*/

extern int optind;
extern char *optarg;
extern int opterr;

/* for config.c */
const int config_need_data = 0;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;

void printastring(const char *s __attribute__((unused)))
{
    fatal("not implemented", EC_SOFTWARE);
}
/* end stuff to make index.c link */

#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *sync_saslconn; /* the sasl connection context */

char *sync_userid = 0;
struct namespace sync_namespace;
struct namespace *sync_namespacep = &sync_namespace;
struct auth_state *sync_authstate = 0;
int sync_userisadmin = 0;
struct sockaddr_storage sync_localaddr, sync_remoteaddr;
int sync_haveaddr = 0;
char sync_clienthost[NI_MAXHOST*2+1] = "[local]";
struct protstream *sync_out = NULL;
struct protstream *sync_in = NULL;
static int sync_logfd = -1;

int sync_starttls_done = 0;

static void cmdloop(void);
static void cmd_authenticate(char *mech, char *resp);
static void cmd_starttls(void);
static void cmd_lock(struct sync_lock *lock);
static void cmd_unlock(struct sync_lock *lock, int restart);
static void cmd_select(struct mailbox **mailboxp, char *name);
static void cmd_reserve(char *mailbox_name,
			struct sync_message_list *message_list);
static void cmd_quota_work(char *quotaroot);
static void cmd_quota(char *quotaroot);
static void cmd_setquota(char *root, int limit);
static void cmd_reset(char *user);
static void cmd_status(struct mailbox *mailbox);
static void cmd_upload(struct mailbox *mailbox,
		       struct sync_message_list *message_list,
		       unsigned long new_last_uid, time_t last_appenddate);
static void cmd_uidlast(struct mailbox *mailbox, unsigned long last_uid,
			time_t last_appenddate);
static void cmd_setflags(struct mailbox *mailbox);
static void cmd_setseen(struct mailbox **mailboxp, char *user, char *mboxname,
			time_t lastread, unsigned int last_recent_uid,
			time_t lastchange, char *seenuid);
static void cmd_setseen_all(char *user, struct buf *data);
static void cmd_setacl(char *name, char *acl);
static void cmd_expunge(struct mailbox *mailbox);
static void cmd_mailboxes();
static void cmd_user(char *userid);
static void cmd_create(char *mailboxname, char *partition,
		       char *uniqueid, char *acl,
		       int mbtype, unsigned long uidvalidity);
static void cmd_delete(char *name);
static void cmd_rename(char *oldmailboxname, char *newmailboxname);
static void cmd_lsub(char *user);
static void cmd_addsub(char *user, char *name);
static void cmd_delsub(char *user, char *name);
static void cmd_set_annotation(char *mailboxname, char *entry, char *userid,
			       char *value);
static void cmd_list_annotations(char *mailboxname);
static void cmd_list_sieve(char *user);
static void cmd_get_sieve(char *user, char *name);
static void cmd_upload_sieve(char *user, char *name, unsigned long last_update);
static void cmd_activate_sieve(char *user, char *name);
static void cmd_deactivate_sieve(char *user);
static void cmd_delete_sieve(char *user, char *name);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));


extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);

extern int saslserver(sasl_conn_t *conn, const char *mech,
		      const char *init_resp, const char *resp_prefix,
		      const char *continuation, const char *empty_resp,
		      struct protstream *pin, struct protstream *pout,
		      int *sasl_result, char **success_data);

static struct {
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

/* the sasl proxy policy context */
static struct proxy_context sync_proxyctx = {
    0, 1, &sync_authstate, &sync_userisadmin, NULL
};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_proxy_policy, (void*) &sync_proxyctx },
    { SASL_CB_CANON_USER, &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static void sync_reset(void)
{
    int i;

    proc_cleanup();

    if (sync_in) {
	prot_NONBLOCK(sync_in);
	prot_fill(sync_in);
	
	prot_free(sync_in);
    }

    if (sync_out) {
	prot_flush(sync_out);
	prot_free(sync_out);
    }
    
    sync_in = sync_out = NULL;

#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    strcpy(sync_clienthost, "[local]");
    if (sync_logfd != -1) {
	close(sync_logfd);
	sync_logfd = -1;
    }
    if (sync_userid != NULL) {
	free(sync_userid);
	sync_userid = NULL;
    }
    if (sync_authstate) {
	auth_freestate(sync_authstate);
	sync_authstate = NULL;
    }
    if (sync_saslconn) {
	sasl_dispose(&sync_saslconn);
	sync_saslconn = NULL;
    }
    sync_starttls_done = 0;

    if(saslprops.iplocalport) {
       free(saslprops.iplocalport);
       saslprops.iplocalport = NULL;
    }
    if(saslprops.ipremoteport) {
       free(saslprops.ipremoteport);
       saslprops.ipremoteport = NULL;
    }
    if(saslprops.authid) {
       free(saslprops.authid);
       saslprops.authid = NULL;
    }
    saslprops.ssf = 0;
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int opt, r;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    while ((opt = getopt(argc, argv, "")) != EOF) {
	switch(opt) {
	default:
	    usage();
	}
    }

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(sync_namespacep, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for real work */
    quotadb_init(0);
    quotadb_open(NULL);

    /* Initialize the annotatemore extention */
    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    return 0;
}

/*
 * Issue the capability banner
 */
static void dobanner(void)
{
    const char *mechlist;
    unsigned int mechcount;

    if (sasl_listmech(sync_saslconn, NULL,
		      "* SASL ", " ", "\r\n",
		      &mechlist, NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_printf(sync_out, "%s", mechlist);
    }

    if (tls_enabled() && !sync_starttls_done) {
	prot_printf(sync_out, "* STARTTLS\r\n");
    }

    prot_printf(sync_out,
		"* OK %s Cyrus sync server %s\r\n",
		config_servername, CYRUS_VERSION);

    prot_flush(sync_out);
}

/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    socklen_t salen;
    char localip[60], remoteip[60];
    char hbuf[NI_MAXHOST];
    int niflags;
    int timeout;
    sasl_security_properties_t *secprops = NULL;

    signals_poll();

    sync_in = prot_new(0, 0);
    sync_out = prot_new(1, 1);

    /* Find out name of client host */
    salen = sizeof(sync_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&sync_remoteaddr, &salen) == 0 &&
	(sync_remoteaddr.ss_family == AF_INET ||
	 sync_remoteaddr.ss_family == AF_INET6)) {
	if (getnameinfo((struct sockaddr *)&sync_remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
	    strncpy(sync_clienthost, hbuf, sizeof(hbuf));
	    strlcat(sync_clienthost, " ", sizeof(sync_clienthost));
	    sync_clienthost[sizeof(sync_clienthost)-30] = '\0';
	} else {
	    sync_clienthost[0] = '\0';
	}
	niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	if (((struct sockaddr *)&sync_remoteaddr)->sa_family == AF_INET6)
	    niflags |= NI_WITHSCOPEID;
#endif
	if (getnameinfo((struct sockaddr *)&sync_remoteaddr, salen, hbuf,
			sizeof(hbuf), NULL, 0, niflags) != 0)
	    strlcpy(hbuf, "unknown", sizeof(hbuf));
	strlcat(sync_clienthost, "[", sizeof(sync_clienthost));
	strlcat(sync_clienthost, hbuf, sizeof(sync_clienthost));
	strlcat(sync_clienthost, "]", sizeof(sync_clienthost));
	salen = sizeof(sync_localaddr);
	if (getsockname(0, (struct sockaddr *)&sync_localaddr, &salen) == 0) {
	    sync_haveaddr = 1;
	}
    }

    /* other params should be filled in */
    if (sasl_server_new("csync", config_servername, NULL, NULL, NULL,
			NULL, 0, &sync_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    sasl_setprop(sync_saslconn, SASL_SEC_PROPS, secprops);
    
    if(iptostring((struct sockaddr *)&sync_localaddr, salen,
		  localip, 60) == 0) {
	sasl_setprop(sync_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }
    
    if(iptostring((struct sockaddr *)&sync_remoteaddr, salen,
		  remoteip, 60) == 0) {
	sasl_setprop(sync_saslconn, SASL_IPREMOTEPORT, remoteip);  
	saslprops.ipremoteport = xstrdup(remoteip);
    }

    proc_register("sync_server", sync_clienthost, NULL, NULL);
#if 0
    /* Set inactivity timer */
    timeout = config_getint(IMAPOPT_TIMEOUT);
    if (timeout < 3) timeout = 3;
    prot_settimeout(sync_in, timeout*60);
#endif
    prot_setflushonread(sync_in, sync_out);

    dobanner();

    cmdloop();

    /* EXIT executed */

    /* cleanup */
    sync_reset();

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

void usage(void)
{
    prot_printf(sync_out, "* usage: sync_server [-C <alt_config>]\r\n");
    prot_flush(sync_out);
    exit(EC_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    int i;

    proc_cleanup();

    seen_done();
    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    annotatemore_close();
    annotatemore_done();

    if (sync_in) {
	prot_NONBLOCK(sync_in);
	prot_fill(sync_in);
	prot_free(sync_in);
    }

    if (sync_out) {
	prot_flush(sync_out);
	prot_free(sync_out);
    }

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    cyrus_done();

    exit(code);
}

void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	proc_cleanup();
	exit(recurse_code);
    }
    recurse_code = code;
    if (sync_out) {
	prot_printf(sync_out, "* Fatal error: %s\r\n", s);
	prot_flush(sync_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn) 
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("csync", config_servername,
                         NULL, NULL, NULL,
                         NULL, 0, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
                          saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;
    
    if(saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
                          saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
       ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    }

    if(ret != SASL_OK) return ret;

    if(saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

static void cmdloop(void)
{
    struct sync_message_list *message_list;
    struct mailbox *mailbox = NULL;
    struct sync_lock sync_lock;
    static struct buf cmd;
    static struct buf arg1, arg2, arg3, arg4, arg5, arg6;
    int c;
    char *p;

    syslog(LOG_DEBUG, "cmdloop(): startup");

    message_list = sync_message_list_create(SYNC_MESSAGE_LIST_HASH_SIZE,
                                            SYNC_MESSAGE_LIST_MAX_OPEN_FILES);

    if (message_list == NULL) {
        fatal("* [BYE] Unable to start up server", EC_TEMPFAIL);
    }

    sync_lock_reset(&sync_lock);

    for (;;) {
        prot_flush(sync_out);

	/* Parse command name */
	if ((c = getword(sync_in, &cmd)) == EOF)
            break;

	if (!cmd.s[0]) {
	    prot_printf(sync_out, "BAD Null command\r\n");
	    eatline(sync_in, c);
	    continue;
	}

	if (islower((unsigned char) cmd.s[0])) 
	    cmd.s[0] = toupper((unsigned char) cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
	}

	/* Only Authenticate/Exit/Restart/Starttls
	   allowed when not logged in */
	if (!sync_userid && !strchr("AERS", cmd.s[0])) goto nologin;
    
	/* Must be an admin */
	if (sync_userid && !sync_userisadmin) goto noperm;

	switch (cmd.s[0]) {
        case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		int haveinitresp = 0;

		if (c != ' ') goto missingargs;
		c = getword(sync_in, &arg1);
		if (!imparse_isatom(arg1.s)) {
		    prot_printf(sync_out, "BAD Invalid authenticate mechanism\r\n");
		    eatline(sync_in, c);
		    continue;
		}
		if (c == ' ') {
		    haveinitresp = 1;
		    c = getword(sync_in, &arg2);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
		
		if (sync_userid) {
		    prot_printf(sync_out, "BAD Already authenticated\r\n");
		    continue;
		}
		cmd_authenticate(arg1.s, haveinitresp ? arg2.s : NULL);
		continue;
	    }
	    else if (!sync_userid) goto nologin;
            else if (!strcmp(cmd.s, "Addsub")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_addsub(arg1.s, arg2.s);
                continue;
            }
	    else if (!strcmp(cmd.s, "Activate_sieve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_activate_sieve(arg1.s, arg2.s);
                continue;
            }
            break;
	case 'C':
            if (!strcmp(cmd.s, "Create")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg3);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg4);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg5);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg6);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                if (!imparse_isnumber(arg5.s) || !imparse_isnumber(arg6.s))
                    goto invalidargs;

                cmd_create(arg1.s, arg2.s, arg3.s, arg4.s,
                           atoi(arg4.s), sync_atoul(arg5.s));
                continue;
            }
            break;
        case 'D':
            if (!strcmp(cmd.s, "Delete")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_delete(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "Delsub")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_delsub(arg1.s, arg2.s);
                continue;
            } else if (!strcmp(cmd.s, "Deactivate_sieve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_deactivate_sieve(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "Delete_sieve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_delete_sieve(arg1.s, arg2.s);
                continue;
            }
            break;
	case 'E':
	    if (!strcmp(cmd.s, "Exit")) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                prot_printf(sync_out, "OK Finished\r\n");
                prot_flush(sync_out);
                goto exit;
                break;
            }
	    else if (!sync_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Expunge")) {
		if (c != ' ') goto missingargs;
                cmd_expunge(mailbox);
                continue;
            }

            break;
        case 'G':
            if (!strcmp(cmd.s, "Get_sieve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_get_sieve(arg1.s, arg2.s);
                continue;
            }
            break;
        case 'L':
	    if (!strcmp(cmd.s, "Lsub")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_lsub(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "List_annotations")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_list_annotations(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "List_sieve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_list_sieve(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "Lock")) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_lock(&sync_lock);
                continue;
            }
            break;
	case 'M':
	    if (!strcmp(cmd.s, "Mailboxes")) {
		if (c != ' ') goto missingargs;
                cmd_mailboxes();
                continue;
	    }
	    break;
	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

		prot_printf(sync_out, "OK Noop completed\r\n");
                continue;
	    }
	    break;
        case 'Q':
            if (!strcmp(cmd.s, "Quota")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                cmd_quota(arg1.s);
                continue;
            }
        case 'R':
	    if (!strcmp(cmd.s, "Restart")) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                prot_printf(sync_out, "OK Restarting\r\n");
                prot_flush(sync_out);
                goto exit;
                break;
            }
	    else if (!sync_userid) goto nologin;
            else if (!strcmp(cmd.s, "Rename")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                cmd_rename(arg1.s, arg2.s);
                continue;
            } else if (!strcmp(cmd.s, "Reset")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_reset(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "Reserve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;

                /* Let cmd_reserve() process list of Message-UUIDs */
                cmd_reserve(arg1.s, message_list);
                continue;
            }
            break;
        case 'S':
	    if (!strcmp(cmd.s, "Starttls") && tls_enabled()) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

		/* if we've already done SASL fail */
		if (sync_userid != NULL) {
		    prot_printf(sync_out, 
				"BAD Can't Starttls after authentication\r\n");
		    continue;
		}
		
		/* check if already did a successful tls */
		if (sync_starttls_done == 1) {
		    prot_printf(sync_out, 
				"BAD Already did a successful Starttls\r\n");
		    continue;
		}
		cmd_starttls();
		continue;
	    }
	    else if (!sync_userid) goto nologin;
            else if (!strcmp(cmd.s, "Select")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
		cmd_select(&mailbox, arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "Status")) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_status(mailbox);
                continue;
            } else if (!strcmp(cmd.s, "Setflags")) {
		if (c != ' ') goto missingargs;
                cmd_setflags(mailbox);
                continue;
            } else if (!strcmp(cmd.s, "Setseen")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg3);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg4);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg5);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg6);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                if (!imparse_isnumber(arg3.s) ||
                    !imparse_isnumber(arg4.s) ||
                    !imparse_isnumber(arg5.s))
                    goto invalidargs;

                cmd_setseen(&mailbox, arg1.s, arg2.s,
                            sync_atoul(arg3.s), sync_atoul(arg4.s),
                            sync_atoul(arg5.s), arg6.s);
                continue;

            } else if (!strcmp(cmd.s, "Setseen_all")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getbastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                cmd_setseen_all(arg1.s, &arg2);
                continue;

            } else if (!strcmp(cmd.s, "Setacl")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                cmd_setacl(arg1.s, arg2.s);
                continue;
            } else if (!strcmp(cmd.s, "Setquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                if (strcmp(arg2.s, "-1") &&
		    !imparse_isnumber(arg2.s)) goto invalidargs;

                cmd_setquota(arg1.s, sync_atoul(arg2.s));
                continue;
            }
            else if (!strcmp(cmd.s, "Setannotation")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg3);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg4);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_set_annotation(arg1.s, arg2.s, arg3.s, arg4.s);
                continue;
            }
	    break;
	case 'U':
            if (!strcmp(cmd.s, "Upload")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c != ' ') goto missingargs;

                if (!imparse_isnumber(arg1.s)) goto invalidargs;
                if (!imparse_isnumber(arg2.s)) goto invalidargs;

                cmd_upload(mailbox, message_list,
                           sync_atoul(arg1.s), sync_atoul(arg2.s));
                continue;
            } else if (!strcmp(cmd.s, "Uidlast")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                if (!imparse_isnumber(arg1.s)) goto invalidargs;
                if (!imparse_isnumber(arg2.s)) goto invalidargs;

                cmd_uidlast(mailbox, sync_atoul(arg1.s), sync_atoul(arg2.s));
                continue;
            } else if (!strcmp(cmd.s, "User")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
                cmd_user(arg1.s);
                continue;
            } else if (!strcmp(cmd.s, "Upload_sieve")) {
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg2);
		if (c != ' ') goto missingargs;
		c = getastring(sync_in, sync_out, &arg3);
		if (c != ' ') goto missingargs;
                if (!imparse_isnumber(arg3.s))
                    goto invalidargs;
                cmd_upload_sieve(arg1.s, arg2.s, sync_atoul(arg3.s));
                continue;
            } else if (!strcmp(cmd.s, "Unlock")) {
		int restart;

		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

                if ((restart = sync_message_list_need_restart(message_list))) {
                    int hash_size = message_list->hash_size;
                    int file_max  = message_list->file_max;

                    /* Reset message list */
                    sync_message_list_free(&message_list);
                    message_list
                        = sync_message_list_create(hash_size, file_max);
		}

		cmd_unlock(&sync_lock, restart);
                continue;
            }

            break;
        }

        prot_printf(sync_out, "BAD Unrecognized command\r\n");
        eatline(sync_in, c);
        continue;

    nologin:
	prot_printf(sync_out, "NO Please authenticate first\r\n");
	eatline(sync_in, c);
	continue;

    noperm:
	prot_printf(sync_out, "NO %s\r\n",
		    error_message(IMAP_PERMISSION_DENIED));
	eatline(sync_in, c);
	continue;


    missingargs:
	prot_printf(sync_out, "BAD Missing required argument to %s\r\n", cmd.s);
	eatline(sync_in, c);
	continue;

    invalidargs:
	prot_printf(sync_out, "BAD Invalid argument to %s\r\n", cmd.s);
	eatline(sync_in, c);
	continue;

    extraargs:
	prot_printf(sync_out, "BAD Unexpected extra arguments to %s\r\n", cmd.s);
	eatline(sync_in, c);
	continue;
    }

 exit:
    if (mailbox) {
        mailbox_close(mailbox);
        mailbox = 0;
    }

    sync_message_list_free(&message_list);
}

static void cmd_authenticate(char *mech, char *resp)
{
    int r, sasl_result;
    const int *ssfp;
    char *ssfmsg = NULL;
    const char *canon_user;

    if (sync_userid) {
	prot_printf(sync_out, "502 Already authenticated\r\n");
	return;
    }

    r = saslserver(sync_saslconn, mech, resp, "", "+ ", "",
		   sync_in, sync_out, &sasl_result, NULL);

    if (r) {
	int code;
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(sync_out,
			"BAD Client canceled authentication\r\n");
	    break;
	case IMAP_SASL_PROTERR:
	    errorstring = prot_error(sync_in);

	    prot_printf(sync_out,
			"NO Error reading client response: %s\r\n",
			errorstring ? errorstring : "");
	    break;
	default: 
	    /* failed authentication */
	    errorstring = sasl_errstring(sasl_result, NULL, NULL);

	    syslog(LOG_NOTICE, "badlogin: %s %s [%s]",
		   sync_clienthost, mech, sasl_errdetail(sync_saslconn));

	    sleep(3);

	    if (errorstring) {
		prot_printf(sync_out, "NO %s\r\n", errorstring);
	    } else {
		prot_printf(sync_out, "NO Error authenticating\r\n");
	    }
	}

	reset_saslconn(&sync_saslconn);
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(sync_saslconn, SASL_USERNAME,
			       (const void **) &canon_user);
    if (sasl_result != SASL_OK) {
	prot_printf(sync_out, "NO weird SASL error %d SASL_USERNAME\r\n", 
		    sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	reset_saslconn(&sync_saslconn);
	return;
    }

    sync_userid = xstrdup(canon_user);
    proc_register("sync_server", sync_clienthost, sync_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", sync_clienthost, sync_userid,
	   mech, sync_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(sync_saslconn, SASL_SSF, (const void **) &ssfp);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (sync_starttls_done) {
	switch(*ssfp) {
	case 0: ssfmsg = "tls protection"; break;
	case 1: ssfmsg = "tls plus integrity protection"; break;
	default: ssfmsg = "tls plus privacy protection"; break;
	}
    } else {
	switch(*ssfp) {
	case 0: ssfmsg = "no protection"; break;
	case 1: ssfmsg = "integrity protection"; break;
	default: ssfmsg = "privacy protection"; break;
	}
    }

    prot_printf(sync_out, "OK Success (%s)\r\n", ssfmsg);

    prot_setsasl(sync_in,  sync_saslconn);
    prot_setsasl(sync_out, sync_saslconn);

    /* Create telemetry log */
    sync_logfd = telemetry_log(sync_userid, sync_in, sync_out, 0);
}

void printstring(const char *s __attribute__((unused)))
{
    /* needed to link against annotate.o */
    fatal("printstring() executed, but its not used for sync_server!",
	  EC_SOFTWARE);
}

#ifdef HAVE_SSL
static void cmd_starttls(void)
{
    int result;
    int *layerp;
    sasl_ssf_t ssf;
    char *auth_id;

    if (sync_starttls_done == 1) {
	prot_printf(sync_out, "NO %s\r\n", 
		    "Already successfully executed STARTTLS");
	return;
    }

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    result=tls_init_serverengine("csync",
				 5,        /* depth to verify */
				 1,        /* can client auth? */
				 1);       /* TLS only? */

    if (result == -1) {

	syslog(LOG_ERR, "error initializing TLS");

	prot_printf(sync_out, "NO %s\r\n", "Error initializing TLS");

	return;
    }

    prot_printf(sync_out, "OK %s\r\n", "Begin TLS negotiation now");
    /* must flush our buffers before starting tls */
    prot_flush(sync_out);
  
    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       layerp,
			       &auth_id,
			       &tls_conn);

    /* if error */
    if (result==-1) {
	prot_printf(sync_out, "NO Starttls failed\r\n");
	syslog(LOG_NOTICE, "STARTTLS failed: %s", sync_clienthost);
	return;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(sync_saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    saslprops.ssf = ssf;

    result = sasl_setprop(sync_saslconn, SASL_AUTH_EXTERNAL, auth_id);
    if (result != SASL_OK) {
        fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    if(saslprops.authid) {
	free(saslprops.authid);
	saslprops.authid = NULL;
    }
    if(auth_id)
	saslprops.authid = xstrdup(auth_id);

    /* tell the prot layer about our new layers */
    prot_settls(sync_in, tls_conn);
    prot_settls(sync_out, tls_conn);

    sync_starttls_done = 1;

    dobanner();
}
#else
static void cmd_starttls(void)
{
    fatal("cmd_starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */

static int
user_master_is_local(char *user)
{
    int rc = 0;
#if 0 /* XXX make sure we're not the replica */
    const char *filename = config_getstring(IMAPOPT_SYNC_MASTER_MAP);
    unsigned long len;
    int fd;

    if ((fd = open(filename, O_RDONLY)) < 0)
        return(0);  /* Couldn't open  */

    rc = cdb_seek(fd, (unsigned char *)user, strlen(user), &len);
    close(fd);
#endif
    /* rc: -1 => error, 0 => lookup failed, 1 => lookup suceeded */
    return(rc == 1);  
}

/* ====================================================================== */

/* Routines implementing individual commands for server */
static void cmd_lock(struct sync_lock *lock)
{
    int r;
#if 0
    if (user_master_is_local(user)) {
        prot_printf(sync_out,
                 "NO IMAP_INVALID_USER Attempt to update master for %s\r\n",
                 user);
        return;
    }
#endif
    r = sync_lock(lock);    
    if (r) {
        prot_printf(sync_out, "NO Failed to lock: %s\r\n", error_message(r));
    } else {
	prot_printf(sync_out, "OK Locked\r\n");
    }
}

static void cmd_unlock(struct sync_lock *lock, int restart)
{
    int r = 0;

    if ((r = sync_unlock(lock))) {
        prot_printf(sync_out, "NO Failed to unlock: %s\r\n",
		    error_message(r));
    } else if (restart) {
        prot_printf(sync_out, "OK [RESTART] Unlocked\r\n");
        syslog(LOG_INFO, "Unlocked [RESTART]");
    } else {
        prot_printf(sync_out, "OK [CONTINUE] Unlocked\r\n");
        syslog(LOG_INFO, "Unlocked");
    }
}

static void cmd_select(struct mailbox **mailboxp, char *name)
{
    static struct mailbox select_mailbox;
    struct mailbox *mailbox = *mailboxp;
    int r = 0;

    if (mailbox) {
        mailbox_close(mailbox);
        *mailboxp = NULL;
    }

    /* Open and lock mailbox */
    r = mailbox_open_header(name, 0, &select_mailbox);
    
    if (!r) mailbox = &select_mailbox;
    if (!r) r = mailbox_open_index(mailbox);
    if (r) {
        prot_printf(sync_out, "NO Failed to select mailbox \"%s\": %s\r\n",
                 name, error_message(r));
        if (mailbox) mailbox_close(mailbox);
        return;
    }
    prot_printf(sync_out, "OK %s %lu\r\n",
		mailbox->uniqueid, mailbox->last_uid);
    *mailboxp = mailbox;
}

/* ====================================================================== */

#define RESERVE_DELTA (100)

static void cmd_reserve(char *mailbox_name,
			struct sync_message_list *message_list)
{
    struct mailbox m;
    struct index_record record;
    static struct buf arg;
    int r = 0, c;
    int mailbox_open = 0;
    int alloc = RESERVE_DELTA, count = 0, i, msgno;
    struct message_uuid *ids = xmalloc(alloc*sizeof(struct message_uuid));
    char *err = NULL;
    char mailbox_msg_path[MAX_MAILBOX_PATH+1];
    char *stage_msg_path;
    struct sync_message *message = NULL;
    struct message_uuid tmp_uuid;

    if ((r = sync_message_list_newstage(message_list, mailbox_name))) {
	eatline(sync_in,c);
	prot_printf(sync_out, "NO %s\r\n", error_message(r));
	return;
    }

    /* Parse list of MessageIDs (must appear in same order as folder) */
    do {
        c = getastring(sync_in, sync_out, &arg);

        if (!arg.s || !message_uuid_from_text(&tmp_uuid, arg.s)) {
            err = "Not a MessageID";
            goto parse_err;
        }
        
        if (alloc == count) {
            alloc += RESERVE_DELTA;
            ids = xrealloc(ids, (alloc*sizeof(struct message_uuid)));
        }
        message_uuid_copy(&ids[count++], &tmp_uuid);
    } while (c == ' ');

    if (c == EOF) {
        err = "Unexpected end of sync_in at end of item";
        goto parse_err;
    }

    if (c == '\r') c = prot_getc(sync_in);
    if (c != '\n') {
        err = "Invalid end of sequence";
        goto parse_err;
    }

    /* Open and lock mailbox */
    r = mailbox_open_header(mailbox_name, 0, &m);
    
    if (!r) mailbox_open = 1;
    if (!r) r = mailbox_open_index(&m);

    if (r) {
        if (mailbox_open) mailbox_close(&m);

        prot_printf(sync_out, "NO Failed to open %s: %s\n",
                 mailbox_name, error_message(r));
        goto cleanup;
    }

    for (i = 0, msgno = 1 ; msgno <= m.exists; msgno++) {
        mailbox_read_index_record(&m, msgno, &record);

        if (!message_uuid_compare(&record.uuid, &ids[i]))
            continue;

        if (sync_message_find(message_list, &record.uuid))
            continue; /* Duplicate UUID on RESERVE list */

        /* Attempt to reserve this message */
        snprintf(mailbox_msg_path, sizeof(mailbox_msg_path),
                 "%s/%lu.", m.path, record.uid);
        stage_msg_path = sync_message_next_path(message_list);

        if (mailbox_copyfile(mailbox_msg_path, stage_msg_path, 0) != 0) {
            syslog(LOG_ERR, "IOERROR: Unable to link %s -> %s: %m",
                   message->msg_path, mailbox_msg_path);
            i++;       /* Failed to reserve message. */
            continue;
        }

        /* Reserve succeeded */
        message = sync_message_add(message_list, &record.uuid);
        message->msg_size     = record.size;
        message->hdr_size     = record.header_size;
        message->cache_offset = sync_message_list_cache_offset(message_list);
        message->content_lines = record.content_lines;
        message->cache_version = record.cache_version;
        message->cache_size   = mailbox_cache_size(&m, msgno);
        
        sync_message_list_cache(message_list,
                                (char *)(m.cache_base+record.cache_offset),
                                message->cache_size);

        prot_printf(sync_out, "* %s\r\n", message_uuid_text(&record.uuid));
        i++;
    }
    mailbox_close(&m);
    
    prot_printf(sync_out, "OK Reserve complete\r\n");
    goto cleanup;

 parse_err:
    eatline(sync_in, c);
    prot_printf(sync_out, "BAD Syntax error in Reserve at item %d: %s\r\n",
             count, err);
    
 cleanup:
    free(ids);
}

/* ====================================================================== */

static void cmd_quota_work(char *quotaroot)
{
    struct mailbox m;
    int mboxopen = 0;
    int r;

    /* Open and lock mailbox */
    r = mailbox_open_header(quotaroot, 0, &m);

    if (!r) mboxopen = 1;
    if (!r) r = quota_read(&m.quota, NULL, 0);

    if (r) {
        prot_printf(sync_out, "OK 0\r\n");
        if (mboxopen) mailbox_close(&m);
        return;
    }

    prot_printf(sync_out, "OK %d\r\n", m.quota.limit);

    if (mboxopen) mailbox_close(&m);
}

static void cmd_quota(char *quotaroot)
{
    return(cmd_quota_work(quotaroot));
}

static void cmd_setquota(char *root, int limit)
{
    char quota_path[MAX_MAILBOX_PATH];
    struct quota quota;
    int r = 0;

    /* NB: Minimal interface without two phase expunge */
    r = mboxlist_setquota(root, limit, 1);

    if (r)
        prot_printf(sync_out, "NO SetQuota failed %s: %s\r\n",
                 root, error_message(r));
    else
        prot_printf(sync_out, "OK SetQuota succeeded\r\n");
}

/* ====================================================================== */

static int addmbox_full(char *name,
			int matchlen __attribute__((unused)),
			int maycreate __attribute__((unused)),
			void *rock)
{
    struct sync_folder_list *list = (struct sync_folder_list *) rock;

    /* List all mailboxes, including directories and deleted items */

    sync_folder_list_add(list, name, name, NULL, NULL);
    return(0);
}

static int addmbox_sub(char *name,
		       int matchlen __attribute__((unused)),
		       int maycreate __attribute__((unused)),
		       void *rock)
{
    struct sync_folder_list *list = (struct sync_folder_list *) rock;

    sync_folder_list_add(list, name, name, NULL, NULL);
    return(0);
}

static void cmd_reset(char *user)
{
    struct sync_folder_list *list = NULL;
    struct sync_folder *item;
    char buf[MAX_MAILBOX_NAME+1];
    int r = 0;
    
    /* Nuke subscriptions */
    list = sync_folder_list_create();
    r = (sync_namespacep->mboxlist_findsub)(sync_namespacep, "*",
					    sync_userisadmin,
                                            user, sync_authstate,
					    addmbox_sub, (void *)list, 1);
    if (r) goto fail;

    for (item = list->head ; item ; item = item->next) {
        r = mboxlist_changesub(item->name, sync_userid, sync_authstate, 0, 0);
        if (r) goto fail;
    }
    sync_folder_list_free(&list);

    /* Nuke normal folders */
    list = sync_folder_list_create();

    (sync_namespacep->mboxname_tointernal)(sync_namespacep, "INBOX",
					   user, buf);
    strlcat(buf, ".*", sizeof(buf));
    r = (sync_namespacep->mboxlist_findall)(sync_namespacep, buf,
					    sync_userisadmin,
					    user, sync_authstate,
					    addmbox_full, (void *)list);
    if (r) goto fail;

    for (item = list->head ; item ; item = item->next) {
        r=mboxlist_deletemailbox(item->name, sync_userisadmin, sync_userid,
				 sync_authstate, 0, 0, 1);

        if (r) goto fail;
    }
    sync_folder_list_free(&list);

    /* Nuke inbox (recursive nuke possible?) */
    (sync_namespacep->mboxname_tointernal)(sync_namespacep, "INBOX",
					   user, buf);
    r = mboxlist_deletemailbox(buf, sync_userisadmin, sync_userid,
			       sync_authstate, 0, 0, 1);
    if (r && (r != IMAP_MAILBOX_NONEXISTENT)) goto fail;

    if ((r=user_deletedata(user, sync_userid, sync_authstate, 1)))
        goto fail;

    prot_printf(sync_out, "OK Account reset\r\n");
    return;

 fail:
    if (list) sync_folder_list_free(&list);
    prot_printf(sync_out, "NO Failed to reset account %s: %s\r\n",
             sync_userid, error_message(r));
}

/* ====================================================================== */

static void cmd_status_work_preload(struct mailbox *mailbox)
{
    unsigned long msgno;
    struct index_record record;
    int lastuid = 0;

    /* Quietly preload data from index */
    for (msgno = 1 ; msgno <= mailbox->exists; msgno++) {
        mailbox_read_index_record(mailbox, msgno, &record);

        /* Fairly pointless, just to ensure that compiler doesn't
           optimise loop away somehow */
        if (record.uid <= lastuid)
            syslog(LOG_ERR, "cmd_status_work_sub(): UIDs out of order!");
    }
}

static void cmd_status_work(struct mailbox *mailbox)
{
    unsigned long msgno;
    struct index_record record;
    int flags_printed, flag;

    for (msgno = 1 ; msgno <= mailbox->exists; msgno++) {
        mailbox_read_index_record(mailbox, msgno, &record);

        prot_printf(sync_out, "* %lu %s (",
                 record.uid, message_uuid_text(&record.uuid));

        flags_printed = 0;

        if (record.system_flags & FLAG_DELETED)
            sync_flag_print(sync_out, &flags_printed, "\\deleted");
        if (record.system_flags & FLAG_ANSWERED)
            sync_flag_print(sync_out, &flags_printed, "\\answered");
        if (record.system_flags & FLAG_FLAGGED)
            sync_flag_print(sync_out, &flags_printed, "\\flagged");
        if (record.system_flags & FLAG_DRAFT)
            sync_flag_print(sync_out, &flags_printed, "\\draft");

        for (flag = 0 ; flag < MAX_USER_FLAGS ; flag++) {
            if (mailbox->flagname[flag] &&
                (record.user_flags[flag/32] & (1<<(flag&31)) ))
                sync_flag_print(sync_out,
                                &flags_printed, mailbox->flagname[flag]);
        }

        prot_printf(sync_out, ")\r\n");
    }
}

static void cmd_status(struct mailbox *mailbox)
{
    if (!mailbox) {
        prot_printf(sync_out, "NO Mailbox not open\r\n");
        return;
    }
    cmd_status_work(mailbox);
    prot_printf(sync_out, "OK %lu\r\n", mailbox->last_uid);
}

/* ====================================================================== */

static const char *
seen_parse(const char *s, unsigned long *first_uidp, unsigned long *last_uidp)
{
    unsigned long uid;

    if (!isdigit(*s)) {
        *first_uidp = *last_uidp = 0L;
        return(NULL);
    }

    uid = 0;
    while (isdigit(*s)) {
        uid *= 10;
        uid += (*s++) -'0';
    }
    *first_uidp = *last_uidp = uid;

    if (*s == ',') {
        s++;
        return(s);
    }

    if (*s == '\0') return(s);
    if (*s != ':')  return(NULL);

    s++;
    uid = 0;
    while (isdigit(*s)) {
        uid *= 10;
        uid += (*s++) -'0';
    }
    *last_uidp = uid;

    if (*s == ',') {
        s++;
        return(s);
    }

    if (*s != '\0') return(NULL);

    return(s);
}

static char *
find_return_path(char *hdr)
{
    char *next, *s;
    int len;

    while (*hdr && *hdr != '\r' && *hdr != '\n') {
        next = hdr;
        do {
            next = strchr(next, '\n');
            if (next)
                next++;
        } while (next && (*next == ' ' || *next == '\t'));
        if (next) *next++ = '\0';

        if (!strncasecmp(hdr, "Return-Path:", strlen("Return-Path:"))) {
            hdr += strlen("Return-Path:");
            while ((*hdr == ' ') || (*hdr == '\t'))
                hdr++;

            /* Don't allow multiline response here */
            if ((s=strchr(hdr, '\r')) || (s=strchr(hdr, '\n')))
                *s = '\0';

            len = strlen(hdr);
            if ((*hdr == '<') && (hdr[len-1] == '>')) {
                hdr[len-1] = '\0';
                hdr++;
            }

            return(hdr);
        }
        hdr = next;
    }
    return(NULL);
}

/* ====================================================================== */

static void cmd_upload(struct mailbox *mailbox,
		       struct sync_message_list *message_list,
		       unsigned long new_last_uid, time_t last_appenddate)
           
{
    struct sync_upload_list *upload_list;
    struct sync_upload_item *item;
    struct sync_message     *message;
    static struct buf arg;
    int   c;
    enum {MSG_SIMPLE, MSG_PARSED, MSG_COPY} msg_type;
    int   r = 0;
    char *err;

    if (!mailbox) {
	eatline(sync_in,c);
        prot_printf(sync_out, "NO Mailbox not selected\r\n");
        return;
    }

    if ((r = sync_message_list_newstage(message_list, mailbox->name))) {
	eatline(sync_in,c);
	prot_printf(sync_out, "NO %s\r\n", error_message(r));
	return;
    }

    upload_list = sync_upload_list_create(new_last_uid, mailbox->flagname);

    do {
        err  = NULL;
        item = sync_upload_list_add(upload_list);

        /* Parse type */
        if ((c = getastring(sync_in, sync_out, &arg)) != ' ') {
            err = "Invalid type";
            goto parse_err;
        }

        if (!strcasecmp(arg.s, "SIMPLE")) {
            msg_type = MSG_SIMPLE;
        } else if (!strcasecmp(arg.s, "PARSED")) {
            msg_type = MSG_PARSED;
        } else if (!strcasecmp(arg.s, "COPY")) {
            msg_type = MSG_COPY;
        } else {
            err = "Invalid type";
            goto parse_err;
        }

        /* Get Message-UUID */
        if ((c = getastring(sync_in, sync_out, &arg)) != ' ') {
            err = "Invalid sequence ID";
            goto parse_err;
        }
        if (!strcmp(arg.s, "NIL"))
            message_uuid_set_null(&item->uuid);
        else if (!message_uuid_from_text(&item->uuid, arg.s)) {
            err = "Invalid Message-UUID";
            goto parse_err;
        }

        /* Parse UID */
        if ((c = getastring(sync_in, sync_out, &arg)) != ' ') {
            err = "Invalid UID";
            goto parse_err;
        }
        item->uid = sync_atoul(arg.s);
        
	/* Parse dates */
        if (((c = getastring(sync_in, sync_out, &arg)) != ' ') ||
            ((item->internaldate = sync_atoul(arg.s)) == 0)) {
            err = "Invalid Internaldate";
            goto parse_err;
        }
        
        if (((c = getastring(sync_in, sync_out, &arg)) != ' ') ||
            ((item->sentdate = sync_atoul(arg.s)) == 0)) {
            err = "Invalid Sentdate";
            goto parse_err;
        }
        
        if (((c = getastring(sync_in, sync_out, &arg)) != ' ') ||
            ((item->last_updated = sync_atoul(arg.s)) == 0)) {
            err = "Invalid Last update";
            goto parse_err;
        }

        /* Parse Flags */
        c = sync_getflags(sync_in, &item->flags, &upload_list->meta);

        switch (msg_type) {
        case MSG_SIMPLE:
            if (c != ' ') {
                err = "Invalid flags";
                goto parse_err;
            }

            if (message_list->cache_buffer_size > 0)
                sync_message_list_cache_flush(message_list);

            /* YYY Problem: sync_server needs source of Message-UUID for
               new uploaded messages. Schema 2? */

            message = sync_message_add(message_list, NULL /* YYY */);

            r = sync_getsimple(sync_in, sync_out, message_list, message);

            if (r != 0) {
                err = "Invalid Message";
                goto parse_err;
            }
            c = prot_getc(sync_in);
            break;
        case MSG_PARSED:
            if (c != ' ') {
                err = "Invalid flags";
                goto parse_err;
            }

            message = sync_message_add(message_list, &item->uuid);

            /* Parse Message (header size, content lines, cache, message body */
            if ((c = getastring(sync_in, sync_out, &arg)) != ' ') {
                err = "Invalid Header Size";
                goto parse_err;
            }
            message->hdr_size = sync_atoul(arg.s);
            
            if ((c = getastring(sync_in, sync_out, &arg)) != ' ') {
                err = "Invalid Content Lines";
                goto parse_err;
            }
            message->content_lines = sync_atoul(arg.s);
            
            if ((r=sync_getcache(sync_in, sync_out, message_list, message)) != 0) {
                err = "Invalid Cache entry";
                goto parse_err;
            }

            r = sync_getmessage(sync_in, sync_out, message_list, message);

            if (r != 0) {
                err = "Invalid Message";
                goto parse_err;
            }
            c = prot_getc(sync_in);

            break;
        case MSG_COPY:
            if (!(message=sync_message_find(message_list, &item->uuid))) {
                err = "Unknown Reserved message";
                goto parse_err;
            }
            break;
        default:
            err = "Invalid type";
            goto parse_err;
        }

        assert(message != NULL);
        item->message = message;

	/* if we see a SP, we're trying to upload more than one message */
    } while (c == ' ');

    if (c == EOF) {
        err = "Unexpected end of sync_in at end of item";
        goto parse_err;
    }

    if (c == '\r') c = prot_getc(sync_in);
    if (c != '\n') {
        err = "Invalid end of sequence";
        goto parse_err;
    }

    /* Make sure cache data flushed to disk before we commit */
    sync_message_fsync(message_list);
    sync_message_list_cache_flush(message_list);

    r=sync_upload_commit(mailbox, last_appenddate, upload_list, message_list);

    if (r) {
        prot_printf(sync_out, "NO Failed to commit message upload to %s: %s\r\n",
                 mailbox->name, error_message(r));
    } else {
        prot_printf(sync_out, "OK Upload %lu messages okay\r\n",
                 upload_list->count);
    }

    sync_upload_list_free(&upload_list);
    return;

 parse_err:
    eatline(sync_in, c);
    prot_printf(sync_out, "BAD Syntax error in Append at item %lu: %s\r\n",
             upload_list->count, err);

    sync_upload_list_free(&upload_list);
}

/* ====================================================================== */

static void cmd_uidlast(struct mailbox *mailbox, unsigned long last_uid,
			time_t last_appenddate)
{
    if (!mailbox) {
        prot_printf(sync_out, "NO Mailbox not open\r\n");
        return;
    }

    if (sync_uidlast_commit(mailbox, last_uid, last_appenddate) ||
        mailbox_open_index(mailbox))
        prot_printf(sync_out, "NO Uidlast failed\r\n");
    else
        prot_printf(sync_out, "OK Uidlast succeeded\r\n");
}

/* ====================================================================== */

static void cmd_setflags(struct mailbox *mailbox)
{
    struct sync_flag_list *flag_list
        = sync_flag_list_create(mailbox->flagname);
    struct sync_flag_item *item;
    static struct buf arg;
    char *err = NULL;
    int   c;
    int   r = 0;

    if (!mailbox) {
        prot_printf(sync_out, "NO Mailbox not open\r\n");
        return;
    }

    do {
        item = sync_flag_list_add(flag_list);
        err  = NULL;

        /* Parse UID */
        if ((c = getastring(sync_in, sync_out, &arg)) == EOF)
            goto bail;

        if ((c != ' ') || ((item->uid = sync_atoul(arg.s)) == 0))
            err = "Invalid UID";
        else if (item->uid > mailbox->last_uid)
            err = "UID out of range";
        else if ((c=sync_getflags(sync_in,&item->flags,&flag_list->meta))==EOF) {
            goto bail;
        } else if ((c != ' ') && (c != '\r') && (c != '\n'))
            err = "Invalid flags";

        if (err != NULL) {
            eatline(sync_in, c);
            prot_printf(sync_out, "BAD Syntax error in Setflags: %s\r\n", err);
            goto bail;
        }
	/* if we see a SP, we're trying to set more than one flag */
    } while (c == ' ');

    if (c == '\r') c = prot_getc(sync_in);
    if (c != '\n') {
        eatline(sync_in, c);
        prot_printf(sync_out, "BAD Garbage at end of Setflags sequence\r\n");
        goto bail;
    }

    r = sync_setflags_commit(mailbox, flag_list);

    if (r) {
        prot_printf(sync_out, "NO Failed to commit flag update for %s: %s\r\n",
                mailbox->name, error_message(r));
    } else {
        prot_printf(sync_out, "OK Updated flags on %lu messages okay\r\n",
                 flag_list->count);
    }

 bail:
    sync_flag_list_free(&flag_list);
}

static void cmd_setseen(struct mailbox **mailboxp, char *user, char *mboxname,
			time_t lastread, unsigned int last_recent_uid,
			time_t lastchange, char *seenuid)
{
    static struct mailbox seen_mailbox;
    struct mailbox *mailbox = *mailboxp;
    int r;
    struct seen *seendb;
    time_t lastread0, lastchange0;
    unsigned int last_recent_uid0;
    char *seenuid0;

    if (mailbox && strcmp(mailbox->name, mboxname)) {
        mailbox_close(mailbox);
	mailbox = *mailboxp = NULL;
    }

    if (!mailbox) {
	/* Open and lock mailbox */
	r = mailbox_open_header(mboxname, 0, &seen_mailbox);
    
	if (!r) mailbox = &seen_mailbox;
	if (!r) r = mailbox_open_index(mailbox);

	if (r) {
	    prot_printf(sync_out, "NO Failed to select mailbox \"%s\": %s\r\n",
			mboxname, error_message(r));
	    if (mailbox) mailbox_close(mailbox);
	    *mailboxp = NULL;
	    return;
	}

	*mailboxp = mailbox;
    }

    r = seen_open(mailbox, user, SEEN_CREATE, &seendb);

    if (r) {
        prot_printf(sync_out,
                 "NO failed to open seen database for (%s, %s): %s\r\n",
                 mailbox->name, user, error_message(r));
    }

    r = seen_lockread(seendb, &lastread0, &last_recent_uid0,
                      &lastchange0, &seenuid0);

    if (!r)
        r = seen_write(seendb, lastread, last_recent_uid, lastchange, seenuid);
    seen_close(seendb);

    if (r)
        prot_printf(sync_out, "NO Setseen Failed on %s %s: %s\r\n",
                 user, mailbox->name, error_message(r));
    else
        prot_printf(sync_out, "OK Setseen Suceeded\r\n");

    free(seenuid0);
}

static void cmd_setseen_all(char *user, struct buf *data)
{
    int r = 0;
    char *seen_file;
    char fnamebuf[MAX_MAILBOX_PATH + 1024];
    int filefd;

    seen_file = seen_getpath(user);
    snprintf(fnamebuf, sizeof(fnamebuf), "%s.%d", seen_file, getpid());

    /* if we haven't opened it, do so */
    filefd = open(fnamebuf, O_WRONLY|O_TRUNC|O_CREAT, 0640);
    if (filefd == -1 && errno == ENOENT) {
	if (cyrus_mkdir(fnamebuf, 0750) == 0) {
	    filefd = open(fnamebuf, O_WRONLY|O_TRUNC|O_CREAT, 0640);
	}
    }

    if (filefd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	r = IMAP_IOERROR;
    }

    if (!r && write(filefd, data->s, data->len) == -1) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
	r = IMAP_IOERROR;
    }

    /* we were operating on the seen state, so merge it and cleanup */
    if (!r) seen_merge(fnamebuf, seen_file);

    free(seen_file);
    unlink(fnamebuf);
    if (filefd != -1) close(filefd);

    if (r)
        prot_printf(sync_out, "NO Setseen_all Failed on %s: %s\r\n",
                 user, error_message(r));
    else
        prot_printf(sync_out, "OK Setseen_all Suceeded\r\n");
}

static void cmd_setacl(char *name, char *acl)
{
    int r = mboxlist_sync_setacls(name, acl);

    if (r)
        prot_printf(sync_out,
                 "NO SetAcl Failed for %s: %s\r\n", name, error_message(r));
    else
        prot_printf(sync_out, "OK SetAcl Suceeded\r\n");
}


/* ====================================================================== */

struct uid_list {
    unsigned long *array;
    unsigned long  alloc;
    unsigned long  current;
    unsigned long  count;
};

static int cmd_expunge_decide(struct mailbox *mailbox __attribute__((unused)),
			      void *rock, char *indexbuf,
			      int expunge_flags __attribute__((unused)))
{
    struct uid_list *uids = (struct uid_list *)rock;
    unsigned long uid = htonl(*((bit32 *)(indexbuf+OFFSET_UID)));
    unsigned long first, last, middle, uid2;

    /* Binary chop */
    first = 0;
    last  = uids->count;

    while (first < last) {
        middle = (first + last) / 2;
        uid2   = uids->array[middle];

        if (uid == uid2)
            return(1);             /* Expunge this message */
        else if (uid2 < uid)
            first = middle + 1;
        else
            last  = middle;
    }
    return(0);
}

static void cmd_expunge(struct mailbox *mailbox)
{
    static struct buf arg;
    int c;
    int r = 0;
    struct uid_list uids;
    unsigned long uid;

    if (!mailbox) {
        prot_printf(sync_out, "NO Mailbox not open\r\n");
        return;
    }

    uids.count = 0;
    uids.current = 0;
    uids.alloc = 64;
    uids.array = xmalloc(uids.alloc * sizeof(unsigned long));

    do {
        if ((c = getastring(sync_in, sync_out, &arg)) == EOF) {
            free(uids.array);
            return;
        }
        if (!imparse_isnumber(arg.s)) {
            eatline(sync_in, c);
            free(uids.array);
            prot_printf(sync_out, "BAD Non integer argument\r\n");
            return;
        }
        uid = sync_atoul(arg.s);

        if (uids.count == uids.alloc) {
            uids.alloc *= 2;
            uids.array = xrealloc(uids.array,uids.alloc*sizeof(unsigned long));
        }

        if ((uids.count > 0) && (uids.array[uids.count-1] > uid)) {
            eatline(sync_in, c);
            free(uids.array);
            prot_printf(sync_out, "BAD UID list out of order\r\n");
            return;
        }
        uids.array[uids.count++] = uid;
    } while (c == ' ');

    if (c == '\r') c = prot_getc(sync_in);
    if (c != '\n') {
        prot_printf(sync_out, "BAD Unexpected arguments\r\n");
        return;
    }

    if (uids.count > 0) {
        /* Make sure that messages are removed immediately */
        r = mailbox_expunge(mailbox, cmd_expunge_decide, (void *)&uids, 0);
    }

    if (r)
        prot_printf(sync_out, "NO Expunge failed on %s: %s\r\n",
                 mailbox->name, error_message(r));
    else
        prot_printf(sync_out, "OK Expunge Complete\r\n");

    free(uids.array);

   /* Update index on open mailbox to reflect change */
    r = mailbox_open_index(mailbox);
    if (r) {
        syslog(LOG_ERR,
               "Failed to reopen mailbox %s after expunge: %s",
               mailbox->name, error_message(r));
    }
}

/* ====================================================================== */

static int do_mailbox_single(char *name, int matchlen, int maycreate, void *rock)
{
    struct mailbox m;
    int r;
    int open = 0;
    int  *livep = (int *)rock;

    r = mailbox_open_header(name, 0, &m);
    if (!r) open = 1;
    if (!r) r = mailbox_open_index(&m);
    if (r) {
        if (open) mailbox_close(&m);
        return(r);
    }

    if (*livep) {
        prot_printf(sync_out, "** ");
        sync_printastring(sync_out, m.uniqueid);
        prot_printf(sync_out, " ");
        sync_printastring(sync_out, m.name);
	prot_printf(sync_out, " ");
        sync_printastring(sync_out, m.acl);
        prot_printf(sync_out, " %lu", m.last_uid);
	if (m.quota.root && !strcmp(name, m.quota.root) &&
	    !quota_read(&m.quota, NULL, 0)) {
	    prot_printf(sync_out, " %d", m.quota.limit);
	}
        prot_printf(sync_out, "\r\n");
        cmd_status_work(&m);
    } else
        cmd_status_work_preload(&m);

    mailbox_close(&m);
    return(0);
}


/* ====================================================================== */

static int do_lsub_all_single(char *name, int matchlen, int maycreate,
			       void *rock)
{
    prot_printf(sync_out, "*** ");
    sync_printastring(sync_out, name);
    prot_printf(sync_out, "\r\n");
    
    return(0);
}

#define USER_DELTA (50)

static void cmd_mailboxes()
{
    static struct buf arg;
    int c = ' ';
    int alloc = USER_DELTA, count = 0, i;
    char **folder_name = xmalloc(alloc*sizeof(char *));
    char *err;
    int live = 1;
    int r = 0;

    /* Parse list of Folders */
    do {
        c = getastring(sync_in, sync_out, &arg);

        if (alloc == count) {
            alloc        += USER_DELTA;
            folder_name   = xrealloc(folder_name, (alloc*sizeof(char *)));
        }
        folder_name[count++] = xstrdup(arg.s);

    } while (c == ' ');

    if (c == '\r') c = prot_getc(sync_in);
    if (c != '\n') {
        err = "Invalid end of sequence";
        goto parse_err;
    }

    for (i = 0 ; i < count ; i++)
        do_mailbox_single(folder_name[i], 0, 0, &live);

    prot_printf(sync_out, "OK Mailboxes finished\r\n");

    for (i = 0 ; i < count; i++) free(folder_name[i]);
    free(folder_name);
    return;

 parse_err:
    eatline(sync_in, c);
    prot_printf(sync_out, "BAD Syntax error in Mailboxes at item %d: %s\r\n",
             count, err);
    
    for (i = 0 ; i < count; i++) free(folder_name[i]);
    free(folder_name);
}

static void cmd_user(char *userid)
{
    char buf[MAX_MAILBOX_PATH];
    int r; 
    int live = 0;
    struct sync_sieve_list *sieve_list;
    struct sync_sieve_item *sieve_item;

    /* Dry run: load all index files into memory before we start
     * generating sync_out: reduces latency */

    live = 0;

    /* inbox */
    ((*sync_namespacep).mboxname_tointernal)(sync_namespacep, "INBOX",
					     userid, buf);
    r = do_mailbox_single(buf, 0, 0, &live);

    if (r) {
        syslog(LOG_NOTICE, "Failed to access inbox for %s", userid);
        prot_printf(sync_out,
                 ("NO IMAP_MAILBOX_NONEXISTENT "
                  "Failed to access inbox for %s: %s\r\n"),
                 userid, error_message(r));

        return;
    }

    /* And then all folders */
    strlcat(buf, ".*", sizeof(buf));
    r = ((*sync_namespacep).mboxlist_findall)(sync_namespacep, buf,
					      sync_userisadmin,
                                              userid, sync_authstate,
                                              do_mailbox_single, &live);
    if (r) {
        syslog(LOG_NOTICE,
               "Failed to enumerate mailboxes for %s", userid);
        prot_printf(sync_out, "NO Failed to enumerate mailboxes for %s: %s\r\n",
                 userid, error_message(r));
        return;
    }
    /* Live run */

    live = 1;

    /* inbox */
    ((*sync_namespacep).mboxname_tointernal)(sync_namespacep, "INBOX",
					     userid, buf);
    r = do_mailbox_single(buf, 0, 0, &live);

    if (r) {
        syslog(LOG_NOTICE, "Failed to access inbox for %s", userid);
        prot_printf(sync_out,
                 ("NO IMAP_MAILBOX_NONEXISTENT "
                  "Failed to access inbox for %s: %s\r\n"),
                 userid, error_message(r));
        return;
    }

    /* And then all folders */
    strlcat(buf, ".*", sizeof(buf));
    r = ((*sync_namespacep).mboxlist_findall)(sync_namespacep, buf,
					      sync_userisadmin,
                                              userid, sync_authstate,
                                              do_mailbox_single, &live);
    if (r) {
        syslog(LOG_NOTICE,
               "Failed to enumerate mailboxes for %s", userid);
        prot_printf(sync_out, "NO Failed to enumerate mailboxes for %s: %s\r\n",
                 userid, error_message(r));
        return;
    }

    /* LSUB */
    r = (((*sync_namespacep).mboxlist_findsub)(sync_namespacep, "*",
					       sync_userisadmin,
					       userid, sync_authstate,
					       do_lsub_all_single, NULL, 1));

    if (r) {
        syslog(LOG_NOTICE,
               "Failed to enumerate mailboxes for %s", userid);
        prot_printf(sync_out, "NO Failed to enumerate mailboxes for %s: %s\r\n",
                 userid, error_message(r));
        return;
    }

    /* Sieve scripts. Make following subroutine? */
    /* XXX Error handling here? */
    if ((sieve_list = sync_sieve_list_generate(sync_userid))) {
        sieve_item = sieve_list->head;
        while (sieve_item) {
            prot_printf(sync_out, "**** ");
            sync_printastring(sync_out, sieve_item->name);
            prot_printf(sync_out, " %lu", sieve_item->last_update);
            if (sieve_item->active)
                prot_printf(sync_out, " *");
            prot_printf(sync_out, "\r\n");
            sieve_item = sieve_item->next;
        }
        sync_sieve_list_free(&sieve_list);
    }

    prot_printf(sync_out, "OK User_all completed\r\n");
}

/* ====================================================================== */

static void cmd_create(char *mailboxname, char *partition,
		       char *uniqueid, char *acl,
		       int mbtype, unsigned long uidvalidity)
{
    int r;
    char buf[MAX_MAILBOX_PATH+1];
    char aclbuf[128];
    int size;

    if (uniqueid && !strcasecmp(uniqueid, "NIL"))
        uniqueid = NULL;

    if (acl && !strcasecmp(acl, "NIL"))
        acl = NULL;
/* XXX Cambridge specific stuff */
    if (acl == NULL) {
        size = strlen(sync_userid) + strlen("\tlrswipcda\tanonymous\t0\t") + 1;

        if (size > sizeof(aclbuf)) {
            prot_printf(sync_out, "NO Create failed: Username too long\r\n");
            return;
        }

        /* Create default ACL, including anonymous 0 flag for FUD */
        sprintf(aclbuf, "%s\tlrswipcda\tanonymous\t0\t", sync_userid);
        acl = aclbuf;
    }

    r = sync_create_commit(mailboxname, partition,
			   uniqueid, acl, mbtype, uidvalidity,
                           1,  sync_userid, sync_authstate);

    if (r)
        prot_printf(sync_out, "NO Create %s failed: %s\r\n",
                 mailboxname, error_message(r));
    else
        prot_printf(sync_out, "OK Create completed\r\n");
}

static void cmd_delete(char *name)
{
    int r;

    /* Delete with admin priveleges */
    r = mboxlist_deletemailbox(name, sync_userisadmin, sync_userid,
			       sync_authstate, 0, 0, 1);

    if (r)
        prot_printf(sync_out, "NO Failed to delete %s: %s\r\n",
                 name, error_message(r));
    else
        prot_printf(sync_out, "OK Delete completed\r\n");
}

static void cmd_rename(char *oldmailboxname, char *newmailboxname)
{
    int r;

    r = mboxlist_renamemailbox(oldmailboxname, newmailboxname, NULL,
                               1,sync_userid, sync_authstate);

    if (r)
        prot_printf(sync_out, "NO Rename failed %s -> %s: %s\r\n",
                 oldmailboxname, newmailboxname, error_message(r));
    else
        prot_printf(sync_out, "OK Rename completed\r\n");

}

static int do_lsub_single(char *name, int matchlen, int maycreate, void *rock)
{
    prot_printf(sync_out, "* ");
    sync_printastring(sync_out, name);
    prot_printf(sync_out, "\r\n");

    return(0);
}

static void cmd_lsub(char *user)
{
    char buf[MAX_MAILBOX_PATH];
    int r;

    r = ((*sync_namespacep).mboxlist_findsub)(sync_namespacep, "*",
					      sync_userisadmin,
                                              user, sync_authstate,
                                              do_lsub_single, NULL, 1);

    if (r) {
        syslog(LOG_NOTICE,
               "Failed to enumerate subscriptions for %s", user);
        prot_printf(sync_out, "NO Failed to enumerate subscriptions for %s: %s\r\n",
                 user, error_message(r));
    } else
        prot_printf(sync_out, "OK Lsub completed\r\n");
}

static void cmd_addsub(char *user, char *name)
{
    int r;

    r = mboxlist_changesub(name, user, sync_authstate, 1, 1);

    if (r) {
        prot_printf(sync_out, "NO Addsub %s %s failed: %s\r\n",
		    user, name, error_message(r));
    } else
        prot_printf(sync_out, "OK Addsub completed\r\n");
}

static void cmd_delsub(char *user, char *name)
{
    int r;

    r = mboxlist_changesub(name, user, sync_authstate, 0, 0);

    if (r) {
        prot_printf(sync_out, "NO Delsub %s %s failed: %s\r\n",
		    user, name, error_message(r));
    } else
        prot_printf(sync_out, "OK Delsub completed\r\n");
}

/* ====================================================================== */

static int find_cb(const char *mailbox __attribute__((unused)),
		   const char *entry, const char *userid,
		   struct annotation_data *attrib,
		   void *rock __attribute__((unused)))
{
    prot_printf(sync_out, "* ");
    sync_printastring(sync_out, entry);
    prot_printf(sync_out, " ");
    sync_printastring(sync_out, userid);
    prot_printf(sync_out, " ");
    sync_printastring(sync_out, attrib->value);
    prot_printf(sync_out, "\r\n");

    return 0;
}

static void cmd_list_annotations(char *mailboxname)
{
    annotatemore_findall(mailboxname, "*", &find_cb, NULL, NULL);

    prot_printf(sync_out, "OK List_annotations completed\r\n");
}

/* ====================================================================== */

static void cmd_list_sieve(char *user)
{
    struct sync_sieve_list *list;
    struct sync_sieve_item *item;

    if(config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) {
        /* XXX No use to us */
        prot_printf(sync_out, "OK List_sieve+sieveusehomedir not implemented\r\n");
        return;
    }

    if (!(list = sync_sieve_list_generate(user))) {
        prot_printf(sync_out, "OK No sieve scripts currently active\r\n");
        return;
    }

    for (item = list->head ; item ; item = item->next) {
        prot_printf(sync_out, "* ");
        sync_printstring(sync_out, item->name);
        prot_printf(sync_out, " %lu", item->last_update);
        if (item->active)
            prot_printf(sync_out, " *");
        prot_printf(sync_out, "\r\n");
    }
    sync_sieve_list_free(&list);

    prot_printf(sync_out, "OK List_sieve completed\r\n");
}

static void cmd_get_sieve(char *user, char *name)
{
    char *s, *sieve;
    unsigned long size;

    if ((sieve = sync_sieve_read(user, name, &size))) {
        prot_printf(sync_out, "OK {%lu+}\r\n", size);

        s = sieve;
        while (size) {
            prot_putc(*s, sync_out);
            s++;
            size--;
        }
        prot_printf(sync_out, "\r\n");
        free(sieve);
    } else
        prot_printf(sync_out, "NO No such sieve file\r\n");
}

static void cmd_upload_sieve(char *user, char *name, unsigned long last_update)
{
    int r;
    int c;

    r = sync_sieve_upload(sync_in, sync_out, user, name, last_update);

    c = prot_getc(sync_in);
    if (c == '\r') c = prot_getc(sync_in);
    if (c != '\n') {
        prot_printf(sync_out, "BAD Unexpected arguments\r\n");
        return;
    }

    if (r)
        prot_printf(sync_out, "NO Upload_sieve failed: %s\r\n", error_message(r));
    else
        prot_printf(sync_out, "OK Upload_sieve completed\r\n");
}

static void cmd_activate_sieve(char *user, char *name)
{
    int r;

    r = sync_sieve_activate(user, name);

    if (r)
        prot_printf(sync_out, "NO Activate_sieve %s failed: %s\r\n",
		    user, error_message(r));
    else
        prot_printf(sync_out, "OK Activate_sieve completed\r\n");
}

static void cmd_deactivate_sieve(char *user)
{
    int r;

    r = sync_sieve_deactivate(user);

    if (r) {
        prot_printf(sync_out, "NO Deactivate_sieve %s failed: %s\r\n",
		    user, error_message(r));
    } else {
        prot_printf(sync_out, "OK Deactivate_sieve completed\r\n");
    }
}

static void cmd_delete_sieve(char *user, char *name)
{
    int r;

    r = sync_sieve_delete(user, name);

    if (r)
        prot_printf(sync_out, "NO Delete_sieve %s failed: %s\r\n",
		    user, error_message(r));
    else
        prot_printf(sync_out, "OK Delete_sieve completed\r\n");
}

/* ====================================================================== */

static void cmd_set_annotation(char *mailboxname, char *entry, char *userid,
			       char *value)
{
    int r;
    struct entryattlist *entryatts = NULL;
    struct attvaluelist *attvalues = NULL;

    appendattvalue(&attvalues, *userid ? "value.priv" : "value.shared", value);
    appendentryatt(&entryatts, entry, attvalues);

    /* annotatemore_store() expects external mailbox names,
       so translate the separator character */
    mboxname_hiersep_toexternal(sync_namespacep, mailboxname, 0);
    r = annotatemore_store(mailboxname, entryatts, sync_namespacep,
			   sync_userisadmin, userid, sync_authstate);

    freeentryatts(entryatts);

    if (r) {
	mboxname_hiersep_tointernal(sync_namespacep, mailboxname, 0);
        prot_printf(sync_out, "NO Setannotation %s failed: %s %s %s %s\r\n",
		    mailboxname, entry, userid, value, error_message(r));
    }
    else
        prot_printf(sync_out, "OK Setannotation completed\r\n");
}
