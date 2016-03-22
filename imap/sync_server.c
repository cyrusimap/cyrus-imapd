/* sync_server.c -- Cyrus synchonization server
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
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#include <config.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#ifdef WITH_DAV
#include "caldav_db.h"
#include "carddav_db.h"
#include "dav_db.h"
#endif /* WITH_DAV */
#include "dlist.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "imap/imap_err.h"
#include "imparse.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "partlist.h"
#include "proc.h"
#include "prot.h"
#include "quota.h"
#include "seen.h"
#include "statuscache.h"
#include "sync_log.h"
#include "telemetry.h"
#include "tls.h"
#include "user.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"

#include "message_guid.h"
#include "sync_support.h"
/*#include "cdb.h"*/

extern int optind;
extern char *optarg;
extern int opterr;

/* for config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

static sasl_ssf_t extprops_ssf = 0;

#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

static sasl_conn_t *sync_saslconn = NULL; /* the sasl connection context */

static char *sync_userid = 0;
static struct namespace sync_namespace;
static struct namespace *sync_namespacep = &sync_namespace;
static struct auth_state *sync_authstate = 0;
static int sync_userisadmin = 0;
static const char *sync_clienthost = "[local]";
static struct protstream *sync_out = NULL;
static struct protstream *sync_in = NULL;
static int sync_logfd = -1;
static int sync_starttls_done = 0;
static int sync_compress_done = 0;

static int opt_force = 0;

/* commands that have specific names */
static void cmdloop(void);
static void cmd_authenticate(char *mech, char *resp);
static void cmd_starttls(void);
static void cmd_restart(struct sync_reserve_list **reserve_listp,
		       int realloc);
static void cmd_compress(char *alg);

/* generic commands - in dlist format */
static void cmd_get(struct dlist *kl);
static void cmd_apply(struct dlist *kl,
		      struct sync_reserve_list *reserve_list);

static void usage(void);
void shut_down(int code) __attribute__ ((noreturn));

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
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &sync_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static void sync_reset(void)
{
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

    sync_clienthost = "[local]";
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
    sync_compress_done = 0;

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

    while ((opt = getopt(argc, argv, "p:f")) != EOF) {
	switch(opt) {
	case 'p': /* external protection */
	    extprops_ssf = atoi(optarg);
	    break;
	case 'f':
	    opt_force = 1;
	    break;
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
    annotate_init(NULL, NULL);
    annotatemore_open();

    /* Open the statuscache so we can invalidate seen states */
    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	statuscache_open();
    }

#ifdef WITH_DAV
    dav_init();
    caldav_init();
    carddav_init();
#endif

    return 0;
}

/*
 * Issue the capability banner
 */
static void dobanner(void)
{
    const char *mechlist;
    int mechcount;

    if (!sync_userid) {
	if (sasl_listmech(sync_saslconn, NULL,
			  "* SASL ", " ", "\r\n",
			  &mechlist, NULL, &mechcount) == SASL_OK
	    && mechcount > 0) {
	    prot_printf(sync_out, "%s", mechlist);
	}

	if (tls_enabled() && !sync_starttls_done) {
	    prot_printf(sync_out, "* STARTTLS\r\n");
	}

#ifdef HAVE_ZLIB
	if (!sync_compress_done && !sync_starttls_done) {
	    prot_printf(sync_out, "* COMPRESS DEFLATE\r\n");
	}
#endif
    }

    prot_printf(sync_out,
		"* OK %s Cyrus sync server %s\r\n",
		config_servername, cyrus_version());

    prot_flush(sync_out);
}

/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    const char *localip, *remoteip;
    sasl_security_properties_t *secprops = NULL;
    int timeout;

    signals_poll();

    sync_in = prot_new(0, 0);
    sync_out = prot_new(1, 1);

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(sync_in, 1);
    prot_setisclient(sync_out, 1);

    /* Find out name of client host */
    sync_clienthost = get_clienthost(0, &localip, &remoteip);
    if (!strcmp(sync_clienthost, UNIX_SOCKET)) {
	/* we're not connected to an internet socket! */
	sync_userid = xstrdup("cyrus");
	sync_userisadmin = 1;
    }
    else {
	/* other params should be filled in */
	if (sasl_server_new("csync", config_servername, NULL, NULL, NULL,
			    NULL, 0, &sync_saslconn) != SASL_OK)
	    fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL);

	/* will always return something valid */
	secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
	if (sasl_setprop(sync_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
	    fatal("Failed to set SASL property", EC_TEMPFAIL);

	if (sasl_setprop(sync_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
	    fatal("Failed to set SASL property", EC_TEMPFAIL);

	if (localip) {
	    sasl_setprop(sync_saslconn, SASL_IPLOCALPORT, localip);
	    saslprops.iplocalport = xstrdup(localip);
	}

	if (remoteip) {
	    if (sasl_setprop(sync_saslconn, SASL_IPREMOTEPORT, remoteip) != SASL_OK)
		fatal("failed to set sasl property", EC_TEMPFAIL);
	    saslprops.ipremoteport = xstrdup(remoteip);
	}

	tcp_disable_nagle(1); /* XXX magic fd */
    }

    proc_register(config_ident, sync_clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getint(IMAPOPT_SYNC_TIMEOUT);
    if (timeout < 3) timeout = 3;
    prot_settimeout(sync_in, timeout);

    prot_setflushonread(sync_in, sync_out);

    sync_log_init();
    if (!config_getswitch(IMAPOPT_SYNC_LOG_CHAIN))
	sync_log_suppress();

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

static void usage(void)
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
    in_shutdown = 1;

    proc_cleanup();

#ifdef WITH_DAV
    carddav_done();
    caldav_done();
    dav_done();
#endif

    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	statuscache_close();
	statuscache_done();
    }

    seen_done();
    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    annotatemore_close();
    annotate_done();

    partlist_local_done();

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

EXPORTED void fatal(const char* s, int code)
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
    if (ret != SASL_OK) return ret;

    if (saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
			  saslprops.ipremoteport);
    if (ret != SASL_OK) return ret;

    if (saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
			  saslprops.iplocalport);
    if (ret != SASL_OK) return ret;
    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if (ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if (saslprops.ssf) {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    } else {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }

    if (ret != SASL_OK) return ret;

    if (saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

static void cmdloop(void)
{
    struct sync_reserve_list *reserve_list;
    static struct buf cmd;
    static struct buf arg1, arg2;
    int c;
    char *p;
    struct dlist *kl;

    syslog(LOG_DEBUG, "cmdloop(): startup");

    reserve_list = sync_reserve_list_create(SYNC_MESSAGE_LIST_HASH_SIZE);

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

	if (Uislower(cmd.s[0])) 
	    cmd.s[0] = toupper((unsigned char) cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (Uisupper(*p)) *p = tolower((unsigned char) *p);
	}

	/* Must be an admin */
	if (sync_userid && !sync_userisadmin) goto noperm;

	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		int haveinitresp = 0;
		if (c != ' ') goto missingargs;
		c = getword(sync_in, &arg1);
		if (!imparse_isatom(arg1.s)) {
		    prot_printf(sync_out, "BAD Invalid mechanism\r\n");
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
	    if (!sync_userid) goto nologin;
	    if (!strcmp(cmd.s, "Apply")) {
		kl = sync_parseline(sync_in);
		if (kl) {
		    cmd_apply(kl, reserve_list);
		    dlist_free(&kl);
		}
		else {
		    syslog(LOG_ERR, "IOERROR: received bad APPLY command");
		    prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Failed to parse APPLY line\r\n");
		}
		continue;
	    }
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Compress")) {
		if (c != ' ') goto missingargs;
		c = getword(sync_in, &arg1);
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
		cmd_compress(arg1.s);
		continue;
	    }
	    break;

	case 'G':
	    if (!sync_userid) goto nologin;
	    if (!strcmp(cmd.s, "Get")) {
		kl = sync_parseline(sync_in);
		if (kl) {
		    cmd_get(kl);
		    dlist_free(&kl);
		}
		else {
		    syslog(LOG_ERR, "IOERROR: received bad GET command");
		    prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Failed to parse GET line\r\n");
		}
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

	case 'R':
	    if (!strcmp(cmd.s, "Restart")) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;
		/* just clear the GUID cache */
		cmd_restart(&reserve_list, 1);
		prot_printf(sync_out, "OK Restarting\r\n");
		continue;
	    }
	    else if (!sync_userid) goto nologin;
	    break;

	case 'S':
	    if (!strcmp(cmd.s, "Starttls") && tls_enabled()) {
		if (c == '\r') c = prot_getc(sync_in);
		if (c != '\n') goto extraargs;

		/* XXX  discard any input pipelined after STARTTLS */
		prot_flush(sync_in);

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
	    break;

	}

	syslog(LOG_ERR, "IOERROR: received bad command: %s", cmd.s);
	prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Unrecognized command\r\n");
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

    extraargs:
	prot_printf(sync_out, "BAD Unexpected extra arguments to %s\r\n", cmd.s);
	eatline(sync_in, c);
	continue;
    }

 exit:
    cmd_restart(&reserve_list, 0);
}

static void cmd_authenticate(char *mech, char *resp)
{
    int r, sasl_result;
    sasl_ssf_t ssf;
    const char *ssfmsg = NULL;
    const void *val;
    int failedloginpause;

    if (sync_userid) {
	prot_printf(sync_out, "BAD Already authenticated\r\n");
	return;
    }

    r = saslserver(sync_saslconn, mech, resp, "", "+ ", "",
		   sync_in, sync_out, &sasl_result, NULL);

    if (r) {
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

	    failedloginpause = config_getint(IMAPOPT_FAILEDLOGINPAUSE);
	    if (failedloginpause != 0) {
		sleep(failedloginpause);
	    }

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
    sasl_result = sasl_getprop(sync_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
	prot_printf(sync_out, "NO weird SASL error %d SASL_USERNAME\r\n",
		    sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME",
	       sasl_result);
	reset_saslconn(&sync_saslconn);
	return;
    }

    sync_userid = xstrdup((const char *) val);
    proc_register(config_ident, sync_clienthost, sync_userid, NULL, NULL);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", sync_clienthost, sync_userid,
	   mech, sync_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(sync_saslconn, SASL_SSF, &val);
    ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (sync_starttls_done) {
	switch(ssf) {
	case 0: ssfmsg = "tls protection"; break;
	case 1: ssfmsg = "tls plus integrity protection"; break;
	default: ssfmsg = "tls plus privacy protection"; break;
	}
    } else {
	switch(ssf) {
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
				 1);       /* can client auth? */

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
			       180, /* 3 minutes */
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
    if (saslprops.authid) {
	free(saslprops.authid);
	saslprops.authid = NULL;
    }
    if (auth_id)
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

#ifdef HAVE_ZLIB
static void cmd_compress(char *alg)
{
    if (sync_compress_done) {
	prot_printf(sync_out, "NO Compression already active: %s\r\n", alg);
	return;
    }
    if (strcasecmp(alg, "DEFLATE")) {
	prot_printf(sync_out, "NO Unknown compression algorithm: %s\r\n", alg);
	return;
    }
    if (ZLIB_VERSION[0] != zlibVersion()[0]) {
	prot_printf(sync_out, "NO Error initializing %s "
		    "(incompatible zlib version)\r\n", alg);
	return;
    }
    prot_printf(sync_out, "OK %s active\r\n", alg);
    prot_flush(sync_out);
    prot_setcompress(sync_in);
    prot_setcompress(sync_out);
    sync_compress_done = 1;
}
#else
static void cmd_compress(char *alg)
{
    prot_printf(sync_out, "NO ZLIB not available\r\n");
}
#endif

/* ====================================================================== */

/* partition_list is simple linked list of names used by cmd_restart */

struct partition_list {
    struct partition_list *next;
    char *name;
};

static struct partition_list *
partition_list_add(char *name, struct partition_list *pl)
{
    struct partition_list *p;

    /* Is name already on list? */
    for (p=pl; p; p = p->next) {
	if (!strcmp(p->name, name))
	    return(pl);
    }

    /* Add entry to start of list and return new list */
    p = xzmalloc(sizeof(struct partition_list));
    p->next = pl;
    p->name = xstrdup(name);

    return(p);
}

static void
partition_list_free(struct partition_list *current)
{
    while (current) {
	struct partition_list *next = current->next;

	free(current->name);
	free(current);

	current = next;
    }
}

static void cmd_restart(struct sync_reserve_list **reserve_listp, int re_alloc)
{
    struct sync_reserve *res;
    struct sync_reserve_list *l = *reserve_listp;
    struct sync_msgid *msg;
    const char *fname;
    int hash_size = l->hash_size;
    struct partition_list *p, *pl = NULL;

    for (res = l->head; res; res = res->next) {
	for (msg = res->list->head; msg; msg = msg->next) {
	    pl = partition_list_add(res->part, pl);

	    fname = dlist_reserve_path(res->part, &msg->guid);
	    unlink(fname);
	}
    }
    sync_reserve_list_free(reserve_listp);

    /* Remove all <partition>/sync./<pid> directories referred to above */
    for (p=pl; p ; p = p->next) {
	static char buf[MAX_MAILBOX_PATH];

	snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu",
		 config_partitiondir(p->name), (unsigned long)getpid());
	rmdir(buf);
    }
    partition_list_free(pl);

    if (re_alloc)
	*reserve_listp = sync_reserve_list_create(hash_size);
    else
	*reserve_listp = NULL;
}

/* ====================================================================== */

static void reserve_folder(const char *part, const char *mboxname,
		    struct sync_msgid_list *part_list)
{
    struct mailbox *mailbox = NULL;
    struct index_record record;
    struct index_record record2;
    int r;
    struct sync_msgid *item;
    const char *mailbox_msg_path, *stage_msg_path;
    uint32_t recno;

    /* Open and lock mailbox */
    r = mailbox_open_irl(mboxname, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r) return;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	/* ok to skip errors here - just means they'll be uploaded
	 * rather than reserved */
	if (mailbox_read_index_record(mailbox, recno, &record))
	    continue;

	if (record.system_flags & FLAG_UNLINKED)
	    continue;

	/* do we need it? */
	item = sync_msgid_lookup(part_list, &record.guid);
	if (!item)
	    continue;

	/* have we already found it? */
	if (!item->need_upload)
	    continue;

	/* Attempt to reserve this message */
	mailbox_msg_path = mailbox_message_fname(mailbox, record.uid);
	stage_msg_path = dlist_reserve_path(part, &record.guid);

	/* check that the sha1 of the file on disk is correct */
	memset(&record2, 0, sizeof(struct index_record));
	r = message_parse(mailbox_msg_path, &record2);
	if (r) {
	    syslog(LOG_ERR, "IOERROR: Unable to parse %s",
		   mailbox_msg_path);
	    continue;
	}
	if (!message_guid_equal(&record.guid, &record2.guid)) {
	    syslog(LOG_ERR, "IOERROR: GUID mismatch on parse for %s",
		   mailbox_msg_path);
	    continue;
	}

	if (mailbox_copyfile(mailbox_msg_path, stage_msg_path, 0) != 0) {
	    syslog(LOG_ERR, "IOERROR: Unable to link %s -> %s: %m",
		   mailbox_msg_path, stage_msg_path);
	    continue;
	}

	item->need_upload = 0;
	part_list->toupload--;

	/* already found everything, drop out */
	if (!part_list->toupload) break;
    }

    mailbox_close(&mailbox);
}

static int do_reserve(struct dlist *kl, struct sync_reserve_list *reserve_list)
{
    struct message_guid *tmpguid;
    struct sync_name_list *folder_names = sync_name_list_create();
    struct sync_msgid_list *part_list;
    struct sync_msgid *item;
    struct sync_name *folder;
    mbentry_t *mbentry = NULL;
    const char *partition = NULL;
    struct dlist *ml;
    struct dlist *gl;
    struct dlist *i;
    struct dlist *kout = NULL;

    if (!dlist_getatom(kl, "PARTITION", &partition)) goto parse_err;
    if (!dlist_getlist(kl, "MBOXNAME", &ml)) goto parse_err;
    if (!dlist_getlist(kl, "GUID", &gl)) goto parse_err;

    part_list = sync_reserve_partlist(reserve_list, partition);
    for (i = gl->head; i; i = i->next) {
	if (!dlist_toguid(i, &tmpguid))
	    goto parse_err;
	sync_msgid_insert(part_list, tmpguid);
    }

    /* need a list so we can mark items */
    for (i = ml->head; i; i = i->next) {
	sync_name_list_add(folder_names, i->sval);
    }

    for (folder = folder_names->head; folder; folder = folder->next) {
	if (!part_list->toupload) break;
	if (mboxlist_lookup(folder->name, &mbentry, 0))
	    continue;
	if (strcmp(mbentry->partition, partition)) {
	    mboxlist_entry_free(&mbentry);
	    continue; /* try folders on the same partition first! */
	}
	mboxlist_entry_free(&mbentry);
	reserve_folder(partition, folder->name, part_list);
	folder->mark = 1;
    }

    /* if we have other folders, check them now */
    for (folder = folder_names->head; folder; folder = folder->next) {
	if (!part_list->toupload) break;
	if (folder->mark)
	    continue;
	reserve_folder(partition, folder->name, part_list);
	folder->mark = 1;
    }

    /* check if we missed any */
    kout = dlist_newlist(NULL, "MISSING");
    for (i = gl->head; i; i = i->next) {
	if (!dlist_toguid(i, &tmpguid))
	    goto parse_err;
	item = sync_msgid_lookup(part_list, tmpguid);
	if (item->need_upload)
	    dlist_setguid(kout, "GUID", tmpguid);
    }

    if (kout->head)
	sync_send_response(kout, sync_out);
    dlist_free(&kout);

    sync_name_list_free(&folder_names);
    mboxlist_entry_free(&mbentry);

    return 0;

 parse_err:
    dlist_free(&kout);
    sync_name_list_free(&folder_names);
    mboxlist_entry_free(&mbentry);

    return IMAP_PROTOCOL_BAD_PARAMETERS;
}

/* ====================================================================== */

static int do_unquota(struct dlist *kin)
{
    return mboxlist_unsetquota(kin->sval);
}

static int do_quota(struct dlist *kin)
{
    const char *root;
    quota_t limits[QUOTA_NUMRESOURCES];

    if (!dlist_getatom(kin, "ROOT", &root))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    sync_decode_quota_limits(kin, limits);
    return mboxlist_setquotas(root, limits, 1);
}

/* ====================================================================== */

static int mailbox_compare_update(struct mailbox *mailbox,
				  struct dlist *kr, int doupdate)
{
    struct index_record mrecord;
    struct index_record rrecord;
    uint32_t recno = 1;
    struct dlist *ki;
    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;
    int r;
    int i;

    rrecord.uid = 0;
    for (ki = kr->head; ki; ki = ki->next) {
	sync_annot_list_free(&mannots);
	sync_annot_list_free(&rannots);

	r = parse_upload(ki, mailbox, &mrecord, &mannots);
	if (r) {
	    syslog(LOG_ERR, "SYNCERROR: failed to parse uploaded record");
	    return IMAP_PROTOCOL_ERROR;
	}

	while (rrecord.uid < mrecord.uid) {
	    /* hit the end?  Magic marker */
	    if (recno > mailbox->i.num_records) {
		rrecord.uid = UINT32_MAX;
		break;
	    }

	    /* read another record */
	    r = mailbox_read_index_record(mailbox, recno, &rrecord);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to read record %s %u",
		       mailbox->name, recno);
		goto out;
	    }
	    recno++;
	}

	/* found a match, check for updates */
	if (rrecord.uid == mrecord.uid) {
	    /* if they're both EXPUNGED then ignore everything else */
	    if ((mrecord.system_flags & FLAG_EXPUNGED) &&
		(rrecord.system_flags & FLAG_EXPUNGED))
		continue;

	    /* higher modseq on the replica is an error */
	    if (rrecord.modseq > mrecord.modseq) {
		if (opt_force) {
		    syslog(LOG_NOTICE, "forcesync: higher modseq on replica %s %u (" MODSEQ_FMT " > " MODSEQ_FMT ")",
			   mailbox->name, mrecord.uid, rrecord.modseq, mrecord.modseq);
		}
		else {
		    syslog(LOG_ERR, "SYNCERROR: higher modseq on replica %s %u (" MODSEQ_FMT " > " MODSEQ_FMT ")",
			   mailbox->name, mrecord.uid, rrecord.modseq, mrecord.modseq);
		    r = IMAP_SYNC_CHECKSUM;
		    goto out;
		}
	    }

	    /* GUID mismatch is an error straight away, it only ever happens if we
	     * had a split brain - and it will take a full sync to sort out the mess */
	    if (!message_guid_equal(&mrecord.guid, &rrecord.guid)) {
		syslog(LOG_ERR, "SYNCERROR: guid mismatch %s %u",
		       mailbox->name, mrecord.uid);
		r = IMAP_SYNC_CHECKSUM;
		goto out;
	    }

	    /* if it's already expunged on the replica, but alive on the master,
	     * that's bad */
	    if (!(mrecord.system_flags & FLAG_EXPUNGED) &&
		 (rrecord.system_flags & FLAG_EXPUNGED)) {
		syslog(LOG_ERR, "SYNCERROR: expunged on replica %s %u",
		       mailbox->name, mrecord.uid);
		r = IMAP_SYNC_CHECKSUM;
		goto out;
	    }

	    /* skip out on the first pass */
	    if (!doupdate) continue;

	    rrecord.modseq = mrecord.modseq;
	    rrecord.last_updated = mrecord.last_updated;
	    rrecord.internaldate = mrecord.internaldate;
	    rrecord.system_flags = (mrecord.system_flags & FLAGS_GLOBAL) |
				   (rrecord.system_flags & FLAGS_LOCAL);
	    for (i = 0; i < MAX_USER_FLAGS/32; i++)
		rrecord.user_flags[i] = mrecord.user_flags[i];

	    r = read_annotations(mailbox, &rrecord, &rannots);
	    if (r) {
		syslog(LOG_ERR, "Failed to read local annotations %s %u: %s",
		       mailbox->name, recno, error_message(r));
		goto out;
	    }

	    r = apply_annotations(mailbox, &rrecord, rannots, mannots, 0);
	    if (r) {
		syslog(LOG_ERR, "Failed to write merged annotations %s %u: %s",
		       mailbox->name, recno, error_message(r));
		goto out;
	    }

	    rrecord.silent = 1;
	    r = mailbox_rewrite_index_record(mailbox, &rrecord);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to rewrite record %s %u",
		       mailbox->name, recno);
		goto out;
	    }
	}

	/* not found and less than LAST_UID, bogus */
	else if (mrecord.uid <= mailbox->i.last_uid) {
	    /* Expunged, just skip it */
	    if (!(mrecord.system_flags & FLAG_EXPUNGED)) {
		r = IMAP_SYNC_CHECKSUM;
		goto out;
	    }
	}

	/* after LAST_UID, it's an append, that's OK */
	else {
	    /* skip out on the first pass */
	    if (!doupdate) continue;

	    mrecord.silent = 1;
	    r = sync_append_copyfile(mailbox, &mrecord, mannots);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: failed to append file %s %d",
		       mailbox->name, recno);
		goto out;
	    }
	}
    }

    r = 0;

out:
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);
    return r;
}


/* if either CRC is zero for a field, then we consider it to match.
 * this lets us bootstrap the case where CRCs weren't being calculated,
 * and also allows a client with incomplete local information to request
 * a change be made on a sync_server without having to fetch all the
 * data first just to calculate the CRC */
static int crceq(struct synccrcs a, struct synccrcs b)
{
    if (a.basic && b.basic && a.basic != b.basic) return 0;
    if (a.annot && b.annot && a.annot != b.annot) return 0;
    return 1;
}

static int do_mailbox(struct dlist *kin)
{
    /* fields from the request */
    const char *uniqueid;
    const char *partition;
    const char *mboxname;
    const char *mboxtype = NULL; /* optional */
    uint32_t mbtype;
    uint32_t last_uid;
    modseq_t highestmodseq;
    uint32_t recentuid;
    time_t recenttime;
    time_t last_appenddate;
    time_t pop3_last_login;
    time_t pop3_show_after = 0; /* optional */
    uint32_t uidvalidity;
    const char *acl;
    const char *options_str;
    struct synccrcs synccrcs = { 0, 0 };

    uint32_t options;

    struct mailbox *mailbox = NULL;
    struct dlist *kr;
    struct dlist *ka = NULL;
    int r;

    struct sync_annot_list *mannots = NULL;
    struct sync_annot_list *rannots = NULL;

    annotate_state_t *astate = NULL;

    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "LAST_UID", &last_uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum64(kin, "HIGHESTMODSEQ", &highestmodseq))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "RECENTUID", &recentuid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "RECENTTIME", &recenttime))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LAST_APPENDDATE", &last_appenddate))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "POP3_LAST_LOGIN", &pop3_last_login))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "UIDVALIDITY", &uidvalidity))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ACL", &acl))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "OPTIONS", &options_str))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kin, "RECORD", &kr))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* optional */
    dlist_getlist(kin, "ANNOTATIONS", &ka);
    dlist_getdate(kin, "POP3_SHOW_AFTER", &pop3_show_after);
    dlist_getatom(kin, "MBOXTYPE", &mboxtype);

    /* Get the CRCs */
    dlist_getnum32(kin, "SYNC_CRC", &synccrcs.basic);
    dlist_getnum32(kin, "SYNC_CRC_ANNOT", &synccrcs.annot);

    options = sync_parse_options(options_str);
    mbtype = mboxlist_string_to_mbtype(mboxtype);

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	r = mboxlist_createsync(mboxname, mbtype, partition,
				sync_userid, sync_authstate,
				options, uidvalidity, acl,
				uniqueid, &mailbox);
	/* set a highestmodseq of 0 so ALL changes are future
	 * changes and get applied */
	if (!r) mailbox->i.highestmodseq = 0;
    }
    if (r) {
	syslog(LOG_ERR, "Failed to open mailbox %s to update: %s",
	       mboxname, error_message(r));
	goto done;
    }

    if (mailbox->mbtype != mbtype) {
	syslog(LOG_ERR, "INVALID MAILBOX TYPE %s (%d, %d)", mailbox->name, mailbox->mbtype, mbtype);
	/* is this even possible? */
	r = IMAP_MAILBOX_BADTYPE;
	goto done;
    }

    /* hold the annotate state open */
    mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    /* and make it hold a transaction open */
    annotate_state_begin(astate);

    if (strcmp(mailbox->uniqueid, uniqueid)) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: fixing uniqueid %s (%s => %s)",
		   mboxname, mailbox->uniqueid, uniqueid);
	    free(mailbox->uniqueid);
	    mailbox->uniqueid = xstrdup(uniqueid);
	    mailbox->header_dirty = 1;
	}
	else {
	    syslog(LOG_ERR, "Mailbox uniqueid changed %s (%s => %s) - retry",
		   mboxname, mailbox->uniqueid, uniqueid);
	    r = IMAP_MAILBOX_MOVED;
	    goto done;
	}
    }

    /* skip out now, it's going to mismatch for sure! */
    if (highestmodseq < mailbox->i.highestmodseq) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: higher modseq on replica %s - "
		   MODSEQ_FMT " < " MODSEQ_FMT,
		   mboxname, highestmodseq, mailbox->i.highestmodseq);
	}
	else {
	    syslog(LOG_ERR, "higher modseq on replica %s - "
		   MODSEQ_FMT " < " MODSEQ_FMT,
		   mboxname, highestmodseq, mailbox->i.highestmodseq);
	    r = IMAP_SYNC_CHECKSUM;
	    goto done;
	}
    }

    /* skip out now, it's going to mismatch for sure! */
    if (uidvalidity < mailbox->i.uidvalidity) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: higher uidvalidity on replica %s - %u < %u",
		   mboxname, uidvalidity, mailbox->i.uidvalidity);
	}
	else {
	    syslog(LOG_ERR, "higher uidvalidity on replica %s - %u < %u",
		   mboxname, uidvalidity, mailbox->i.uidvalidity);
	    r = IMAP_SYNC_CHECKSUM;
	    goto done;
	}
    }

    /* skip out now, it's going to mismatch for sure! */
    if (last_uid < mailbox->i.last_uid) {
	if (opt_force) {
	    syslog(LOG_NOTICE, "forcesync: higher last_uid on replica %s - %u < %u",
		   mboxname, last_uid, mailbox->i.last_uid);
	}
	else {
	    syslog(LOG_ERR, "higher last_uid on replica %s - %u < %u",
		   mboxname, last_uid, mailbox->i.last_uid);
	    r = IMAP_SYNC_CHECKSUM;
	    goto done;
	}
    }

    /* always take the ACL from the master, it's not versioned */
    if (strcmp(mailbox->acl, acl)) {
	mailbox_set_acl(mailbox, acl, 0);
	r = mboxlist_sync_setacls(mboxname, acl);
	if (r) goto done;
    }

    r = mailbox_compare_update(mailbox, kr, 0);
    if (r) goto done;

    /* take all mailbox (not message) annotations - aka metadata,
     * they're not versioned either */
    if (ka)
	decode_annotations(ka, &mannots, NULL);

    r = read_annotations(mailbox, NULL, &rannots);
    if (!r) r = apply_annotations(mailbox, NULL, rannots, mannots, 0);

    if (r) {
	syslog(LOG_ERR, "syncerror: annotations failed to apply to %s",
	       mailbox->name);
	goto done;
    }

    r = mailbox_compare_update(mailbox, kr, 1);
    if (r) {
	abort();
	return r;
    }

    mailbox_index_dirty(mailbox);
    if (!opt_force) {
	assert(mailbox->i.last_uid <= last_uid);
    }
    mailbox->i.last_uid = last_uid;
    mailbox->i.recentuid = recentuid;
    mailbox->i.recenttime = recenttime;
    mailbox->i.last_appenddate = last_appenddate;
    mailbox->i.pop3_last_login = pop3_last_login;
    mailbox->i.pop3_show_after = pop3_show_after;
    /* only alter the syncable options */
    mailbox->i.options = (options & MAILBOX_OPTIONS_MASK) |
			 (mailbox->i.options & ~MAILBOX_OPTIONS_MASK);

    /* this happens all the time! */
    if (mailbox->i.highestmodseq < highestmodseq) {
	mailbox->i.highestmodseq = highestmodseq;
    }

    /* this happens rarely, so let us know */
    if (mailbox->i.uidvalidity != uidvalidity) {
	syslog(LOG_NOTICE, "%s uidvalidity changed, updating %u => %u",
	       mailbox->name, mailbox->i.uidvalidity, uidvalidity);
	mailbox->i.uidvalidity = uidvalidity;
    }

done:
    sync_annot_list_free(&mannots);
    sync_annot_list_free(&rannots);

    /* check the CRC too */
    if (!r && !crceq(synccrcs, mailbox_synccrcs(mailbox, 0))) {
	/* try forcing a recalculation */
	if (!crceq(synccrcs, mailbox_synccrcs(mailbox, 1)))
	    r = IMAP_SYNC_CHECKSUM;
    }

    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

static int getannotation_cb(const char *mailbox __attribute__((unused)),
			    uint32_t uid __attribute__((unused)),
			    const char *entry, const char *userid,
			    const struct buf *value,
			    void *rock)
{
    const char *mboxname = (char *)rock;
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, "ANNOTATION");
    dlist_setatom(kl, "MBOXNAME", mboxname);
    dlist_setatom(kl, "ENTRY", entry);
    dlist_setatom(kl, "USERID", userid);
    dlist_setmap(kl, "VALUE", value->s, value->len);
    sync_send_response(kl, sync_out);
    dlist_free(&kl);

    return 0;
}

static int do_getannotation(struct dlist *kin)
{
    const char *mboxname = kin->sval;
    return annotatemore_findall(mboxname, 0, "*", &getannotation_cb,
				(void *)mboxname);
}

static void print_quota(struct quota *q)
{
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, "QUOTA");
    dlist_setatom(kl, "ROOT", q->root);
    sync_encode_quota_limits(kl, q->limits);
    sync_send_response(kl, sync_out);
    dlist_free(&kl);
}

static int quota_work(const char *root)
{
    struct quota q;

    quota_init(&q, root);
    if (!quota_read(&q, NULL, 0))
	print_quota(&q);
    quota_free(&q);

    return 0;
}

static int do_getquota(struct dlist *kin)
{
    return quota_work(kin->sval);
}

static int mailbox_cb(char *name,
		      int matchlen __attribute__((unused)),
		      int maycreate __attribute__((unused)),
		      void *rock)
{
    struct sync_name_list *qrl = (struct sync_name_list *)rock;
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");
    annotate_state_t *astate = NULL;
    int r;

    /* XXX - we don't write anything, but there's no interface
     * to safely get read-only access to the annotation and
     * other "side" databases here */
    r = mailbox_open_iwl(name, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT ||
	r == IMAP_MAILBOX_RESERVED) {
	r = 0;
	goto out;
    }
    if (r) goto out;

    /* hold the annotate state open */
    mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    /* and make it hold a transaction open */
    annotate_state_begin(astate);

    if (qrl && mailbox->quotaroot &&
	 !sync_name_lookup(qrl, mailbox->quotaroot))
	sync_name_list_add(qrl, mailbox->quotaroot);

    r = sync_mailbox(mailbox, NULL, NULL, kl, NULL, 0);
    if (!r) sync_send_response(kl, sync_out);

out:
    mailbox_close(&mailbox);
    dlist_free(&kl);

    return r;
}

static int do_getfullmailbox(struct dlist *kin)
{
    struct mailbox *mailbox = NULL;
    struct dlist *kl = dlist_newkvlist(NULL, "MAILBOX");
    int r;

    /* XXX again - this is a read-only request, but we
     * don't have a good way to express that, so we use
     * write locks anyway */
    r = mailbox_open_iwl(kin->sval, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r) goto out;

    r = sync_mailbox(mailbox, NULL, NULL, kl, NULL, 1);
    if (r) goto out;

    sync_send_response(kl, sync_out);

out:
    dlist_free(&kl);
    mailbox_close(&mailbox);
    return r;
}

static int do_getmailboxes(struct dlist *kin)
{
    struct dlist *ki;

    for (ki = kin->head; ki; ki = ki->next)
	mailbox_cb(ki->sval, 0, 0, NULL);

    return 0;
}

/* ====================================================================== */

static int print_seen(const char *uniqueid, struct seendata *sd,
		      void *rock __attribute__((unused)))
{
    struct dlist *kl;

    kl = dlist_newkvlist(NULL, "SEEN");
    dlist_setatom(kl, "UNIQUEID", uniqueid);
    dlist_setdate(kl, "LASTREAD", sd->lastread);
    dlist_setnum32(kl, "LASTUID", sd->lastuid);
    dlist_setdate(kl, "LASTCHANGE", sd->lastchange);
    dlist_setatom(kl, "SEENUIDS", sd->seenuids);
    sync_send_response(kl, sync_out);
    dlist_free(&kl);

    return 0;
}

static int user_seen(const char *userid)
{
    struct seen *seendb = NULL;

    /* no SEEN DB is OK, just return */
    if (seen_open(userid, SEEN_SILENT, &seendb))
	return 0;

    seen_foreach(seendb, print_seen, NULL);
    seen_close(&seendb);

    return 0;
}


static int user_sub(const char *userid)
{
    struct sync_name_list *list = sync_name_list_create();
    struct sync_name *item;
    struct dlist *kl;

    mboxlist_allsubs(userid, addmbox_sub, list);

    kl = dlist_newlist(NULL, "LSUB");
    for (item = list->head; item; item = item->next) {
	dlist_setatom(kl, "MBOXNAME", item->name);
    }
    if (kl->head)
	sync_send_response(kl, sync_out);

    dlist_free(&kl);
    sync_name_list_free(&list);

    return 0;
}

static int user_sieve(const char *userid)
{
    struct sync_sieve_list *sieve_list;
    struct sync_sieve *sieve;
    struct dlist *kl;

    sieve_list = sync_sieve_list_generate(userid);

    if (!sieve_list) return 0;

    for (sieve = sieve_list->head; sieve; sieve = sieve->next) {
	kl = dlist_newkvlist(NULL, "SIEVE");
	dlist_setatom(kl, "FILENAME", sieve->name);
	dlist_setdate(kl, "LAST_UPDATE", sieve->last_update);
	dlist_setatom(kl, "GUID", message_guid_encode(&sieve->guid));
	dlist_setnum32(kl, "ISACTIVE", sieve->active ? 1 : 0);
	sync_send_response(kl, sync_out);
	dlist_free(&kl);
    }

    sync_sieve_list_free(&sieve_list);

    return 0;
}

static int user_meta(const char *userid)
{
    user_seen(userid);
    user_sub(userid);
    user_sieve(userid);
    return 0;
}

static int do_getmeta(struct dlist *kin)
{
    return user_meta(kin->sval);
}

static int do_getuser(struct dlist *kin)
{
    char buf[MAX_MAILBOX_PATH];
    int r;
    struct sync_name_list *quotaroots;
    struct sync_name *qr;
    const char *userid = kin->sval;

    quotaroots = sync_name_list_create();

    /* inbox */
    ((*sync_namespacep).mboxname_tointernal)(sync_namespacep, "INBOX",
					     userid, buf);
    r = mailbox_cb(buf, 0, 0, quotaroots);
    if (r) goto bail;

    /* deleted namespace items if enabled */
    if (mboxlist_delayed_delete_isenabled()) {
	char deletedname[MAX_MAILBOX_BUFFER];
	mboxname_todeleted(buf, deletedname, 0);
	strlcat(deletedname, ".*", sizeof(deletedname));
	r = (sync_namespace.mboxlist_findall)(sync_namespacep, deletedname,
					      sync_userisadmin,
					      userid, sync_authstate,
					      mailbox_cb, quotaroots);
	if (r) goto bail;
    }

    /* And then all folders */
    strlcat(buf, ".*", sizeof(buf));
    r = ((*sync_namespacep).mboxlist_findall)(sync_namespacep, buf,
					      sync_userisadmin,
					      userid, sync_authstate,
					      mailbox_cb, quotaroots);
    if (r) goto bail;

    for (qr = quotaroots->head; qr; qr = qr->next) {
	r = quota_work(qr->name);
	if (r) goto bail;
    }

    r = user_meta(userid);
    if (r) goto bail;

    sync_log_user(userid);

bail:
    sync_name_list_free(&quotaroots);
    return r;
}

/* ====================================================================== */

static int do_unmailbox(struct dlist *kin)
{
    const char *mboxname = kin->sval;

    /* Delete with admin priveleges */
    return mboxlist_deletemailbox(mboxname, sync_userisadmin, sync_userid,
				  sync_authstate, NULL, 0, 1, 0);
}

static int do_rename(struct dlist *kin)
{
    const char *oldmboxname;
    const char *newmboxname;
    const char *partition;
    uint32_t uidvalidity = 0;

    if (!dlist_getatom(kin, "OLDMBOXNAME", &oldmboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "NEWMBOXNAME", &newmboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* optional */
    dlist_getnum32(kin, "UIDVALIDITY", &uidvalidity);

    return mboxlist_renamemailbox(oldmboxname, newmboxname, partition,
				  uidvalidity,
				  1, sync_userid, sync_authstate, NULL, 0, 1, 1);
}

static int do_changesub(struct dlist *kin)
{
    const char *mboxname;
    const char *userid;
    int add;

    /* SUB or UNSUB */
    add = strcmp(kin->name, "SUB") ? 0 : 1;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return mboxlist_changesub(mboxname, userid, sync_authstate, add, add, 0);
}

/* ====================================================================== */

static int do_annotation(struct dlist *kin)
{
    struct entryattlist *entryatts = NULL;
    struct attvaluelist *attvalues = NULL;
    const char *mboxname = NULL;
    const char *entry = NULL;
    const char *mapval = NULL;
    size_t maplen = 0;
    struct buf value = BUF_INITIALIZER;
    const char *userid = NULL;
    char *name = NULL;
    struct mailbox *mailbox = NULL;
    annotate_state_t *astate = NULL;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ENTRY", &entry))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getmap(kin, "VALUE", &mapval, &maplen))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    buf_init_ro(&value, mapval, maplen);

    /* annotate_state_store() expects external mailbox names,
       so translate the separator character */
    name = xstrdup(mboxname);
    mboxname_hiersep_toexternal(sync_namespacep, name, 0);

    r = mailbox_open_iwl(name, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r) goto done;

    appendattvalue(&attvalues,
		   *userid ? "value.priv" : "value.shared",
		   &value);
    appendentryatt(&entryatts, entry, attvalues);
    astate = annotate_state_new();
    annotate_state_set_auth(astate,
			    sync_userisadmin, userid, sync_authstate);
    r = annotate_state_set_mailbox(astate, mailbox);
    if (r) goto done;

    r = annotate_state_store(astate, entryatts);

done:
    if (!r)
	r = annotate_state_commit(&astate);
    else
	annotate_state_abort(&astate);

    mailbox_close(&mailbox);

    freeentryatts(entryatts);
    free(name);

    return r;
}

static int do_unannotation(struct dlist *kin)
{
    struct entryattlist *entryatts = NULL;
    struct attvaluelist *attvalues = NULL;
    const char *mboxname = NULL;
    const char *entry = NULL;
    const char *userid = NULL;
    struct buf empty = BUF_INITIALIZER;
    char *name = NULL;
    struct mailbox *mailbox = NULL;
    annotate_state_t *astate = NULL;
    int r;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "ENTRY", &entry))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* (gnb)TODO: this is broken with unixhierarchysep */
    /* annotatemore_store() expects external mailbox names,
       so translate the separator character */
    name = xstrdup(mboxname);
    mboxname_hiersep_toexternal(sync_namespacep, name, 0);

    r = mailbox_open_iwl(name, &mailbox);
    if (!r)
	r = sync_mailbox_version_check(&mailbox);
    if (r)
	goto done;

    appendattvalue(&attvalues,
		   *userid ? "value.priv" : "value.shared",
		   &empty);
    appendentryatt(&entryatts, entry, attvalues);
    astate = annotate_state_new();
    annotate_state_set_auth(astate,
			    sync_userisadmin, userid, sync_authstate);
    r = annotate_state_set_mailbox(astate, mailbox);
    if (r) goto done;

    r = annotate_state_store(astate, entryatts);

done:
    if (!r)
	r = annotate_state_commit(&astate);
    else
	annotate_state_abort(&astate);
    mailbox_close(&mailbox);
    freeentryatts(entryatts);
    free(name);

    return r;
}

static int do_sieve(struct dlist *kin)
{
    const char *userid;
    const char *filename;
    time_t last_update;
    const char *content;
    size_t len;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LAST_UPDATE", &last_update))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getmap(kin, "CONTENT", &content, &len))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_upload(userid, filename, last_update, content, len);
}

static int do_unsieve(struct dlist *kin)
{
    const char *userid;
    const char *filename;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_delete(userid, filename);
}

static int do_activate_sieve(struct dlist *kin)
{
    const char *userid;
    const char *filename;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_activate(userid, filename);
}

static int do_unactivate_sieve(struct dlist *kin)
{
    const char *userid;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    return sync_sieve_deactivate(userid);
}

static int do_seen(struct dlist *kin)
{
    int r;
    struct seen *seendb = NULL;
    struct seendata sd = SEENDATA_INITIALIZER;
    const char *seenuids;
    const char *userid;
    const char *uniqueid;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LASTREAD", &sd.lastread))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "LASTUID", &sd.lastuid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(kin, "LASTCHANGE", &sd.lastchange))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "SEENUIDS", &seenuids))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    sd.seenuids = xstrdup(seenuids);

    r = seen_open(userid, SEEN_CREATE, &seendb);
    if (r) return r;

    r = seen_write(seendb, uniqueid, &sd);
    seen_close(&seendb);

    seen_freedata(&sd);

    return r;
}

static int do_unuser(struct dlist *kin)
{
    struct sync_name_list *list = sync_name_list_create();
    struct sync_name *item;
    const char *userid = kin->sval;
    char buf[MAX_MAILBOX_NAME];
    int r = 0;

    /* nothing to do if there's no userid */
    if (!userid || !userid[0]) {
	syslog(LOG_WARNING, "ignoring attempt to %s() without userid", __func__);
	return 0;
    }

    /* Nuke subscriptions */
    mboxlist_allsubs(userid, addmbox_sub, list);

    /* ignore failures here - the subs file gets deleted soon anyway */
    for (item = list->head; item; item = item->next) {
	mboxlist_changesub(item->name, userid, sync_authstate, 0, 0, 0);
    }
    sync_name_list_free(&list);

    /* Nuke normal folders */
    list = sync_name_list_create();

    (sync_namespacep->mboxname_tointernal)(sync_namespacep, "INBOX",
					   userid, buf);
    strlcat(buf, ".*", sizeof(buf));
    r = (sync_namespacep->mboxlist_findall)(sync_namespacep, buf,
					    sync_userisadmin,
					    sync_userid, sync_authstate,
					    addmbox, (void *)list);
    if (r) goto fail;

    for (item = list->head; item; item = item->next) {
	r = mboxlist_deletemailbox(item->name, sync_userisadmin,
				   sync_userid, sync_authstate, NULL, 0, 0, 1);
	if (r) goto fail;
    }

    /* Nuke inbox (recursive nuke possible?) */
    (sync_namespacep->mboxname_tointernal)(sync_namespacep, "INBOX",
					   userid, buf);
    r = mboxlist_deletemailbox(buf, sync_userisadmin, sync_userid,
			       sync_authstate, NULL, 0, 1, 0);
    if (r && (r != IMAP_MAILBOX_NONEXISTENT)) goto fail;

    r = user_deletedata(userid, 1);

 fail:
    sync_name_list_free(&list);

    return r;
}

/* ====================================================================== */

static int do_fetchsieve(struct dlist *kin)
{
    struct dlist *kl;
    const char *userid;
    const char *filename;
    uint32_t size;
    char *sieve;

    if (!dlist_getatom(kin, "USERID", &userid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "FILENAME", &filename))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    sieve = sync_sieve_read(userid, filename, &size);
    if (!sieve)
	return IMAP_MAILBOX_NONEXISTENT;

    kl = dlist_newkvlist(NULL, "SIEVE");
    dlist_setatom(kl, "USERID", userid);
    dlist_setatom(kl, "FILENAME", filename);
    dlist_setmap(kl, "CONTENT", sieve, size);
    sync_send_response(kl, sync_out);
    dlist_free(&kl);
    free(sieve);

    return 0;
}

/* NOTE - can't lock a mailbox here, because it could deadlock,
 * so just pick the file out from under the hood */
static int do_fetch(struct dlist *kin)
{
    const char *mboxname;
    const char *partition;
    const char *guid;
    uint32_t uid;
    const char *fname;
    struct dlist *kl;
    struct message_guid tmp_guid;
    struct stat sbuf;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "PARTITION", &partition))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "GUID", &guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(kin, "UID", &uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!message_guid_decode(&tmp_guid, guid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    fname = mboxname_datapath(partition, mboxname, uid);
    if (stat(fname, &sbuf) == -1)
	return IMAP_MAILBOX_NONEXISTENT;

    kl = dlist_setfile(NULL, "MESSAGE", partition, &tmp_guid, sbuf.st_size, fname);
    sync_send_response(kl, sync_out);
    dlist_free(&kl);

    return 0;
}

static int do_expunge(struct dlist *kin)
{
    const char *mboxname;
    const char *uniqueid;
    struct dlist *ul;
    struct dlist *ui;
    struct mailbox *mailbox = NULL;
    struct index_record record;
    uint32_t recno;
    int r = 0;

    if (!dlist_getatom(kin, "MBOXNAME", &mboxname))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(kin, "UNIQUEID", &uniqueid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(kin, "UID", &ul))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (!r) r = sync_mailbox_version_check(&mailbox);
    if (r) goto done;

    /* don't want to expunge the wrong mailbox! */
    if (strcmp(mailbox->uniqueid, uniqueid)) {
	r = IMAP_MAILBOX_MOVED;
	goto done;
    }

    ui = ul->head;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);
	if (r) goto done;
	if (record.system_flags & FLAG_EXPUNGED) continue;
	while (ui && dlist_num(ui) < record.uid) ui = ui->next;
	if (!ui) break; /* no point continuing */
	if (record.uid == dlist_num(ui)) {
	    record.system_flags |= FLAG_EXPUNGED;
	    record.silent = 1; /* so the next sync will succeed */
	    r = mailbox_rewrite_index_record(mailbox, &record);
	    if (r) goto done;
	}
    }

done:
    mailbox_close(&mailbox);
    return r;
}

static int do_upload(struct dlist *kin, struct sync_reserve_list *reserve_list)
{
    struct sync_msgid_list *part_list;
    struct dlist *ki;
    struct sync_msgid *msgid;

    for (ki = kin->head; ki; ki = ki->next) {
	struct message_guid *guid;
	const char *part;

	/* XXX - complain more? */
	if (!dlist_tofile(ki, &part, &guid, NULL, NULL))
	    continue;

	part_list = sync_reserve_partlist(reserve_list, part);
	msgid = sync_msgid_insert(part_list, guid);
	if (msgid->need_upload) {
	    msgid->need_upload = 0;
	    part_list->toupload--;
	}
    }

    return 0;
}

static void print_response(int r)
{
    switch (r) {
    case 0:
	prot_printf(sync_out, "OK success\r\n");
	break;
    case IMAP_INVALID_USER:
	prot_printf(sync_out, "NO IMAP_INVALID_USER No Such User\r\n");
	break;
    case IMAP_MAILBOX_NONEXISTENT:
	prot_printf(sync_out, "NO IMAP_MAILBOX_NONEXISTENT No Such Mailbox\r\n");
	break;
    case IMAP_SYNC_CHECKSUM:
	prot_printf(sync_out, "NO IMAP_SYNC_CHECKSUM Checksum Failure\r\n");
	break;
    case IMAP_PROTOCOL_ERROR:
	prot_printf(sync_out, "NO IMAP_PROTOCOL_ERROR Protocol error\r\n");
	break;
    case IMAP_PROTOCOL_BAD_PARAMETERS:
	prot_printf(sync_out, "NO IMAP_PROTOCOL_BAD_PARAMETERS near %s\r\n", dlist_lastkey());
	break;
    case IMAP_MAILBOX_NOTSUPPORTED:
	prot_printf(sync_out, "NO IMAP_MAILBOX_NOTSUPPORTED Operation is not supported on mailbox\r\n");
	break;
    default:
	prot_printf(sync_out, "NO %s\r\n", error_message(r));
    }
}

static void cmd_apply(struct dlist *kin, struct sync_reserve_list *reserve_list)
{
    int r;

    if (!strcmp(kin->name, "MESSAGE"))
	r = do_upload(kin, reserve_list);
    else if (!strcmp(kin->name, "EXPUNGE"))
	r = do_expunge(kin);

    /* dump protocol */
    else if (!strcmp(kin->name, "ACTIVATE_SIEVE"))
	r = do_activate_sieve(kin);
    else if (!strcmp(kin->name, "ANNOTATION"))
	r = do_annotation(kin);
    else if (!strcmp(kin->name, "MAILBOX"))
	r = do_mailbox(kin);
    else if (!strcmp(kin->name, "QUOTA"))
	r = do_quota(kin);
    else if (!strcmp(kin->name, "SEEN"))
	r = do_seen(kin);
    else if (!strcmp(kin->name, "RENAME"))
	r = do_rename(kin);
    else if (!strcmp(kin->name, "RESERVE"))
	r = do_reserve(kin, reserve_list);
    else if (!strcmp(kin->name, "SIEVE"))
	r = do_sieve(kin);
    else if (!strcmp(kin->name, "SUB"))
	r = do_changesub(kin);

    /* "un"dump protocol ;) */
    else if (!strcmp(kin->name, "UNACTIVATE_SIEVE"))
	r = do_unactivate_sieve(kin);
    else if (!strcmp(kin->name, "UNANNOTATION"))
	r = do_unannotation(kin);
    else if (!strcmp(kin->name, "UNMAILBOX"))
	r = do_unmailbox(kin);
    else if (!strcmp(kin->name, "UNQUOTA"))
	r = do_unquota(kin);
    else if (!strcmp(kin->name, "UNSIEVE"))
	r = do_unsieve(kin);
    else if (!strcmp(kin->name, "UNSUB"))
	r = do_changesub(kin);

    /* user is a special case that's not paired, there's no "upload user"
     * as such - we just call the individual commands with their items */
    else if (!strcmp(kin->name, "UNUSER"))
	r = do_unuser(kin);

    else {
	syslog(LOG_ERR, "SYNCERROR: unknown command %s", kin->name);
	r = IMAP_PROTOCOL_ERROR;
    }

    print_response(r);
}

static void cmd_get(struct dlist *kin)
{
    int r;

    if (!strcmp(kin->name, "ANNOTATION"))
	r = do_getannotation(kin);
    else if (!strcmp(kin->name, "FETCH"))
	r = do_fetch(kin);
    else if (!strcmp(kin->name, "FETCH_SIEVE"))
	r = do_fetchsieve(kin);
    else if (!strcmp(kin->name, "FULLMAILBOX"))
	r = do_getfullmailbox(kin);
    else if (!strcmp(kin->name, "MAILBOXES"))
	r = do_getmailboxes(kin);
    else if (!strcmp(kin->name, "META"))
	r = do_getmeta(kin);
    else if (!strcmp(kin->name, "QUOTA"))
	r = do_getquota(kin);
    else if (!strcmp(kin->name, "USER"))
	r = do_getuser(kin);
    else
	r = IMAP_PROTOCOL_ERROR;

    print_response(r);
}
