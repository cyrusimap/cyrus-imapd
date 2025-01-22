/* timsieved.c -- main file for timsieved (sieve script accepting program)
 * Tim Martin
 * 9/21/99
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sasl/sasl.h> /* yay! sasl */
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "auth.h"
#include "libconfig.h"
#include "slowio.h"
#include "xmalloc.h"
#include "imap/backend.h"
#include "imap/global.h"
#include "imap/mboxlist.h"
#include "imap/proxy.h"
#include "imap/sync_log.h"
#include "lib/assert.h"
#include "master/service.h"
#include "sieve/sieve_interface.h"
#include "timsieved/actions.h"
#include "timsieved/codes.h"
#include "timsieved/parser.h"
#include "timsieved/lex.h"

/* global state */
const int config_need_data = 0;

int sieved_tls_required = 0;

sieve_interp_t *interp = NULL;

static struct saslprops_t saslprops = SASLPROPS_INITIALIZER;

sasl_conn_t *sieved_saslconn; /* the sasl connection context */

static struct auth_state *sieved_authstate = 0;

int sieved_timeout;
static struct protstream *sieved_out;
static struct protstream *sieved_in;

int sieved_logfd = -1;

const char *sieved_clienthost = "[local]";

int sieved_userisadmin;
int sieved_domainfromip = 0;

/* the sasl proxy policy context */
static struct proxy_context sieved_proxyctx = {
    1, 1, &sieved_authstate, &sieved_userisadmin, NULL
};

/* PROXY stuff */
struct backend *backend = NULL;

static void bitpipe(void);
/* end PROXY stuff */

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__ ((noreturn));
void shut_down(int code)
{
    /* free interpreter */
    if (interp) sieve_interp_free(&interp);

    /* close backend connection */
    if (backend) {
        backend_disconnect(backend);
        free(backend);
    }

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    saslprops_free(&saslprops);

    cyrus_done();

    /* cleanup */
    if (sieved_out) {
        prot_flush(sieved_out);
        prot_free(sieved_out);
    }
    if (sieved_in) prot_free(sieved_in);

    if (sieved_logfd != -1) close(sieved_logfd);

    cyrus_reset_stdio();

    /* done */
    exit(code);
}

static void cmdloop(void)
{
    int ret = FALSE;

    if (chdir("/tmp/")) {
        syslog(LOG_ERR, "Failed to chdir to /tmp/");
        ret = TRUE; /* exit immediately */
    }

    capabilities(sieved_out, sieved_saslconn, 0, 0, 0);

    /* initialize lexer */
    lex_init();

    while (ret != TRUE)
    {
        if (backend) {
            /* create a pipe from client to backend */
            bitpipe();

            /* pipe has been closed */
            return;
        }

        ret = parser(sieved_out, sieved_in, &saslprops);
    }

    sync_log_done();

    /* done */
    shut_down(0);
}

EXPORTED void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        /* We were called recursively. Just give up */
        exit(recurse_code);
    }
    recurse_code = code;

    prot_printf(sieved_out, "NO Fatal error: %s\r\n", s);
    prot_flush(sieved_out);

    if (code != EX_PROTOCOL && config_fatals_abort) abort();

    shut_down(EX_TEMPFAIL);
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &sieved_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, (void*) &sieved_domainfromip },
    { SASL_CB_LIST_END, NULL, NULL }
};

EXPORTED int service_init(int argc, char **argv,
                 char **envp __attribute__((unused)))
{
    int opt;

    global_sasl_init(1, 1, mysasl_cb);

    /* build interpreter for compiling */
    interp = sieve_build_nonexec_interp();
    if (interp == NULL) shut_down(EX_SOFTWARE);

    while ((opt = getopt(argc, argv, "H")) != EOF) {
        switch(opt) {
        case 'H': /* expect HAProxy protocol header */
            haproxy_protocol = 1;
            break;

        default:
            break;
        }
    }

    return 0;
}

/* Called by service API to shut down the service */
EXPORTED void service_abort(int error)
{
    shut_down(error);
}

EXPORTED int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    const char *remoteip, *localip;
    sasl_security_properties_t *secprops = NULL;

    sync_log_init();

    /* set up the prot streams */
    sieved_in = prot_new(0, 0);
    sieved_out = prot_new(1, 1);

    sieved_timeout = config_getduration(IMAPOPT_TIMEOUT, 'm');
    if (sieved_timeout < 10 * 60) sieved_timeout = 10 * 60;
    prot_settimeout(sieved_in, sieved_timeout);
    prot_setflushonread(sieved_in, sieved_out);

    signal(SIGPIPE, SIG_IGN);

    if (geteuid() == 0) fatal("must run as the Cyrus user", -6);

    /* Find out name of client host */
    sieved_clienthost = get_clienthost(0, &localip, &remoteip);

    if (localip && remoteip) {
        buf_setcstr(&saslprops.ipremoteport, remoteip);
        buf_setcstr(&saslprops.iplocalport, localip);
    }

    /* other params should be filled in */
    if (sasl_server_new(SIEVE_SERVICE_NAME, config_servername, NULL,
                        buf_cstringnull_ifempty(&saslprops.iplocalport),
                        buf_cstringnull_ifempty(&saslprops.ipremoteport),
                        NULL, SASL_SUCCESS_DATA, &sieved_saslconn) != SASL_OK)
        fatal("SASL failed initializing: sasl_server_new()", -1);

    /* will always return something valid */
    secprops = mysasl_secprops(0);
    sasl_setprop(sieved_saslconn, SASL_SEC_PROPS, secprops);

    if (actions_init() != TIMSIEVE_OK)
      fatal("Error initializing actions",-1);

    sieved_tls_required = config_getswitch(IMAPOPT_TLS_REQUIRED);

    cmdloop();

    slowio_reset();

    /* never reaches */
    exit(EX_SOFTWARE);
}

/* Reset the given sasl_conn_t to a sane state */
int reset_saslconn(sasl_conn_t **conn)
{
    int ret = 0;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new(SIEVE_SERVICE_NAME, config_servername, NULL,
                          buf_cstringnull_ifempty(&saslprops.iplocalport),
                          buf_cstringnull_ifempty(&saslprops.ipremoteport),
                          NULL, SASL_SUCCESS_DATA, conn);
    if(ret != SASL_OK) return ret;

    secprops = mysasl_secprops(0);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;

    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
        ret = saslprops_set_tls(&saslprops, *conn);
        if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

/* we've authenticated the client, we've connected to the backend.
   now it's all up to them */
static void bitpipe(void)
{
    struct protgroup *protin = protgroup_new(2);
    int shutdown = 0;
    char buf[4096];

    protgroup_insert(protin, sieved_in);
    protgroup_insert(protin, backend->in);

    do {
        /* Flush any buffered output */
        prot_flush(sieved_out);
        prot_flush(backend->out);

        /* check for shutdown file */
        if (shutdown_file(buf, sizeof(buf))) {
            shutdown = 1;
            goto done;
        }
    } while (!proxy_check_input(protin, sieved_in, sieved_out,
                                backend->in, backend->out, PROT_NO_FD, NULL, 0));

 done:
    /* ok, we're done. */
    protgroup_free(protin);

    if (shutdown) prot_printf(sieved_out, "NO \"%s\"\r\n", buf);

    return;
}
