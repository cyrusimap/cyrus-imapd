/* deliver.c -- deliver shell - just calls lmtpd
 * Tim Martin
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "lmtpengine.h"
#include "prot.h"
#include "proxy.h"
#include "version.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

static int logdebug = 0;

static struct protstream *deliver_out, *deliver_in;

static const char *sockaddr;

static struct protocol_t lmtp_protocol =
{ "lmtp", "lmtp", TYPE_STD,
  { { { 0, "220 " },
      { "LHLO", "deliver", "250 ", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_SKIP_FIRST_WORD|CAPAF_DASH_STUFFING,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "PIPELINING", CAPA_PIPELINING },
          { "IGNOREQUOTA", CAPA_IGNOREQUOTA },
          { NULL, 0 } } },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL },
      { "NOOP", NULL, "250" },
      { "QUIT", NULL, "221" } } }
};

/* unused for deliver.c, but needed to make lmtpengine.c happy */
int deliver_logfd = -1;

/* forward declarations */

static int deliver_msg(char *return_path, char *authuser, int ignorequota,
                       char **users, int numusers, char *mailbox);
static struct backend *init_net(const char *sockaddr);

static void usage(void)
{
    fprintf(stderr,
            "421-4.3.0 usage: deliver [-C <alt_config> ] [-m mailbox]"
            " [-a auth] [-r return_path] [-l] [-D]\r\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EX_USAGE);
}

EXPORTED void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if(recurse_code) exit(code);
    else recurse_code = 0;

    prot_printf(deliver_out,"421 4.3.0 deliver: %s\r\n", s);
    prot_flush(deliver_out);
    cyrus_done();
    exit(code);
}

/*
 * Here we're just an intermediatory piping stdin to lmtp socket
 * and lmtp socket to stdout
 */
void pipe_through(struct backend *conn)
{
    struct protgroup *protin = protgroup_new(2);

    protgroup_insert(protin, deliver_in);
    protgroup_insert(protin, conn->in);

    do {
        /* Flush any buffered output */
        prot_flush(deliver_out);
        prot_flush(conn->out);

    } while (!proxy_check_input(protin, deliver_in, deliver_out,
                                conn->in, conn->out, 0));

    /* ok, we're done. */
    protgroup_free(protin);

    return;
}

int main(int argc, char **argv)
{
    int r = 0;
    int opt;
    int lmtpflag = 0;
    int ignorequota = 0;
    char *mailboxname = NULL;
    char *authuser = NULL;
    char *return_path = NULL;
    char buf[1024];
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:df:r:m:a:F:eE:lqD")) != EOF) {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'd':
            /* Ignore -- /bin/mail compatibility flags */
            break;

        case 'D':
            logdebug = 1;
            break;

        case 'r':
        case 'f':
            return_path = optarg;
            break;

        case 'm':
            if (mailboxname) {
                fprintf(stderr, "deliver: multiple -m options\n");
                usage();
                /* NOTREACHED */
            }
            if (*optarg) mailboxname = optarg;
            break;

        case 'a':
            if (authuser) {
                fprintf(stderr, "deliver: multiple -a options\n");
                usage();
                /* NOTREACHED */
            }
            authuser = optarg;
            break;

        case 'F': /* set IMAP flag. we no longer support this */
            fprintf(stderr,"deliver: 'F' option no longer supported\n");
            usage();
            break;

        case 'e':
            /* duplicate delivery. ignore */
            break;

        case 'E':
            fprintf(stderr,"deliver: 'E' option no longer supported\n");
            usage();
            break;

        case 'l':
            lmtpflag = 1;
            break;

        case 'q':
            ignorequota = 1;
            break;

        default:
            usage();
            /* NOTREACHED */
        }
    }

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

    cyrus_init(alt_config, "deliver", CYRUSINIT_NODB, CONFIG_NEED_PARTITION_DATA);
    global_sasl_init(1, 0, NULL);

    sockaddr = config_getstring(IMAPOPT_LMTPSOCKET);
    if (!sockaddr) {
        strlcpy(buf, config_dir, sizeof(buf));
        strlcat(buf, "/socket/lmtp", sizeof(buf));
        sockaddr = buf;
    }

    if (lmtpflag == 1) {
        struct backend *conn = init_net(sockaddr);

        pipe_through(conn);

        backend_disconnect(conn);
        free(conn);
    }
    else {
        if (return_path == NULL) {
            uid_t me = getuid();
            struct passwd *p = getpwuid(me);
            return_path = p->pw_name;
        }

        /* deliver to users or global mailbox */
        r = deliver_msg(return_path,authuser, ignorequota,
                        argv+optind, argc - optind, mailboxname);
    }

    cyrus_done();

    return r;
}

static void just_exit(const char *msg)
{
    com_err(msg, 0, "%s", error_message(errno));

    fatal(msg, EX_CONFIG);
}

/* initialize the network
 * we talk on unix sockets
 */
static struct backend *init_net(const char *unixpath)
{
  int lmtpdsock;
  struct sockaddr_un addr;
  struct backend *conn;

  if ((lmtpdsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
      just_exit("socket failed");
  }

  addr.sun_family = AF_UNIX;
  strlcpy(addr.sun_path, unixpath, sizeof(addr.sun_path));

  if (connect(lmtpdsock, (struct sockaddr *) &addr,
              sizeof(addr.sun_family) + strlen(addr.sun_path) + 1) < 0) {
      just_exit("connect failed");
  }

  conn = xzmalloc(sizeof(struct backend));
  conn->timeout = NULL;
  conn->in = prot_new(lmtpdsock, 0);
  conn->out = prot_new(lmtpdsock, 1);
  conn->sock = lmtpdsock;
  prot_setflushonread(conn->in, conn->out);
  conn->prot = &lmtp_protocol;

  return conn;
}

static int deliver_msg(char *return_path, char *authuser, int ignorequota,
                       char **users, int numusers, char *mailbox)
{
    int r;
    struct backend *conn;
    struct lmtp_txn *txn = LMTP_TXN_ALLOC(numusers ? numusers : 1);
    int j;
    int ml = 0;

    /* must have either some users or a mailbox */
    if (!numusers && !mailbox) {
        usage();
    }

    /* connect */
    conn = backend_connect(NULL, sockaddr, &lmtp_protocol,
                           "", NULL, NULL, -1);
    if (!conn) {
        just_exit("couldn't connect to lmtpd");
    }

    /* setup txn */
    txn->from = return_path;
    txn->auth = authuser;
    txn->data = deliver_in;
    txn->isdotstuffed = 0;
    txn->tempfail_unknown_mailbox = 0;
    txn->rcpt_num = numusers ? numusers : 1;
    if (mailbox) ml = strlen(mailbox);
    if (numusers == 0) {
        /* just deliver to mailbox 'mailbox' */
        const char *BB = config_getstring(IMAPOPT_POSTUSER);
        txn->rcpt[0].addr = (char *) xmalloc(ml + strlen(BB) + 2); /* xxx leaks! */
        sprintf(txn->rcpt[0].addr, "%s+%s", BB, mailbox);
        txn->rcpt[0].ignorequota = ignorequota;
    } else {
        /* setup each recipient */
        for (j = 0; j < numusers; j++) {
            if (mailbox) {
                size_t ulen;

                txn->rcpt[j].addr =
                    (char *) xmalloc(strlen(users[j]) + ml + 2);

                /* find the length of the userid minus the domain */
                ulen = strcspn(users[j], "@");
                sprintf(txn->rcpt[j].addr, "%.*s+%s",
                        (int) ulen, users[j], mailbox);

                /* add the domain if we have one */
                if (ulen < strlen(users[j]))
                    strcat(txn->rcpt[j].addr, users[j]+ulen);
            } else {
                txn->rcpt[j].addr = xstrdup(users[j]);
            }
            txn->rcpt[j].ignorequota = ignorequota;
        }
    }

    /* run txn */
    r = lmtp_runtxn(conn, txn);

    /* disconnect */
    backend_disconnect(conn);
    free(conn);

    /* examine txn for error state */
    r = 0;
    for (j = 0; j < txn->rcpt_num; j++) {
        switch (txn->rcpt[j].result) {
        case RCPT_GOOD:
            break;

        case RCPT_TEMPFAIL:
            r = EX_TEMPFAIL;
            break;

        case RCPT_PERMFAIL:
            /* we just need any permanent failure, though we should
               probably return data from the client-side LMTP info */
            printf("554 5.6.0 %s: %s\n",
                   txn->rcpt[j].addr, error_message(txn->rcpt[j].r));
            if (r != EX_TEMPFAIL) {
                r = EX_DATAERR;
            }
            break;
        }
        free(txn->rcpt[j].addr);
        strarray_free(txn->rcpt[j].resp);
    }

    free(txn);

    /* return appropriately */
    return r;
}
