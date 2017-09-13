/* smtpclient.c -- Routines for sending a message via SMTP
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>

#include "xmalloc.h"
#include "global.h"
#include "exitcodes.h"
#include "smtpclient.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

EXPORTED pid_t open_sendmail(const char *argv[], FILE **sm)
{
    int fds[2];
    FILE *ret;
    pid_t p;

    if (pipe(fds)) {
        printf("451 lmtpd: didn't start pipe()?!?\r\n");
        fatal("couldn't start pipe()", EC_OSERR);
    }
    if ((p = fork()) == 0) {
        /* i'm the child! run sendmail! */
        close(fds[1]);
        /* make the pipe be stdin */
        dup2(fds[0], 0);
        execv(config_getstring(IMAPOPT_SENDMAIL), (char **) argv);

        /* if we're here we suck */
        printf("451 lmtpd: didn't exec() sendmail?!?\r\n");
        exit(EXIT_FAILURE);
    }

    if (p < 0) {
        /* failure */
        *sm = NULL;
        return p;
    }

    /* parent */
    close(fds[0]);
    ret = fdopen(fds[1], "w");
    *sm = ret;

    return p;
}

/* sendmail_errstr.  create a descriptive message given 'sm_stat':
   the exit code from wait() from sendmail.

   not thread safe, but probably ok */
EXPORTED char *sendmail_errstr(int sm_stat)
{
    static char errstr[200];

    if (WIFEXITED(sm_stat)) {
        snprintf(errstr, sizeof errstr,
                 "Sendmail process terminated normally, exit status %d\n",
                 WEXITSTATUS(sm_stat));
    } else if (WIFSIGNALED(sm_stat)) {
        snprintf(errstr, sizeof errstr,
                "Sendmail process terminated abnormally, signal = %d %s\n",
                WTERMSIG(sm_stat),
#ifdef WCOREDUMP
                WCOREDUMP(sm_stat) ? " -- core file generated" :
#endif
                "");
    } else if (WIFSTOPPED(sm_stat)) {
        snprintf(errstr, sizeof errstr,
                 "Sendmail process stopped, signal = %d\n",
                WTERMSIG(sm_stat));
    } else {
        return NULL;
    }

    return errstr;
}

/* smtpclient implements SMTP communication */
struct smtpclient {
    /* TCP socket for the host backend */
    int sockfd;

    /* Pipes for the sendmail process backend */
    int p_child[2];
    int p_parent[2];

    /* File descriptor and name for file backend */
    int tmpfd;
    char *filename;

    /* Protocol layer shared by backends */
    struct protstream *reader;
    struct protstream *writer;
};

static smtpclient_t *smtpclient_new()
{
    smtpclient_t *sm = xzmalloc(sizeof(smtpclient_t));
    sm->sockfd = -1;
    sm->p_child[0] = -1;
    sm->p_child[1] = -1;
    sm->p_parent[0] = -1;
    sm->p_parent[1] = -1;
    sm->tmpfd = -1;
    return sm;
}

EXPORTED int smtpclient_open_host(const char *addr, smtpclient_t **smp)
{
    int r = 0, err = 0;
    struct addrinfo hints, *startres = NULL, *res;
    smtpclient_t *sm = smtpclient_new();
    char *host = NULL, *port;

    /* Parse address. */
    host = xstrdup(addr);
    port = strchr(host, ':');
    if (port) {
        *port = '\0';
        port++;
    }
    else {
        port = "25";
    }

    /* Lookup the host address */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;
    if ((err = getaddrinfo(host, port, &hints, &startres))) {
        r = IMAP_IOERROR;
        syslog(LOG_ERR, "smtpclient: getaddrinfo %s:%s: %s",
                host, port, gai_strerror(err));
        goto done;
    }

    /* Open sockets, stopping at the first successful connection. */
    for (res = startres; res && sm->sockfd < 0; res = res->ai_next) {
        sm->sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sm->sockfd < 0) {
            continue;
        }
        if (connect(sm->sockfd, res->ai_addr, res->ai_addrlen)) {
            close(sm->sockfd);
            sm->sockfd = -1;
            continue;
        }
    }
    if (sm->sockfd < 0) {
        syslog(LOG_ERR, "smtpclient: cannot connect to %s:%s", host, port);
        r = IMAP_IOERROR;
        goto done;
    }

    /* All done. */
    sm->reader = prot_new(sm->sockfd, 0);
    sm->writer = prot_new(sm->sockfd, 1);
    *smp = sm;

done:
    if (startres) {
        freeaddrinfo(startres);
    }
    if (r) {
        smtpclient_close(&sm);
    }
    free(host);
    return r;
}

EXPORTED int smtpclient_open_sendmail(smtpclient_t **smp)
{
    int r = 0;
    smtpclient_t *sm = smtpclient_new();

    /* Create the pipes and fork */
    r = pipe(sm->p_child);
    if (!r) {
        r = pipe(sm->p_parent);
    }
    if (r < 0) {
        syslog(LOG_ERR, "smtpclient_open: can't create pipe: %m");
        r = IMAP_SYS_ERROR;
        goto done;
    }
    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "smtpclient_open: can't fork: %m");
        r = IMAP_SYS_ERROR;
        goto done;
    }

    if (pid == 0) {
        /* child process */
        close(sm->p_child[1]);
        dup2(sm->p_child[0], /*FILENO_STDIN*/0);
        close(sm->p_child[0]);

        close(sm->p_parent[0]);
        dup2(sm->p_parent[1], /*FILENO_STDOUT*/1);
        close(sm->p_parent[1]);

        execl(config_getstring(IMAPOPT_SENDMAIL), "sendmail", "-bs", (char *)NULL);
        syslog(LOG_ERR, "smtpclient_open: can't exec sendmail: %m");
        exit(1);
    }

    /* parent process */
    close(sm->p_child[0]);
    sm->p_child[0] = -1;
    close(sm->p_parent[1]);
    sm->p_parent[1] = -1;

    /* All done.*/
    sm->reader = prot_new(sm->p_parent[0], 0);
    sm->writer = prot_new(sm->p_child[1], 1);
    *smp = sm;

done:
    if (r) {
        smtpclient_close(&sm);
    }
    return r;
}

EXPORTED int smtpclient_open_file(const char *template, smtpclient_t **smp)
{
    int r = 0;
    smtpclient_t *sm = smtpclient_new();
    sm->filename = xstrdup(template);

    sm->tmpfd = mkstemp(sm->filename);
    if (sm->tmpfd < 0) {
        syslog(LOG_ERR, "smtpclient: mkstemp failed: %m");
        r = IMAP_IOERROR;
        goto done;
    }
    sm->writer = prot_new(sm->tmpfd, 1);
    *smp = sm;

done:
    if (r) {
        smtpclient_close(&sm);
    }
    return r;
}

EXPORTED int smtpclient_close(smtpclient_t **smp)
{
    if (smp == NULL || *smp == NULL) return 0;
    smtpclient_t *sm = *smp;

    /* Close TCP socket */
    if (sm->sockfd >= 0) {
        close(sm->sockfd);
    }

    /* Close sendmail pipes */
    if (sm->p_parent[0] >= 0) {
        close(sm->p_parent[0]);
    }
    if (sm->p_parent[1] >= 0) {
        close(sm->p_parent[1]);
    }
    if (sm->p_child[0] >= 0) {
        close(sm->p_child[0]);
    }
    if (sm->p_child[1] >= 0) {
        close(sm->p_child[1]);
    }

    /* Close file backend */
    if (sm->tmpfd >= 0) {
        close(sm->tmpfd);
    }
    free(sm->filename);

    /* Close protocols */
    if (sm->reader) {
        prot_free(sm->reader);
    }
    if (sm->writer) {
        prot_free(sm->writer);
    }

    free(sm);
    *smp = NULL;
    return 0;
}

EXPORTED int smtpclient_expect(smtpclient_t *sm, int code, struct buf *buf)
{
    char resp[513];
    int got = -1;
    char sep;
    int r = IMAP_IOERROR;

    /* The file system backend always return what's expected. */
    if (sm->tmpfd >= 0) {
        buf_printf(buf, "%d Fake reply of the SMTP backend for file %s\r\n",
                        code, sm->filename);
        return 0;
    }

    /* All other backends actually talk to a real service. */
    do {
        /* RFC 5321, 4.5.3.1.4.
         * The maximum total length of a command line including the command
         * word and the <CRLF> is 512 octets.
         */
        if (!prot_fgets(resp, 513, sm->reader)) {
            r = IMAP_IOERROR;
            return r;
        }
        if (memchr(resp, '\n', 512) == NULL) {
            r = IMAP_IOERROR;
            return r;
        }
        if (sscanf(resp, "%i%c", &got, &sep) != 2) {
            r = IMAP_IOERROR;
            return r;
        }
        buf_appendcstr(buf, resp);
    } while (sep == '-');

    if (sep != ' ' || code != got) {
        syslog(LOG_ERR, "smtpclient_expect: want %d, got %s", code, buf_cstring(buf));
        return IMAP_PROTOCOL_ERROR;
    }

    return 0;
}

EXPORTED int smtpclient_writebuf(smtpclient_t *sm, struct buf *buf, int flush)
{
    if (prot_putbuf(sm->writer, buf)) {
        return IMAP_IOERROR;
    }
    if (flush && prot_flush(sm->writer)) {
        return IMAP_IOERROR;
    }
    return 0;
}
