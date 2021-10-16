/* fetchnews.c -- Program to pull new articles from a peer and push to server
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
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <signal.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "cyrusdb.h"
#include "global.h"
#include "gmtoff.h"
#include "cyr_lock.h"
#include "prot.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "strarray.h"

#define FNAME_NEWSRCDB "/fetchnews.db"
#define DB ("flat")

static struct db *newsrc_db = NULL;
static int newsrc_dbopen = 0;

/* must be called after cyrus_init */
static int newsrc_init(const char *fname, int myflags __attribute__((unused)))
{
    char buf[1024];
    int r = 0;

    if (r != 0)
        syslog(LOG_ERR, "DBERROR: init %s: %s", buf,
               cyrusdb_strerror(r));
    else {
        char *tofree = NULL;

        if (!fname)
            fname = config_getstring(IMAPOPT_NEWSRC_DB_PATH);

        /* create db file name */
        if (!fname) {
            tofree = strconcat(config_dir, FNAME_NEWSRCDB, (char *)NULL);
            fname = tofree;
        }

        r = cyrusdb_open(DB, fname, CYRUSDB_CREATE, &newsrc_db);
        if (r != 0)
            syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
                   cyrusdb_strerror(r));
        else
            newsrc_dbopen = 1;

        free(tofree);
    }

    return r;
}

static int newsrc_done(void)
{
    int r = 0;

    if (newsrc_dbopen) {
        r = cyrusdb_close(newsrc_db);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing fetchnews.db: %s",
                   cyrusdb_strerror(r));
        }
        newsrc_dbopen = 0;
    }

    return r;
}

static void usage(void)
{
    fprintf(stderr,
            "fetchnews [-C <altconfig>] [-s <server>] [-n] [-y] [-w <wildmat>] [-f <tstamp file>]\n"
            "          [-a <authname> [-p <password>]] <peer>\n");
    exit(-1);
}

static int init_net(const char *host, const char *port,
             struct protstream **in, struct protstream **out)
{
    int sock = -1, err;
    struct addrinfo hints, *res, *res0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    if ((err = getaddrinfo(host, port, &hints, &res0)) != 0) {
        syslog(LOG_ERR, "getaddrinfo(%s, %s) failed: %m", host, port);
        return -1;
    }

    for (res = res0; res; res = res->ai_next) {
        if ((sock = socket(res->ai_family, res->ai_socktype,
                           res->ai_protocol)) < 0)
            continue;
        if (connect(sock, res->ai_addr, res->ai_addrlen) >= 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res0);
    if(sock < 0) {
        syslog(LOG_ERR, "connect(%s:%s) failed: %m", host, port);
        return -1;
    }

    *in = prot_new(sock, 0);
    *out = prot_new(sock, 1);
    prot_setflushonread(*in, *out);

    return sock;
}

static int fetch(char *msgid, int bymsgid,
          struct protstream *pin, struct protstream *pout,
          struct protstream *sin, struct protstream *sout,
          int *rejected, int *accepted, int *failed)
{
    char buf[4096];

    /* see if we want this article */
    prot_printf(sout, "IHAVE %s\r\n", msgid);
    if (!prot_fgets(buf, sizeof(buf), sin)) {
        syslog(LOG_ERR, "IHAVE terminated abnormally");
        return -1;
    }
    else if (strncmp("335", buf, 3)) {
        /* don't want it */
        (*rejected)++;
        return 0;
    }

    /* fetch the article */
    if (bymsgid)
        prot_printf(pout, "ARTICLE %s\r\n", msgid);
    else
        prot_printf(pout, "ARTICLE\r\n");

    if (!prot_fgets(buf, sizeof(buf), pin)) {
        syslog(LOG_ERR, "ARTICLE terminated abnormally");
        return -1;
    }
    else if (strncmp("220", buf, 3)) {
        /* doh! the article doesn't exist, terminate IHAVE */
        prot_printf(sout, ".\r\n");
    }
    else {
        /* store the article */
        while (prot_fgets(buf, sizeof(buf), pin)) {
            if (buf[0] == '.') {
                if (buf[1] == '\r' && buf[2] == '\n') {
                    /* End of message */
                    prot_printf(sout, ".\r\n");
                    break;
                }
                else if (buf[1] != '.') {
                    /* Add missing dot-stuffing */
                    prot_putc('.', sout);
                }
            }

            do {
                /* look for malformed lines with NUL CR LF */
                if (buf[strlen(buf)-1] != '\n' &&
                    strlen(buf)+2 < sizeof(buf)-1 &&
                    buf[strlen(buf)+2] == '\n') {
                    strlcat(buf, "\r\n", sizeof(buf));
                }
                prot_printf(sout, "%s", buf);
            } while (buf[strlen(buf)-1] != '\n' &&
                     prot_fgets(buf, sizeof(buf), pin));
        }

        if (buf[0] != '.') {
            syslog(LOG_ERR, "ARTICLE terminated abnormally");
            return -1;
        }
    }

    /* see how we did */
    if (!prot_fgets(buf, sizeof(buf), sin)) {
        syslog(LOG_ERR, "IHAVE terminated abnormally");
        return -1;
    }
    else if (!strncmp("235", buf, 3))
        (*accepted)++;
    else
        (*failed)++;

    return 0;
}

#define BUFFERSIZE 4096

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *alt_config = NULL;
    /*const*/ char *port = "119";  /* xxx may point into server! */
    const char *peer = NULL, *server = "localhost", *wildmat = "*";
    char *authname = NULL, *password = NULL;
    int psock = -1, ssock = -1;
    struct protstream *pin, *pout, *sin, *sout;
    char buf[BUFFERSIZE];
    char sfile[1024] = "";
    int fd = -1, i, offered, rejected, accepted, failed;
    time_t stamp;
    strarray_t resp = STRARRAY_INITIALIZER;
    int newnews = 1;
    int y2k_compliant_date_format = 0;

    while ((opt = getopt(argc, argv, "C:s:w:f:a:p:ny")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 's': /* server */
            server = xstrdup(optarg);
            if ((port = strchr(server, ':')))
                *port++ = '\0';
            else
                port = "119";
            break;

        case 'w': /* wildmat */
            wildmat = optarg;
            break;

        case 'f': /* timestamp file */
            snprintf(sfile, sizeof(sfile), "%s", optarg);
            break;

        case 'a': /* authname */
            authname = optarg;
            break;

        case 'p': /* password */
            password = optarg;
            break;

        case 'n': /* no newnews */
            newnews = 0;
            break;

        case 'y': /* newsserver is y2k compliant */
            y2k_compliant_date_format = 1;
            break;

        default:
            usage();
            /* NOTREACHED */
        }
    }
    if (argc - optind < 1) {
        usage();
        /* NOTREACHED */
    }

    peer = argv[optind++];

    cyrus_init(alt_config, "fetchnews", 0, 0);

    /* connect to the peer */
    /* xxx configurable port number? */
    if ((psock = init_net(peer, "119", &pin, &pout)) < 0) {
        fprintf(stderr, "connection to %s failed\n", peer);
        cyrus_done();
        exit(-1);
    }

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("20", buf, 2)) {
        syslog(LOG_ERR, "peer not available");
        goto quit;
    }

    if (authname) {
        /* authenticate to peer */
        /* XXX this should be modified to support SASL and STARTTLS */

        prot_printf(pout, "AUTHINFO USER %s\r\n", authname);
        if (!prot_fgets(buf, sizeof(buf), pin)) {
            syslog(LOG_ERR, "AUTHINFO USER terminated abnormally");
            goto quit;
        }
        else if (!strncmp("381", buf, 3)) {
            /* password required */
            if (!password)
                password = cyrus_getpass("Please enter the password: ");

            if (!password) {
                fprintf(stderr, "failed to get password\n");
                goto quit;
            }

            prot_printf(pout, "AUTHINFO PASS %s\r\n", password);
            if (!prot_fgets(buf, sizeof(buf), pin)) {
                syslog(LOG_ERR, "AUTHINFO PASS terminated abnormally");
                goto quit;
            }
        }

        if (strncmp("281", buf, 3)) {
            /* auth failed */
            goto quit;
        }
    }

    /* change to reader mode - not always necessary, so ignore result */
    prot_printf(pout, "MODE READER\r\n");
    prot_fgets(buf, sizeof(buf), pin);

    if (newnews) {
        struct tm ctime, *ptime;

        /* fetch the server's current time */
        prot_printf(pout, "DATE\r\n");

        if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("111 ", buf, 4)) {
            syslog(LOG_ERR, "error fetching DATE");
            goto quit;
        }

        /* parse and normalize the server time */
        memset(&ctime, 0, sizeof(struct tm));
        sscanf(buf+4, "%4d%02d%02d%02d%02d%02d",
               &ctime.tm_year, &ctime.tm_mon, &ctime.tm_mday,
               &ctime.tm_hour, &ctime.tm_min, &ctime.tm_sec);
        ctime.tm_year -= 1900;
        ctime.tm_mon--;
        ctime.tm_isdst = -1;

        /* read the previous timestamp */
        if (!sfile[0]) {
            char oldfile[1024];

            snprintf(sfile, sizeof(sfile), "%s/fetchnews.stamp", config_dir);

            /* upgrade from the old stamp filename to the new */
            snprintf(oldfile, sizeof(oldfile), "%s/newsstamp", config_dir);
            rename(oldfile, sfile);
        }

        if ((fd = open(sfile, O_RDWR | O_CREAT, 0644)) == -1) {
            syslog(LOG_ERR, "cannot open %s", sfile);
            goto quit;
        }
        if (lock_nonblocking(fd, sfile) == -1) {
            syslog(LOG_ERR, "cannot lock %s: %m", sfile);
            goto quit;
        }

        if (read(fd, &stamp, sizeof(stamp)) < (int) sizeof(stamp)) {
            /* XXX do something better here */
            stamp = 0;
        }

        /* ask for new articles */
        if (stamp) stamp -= 180; /* adjust back 3 minutes */
        ptime = gmtime(&stamp);	 /* xxx should use gmtime_r()? */
        ptime->tm_isdst = -1;

        if (y2k_compliant_date_format) {
            strftime(buf, sizeof(buf), "%Y%m%d %H%M%S", ptime);
        }
        else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-y2k"
            /* We know this is not y2k compliant! */
            strftime(buf, sizeof(buf), "%y%m%d %H%M%S", ptime);
#pragma GCC diagnostic pop
        }

        prot_printf(pout, "NEWNEWS %s %s GMT\r\n", wildmat, buf);

        if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("230", buf, 3)) {
            syslog(LOG_ERR, "peer doesn't support NEWNEWS");
            newnews = 0;
        }

        /* prepare server's current time as new timestamp */
        stamp = mktime(&ctime);
        /* adjust for local timezone

           XXX  We need to do this because we use gmtime() above.
           We can't change this, otherwise we'd be incompatible
           with an old localtime timestamp.
        */
        stamp += gmtoff_of(&ctime, stamp);
    }

    if (!newnews) {
        prot_printf(pout, "LIST ACTIVE %s\r\n", wildmat);

        if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("215", buf, 3)) {
            syslog(LOG_ERR, "peer doesn't support LIST ACTIVE");
            goto quit;
        }
    }

    /* process the NEWNEWS/LIST ACTIVE list */
    while (prot_fgets(buf, sizeof(buf), pin)) {
        if (buf[0] == '.') break;
        strarray_append(&resp, buf);
    }
    if (buf[0] != '.') {
        syslog(LOG_ERR, "%s terminated abnormally",
               newnews ? "NEWNEWS" : "LIST ACTIVE");
        goto quit;
    }

    if (!resp.count) {
        /* nothing matches our wildmat */
        goto quit;
    }

    /* connect to the server */
    if ((ssock = init_net(server, port, &sin, &sout)) < 0) {
        fprintf(stderr, "connection to %s failed\n", server);
        goto quit;
    }

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), sin) || strncmp("20", buf, 2)) {
        syslog(LOG_ERR, "server not available");
        goto quit;
    }

    /* fetch and store articles */
    offered = rejected = accepted = failed = 0;
    if (newnews) {
        /* response is a list of msgids */
        for (i = 0; i < resp.count; i++) {
            /* find the end of the msgid */
            *(strrchr(resp.data[i], '>') + 1) = '\0';

            offered++;
            if (fetch(resp.data[i], 1, pin, pout, sin, sout,
                      &rejected, &accepted, &failed)) {
                goto quit;
            }
        }

        /* write the current timestamp */
        lseek(fd, 0, SEEK_SET);
        if (write(fd, &stamp, sizeof(stamp)) < (int) sizeof(stamp))
            syslog(LOG_ERR, "error writing %s", sfile);
        lock_unlock(fd, sfile);
        close(fd);
    }
    else {
        char group[BUFFERSIZE], msgid[BUFFERSIZE], lastbuf[50];
        const char *data;
        unsigned long low, high, last, cur;
        int start;
        size_t datalen;
        struct txn *tid = NULL;

        newsrc_init(NULL, 0);

        /*
         * response is a list of groups.
         * select each group, and STAT each article we haven't seen yet.
         */
        for (i = 0; i < resp.count; i++) {
            /* parse the LIST ACTIVE response */
            sscanf(resp.data[i], "%s %lu %lu", group, &high, &low);

            last = 0;
            if (!cyrusdb_fetchlock(newsrc_db, group, strlen(group),
                               &data, &datalen, &tid)) {
                last = strtoul(data, NULL, 10);
            }
            if (high <= last) continue;

            /* select the group */
            prot_printf(pout, "GROUP %s\r\n", group);
            if (!prot_fgets(buf, sizeof(buf), pin)) {
                syslog(LOG_ERR, "GROUP terminated abnormally");
                continue;
            }
            else if (strncmp("211", buf, 3)) break;

            for (start = 1, cur = low > last ? low : ++last;; cur++) {
                if (start) {
                    /* STAT the first article we haven't seen */
                    prot_printf(pout, "STAT %lu\r\n", cur);
                } else {
                    /* continue with the NEXT article */
                    prot_printf(pout, "NEXT\r\n");
                }

                if (!prot_fgets(buf, sizeof(buf), pin)) {
                    syslog(LOG_ERR, "STAT/NEXT terminated abnormally");
                    cur--;
                    break;
                }
                if (!strncmp("223", buf, 3)) {
                    /* parse the STAT/NEXT response */
                    sscanf(buf, "223 %lu %s", &cur, msgid);

                    /* find the end of the msgid */
                    *(strrchr(msgid, '>') + 1) = '\0';

                    if (fetch(msgid, 0, pin, pout, sin, sout,
                              &rejected, &accepted, &failed)) {
                        cur--;
                        break;
                    }
                    offered++;
                    start = 0;
                }

                /* have we reached the highwater mark? */
                if (cur >= high) break;
            }

            snprintf(lastbuf, sizeof(lastbuf), "%lu", cur);
            cyrusdb_store(newsrc_db, group, strlen(group),
                      lastbuf, strlen(lastbuf)+1, &tid);
        }

        if (tid) cyrusdb_commit(newsrc_db, tid);
        newsrc_done();
    }

    syslog(LOG_NOTICE,
           "fetchnews: %s offered %d; %s rejected %d, accepted %d, failed %d",
           peer, offered, server, rejected, accepted, failed);

  quit:
    if (psock >= 0) {
        prot_printf(pout, "QUIT\r\n");
        prot_flush(pout);

        /* Flush the incoming buffer */
        prot_NONBLOCK(pin);
        prot_fill(pin);

        /* close/free socket & prot layer */
        close(psock);

        prot_free(pin);
        prot_free(pout);
    }

    if (ssock >= 0) {
        prot_printf(sout, "QUIT\r\n");
        prot_flush(sout);

        /* Flush the incoming buffer */
        prot_NONBLOCK(sin);
        prot_fill(sin);

        /* close/free socket & prot layer */
        close(psock);

        prot_free(sin);
        prot_free(sout);
    }

    cyrus_done();

    return 0;
}
