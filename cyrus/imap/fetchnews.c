/* fetchnews.c -- Program to pull new articles from a peer and push to server
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 * $Id: fetchnews.c,v 1.1.2.11 2003/02/14 19:47:09 ken3 Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "exitcodes.h"
#include "global.h"
#include "prot.h"
#include "xmalloc.h"

/* global state */
const int config_need_data = 0;

void usage(void)
{
    fprintf(stderr,
	    "fetchnews [-C <altconfig>] [-s <server>] [-w <wildmat>] [-f <tstamp file>] <peer>\n");
    exit(-1);
}

int init_net(const char *host, char *port,
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

#define MSGID_GROW 100

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *alt_config = NULL, *port = "119";
    const char *peer = NULL, *server = "localhost", *wildmat = "*";
    int psock = -1, ssock = -1;
    struct protstream *pin, *pout, *sin, *sout;
    char buf[4096], sbuf[4096];
    char sfile[1024] = "";
    int fd, i, offered, rejected, accepted, failed;
    time_t stamp;
    struct tm *tm;
    char **msgid = NULL;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:s:p:w:f:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 's': /* server */
	    server = optarg;
	    break;

	case 'p': /* pot on server */
	    port = optarg;
	    break;

	case 'w': /* wildmat */
	    wildmat = optarg;
	    break;

	case 'f': /* timestamp file */
	    snprintf(sfile, sizeof(sfile), optarg);
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

    cyrus_init(alt_config, "fetchnews");

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

    /* change to reader mode - not always necessary, so ignore result */
    prot_printf(pout, "MODE READER\r\n");
    prot_fgets(buf, sizeof(buf), pin);

    /* connect to the server */
    if ((ssock = init_net(server, port, &sin, &sout)) < 0) {
	fprintf(stderr, "connection to %s failed\n", server);
	goto quit;
    }

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), sin) || strncmp("200", buf, 3)) {
	syslog(LOG_ERR, "server not available");
	goto quit;
    }

    /* read the previous timestamp */
    if (!sfile[0]) snprintf(sfile, sizeof(sfile), "%s/newsstamp", config_dir);

    fd = open(sfile, O_RDONLY, 0644);
    if (fd == -1 || read(fd, &stamp, sizeof(stamp)) < sizeof(stamp)) {
	/* XXX do something better here */
	stamp = time(NULL);
    }
    if (fd != -1) close(fd);

    /* ask for new articles */
    tm = gmtime(&stamp);
    strftime(buf, sizeof(buf), "%Y%m%d %H%M%S", tm);
    prot_printf(pout, "NEWNEWS %s %s GMT\r\n", wildmat, buf);

    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("23", buf, 2)) {
	syslog(LOG_ERR, "peer doesn't support NEWNEWS");
	goto quit;
    }

    /* process the list */
    stamp = time(NULL);
    offered = rejected = accepted = failed = 0;
    while (prot_fgets(buf, sizeof(buf), pin)) {
	if (buf[0] == '.') break;

	if (!(offered % MSGID_GROW)) { /* time to alloc more */
	    msgid = (char **)
		xrealloc(msgid, (offered + MSGID_GROW) * sizeof(char *));
	}
	msgid[offered++] = xstrdup(buf);
    }
    if (buf[0] != '.') {
	syslog(LOG_ERR, "NEWNEWS terminated abnormally");
	goto quit;
    }

    /* fetch and store articles */
    for (i = 0; i < offered; i++) {

	/* see if we want this article */
	prot_printf(sout, "IHAVE %s", msgid[i]);
	if (!prot_fgets(sbuf, sizeof(sbuf), sin)) {
	    syslog(LOG_ERR, "IHAVE terminated abnormally");
	    goto quit;
	}
	else if (strncmp("335", sbuf, 3)) {
	    /* don't want it */
	    rejected++;
	    continue;
	}

	/* fetch the article */
	prot_printf(pout, "ARTICLE %s", msgid[i]);
	if (!prot_fgets(buf, sizeof(buf), pin)) {
	    syslog(LOG_ERR, "ARTICLE terminated abnormally");
	    goto quit;
	}
	else if (strncmp("220", buf, 3)) {
	    /* doh! the article doesn't exist, abort IHAVE */
	    prot_printf(sout, ".\r\n");
	}
	else {
	    /* store the article */
	    while (prot_fgets(buf, sizeof(buf), pin)) {
		prot_write(sout, buf, strlen(buf));
		if (buf[0] == '.' && buf[1] != '.') break;
	    }

	    if (buf[0] != '.') {
		syslog(LOG_ERR, "ARTICLE terminated abnormally");
		goto quit;
	    }
	}

	/* see how we did */
	if (!prot_fgets(buf, sizeof(buf), sin)) {
	    syslog(LOG_ERR, "IHAVE terminated abnormally");
	    goto quit;
	}
	else if (!strncmp("235", buf, 3))
	    accepted++;
	else if (!strncmp("437", buf, 3))
	    rejected++;
	else
	    failed++;
    }

    syslog(LOG_NOTICE,
	   "fetchnews: offered %d, rejected %d, accepted %d, failed %d",
	   offered, rejected, accepted, failed);

    /* write the current timestamp */
    fd = open(sfile, O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
	write(fd, &stamp, sizeof(stamp));
	close(fd);
    }

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
