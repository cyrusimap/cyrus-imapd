/* fetchnews.c -- Program to pull new articles from a peer and push to a server
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 * $Id: fetchnews.c,v 1.1.2.1 2002/10/08 16:25:11 ken3 Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <signal.h>

#include "prot.h"
#include "imapconf.h"


void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    exit(code);
}

void usage(void)
{
    fprintf(stderr,
	    "nntpget [-C <altconfig>] <peer> <server>\n");
    exit(-1);
}

int init_net(const char *host, int port,
	     struct protstream **in, struct protstream **out)
{
    int sock;
    struct hostent *hp;
    struct sockaddr_in sin;

    if ((hp = gethostbyname(host)) == NULL) {
	syslog(LOG_ERR, "gethostbyname(%s) failed: %m", host);
	return -1;
    }

    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_port = htons(port);
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "socket() failed: %m");
	return -1;
    }
    if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	syslog(LOG_ERR, "connect() failed: %m");
	return -1;
    }
    
    *in = prot_new(sock, 0);
    *out = prot_new(sock, 1);
    prot_setflushonread(*in, *out);

    return sock;
}

/*
 * We use the following streaming procedure for fetching new articles:
 *
 *	Peer			Server
 *	----			------
 *	MODE READER		MODE STREAM
 *	NEWNEWS
 *	<msgid1>  ----------->  CHECK <msgid1>  (want it)
 *						    |
 *	ARTICLE <msgid1>  <-------------------------+
 *	  .
 *	  .
 *	  .
 *	<msgidN>  ----------->  CHECK <msgidN>  (don't want it)
 *	read article 1  ----->	TAKETHIS <msgid1>
 *	  .
 *	  .
 *	  .
 *	QUIT			QUIT
 */

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *alt_config = NULL;
    const char *peer = NULL, *server = NULL;
    int psock = -1, ssock = -1;
    struct protstream *pin, *pout, *sin, *sout;
    char buf[4096];
    time_t stamp;
    struct tm *tm;
    int n = 0;
#if 0
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
#endif
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	default:
	    usage();
	    break;
	}
    }
    if (argc - optind < 2) usage();

    peer = argv[optind++];
    server = argv[optind++];

    config_init(alt_config, "nntpget");

    /* connect to the peer */
    if ((psock = init_net(peer, 119, &pin, &pout)) < 0) {
	fprintf(stderr, "connection to %s failed\n", peer);
	exit(-1);
    }

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("20", buf, 2)) {
	syslog(LOG_ERR, "peer not available");
	goto quit;
    }

    /* change to reader mode */
    prot_printf(pout, "MODE READER\r\n");
    prot_fgets(buf, sizeof(buf), pin);

    /* connect to the server */
    if ((ssock = init_net(server, 9119, &sin, &sout)) < 0) {
	fprintf(stderr, "connection to %s failed\n", server);
	goto quit;
    }

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), sin) || strncmp("200", buf, 3)) {
	syslog(LOG_ERR, "server not available");
	goto quit;
    }

    /* change to stream mode */
    prot_printf(sout, "MODE STREAM\r\n");

    if (!prot_fgets(buf, sizeof(buf), sin) || strncmp("203", buf, 3)) {
	syslog(LOG_ERR, "server does not support streaming");
	goto quit;
    }

    /* ask for news articles */
    /* XXX hack - ask for last 60 sec 
     *
     * change this to use a timestamp from a file
     */
    stamp = time(NULL);
    stamp -= 60;
    tm = gmtime(&stamp);
    strftime(buf, sizeof(buf), "%Y%m%d %H%M%S", tm);
    prot_printf(pout, "NEWNEWS %s %s GMT\r\n", "*", buf);

    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("23", buf, 2)) {
	syslog(LOG_ERR, "peer doesn't support NEWNEWS");
	goto quit;
    }

    /* process the list */
    while (prot_fgets(buf, sizeof(buf), pin)) {
	char sbuf[4096];

	if (buf[0] == '.') break;
	/* see if we want this article */
	prot_printf(sout, "CHECK %s", buf);

	prot_fgets(sbuf, sizeof(sbuf), sin);
	if (!strncmp("238", sbuf, 3)) {
	    prot_printf(pout, "ARTICLE %s", buf);
	    n++;
	}
    }
    if (buf[0] != '.') {
	syslog(LOG_ERR, "NEWNEWS terminated abnormally");
	goto quit;
    }

    /* read and push articles */
    while (n--) {
	prot_fgets(buf, sizeof(buf), pin);
	prot_printf(sout, "TAKETHIS %s", strrchr(buf, '<'));

	while (prot_fgets(buf, sizeof(buf), pin)) {
	    prot_write(sout, buf, strlen(buf));
	    if (buf[0] == '.' && buf[1] == '\r') break;
	    /* save article */
	}
	prot_flush(sout);

	if (buf[0] != '.') {
	    syslog(LOG_ERR, "ARTICLE terminated abnormally");
	    goto quit;
	}
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

    return 0;
}
