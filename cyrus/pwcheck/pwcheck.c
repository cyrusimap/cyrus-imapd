/* pwcheck.c -- Unix pwcheck daemon
 *
 *      (C) Copyright 1995 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

extern int errno;

/*
 * Unix pwcheck daemon-authenticated login (shadow password)
 */

int
main()
{
    char fnamebuf[1024];
    int s;
    int c;
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    int r;
    int len;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	perror("socket");
	exit(1);
    }

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, "/pwcheck/pwcheck");

    (void) unlink(fnamebuf);

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    r = bind(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	perror(fnamebuf);
	exit(1);
    }
    r = listen(s, 5);
    if (r == -1) {
	perror("listen");
	exit(1);
    }

    for (;;) {
	len = sizeof(clientaddr);
	c = accept(s, (struct sockaddr *)&clientaddr, &len);
	if (c == -1) {
	    perror("accept");
	    continue;
	}

	newclient(c);
    }
}

newclient(c)
int c;
{
    char request[1024];
    int start, n;
    char *reply;
    
    start = 0;
    while (start < sizeof(request) - 1) {
	n = read(c, request+start, sizeof(request) - 1 - start);
	if (n < 1) {
	    reply = "Error reading request";
	    goto sendreply;
	}
		
	start += n;

	if (request[start-1] == '\0' && strlen(request) < start) {
	    break;
	}
    }

    if (start >= sizeof(request) - 1) {
	reply = "Request too big";
    }
    else {
	reply = pwcheck(request, request + strlen(request) + 1);
    }

sendreply:

    retry_write(c, reply, strlen(reply));
    close(c);
}
  
