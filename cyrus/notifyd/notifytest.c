/* notifytest.c: notifyd test utility
 * Ken Murchison
 * Rob Siemborski
 */
/* 
 * Copyright (c) 2002 Carnegie Mellon University.  All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "retry.h"

extern int errno;

#define MAX_OPT 10

static int notify(const char *notifyd_path, const char *method,
		  const char *class, const char *priority,
		  const char *user, const char *mailbox,
		  int nopt, char **options,
		  const char *message)
{
    static char response[1024];
    int s;
    struct sockaddr_un srvaddr;
    int r;
    unsigned short count;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	perror("socket() ");
	return -1;
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strncpy(srvaddr.sun_path, notifyd_path, sizeof(srvaddr.sun_path));

    r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
    if (r == -1) {
        perror("connect() ");
	return -1;
    }

    /*
     * build request of the form:
     *
     * count method count class count priority count user count mailbox
     *   nopt N(count option) count message
     */
    {
	unsigned short n_len, c_len, p_len, u_len, m_len, o_len[MAX_OPT], t_len;
 	struct iovec iov[13 + 2*MAX_OPT];
	int num_iov = 0;
	int i;

 	n_len = htons(strlen(method));
 	c_len = htons(strlen(class));
 	p_len = htons(strlen(priority));
 	u_len = htons(strlen(user));
 	m_len = htons(strlen(mailbox));
	count = htons((unsigned short) nopt);
	t_len = htons(strlen(message));

	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &n_len, sizeof(n_len));
	WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) method);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &c_len, sizeof(c_len));
	WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) class);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &p_len, sizeof(p_len));
	WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) priority);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &u_len, sizeof(u_len));
	WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) user);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &m_len, sizeof(m_len));
	WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) mailbox);

	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &count, sizeof(count));

	for (i = 0; i < nopt; i++) {
	    o_len[i] = htons(strlen(options[i]));
	    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &o_len[i], sizeof(o_len[i]));
	    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, options[i]);
	}	    

	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &t_len, sizeof(t_len));
	WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) message);

	if (retry_writev(s, iov, num_iov) == -1) {
            fprintf(stderr,"write failed\n");
  	    return -1;
  	}
    }

    /*
     * read response of the form:
     *
     * count result
     */
    if (retry_read(s, &count, sizeof(count)) < (int) sizeof(count)) {
        fprintf(stderr,"size read failed\n");
	return -1;
    }
  
    count = ntohs(count);
    if (count < 2) { /* MUST have at least "OK" or "NO" */
	close(s);
        fprintf(stderr,"bad response from notifyd\n");
	return -1;
    }
  
    count = (int)sizeof(response) < count ? sizeof(response) : count;
    if (retry_read(s, response, count) < count) {
	close(s);
        fprintf(stderr,"read failed\n");
	return -1;
    }
    response[count] = '\0';

    close(s);
  
    printf("\"%s\"\n", response);

    if (!strncmp(response, "OK", 2))
	return 0;
    else
	return -1;
}

int
main(int argc, char *argv[])
{
  const char *method = "", *priority = "normal";
  const char *class = "TEST", *user = "", *mailbox = "";
  const char *message = NULL, *path = NULL;
  int c;
  int flag_error = 0;

  while ((c = getopt(argc, argv, "f:n:c:p:u:m:t:")) != EOF)
      switch (c) {
      case 'f':
	  path = optarg;
	  break;
      case 'n':
	  method = optarg;
	  break;
      case 'c':
	  class = optarg;
	  break;
      case 'p':
	  priority = optarg;
	  break;
      case 'u':
	  user = optarg;
	  break;
      case 'm':
	  mailbox = optarg;
	  break;
      case 't':
	  message = optarg;
	  break;
      default:
	  flag_error = 1;
	  break;
    }

  if (!path || !message)
    flag_error = 1;

  if (flag_error) {
    (void)fprintf(stderr,
		 "%s: usage: %s -f socket_path -t text [-n method]\n"
		  "              [-c class] [-p priority]\n"
		  "              [-u user] [-m mailbox]\n"
		  "              [option ...]\n",
		  argv[0], argv[0]);
    exit(1);
  }

  if ((argc - optind) > 10) {
      fprintf(stderr,"too many options (> %d)\n", MAX_OPT);
      exit(1);
  }
 
  if (!user) user = getpwuid(getuid())->pw_name;

  return notify(path, method, class, priority, user, mailbox,
		argc - optind, argv+optind, message);
}

