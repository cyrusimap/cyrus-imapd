/* notifytest.c: notifyd test utility
 * Ken Murchison
 * Rob Siemborski
 * $Id: notifytest.c,v 1.7.4.2 2002/11/07 15:11:23 ken3 Exp $
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

#define MAX_OPT 10
#define MAXSIZE 8192

static int add_arg(char *buf, int max_size, const char *arg, int *buflen)
{
    const char *myarg = (arg ? arg : "");
    int len = strlen(myarg) + 1;

    if (*buflen + len > max_size) return -1;

    strcat(buf+*buflen, myarg);
    *buflen += len;

    return 0;
}

static int notify(const char *notifyd_path, const char *method,
		  const char *class, const char *priority,
		  const char *user, const char *mailbox,
		  int nopt, char **options,
		  const char *message)
{
    int soc;
    struct sockaddr_un sun;
    char buf[MAXSIZE] = "", noptstr[20];
    int buflen = 0;
    int i, r = 0;

    soc = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (soc == -1) {
	perror("socket() ");
	return -1;
    }

    memset((char *)&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, notifyd_path, sizeof(sun.sun_path));

    /*
     * build request of the form:
     *
     * method NUL class NUL priority NUL user NUL mailbox NUL
     *   nopt NUL N(option NUL) NUL message NUL
     */

    r = add_arg(buf, MAXSIZE, method, &buflen);
    if (!r) r = add_arg(buf, MAXSIZE, class, &buflen);
    if (!r) r = add_arg(buf, MAXSIZE, priority, &buflen);
    if (!r) r = add_arg(buf, MAXSIZE, user, &buflen);
    if (!r) r = add_arg(buf, MAXSIZE, mailbox, &buflen);

    snprintf(noptstr, sizeof(noptstr), "%d", nopt);
    if (!r) r = add_arg(buf, MAXSIZE, noptstr, &buflen);

    for (i = 0; !r && i < nopt; i++) {
	r = add_arg(buf, MAXSIZE, options[i], &buflen);
    }

    if (!r) r = add_arg(buf, MAXSIZE, message, &buflen);

    if (r) {
        perror("dgram too big");
	return -1;
    }

    r = sendto(soc, buf, buflen, 0, (struct sockaddr *) &sun, sizeof(sun));
    if (r < buflen) {
        perror("sendto() ");
	return -1;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
  const char *method = "", *priority = "normal";
  const char *class = "MESSAGE", *user = "", *mailbox = NULL;
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
 
  if (!*user) user = getpwuid(getuid())->pw_name;

  return notify(path, method, class, priority, user, mailbox,
		argc - optind, argv+optind, message);
}
