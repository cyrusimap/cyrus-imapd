/* notifytest.c: notifyd test utility */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include "util.h"

#define MAX_OPT 10
#define MAXSIZE 8192


/* generic fatal() routine for command line utilities
   it is here, because libcyrus requires a global function fatal */
EXPORTED void fatal(const char *message, int code)
{
  static int recurse_code = 0;

  if (recurse_code) {
    exit(code);
  }

  recurse_code = code;
  fprintf(stderr, "fatal error: %s\n", message);
  exit(code);
}


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
    xstrncpy(sun.sun_path, notifyd_path, sizeof(sun.sun_path));

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
