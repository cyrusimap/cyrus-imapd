/* test2.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "config.h"
#include <stdio.h>
#include <sys/syslog.h>

int main(void) {
  char cacheid[16]="4224423";
  openlog("testr", LOG_PID, SYSLOG_FACILITY);

  if (!auth_setid("cg2v@club.cc.cmu.edu",cacheid))
    printf ("Auth_memberof(cg2v,cg2v:me) is %d\n",
            auth_memberof("cg2v:me"));

  else
    printf ("Auth_setid(cg2v@club.cc.cmu.edu) failed\n");

}

int fatal(char *foo) {
  fprintf(stderr, "Fatal error: %s\n", foo);
  exit(1);
}
