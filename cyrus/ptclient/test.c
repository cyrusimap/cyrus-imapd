/*
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

/* $Id: test.c,v 1.3.4.1 2003/01/08 22:18:22 rjs3 Exp $ */

#include <stdio.h>
#include <sys/syslog.h>
int main(int argc, char **argv) {
  char *cacheid;
  char cache[16];
  
  if (argc < 3 || argc > 4) {
    printf("Usage: pttset user group [cachearg]\n");
    exit(1);
  }
  if (argc == 4) {
    memset(cache,0,16);
    strncpy(cache,argv[3],16);
    cacheid=cache;
  } else
    cacheid=NULL;
  openlog("pttest", LOG_PID, SYSLOG_FACILITY);  
  
  if (!auth_setid(argv[1],cacheid))
    printf ("Auth_memberof(%s,%s) is %d\n", argv[1], argv[2],
            auth_memberof(argv[2]));
  
  else
    printf ("Auth_setid(%s) failed\n", argv[1]);
  
}

int fatal(char *foo) {
  fprintf(stderr, "Fatal error: %s\n", foo);
  exit(1);
}
