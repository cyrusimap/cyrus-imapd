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

/* $Id: ptextract.c,v 1.3 2002/05/25 19:57:52 leg Exp $ */

#include <sys/types.h>
#include <krb.h>
#include <sysexits.h>

#include "auth.h"
#include "auth_krb_pts.h"

/* from auth_krb_pts.c */
struct auth_state {
    char userid[PR_MAXNAMELEN];
    char name[PR_MAXNAMELEN];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    int ngroups;
    char (*groups)[PR_MAXNAMELEN];
};

int main(int argc, char* argv[]) {
    struct auth_state* auth_state;
    char* user = 0, *cacheid = 0;
    int i;
    
    if (argv[1] && *argv[1]) {
	user = argv[1];
	if (argv[2] && *argv[2]) cacheid = argv[2];
    }

    if (! user || ! cacheid) {
	fatal("Not enough arguments.\n", EX_CONFIG);
    }
    
    printf("extracting record...\n");

    auth_state = auth_newstate(user, cacheid);

    if (auth_state) {
	for (i = 0; i < auth_state->ngroups; i++) {
	    printf("group %s\n", auth_state->groups[i]);
	}
    } else {
	printf("Extracting failed.\n");
    }
}

void fatal(char* message, int rc) {
    fprintf(stderr, "fatal error: %s\n", message);
    exit(rc);
}
