/* chk_cyrus.c: cyrus mailstore consistancy checker
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
 * 
 * $Id: chk_cyrus.c,v 1.9 2003/04/09 17:49:20 rjs3 Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "exitcodes.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "index.h"
#include "imapconf.h"
#include "map.h"

/* need to use these names so the macros are happy */

static const char *index_base;
static unsigned long index_len;
static unsigned long start_offset;
static unsigned long record_size;

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void usage(void)
{
    fprintf(stderr, "chk_cyrus [-C <altconfig>] partition\n");
    exit(-1);
}

const char *check_part = NULL; /* partition we are checking */

static int chkmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock __attribute__((unused))) 
{
    int r;
    char *part, *path;

    unsigned long real_len;
    int fd=-1;
    int i,exists;
    struct stat sbuf;

    index_base = NULL;

    /* Do an mboxlist_detail on the mailbox */
    r = mboxlist_detail(name, NULL, &path, &part, NULL, NULL);

    /* xxx reserved mailboxes? */

    if(r) {
	fprintf(stderr, "bad mailbox %s in chkmbox\n", name);
	fatal("fatal error",EC_TEMPFAIL);
    }

    /* are we on the partition we are checking? */
    if(check_part && strcmp(part,check_part)) goto done;

    fprintf(stderr, "checking: %s (%s)\n", name, path);

    if(chdir(path) == -1) {
	fprintf(stderr, "can't chdir to %s\n", path);
	/* whole mailbox! */
	printf("%s\n",path);
	goto done;
    }

    fd = open("cyrus.index", O_RDONLY, 0666);
    if(fd == -1) {
	fprintf(stderr, "can't open cyrus.index\n");
	/* whole mailbox! */
	printf("%s\n",path);
	goto done;
    }

    if(fstat(fd, &sbuf) == -1) {
	fprintf(stderr, "can't stat cyrus.index\n");
	/* whole mailbox! */
	printf("%s\n",path);
	goto done;
    }

    index_len = sbuf.st_size;
    real_len = 0;
    map_refresh(fd, 1, &index_base, &real_len, index_len,
		"cyrus.index", name);

    if(!index_base) {
	fprintf(stderr, "mmap failed\n");
	exit(3);
    }

    /* xxx index file versions */

    exists = ntohl(*((bit32 *)(index_base + OFFSET_EXISTS)));
    start_offset =
	ntohl(*((bit32 *)(index_base+OFFSET_START_OFFSET)));
    record_size =
	ntohl(*((bit32 *)(index_base+OFFSET_RECORD_SIZE)));

    fprintf(stderr, " -> %d records\n", exists);

    for(i=1;i<=exists;i++) {
	char filebuf[1024];

	/* xxx check for monotonic increasing UIDs in the index file */

	snprintf(filebuf, sizeof(filebuf), "%s/%d.", path, UID(i));
	if(stat(filebuf, &sbuf) == -1) {
	    fprintf(stderr, " -> %s missing\n", filebuf);
	    printf("%s\n",filebuf);
	    fflush(stdout);
	}
	
    }

 done:
    if(index_base) map_free(&index_base, &real_len);
    if(fd != -1) close(fd);

    return 0;
}

int main(int argc, char **argv) 
{
    char *alt_config = NULL;
    char pattern[2] = { '*', '\0' };
    const char *mailbox = NULL;

    extern char *optarg;
    int opt;

    while ((opt = getopt(argc, argv, "C:P:M:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'P':
	    if(mailbox) {
		usage();
		exit(EC_USAGE);
	    }
	    check_part = optarg;
	    break;

	case 'M':
	    if(check_part) {
		usage();
		exit(EC_USAGE);
	    }
	    mailbox = optarg;
	    break;

	default:
	    usage();
	    exit(EC_USAGE);
	    break;
	}
    }

    config_init(alt_config, "chk_cyrus");    

    mboxlist_init(0);
    mboxlist_open(NULL);

    if(mailbox) {
	fprintf(stderr, "Examining mailbox: %s\n", mailbox);
	chkmbox((char *)mailbox,0,0,NULL);
    } else {
	fprintf(stderr, "Examining partition: %s\n",
		(check_part ? check_part : "ALL PARTITIONS"));
	
	/* build a list of mailboxes - we're using internal names here */
	mboxlist_findall(NULL, pattern, 1, NULL,
			 NULL, chkmbox, NULL);
    }
    
    mboxlist_close();
    mboxlist_done();

    return 0;
}
