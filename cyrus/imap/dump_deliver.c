/* deliver.c -- Program to deliver mail to a mailbox
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

static char _rcsid[] = "$Id: dump_deliver.c,v 1.1 1998/05/01 21:55:09 tjs Exp $";

#include <string.h>
#include <errno.h>
#ifdef HAVE_LIBDB
#ifdef HAVE_DB_185_H
#include <db_185.h>
#else
#include <db.h>
#endif
#else
#include <ndbm.h>
#endif

int
dump_deliver(fname)
     char *fname;
{
    char buf[MAX_MAILBOX_PATH];
    int lockfd;
    int rcode = 0;
    char datebuf[40];
    int len;

#ifdef HAVE_LIBDB
    int rc, mode;
    DBT date, delivery;
    DBT *deletions = 0;
    HASHINFO info;
    int num_deletions = 0, alloc_deletions = 0;
#else /* HAVE_LIBDB */
    datum date, delivery;
#endif

    DeliveredDBptr = dbopen(fname, O_RDONLY, 0666, DB_HASH, NULL);
    if (!DeliveredDBptr) {
      fprintf(stderr, "Unable to open db file: %s", fname);
      return -1;
    }
    
    mode = R_FIRST;
    while ((rc = DeliveredDBptr->seq(DeliveredDBptr, &delivery, &date, mode)) == 0) {
	mode = R_NEXT;
	
    }
    if (rc < 0) {
      fprintf(stderr, "error detected looking up entry: %m");
    }
    
#else /* HAVE_LIBDB */

    /* initialize database */
    checkdelivered("", "");

    if (!DeliveredDBptr) return 1;

    for (delivery = dbm_firstkey(DeliveredDBptr); delivery.dptr;
	 delivery = dbm_nextkey(DeliveredDBptr)) {
	date = dbm_fetch(DeliveredDBptr, delivery);
	if (!date.dptr) continue;
	if (date.dsize < len ||
	    (date.dsize == len  && memcmp(date.dptr, datebuf, len) < 0)) {
	    if (dbm_delete(DeliveredDBptr, delivery)) {
		rcode = 1;
	    }
	}
    }
    dbm_close(DeliveredDBptr);

#endif /* HAVE_LIBDB */
    close(lockfd);

    return rcode;
}
