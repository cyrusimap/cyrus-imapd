/* auth_krb_pts.h -- Kerberos authorization with AFS PTServer groups
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

#ifndef INCLUDED_AUTH_KRB_PTS_H
#define INCLUDED_AUTH_KRB_PTS_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/file.h>
#include <errno.h>
#include <db.h>
#include <syslog.h>
#include <ctype.h>
#include <afs/ptserver.h>
#include <afs/cellconfig.h>

#define PTS_DBFIL "/ptclient/ptscache.db"
#define PTS_DBLOCK "/ptclient/ptscache.lock"
#define PTS_DBSOCKET "/ptclient/ptsock"


#define PTCLIENT  "ptloader"

typedef struct {
    time_t cached;
    char user[PR_MAXNAMELEN];
    int ngroups;
} ptluser;


#define CLOSE(db) (db)->close((db))
#define GET(db,key,data,flags) (db)->get((db),(key),(data),(flags))
#define PUT(db,key,data,flags) (db)->put((db),(key),(data),(flags))
#define SEQ(db,key,data,flags) (db)->seq((db),(key),(data),(flags))
#define DEL(db,key,flags) (db)->del((db),(key),(flags))
#define SYNC(db,flags) (db)->sync((db),(flags))
#define EXPIRE_TIME 7200 /* 2 hours */

extern int errno;

static int32_t hashfn P((const void *, size_t));

/* Do not make this unsigned. you'll lose! (db won't open the file) */
static int32_t hashfn(data, size)
const void *data;
size_t size;
{
    int32_t ret, val;
    int i;
    ret=0;
    if (size % 4) {
        syslog(LOG_WARNING,
             "Database key size %d not multiple of 4; continuing anyway",
               size);
    }
    for (i=0; i*4<size; i++) {
        memcpy(&val, ((char *)data)+4*i, 4);
        ret = ret ^ val;
    }
    return ret;
}


#endif /* INCLUDED_AUTH_KRB_PTS_H */
