/* auth_krb_pts.h -- Kerberos authorization with AFS PTServer groups
   $Id: auth_krb_pts.h,v 1.17 2000/01/28 22:09:54 leg Exp $
	
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.

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
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_DB_185_H
#  define DB_LIBRARY_COMPATIBILITY_API
#  include <db_185.h>
#else
#  include <db.h>
#endif
#include <syslog.h>
#include <ctype.h>
#include <des.h> /* for int32, necessary for the AFS includes below */
#include <afs/ptserver.h>
#include <afs/cellconfig.h>

#define PTS_DBFIL "/ptclient/ptscache.db"
#define PTS_DBLOCK "/ptclient/ptscache.lock"
#define PTS_DBSOCKET "/ptclient/ptsock"
#define PTS_DB_HOFFSET PR_MAXNAMELEN  /* index to the header character 'H' or 'D' */
#define PTS_DB_KEYSIZE (PR_MAXNAMELEN+4) /* full key size; header char + 3 NULL */


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
#define EXPIRE_TIME (3 * 60 * 60) /* 3 hours */


#endif /* INCLUDED_AUTH_KRB_PTS_H */
