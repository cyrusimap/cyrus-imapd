/* auth_krb_pts.h -- Kerberos authorization with AFS PTServer groups
   $Id: auth_krb_pts.h,v 1.19 2000/02/10 21:25:38 leg Exp $
	
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/file.h>
#include <errno.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <db.h>
#include <syslog.h>
#include <ctype.h>
#include <des.h> /* for int32, necessary for the AFS includes below */
#include <afs/ptserver.h>
#include <afs/cellconfig.h>
#include <krb.h>

#define PTS_DBFIL "/ptclient/ptscache.db"
#define PTS_DBLOCK "/ptclient/ptscache.lock"
#define PTS_DBSOCKET "/ptclient/ptsock"
#define PTS_DB_HOFFSET PR_MAXNAMELEN  /* index to the header character 'H' or 'D' */
#define PTS_DB_KEYSIZE (PR_MAXNAMELEN+4) /* full key size; header char + 3 NULL */


#define PTCLIENT  "ptloader"
#define EXPIRE_TIME (3 * 60 * 60) /* 3 hours */

struct auth_state {
    char userid[PR_MAXNAMELEN];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    time_t mark;
    int ngroups;
    char groups[1][PR_MAXNAMELEN];
};

#endif /* INCLUDED_AUTH_KRB_PTS_H */
