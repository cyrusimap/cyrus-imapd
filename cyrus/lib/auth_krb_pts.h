/* auth_krb_pts.h -- Kerberos authorization with AFS PTServer groups
   $Id: auth_krb_pts.h,v 1.23 2003/02/13 20:15:39 rjs3 Exp $
	
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

#define EXPIRE_TIME (3 * 60 * 60) /* 3 hours */

struct auth_ident {
    unsigned hash;
    char id[PR_MAXNAMELEN];
};

struct auth_state {
    struct auth_ident userid;
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    time_t mark;
    int ngroups;
    struct auth_ident groups[1];
};

#endif /* INCLUDED_AUTH_KRB_PTS_H */
