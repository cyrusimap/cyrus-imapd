/* auth_pts.h -- PTLOADER authorization module.
   $Id: auth_pts.h,v 1.1.2.1 2002/12/13 17:10:36 rjs3 Exp $
	
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
 *
 */ 

#ifndef INCLUDED_AUTH_PTS_H
#define INCLUDED_AUTH_PTS_H

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

#include "auth.h"

#define PTS_DBFIL FNAME_PTSDB
#define PTS_DBSOCKET "/ptclient/ptsock"
#define PTS_DB_KEYSIZE 512

struct auth_ident {
    unsigned hash;
    char id[PTS_DB_KEYSIZE];
};

struct auth_state {
    struct auth_ident userid; /* the CANONICAL userid */
    time_t mark;
    int ngroups;
    struct auth_ident groups[1]; /* variable sized */
};

#endif /* INCLUDED_AUTH_PTS_H */
