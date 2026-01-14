/* auth_pts.h - PTLOADER authorization module. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_AUTH_PTS_H
#define INCLUDED_AUTH_PTS_H

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/file.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
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
