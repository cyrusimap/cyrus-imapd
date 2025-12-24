/* version.h: the version number */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _CYRUS_VERSION_H
#define _CYRUS_VERSION_H

#include "prot.h"
#include "util.h"

/* Values for ID processing */
enum {
    MAXIDFIELDLEN = 30,
    MAXIDVALUELEN = 1024,
    MAXIDPAIRS = 30,
};

extern void id_getcmdline(int argc, char **argv);
extern void id_response(struct protstream *pout);

#endif /* _CYRUS_VERSION_H */
