/* autocreate.h -- auto-creation routines for mailboxes */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_AUTOCREATE_H
#define INCLUDED_AUTOCREATE_H

#include "config.h"
#include "mboxname.h"

extern int autocreate_user(struct namespace *namespace, const char *userid);

#endif /* INCLUDED_AUTOCREATE_H */
