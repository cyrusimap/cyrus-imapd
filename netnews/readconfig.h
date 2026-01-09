/* netnews/readconfig.h - code for reading expire.ctl files */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef READCONFIG_H
#define READCONFIG_H

#include "macros.h"

int EXPreadfile(FILE *F);

int ExpireExists(int num);

time_t GetExpireTime(int num);

char *GetExpireName(int num);

int readconfig_init(void);

void artificial_matchall(int days);

void
callback_list(struct imclient *imclient,
              void *rock,
              struct imclient_reply *reply);

#endif /* READCONFIG_H */
