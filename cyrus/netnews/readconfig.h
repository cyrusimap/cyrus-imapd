
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
