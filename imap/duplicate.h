#ifndef DUPLICATE_H
#define DUPLICATE_H

#include <db.h>

extern DB_ENV *duplicate_dbenv;

#define DUPLICATE_RECOVER 0x01

int duplicate_init(int);

time_t duplicate_check(char *id, int idlen, char *to, int tolen);
void duplicate_mark(char *id, int idlen, char *to, int tolen, time_t mark);

int duplicate_prune(int days);

int duplicate_done(void);

#endif /* DUPLICATE_H */

