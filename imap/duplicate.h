#ifndef DUPLICATE_H
#define DUPLICATE_H

#include <db.h>

extern DB_ENV *duplicate_dbenv;

int duplicate_init(void);

time_t duplicate_check(char *id, int idlen, char *to, int tolen);
void duplicate_mark(char *id, int idlen, char *to, int tolen, time_t mark);

int duplicate_prune();

int duplicate_done(void);

#endif /* DUPLICATE_H */

