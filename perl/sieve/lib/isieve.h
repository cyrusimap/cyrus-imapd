/* isieve.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef ISIEVE_H_
#define ISIEVE_H_

#include "prot.h"
#include <sasl/sasl.h>

typedef struct iseive_s isieve_t;

int init_net(char *serverFQDN, int port, isieve_t **obj);
void sieve_free_net(isieve_t *obj);

/* The callbacks that are passed to init_sasl need to persist until
 * after sieve_free_net is called on the object, so that referrals can
 * continue to work */
int init_sasl(isieve_t *obj,
              int ssf,
              sasl_callback_t *callbacks);

char * read_capability(isieve_t *obj);
int detect_mitm(isieve_t *obj, char *mechlist);

typedef enum {
    STAT_CONT = 0,
    STAT_NO = 1,
    STAT_OK = 2
} imt_stat;

int auth_sasl(char *mechlist, isieve_t *obj, const char **mechusing, sasl_ssf_t *ssf, char **errstr);

int isieve_logout(isieve_t **obj);
int isieve_put_file(isieve_t *obj, char *filename, char *destname,
                    char **errstr);
int isieve_put(isieve_t *obj, char *name, char *data, int len, char **errstr);
int isieve_delete(isieve_t *obj, char *name, char **errstr);
typedef void *isieve_listcb_t(char *name, int isactive, void *rock);
int isieve_list(isieve_t *obj, isieve_listcb_t *cb,void *rock, char **errstr);
int isieve_activate(isieve_t *obj, char *name, char **errstr);
int isieve_get(isieve_t *obj,char *name, char **output, char **errstr);

#endif /* ISIEVE_H_ */
