
#ifndef ISIEVE_H_
#define ISIEVE_H_

#include "prot.h"
#include <sasl.h>

typedef struct iseive_s isieve_t;

int init_net(char *serverFQDN, int port, isieve_t **obj);


int init_sasl(isieve_t *obj,
	      int ssf,
	      sasl_callback_t *callbacks);

char * read_capability(isieve_t *obj);

typedef enum {
    STAT_CONT = 0,
    STAT_NO = 1,
    STAT_OK = 2
} imt_stat;

int auth_sasl(char *mechlist, isieve_t *obj);


int isieve_put_file(isieve_t *obj, char *filename);

int isieve_put(isieve_t *obj, char *name, char *data, int len);

int isieve_delete(isieve_t *obj, char *name);

typedef void *isieve_listcb_t(char *name, int isactive, void *rock);

int isieve_list(isieve_t *obj, isieve_listcb_t *cb,void *rock);

int isieve_activate(isieve_t *obj, char *name);

int isieve_get(isieve_t *obj,char *name, char **output);  


#endif /* ISIEVE_H_ */
