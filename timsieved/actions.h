#include "prot.h"
#include "mystring.h"

int getscript(struct protstream *conn, string_t *name);

int putscript(struct protstream *conn, string_t *name, string_t *data);

int deletescript(struct protstream *conn, string_t *name);

int verifyscriptname(string_t *name);

int listscripts(struct protstream *conn);

int setactive(struct protstream *conn, string_t *name);

int actions_init(void);

int actions_setuser(char *userid);
