/* script.h - script definition */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SIEVE_SCRIPT_H
#define SIEVE_SCRIPT_H

#include <sys/types.h>

#include "sieve_interface.h"
#include "interp.h"
#include "tree.h"
#include "util.h"

struct sieve_script {
    sieve_interp_t interp;

    unsigned long long support; /* bitmask of extensions required by script */

    void *script_context;
    commandlist_t *cmds;

    int err;
    int ignore_err;
    char addrerr[500]; /* buffer for address parser error messages */
    struct buf sieveerr;
};

typedef struct sieve_bytecode sieve_bytecode_t;

struct sieve_bytecode {
    ino_t inode;                /* used to prevent mmapping the same script */
    const char *data;
    size_t len;
    int fd;

    int is_executing;           /* used to prevent recursive INCLUDEs */

    sieve_bytecode_t *next;
};

struct sieve_execute {
    sieve_bytecode_t *bc_list;  /* list of loaded bytecode buffers */
    sieve_bytecode_t *bc_cur;   /* currently active bytecode buffer */
};

int script_require(sieve_script_t *s, const char *req);

#endif /*  SIEVE_SCRIPT_H */
