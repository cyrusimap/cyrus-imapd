/* script.h -- script definition
 * Larry Greenfield
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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

#include "message.h"
#include "varlist.h"

int sieve_eval_bc(sieve_execute_t *exe, int is_incl, sieve_interp_t *i,
                  void *sc, void *m, variable_list_t *variables,
                  action_list_t *actions, notify_list_t *notify_list,
                  duptrack_list_t *duptrack_list, const char **errmsg);

#endif /*  SIEVE_SCRIPT_H */
