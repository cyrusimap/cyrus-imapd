/* script.h -- script definition
 * Larry Greenfield
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

struct sieve_script {
    sieve_interp_t interp;

    /* was a "require" done for these? */
    struct sieve_support {
        int fileinto       : 1;
        int reject         : 1;
        int envelope       : 1;
        int body           : 1;
        int vacation       : 1;
        int imapflags      : 1;
        int notify         : 1;
        int regex          : 1;
        int subaddress     : 1;
        int relational     : 1;
        int i_ascii_numeric: 1;
        int include        : 1;
        int copy           : 1;
        int date           : 1;
        int index          : 1;
        int vacation_seconds: 1;
        int imap4flags     : 1;
        int mailbox        : 1;
        int mboxmetadata   : 1;
        int servermetadata : 1;
        int variables      : 1;
        int editheader     : 1;
    } support;

    void *script_context;
    commandlist_t *cmds;

    int err;
    char addrerr[500]; /* buffer for address parser error messages */
    char sieveerr[1024];
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

int script_require(sieve_script_t *s, char *req);

#endif
