/* init_et.c
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
 *
 * Copyright 1986, 1987, 1988 by MIT Information Systems and
 *      the MIT Student Information Processing Board.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include "error_table.h"
#include "mit-sipb-copyright.h"

extern struct et_list * _et_list;

int init_error_table(msgs, base, count)
    const char * const * msgs;
    int base;
    int count;
{
    struct et_list *etl;
    struct error_table *et;

    if (!base || !count || !msgs)
        return 0;

    etl = malloc(sizeof *etl);
    et = malloc(sizeof *et);
    if (!etl || !et) {
        free(etl);
        free(et);
        return errno; /* oops */
    }
    etl->table = et;
    et->msgs = msgs;
    et->base = base;
    et->n_msgs = count;

    etl->next = _et_list;
    _et_list = etl;
    return 0;
}
