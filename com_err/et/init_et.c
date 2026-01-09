/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include "error_table.h"
#include "mit-sipb-copyright.h"

extern struct et_list * _et_list;

int init_error_table(const char * const * msgs,
                     int base,
                     int count)
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
