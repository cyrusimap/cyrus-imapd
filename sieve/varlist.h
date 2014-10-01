/*
 * varlist.h
 *
 *  Created on: Sep 29, 2014
 *      Author: James Cassell
 */

#ifndef VARLIST_H_
#define VARLIST_H_

#include "strarray.h"

typedef struct variable_list {
    char *name;
    strarray_t *var;
    struct variable_list *next;
} variable_list_t;

#define VARIABLE_LIST_INITIALIZER {NULL, NULL, NULL}

variable_list_t *varlist_new(void);

void varlist_fini(variable_list_t *vl);

void varlist_free(variable_list_t *vl);

variable_list_t *varlist_extend(variable_list_t *vl);

variable_list_t *varlist_select(variable_list_t *vl, const char *name);
variable_list_t *varlist_end(variable_list_t *vl);

#endif /* VARLIST_H_ */
