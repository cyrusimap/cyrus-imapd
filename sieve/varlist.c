/*
 * varlist.c
 *
 *  Created on: Sep 29, 2014
 *      Author: James Cassell
 */

#include "varlist.h"
#include "xmalloc.h"

variable_list_t *varlist_new(void)
{
    variable_list_t *vl;
    vl = xzmalloc(sizeof(variable_list_t));
    vl->var = strarray_new();
    return vl;
}

variable_list_t *varlist_select(variable_list_t *vl, const char *name)
{
    if (!vl) {
        return NULL;
    }
    if ((!name && !vl->name)
        || ((name && vl->name) && !strcasecmp(name, vl->name)))
    {
        return vl;
    }
    return varlist_select(vl->next, name);
}

variable_list_t *varlist_end(variable_list_t *vl)
{
    if (!vl) {
        return NULL;
    }
    if (!vl->next) {
        return vl;
    }
    return varlist_end(vl->next);
}

variable_list_t *varlist_extend(variable_list_t *vl)
{
    if (!vl) {
        return NULL;
    }
    return (varlist_end(vl))->next = varlist_new();
}

void varlist_fini(variable_list_t *vl)
{
    if (!vl) {
        return;
    }
    if (vl->name) {
        free(vl->name);
        vl->name = NULL;
    }
    if (vl->var) {
        strarray_fini(vl->var);
        vl->var = NULL;
    }
    varlist_free(vl->next);
    vl->next = NULL;
}

void varlist_free(variable_list_t *vl)
{
    variable_list_t *next = NULL;
    if (!vl) {
        return;
    }
    next = vl->next;
    if (vl->name) {
        free(vl->name);
    }
    if (vl->var) {
        strarray_free(vl->var);
    }
    free(vl);
    varlist_free(next);
}
