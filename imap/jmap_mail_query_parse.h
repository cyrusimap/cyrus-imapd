/* jmap_mail_query_parse.h - Helper routines for JMAP Email/query */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_MAIL_QUERY_PARSE_H
#define JMAP_MAIL_QUERY_PARSE_H

#include <jansson.h>

#include "strarray.h"

typedef struct jmap_email_filter_parse_context jmap_email_filter_parse_ctx_t;

struct jmap_email_filter_parse_context {
    void (*validate_field)(const char *field, json_t *arg, void *rock);
    void (*invalid_field)(const char *field, void *rock);
    void (*path_push_index)(const char *field, size_t index,
                            const char *name, void *rock);
    void (*path_pop)(void *rock);
    const strarray_t *capabilities;
    void *rock;
};

extern void jmap_email_filtercondition_parse(json_t *filter,
                                             jmap_email_filter_parse_ctx_t *ctx);

extern void jmap_email_filter_parse(json_t *filter,
                                    jmap_email_filter_parse_ctx_t *ctx);

#endif /* JMAP_MAIL_QUERY_PARSER_H */
