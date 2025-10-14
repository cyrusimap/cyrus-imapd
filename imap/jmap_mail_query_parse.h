/* jmap_mail_query_parse.h -- Helper routines for JMAP Email/query
 *
 * Copyright (c) 1994-20 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef JMAP_MAIL_QUERY_PARSE_H
#define JMAP_MAIL_QUERY_PARSE_H

#include <jansson.h>

#include "strarray.h"

typedef struct jmap_email_filter_parse_context jmap_email_filter_parse_ctx_t;

struct jmap_email_filter_parse_context
{
    void (*validate_field)(const char *field, json_t *arg, void *rock);
    void (*invalid_field)(const char *field, void *rock);
    void (*path_push_index)(const char *field,
                            size_t index,
                            const char *name,
                            void *rock);
    void (*path_pop)(void *rock);
    const strarray_t *capabilities;
    void *rock;
};

extern void jmap_email_filtercondition_parse(
    json_t *filter,
    jmap_email_filter_parse_ctx_t *ctx);

extern void jmap_email_filter_parse(json_t *filter,
                                    jmap_email_filter_parse_ctx_t *ctx);

#endif /* JMAP_MAIL_QUERY_PARSER_H */
