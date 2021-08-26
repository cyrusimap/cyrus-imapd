/* jmap_mail_query_parse.c -- Helper routines for JMAP Email/query
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <string.h>
#include <syslog.h>

#include "jmap_api.h"
#include "jmap_mail_query_parse.h"
#include "json_support.h"

HIDDEN void jmap_email_filtercondition_parse(json_t *filter,
                                             jmap_email_filter_parse_ctx_t *ctx)
{
    const char *field, *s = NULL;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "before") ||
                 !strcmp(field, "after")) {
            if (!json_is_utcdate(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (!strcmp(field, "minSize") ||
                 !strcmp(field, "maxSize")) {
            if (!json_is_integer(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (!strcmp(field, "hasAttachment")) {
            if (!json_is_boolean(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (!strcmp(field, "text") ||
                 !strcmp(field, "from") ||
                 !strcmp(field, "to") ||
                 !strcmp(field, "cc") ||
                 !strcmp(field, "bcc") ||
                 !strcmp(field, "subject") ||
                 !strcmp(field, "body") ||
                 (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                  (!strcmp(field, "attachmentName") ||    /* FM-specific */
                   !strcmp(field, "attachmentType"))) ||  /* FM-specific */
                 (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                   !strcmp(field, "attachmentBody"))) {
            if (!json_is_string(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (!strcmp(field, "header")) {
            if (!json_is_array(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
            else {
                switch (json_array_size(arg)) {
                case 3:
                    s = json_string_value(json_array_get(arg, 2));
                    if (strcmpsafe(s, "equals") &&
                        strcmpsafe(s, "startsWith") &&
                        strcmpsafe(s, "endsWith") &&
                        strcmpsafe(s, "contains")) {

                        ctx->path_push_index(field, 2, s, ctx->rock);
                        ctx->invalid_field(NULL, ctx->rock);
                        ctx->path_pop(ctx->rock);
                    }

                    GCC_FALLTHROUGH

                case 2:
                    s = json_string_value(json_array_get(arg, 1));
                    if (!s || !strlen(s)) {
                        ctx->path_push_index(field, 1, s, ctx->rock);
                        ctx->invalid_field(NULL, ctx->rock);
                        ctx->path_pop(ctx->rock);
                    }

                    GCC_FALLTHROUGH

                case 1:
                    s = json_string_value(json_array_get(arg, 0));
                    if (!s || !strlen(s)) {
                        ctx->path_push_index(field, 0, s, ctx->rock);
                        ctx->invalid_field(NULL, ctx->rock);
                        ctx->path_pop(ctx->rock);
                    }
                    break;

                default:
                    ctx->invalid_field(field, ctx->rock);
                }
            }
        }
        else if (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                 (!strcmp(field, "fromContactGroupId") ||
                  !strcmp(field, "toContactGroupId") ||
                  !strcmp(field, "ccContactGroupId") ||
                  !strcmp(field, "bccContactGroupId"))) {
            if (!json_is_string(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                 (!strcmp(field, "fromAnyContact") ||
                  !strcmp(field, "toAnyContact") ||
                  !strcmp(field, "ccAnyContact") ||
                  !strcmp(field, "bccAnyContact"))) {
            if (!json_is_boolean(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                !strcmp(field, "deliveredTo")) {
            if (!json_is_string(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                !strcmp(field, "isHighPriority")) {
            if (!json_is_boolean(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                !strcmp(field, "language")) {
            if (json_is_string(arg)) {
                const char *s = json_string_value(arg);
                if (!(isalpha(s[0]) && isalpha(s[1]) &&
                            (s[2] == '\0' || (isalpha(s[2]) && s[3] == '\0')))) {
                    /* not a two or three-letter code */
                    ctx->invalid_field(field, ctx->rock);
                }
            }
            else {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (strarray_find(ctx->capabilities, JMAP_MAIL_EXTENSION, 0) >= 0 &&
                !strcmp(field, "listId")) {
            if (!json_is_string(arg)) {
                ctx->invalid_field(field, ctx->rock);
            }
        }
        else if (ctx->validate_field) {
            ctx->validate_field(field, arg, ctx->rock);
        }
        else {
            // can just check for syntactical correctness
            if (!strcmp(field, "inMailbox")) {
                if (!json_is_string(arg)) {
                    ctx->invalid_field(field, ctx->rock);
                }
            }
            else if (!strcmp(field, "inMailboxOtherThan")) {
                if (!json_is_array(arg)) {
                    ctx->invalid_field(field, ctx->rock);
                }
            }
            else if (!strcmp(field, "allInThreadHaveKeyword") ||
                    !strcmp(field, "someInThreadHaveKeyword") ||
                    !strcmp(field, "noneInThreadHaveKeyword")) {
                if (!json_string_value(arg)) {
                    ctx->invalid_field(field, ctx->rock);
                }
            }
            else if (!strcmp(field, "hasKeyword") ||
                    !strcmp(field, "notKeyword")) {
                if (!json_string_value(arg)) {
                    ctx->invalid_field(field, ctx->rock);
                }
            }
            else {
                ctx->invalid_field(field, ctx->rock);
            }
        }
    }
}

HIDDEN void jmap_email_filter_parse(json_t *filter,
                                    jmap_email_filter_parse_ctx_t *ctx)
{
    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        ctx->invalid_field(NULL, ctx->rock);
        return;
    }
    json_t *jop = json_object_get(filter, "operator");
    if (json_is_string(jop)) {
        const char *op = json_string_value(jop);
        if (strcmp("AND", op) && strcmp("OR", op) && strcmp("NOT", op)) {
            ctx->invalid_field("operator", ctx->rock);
        }
        json_t *jconds = json_object_get(filter, "conditions");
        if (!json_array_size(jconds)) {
            ctx->invalid_field("conditions", ctx->rock);
        }
        size_t i;
        json_t *jcond;
        json_array_foreach(jconds, i, jcond) {
            ctx->path_push_index("conditions", i, NULL, ctx->rock);
            jmap_email_filter_parse(jcond, ctx);
            ctx->path_pop(ctx->rock);
        }
    } else if (jop) {
        ctx->invalid_field("operator", ctx->rock);
    } else {
        jmap_email_filtercondition_parse(filter, ctx);
    }
}
