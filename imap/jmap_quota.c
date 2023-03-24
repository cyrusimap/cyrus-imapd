/* jmap_quota.c -- Routines for handling JMAP Quota requests
 *
 * Copyright (c) 1994-2023 Carnegie Mellon University.  All rights reserved.
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

#include <syslog.h>

#include "http_jmap.h"
#include "jmap_api.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


static int jmap_quota_get(jmap_req_t *req);

static jmap_method_t jmap_quota_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_quota_methods_nonstandard[] = {
    {
        "Quota/get",
        JMAP_QUOTA_EXTENSION,
        &jmap_quota_get,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_quota_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_quota_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_QUOTA_EXTENSION, json_object());

        for (mp = jmap_quota_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

}

HIDDEN void jmap_quota_capabilities(json_t *account_capabilities)
{
    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                JMAP_QUOTA_EXTENSION, json_object());
    }
}

/* Quota/get method */
static const jmap_property_t quota_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "used",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "total",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};

static int jmap_quota_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    char *inboxname = mboxname_user_mbox(req->accountid, NULL);

    /* Parse request */
    jmap_get_parse(req, &parser, quota_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int want_mail_quota = !get.ids || json_is_null(get.ids);
    size_t i;
    json_t *jval;
    json_array_foreach(get.ids, i, jval) {
        if (strcmp("mail", json_string_value(jval))) {
            json_array_append(get.not_found, jval);
        }
        else want_mail_quota = 1;
    }

    if (want_mail_quota) {
        struct quota quota;
        quota_init(&quota, inboxname);
        int r = quota_read_withconversations(&quota);
        if (!r) {
            quota_t total = quota.limits[QUOTA_STORAGE] * quota_units[QUOTA_STORAGE];
            quota_t used = quota.useds[QUOTA_STORAGE];
            json_t *jquota = json_object();
            json_object_set_new(jquota, "id", json_string("mail"));
            json_object_set_new(jquota, "used", json_integer(used));
            json_object_set_new(jquota, "total", json_integer(total));
            json_array_append_new(get.list, jquota);
        }
        else {
            syslog(LOG_ERR, "jmap_quota_get: can't read quota for %s: %s",
                    inboxname, error_message(r));
            json_array_append_new(get.not_found, json_string("mail"));
        }
        quota_free(&quota);
    }


    modseq_t quotamodseq = mboxname_readquotamodseq(inboxname);
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, quotamodseq);
    get.state = buf_release(&buf);

    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(inboxname);
    return 0;
}
