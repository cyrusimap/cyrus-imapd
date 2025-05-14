/* jmap_core.c -- Routines for handling JMAP Core requests
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

#include <errno.h>

#include <syslog.h>
#include <sys/utsname.h>

#include "http_jmap.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


/* JMAP Core API Methods */
static int jmap_core_echo(jmap_req_t *req);

/* JMAP extension methods */
static int jmap_usercounters_get(jmap_req_t *req);

// clang-format off
static jmap_method_t jmap_core_methods_standard[] = {
    {
        "Core/echo",
        JMAP_URN_CORE,
        &jmap_core_echo,
        0/*flags*/
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
static jmap_method_t jmap_core_methods_nonstandard[] = {
    {
        "UserCounters/get",
        JMAP_USERCOUNTERS_EXTENSION,
        &jmap_usercounters_get,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

HIDDEN void jmap_core_init(jmap_settings_t *settings)
{
#define _read_int_opt(val, optkey) do { \
    val = config_getint(optkey); \
    if (val <= 0) { \
        syslog(LOG_ERR, "jmap: invalid property value: %s", \
                imapopts[optkey].optname); \
        val = 0; \
    } \
} while (0)

#define _read_bytesize_opt(val, optkey, defunit) do { \
    val = config_getbytesize(optkey, defunit); \
    if (val <= 0) { \
        syslog(LOG_ERR, "jmap: invalid property value: %s", \
               imapopts[optkey].optname); \
        val = 0; \
    } \
} while (0)

    int64_t *limits = settings->limits;

    _read_bytesize_opt(limits[MAX_SIZE_UPLOAD],
                       IMAPOPT_JMAP_MAX_SIZE_UPLOAD, 'K');
    _read_int_opt(limits[MAX_CONCURRENT_UPLOAD],
                  IMAPOPT_JMAP_MAX_CONCURRENT_UPLOAD);
    _read_bytesize_opt(limits[MAX_SIZE_REQUEST],
                       IMAPOPT_JMAP_MAX_SIZE_REQUEST, 'K');
    _read_int_opt(limits[MAX_CONCURRENT_REQUESTS],
                  IMAPOPT_JMAP_MAX_CONCURRENT_REQUESTS);
    _read_int_opt(limits[MAX_CALLS_IN_REQUEST],
                  IMAPOPT_JMAP_MAX_CALLS_IN_REQUEST);
    _read_int_opt(limits[MAX_OBJECTS_IN_GET],
                  IMAPOPT_JMAP_MAX_OBJECTS_IN_GET);
    _read_int_opt(limits[MAX_OBJECTS_IN_SET],
                  IMAPOPT_JMAP_MAX_OBJECTS_IN_SET);
    _read_bytesize_opt(limits[MAX_SIZE_BLOB_SET],
                       IMAPOPT_JMAP_MAX_SIZE_BLOB_SET, 'K');
    _read_int_opt(limits[MAX_CATENATE_ITEMS],
                  IMAPOPT_JMAP_MAX_CATENATE_ITEMS);

#undef _read_int_opt
#undef _read_bytesize_opt

    limits[MAX_CREATEDIDS_IN_REQUEST] =
        limits[MAX_CALLS_IN_REQUEST] * limits[MAX_OBJECTS_IN_SET];

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CORE,
            json_pack("{s:i s:i s:i s:i s:i s:i s:i s:o}",
                "maxSizeUpload",          limits[MAX_SIZE_UPLOAD],
                "maxConcurrentUpload",    limits[MAX_CONCURRENT_UPLOAD],
                "maxSizeRequest",         limits[MAX_SIZE_REQUEST],
                "maxConcurrentRequests",  limits[MAX_CONCURRENT_REQUESTS],
                "maxCallsInRequest",      limits[MAX_CALLS_IN_REQUEST],
                "maxObjectsInGet",        limits[MAX_OBJECTS_IN_GET],
                "maxObjectsInSet",        limits[MAX_OBJECTS_IN_SET],
                "collationAlgorithms",    json_array()));

    json_object_set_new(settings->server_capabilities,
            JMAP_CORE_EXTENSION,
            json_pack("{s:i}",
                "maxCreatedIdsInRequest", limits[MAX_CREATEDIDS_IN_REQUEST]));

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        struct utsname buf;

        uname(&buf);
        json_object_set_new(settings->server_capabilities,
                            JMAP_URN_CORE_INFO,
                            json_pack("{s:{s:s s:s} s:n s:{s:s s:s} s:n}",
                                      "product",
                                      "name", "Cyrus JMAP",
                                      "version", CYRUS_VERSION,
                                      "backend",
                                      "environment",
                                      "name", buf.sysname,
                                      "version", buf.release,
                                      "capabilitiesOverrides"));
    }

    jmap_add_methods(jmap_core_methods_standard, settings);

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_PERFORMANCE_EXTENSION, json_object());
        json_object_set_new(settings->server_capabilities,
                JMAP_DEBUG_EXTENSION, json_object());
        json_object_set_new(settings->server_capabilities,
                JMAP_USERCOUNTERS_EXTENSION, json_object());

        jmap_add_methods(jmap_core_methods_nonstandard, settings);
    }

}

HIDDEN void jmap_core_capabilities(json_t *account_capabilities)
{
    json_object_set_new(account_capabilities,
            JMAP_URN_CORE, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                JMAP_PERFORMANCE_EXTENSION, json_object());

        json_object_set_new(account_capabilities,
                JMAP_DEBUG_EXTENSION, json_object());

        json_object_set_new(account_capabilities,
                JMAP_USERCOUNTERS_EXTENSION, json_object());
    }
}

/* Core/echo method */
static int jmap_core_echo(jmap_req_t *req)
{
    json_array_append_new(req->response,
                          json_pack("[s,O,s]", "Core/echo", req->args, req->tag));
    return 0;
}

/* UserCounters/get method */
// clang-format off
static const jmap_property_t usercounters_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "highestModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactsModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "sieveScriptModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactsDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "sieveScriptDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactsFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "sieveScriptFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactsFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "sieveScriptFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "quotaModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "raclModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "uidValidity",
        NULL,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};
// clang-format on

static void usercounters_get(jmap_req_t *req, struct jmap_get *get)
{
    /* Read script */
    json_t *res = json_pack("{s:s}", "id", "singleton");

    if (jmap_wantprop(get->props, "highestModSeq"))
        json_object_set_new(res, "highestModSeq",
                            json_integer(req->counters.highestmodseq));

    if (jmap_wantprop(get->props, "mailModSeq"))
        json_object_set_new(res, "mailModSeq",
                            json_integer(req->counters.mailmodseq));
    if (jmap_wantprop(get->props, "calendarModSeq"))
        json_object_set_new(res, "calendarModSeq",
                            json_integer(req->counters.caldavmodseq));
    if (jmap_wantprop(get->props, "contactsModSeq"))
        json_object_set_new(res, "contactsModSeq",
                            json_integer(req->counters.carddavmodseq));
    if (jmap_wantprop(get->props, "notesModSeq"))
        json_object_set_new(res, "notesModSeq",
                            json_integer(req->counters.notesmodseq));
    if (jmap_wantprop(get->props, "submissionModSeq"))
        json_object_set_new(res, "submissionModSeq",
                            json_integer(req->counters.submissionmodseq));
    if (jmap_wantprop(get->props, "sieveScriptModSeq"))
        json_object_set_new(res, "sieveScriptModSeq",
                            json_integer(req->counters.sievemodseq));

    if (jmap_wantprop(get->props, "mailDeletedModSeq"))
        json_object_set_new(res, "mailDeletedModSeq",
                            json_integer(req->counters.maildeletedmodseq));
    if (jmap_wantprop(get->props, "calendarDeletedModSeq"))
        json_object_set_new(res, "calendarDeletedModSeq",
                            json_integer(req->counters.caldavdeletedmodseq));
    if (jmap_wantprop(get->props, "contactsDeletedModSeq"))
        json_object_set_new(res, "contactsDeletedModSeq",
                            json_integer(req->counters.carddavdeletedmodseq));
    if (jmap_wantprop(get->props, "notesDeletedModSeq"))
        json_object_set_new(res, "notesDeletedModSeq",
                            json_integer(req->counters.notesdeletedmodseq));
    if (jmap_wantprop(get->props, "submissionDeletedModSeq"))
        json_object_set_new(res, "submissionDeletedModSeq",
                            json_integer(req->counters.submissiondeletedmodseq));
    if (jmap_wantprop(get->props, "sieveScriptDeletedModSeq"))
        json_object_set_new(res, "sieveScriptDeletedModSeq",
                            json_integer(req->counters.sievedeletedmodseq));

    if (jmap_wantprop(get->props, "mailFoldersModSeq"))
        json_object_set_new(res, "mailFoldersModSeq",
                            json_integer(req->counters.mailfoldersmodseq));
    if (jmap_wantprop(get->props, "calendarFoldersModSeq"))
        json_object_set_new(res, "calendarFoldersModSeq",
                            json_integer(req->counters.caldavfoldersmodseq));
    if (jmap_wantprop(get->props, "contactsFoldersModSeq"))
        json_object_set_new(res, "contactsFoldersModSeq",
                            json_integer(req->counters.carddavfoldersmodseq));
    if (jmap_wantprop(get->props, "notesFoldersModSeq"))
        json_object_set_new(res, "notesFoldersModSeq",
                            json_integer(req->counters.notesfoldersmodseq));
    if (jmap_wantprop(get->props, "submissionFoldersModSeq"))
        json_object_set_new(res, "submissionFoldersModSeq",
                            json_integer(req->counters.submissionfoldersmodseq));
    if (jmap_wantprop(get->props, "sieveScriptFoldersModSeq"))
        json_object_set_new(res, "sieveScriptFoldersModSeq",
                            json_integer(req->counters.sievefoldersmodseq));

    if (jmap_wantprop(get->props, "mailFoldersDeletedModSeq"))
        json_object_set_new(res, "mailFoldersDeletedModSeq",
                            json_integer(req->counters.mailfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "calendarFoldersDeletedModSeq"))
        json_object_set_new(res, "calendarFoldersDeletedModSeq",
                            json_integer(req->counters.caldavfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "contactsFoldersDeletedModSeq"))
        json_object_set_new(res, "contactsFoldersDeletedModSeq",
                            json_integer(req->counters.carddavfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "notesFoldersDeletedModSeq"))
        json_object_set_new(res, "notesFoldersDeletedModSeq",
                            json_integer(req->counters.notesfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "submissionFoldersDeletedModSeq"))
        json_object_set_new(res, "submissionFoldersDeletedModSeq",
                            json_integer(req->counters.submissionfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "sieveScriptFoldersDeletedModSeq"))
        json_object_set_new(res, "sieveScriptFoldersDeletedModSeq",
                            json_integer(req->counters.sievefoldersdeletedmodseq));

    if (jmap_wantprop(get->props, "quotaModSeq"))
        json_object_set_new(res, "quotaModSeq",
                            json_integer(req->counters.quotamodseq));
    if (jmap_wantprop(get->props, "raclModSeq"))
        json_object_set_new(res, "raclModSeq",
                            json_integer(req->counters.raclmodseq));

    if (jmap_wantprop(get->props, "uidValidity"))
        json_object_set_new(res, "uidValidity",
                            json_integer(req->counters.uidvalidity));

    json_array_append_new(get->list, res);
}

static int jmap_usercounters_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, usercounters_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);

            if (!strcmp(id, "singleton"))
                usercounters_get(req, &get);
            else
                json_array_append(get.not_found, jval);
        }
    }
    else usercounters_get(req, &get);

    /* Build response */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.highestmodseq);
    get.state = buf_release(&buf);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    return 0;
}
