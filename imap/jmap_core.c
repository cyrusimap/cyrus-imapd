/* jmap_core.c - Routines for handling JMAP Core requests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
extern int jmap_pushsub_get(jmap_req_t *req);
extern int jmap_pushsub_set(jmap_req_t *req);

/* JMAP extension methods */
static int jmap_userstate_get(jmap_req_t *req);

// clang-format off
static jmap_method_t jmap_core_methods_standard[] = {
    {
        "Core/echo",
        JMAP_URN_CORE,
        &jmap_core_echo,
        JMAP_NO_ACCOUNTID
    },
    {
        "PushSubscription/get",
        JMAP_URN_CORE,
        &jmap_pushsub_get,
        JMAP_NO_ACCOUNTID
    },
    {
        "PushSubscription/set",
        JMAP_URN_CORE,
        &jmap_pushsub_set,
        JMAP_NO_ACCOUNTID | JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
static jmap_method_t jmap_core_methods_nonstandard[] = {
    {
        "UserState/get",
        JMAP_USERCOUNTERS_EXTENSION,
        &jmap_userstate_get,
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
        xsyslog_ev(LOG_ERR, "jmap.config.invalid", \
                   lf_s("config.option", imapopts[optkey].name)); \
        val = 0; \
    } \
} while (0)

#define _read_bytesize_opt(val, optkey) do { \
    val = config_getbytesize(optkey); \
    if (val <= 0) { \
        xsyslog_ev(LOG_ERR, "jmap.config.invalid", \
                   lf_s("config.option", imapopts[optkey].name)); \
        val = 0; \
    } \
} while (0)

    int64_t *limits = settings->limits;

    _read_bytesize_opt(limits[MAX_SIZE_UPLOAD],
                       IMAPOPT_JMAP_MAX_SIZE_UPLOAD);
    _read_int_opt(limits[MAX_CONCURRENT_UPLOAD],
                  IMAPOPT_JMAP_MAX_CONCURRENT_UPLOAD);
    _read_bytesize_opt(limits[MAX_SIZE_REQUEST],
                       IMAPOPT_JMAP_MAX_SIZE_REQUEST);
    _read_int_opt(limits[MAX_CONCURRENT_REQUESTS],
                  IMAPOPT_JMAP_MAX_CONCURRENT_REQUESTS);
    _read_int_opt(limits[MAX_CALLS_IN_REQUEST],
                  IMAPOPT_JMAP_MAX_CALLS_IN_REQUEST);
    _read_int_opt(limits[MAX_OBJECTS_IN_GET],
                  IMAPOPT_JMAP_MAX_OBJECTS_IN_GET);
    _read_int_opt(limits[MAX_OBJECTS_IN_SET],
                  IMAPOPT_JMAP_MAX_OBJECTS_IN_SET);
    _read_bytesize_opt(limits[MAX_SIZE_BLOB_SET],
                       IMAPOPT_JMAP_MAX_SIZE_BLOB_SET);
    _read_int_opt(limits[MAX_CATENATE_ITEMS],
                  IMAPOPT_JMAP_MAX_CATENATE_ITEMS);

#undef _read_int_opt
#undef _read_bytesize_opt

    limits[MAX_CREATEDIDS_IN_REQUEST] =
        limits[MAX_CALLS_IN_REQUEST] * limits[MAX_OBJECTS_IN_SET];

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CORE,
            json_pack("{s:I s:I s:I s:I s:I s:I s:I s:o}",
                "maxSizeUpload",          (json_int_t) limits[MAX_SIZE_UPLOAD],
                "maxConcurrentUpload",    (json_int_t) limits[MAX_CONCURRENT_UPLOAD],
                "maxSizeRequest",         (json_int_t) limits[MAX_SIZE_REQUEST],
                "maxConcurrentRequests",  (json_int_t) limits[MAX_CONCURRENT_REQUESTS],
                "maxCallsInRequest",      (json_int_t) limits[MAX_CALLS_IN_REQUEST],
                "maxObjectsInGet",        (json_int_t) limits[MAX_OBJECTS_IN_GET],
                "maxObjectsInSet",        (json_int_t) limits[MAX_OBJECTS_IN_SET],
                "collationAlgorithms",    json_array()));

    json_object_set_new(settings->server_capabilities,
            JMAP_CORE_EXTENSION,
            json_pack("{s:I}",
                "maxCreatedIdsInRequest",
                (json_int_t) limits[MAX_CREATEDIDS_IN_REQUEST]));

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

/* UserState/get method */

struct userstate_rock {
    jmap_req_t *req;
    struct jmap_get *get;
    json_t *res;
};

static void add_userstate_cb(const jmap_data_type_t *dtype, void *rock)
{
    struct userstate_rock *srock = rock;

    if (dtype->modseq_offset < 0) return;
    if (!jmap_wantprop(srock->get->props, dtype->name)) return;

    modseq_t modseq =
        *(modseq_t *)((off_t) &srock->req->counters + dtype->modseq_offset);
    char *state =
        jmap_state_string_cstate(srock->req->cstate, modseq, dtype->mbtype);

    json_object_set_new(srock->res, dtype->name, json_string(state));
    free(state);
}

static void userstate_get(jmap_req_t *req, struct jmap_get *get)
{
    json_t *res = json_pack("{s:s}", "id", "singleton");
    struct userstate_rock srock = { req, get, res };

    jmap_data_types_foreach(&add_userstate_cb, &srock);

    json_array_append_new(get->list, res);
}

static int jmap_userstate_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    const char *key;
    json_t *arg;

    get.list = json_array();
    get.not_found = json_array();

    /* We can't lean on jmap_get_parse's property validation here: its valid
     * property set is a gperf perfect-hash table, whereas our valid properties
     * are the JMAP data type names.  So parse by hand and validate properties
     * against jmap_data_types_lookup. */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }
        else if (!strcmp(key, "ids")) {
            if (json_is_array(arg)) {
                get.ids = json_incref(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, "ids");
            }
        }
        else if (!strcmp(key, "properties")) {
            if (json_is_array(arg)) {
                json_t *val;
                size_t i;

                get.props = xzmalloc(sizeof(hash_table));
                construct_hash_table(get.props, json_array_size(arg) + 1, 0);

                json_array_foreach(arg, i, val) {
                    const char *name = json_string_value(val);
                    const jmap_data_type_t *dtype = name ?
                        jmap_data_types_lookup(name, strlen(name)) : NULL;

                    if (dtype && dtype->modseq_offset >= 0) {
                        hash_insert(name, (void *)1, get.props);
                    }
                    else {
                        jmap_parser_push_index(&parser, "properties", i, name);
                        jmap_parser_invalid(&parser, NULL);
                        jmap_parser_pop(&parser);
                    }
                }
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, "properties");
            }
        }
        else {
            jmap_parser_invalid(&parser, key);
        }
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s s:O}", "type", "invalidArguments",
                        "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);

            if (id && !strcmp(id, "singleton"))
                userstate_get(req, &get);
            else
                json_array_append(get.not_found, jval);
        }
    }
    else userstate_get(req, &get);

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
