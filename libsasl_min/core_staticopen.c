/* core_staticopen.c - static-only plugin loading */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/core_saslint.h"
#include "libsasl_min/mech_external.h"
#include "libsasl_min/mech_plain.h"

#include <string.h>

struct plugin
{
    const char *name;
    union {
        sasl_auxprop_init_t *auxprop_init_fn;
        sasl_canonuser_init_t *canonuser_init_fn;
        sasl_client_plug_init_t *client_init_fn;
        sasl_server_plug_init_t *server_init_fn;
    };
};

static const struct plugin auxprop_plugins[] =
{
    /* none by default */
};
static const size_t n_auxprop_plugins = sizeof(auxprop_plugins)
                                        / sizeof(auxprop_plugins[0]);

static const struct plugin canonuser_plugins[] =
{
    /* none by default */
};
static const size_t n_canonuser_plugins = sizeof(canonuser_plugins)
                                          / sizeof(canonuser_plugins[0]);


static const struct plugin client_plugins[] =
{
    { "PLAIN", { .client_init_fn = plain_client_plug_init } },
};
static const size_t n_client_plugins = sizeof(client_plugins)
                                       / sizeof(client_plugins[0]);

static const struct plugin server_plugins[] =
{
    { "PLAIN", { .server_init_fn = plain_server_plug_init } },
};
static const size_t n_server_plugins = sizeof(server_plugins)
                                       / sizeof(server_plugins[0]);

EXPORTED int _sasl_load_plugins(
    const add_plugin_list_t *entrypoints,
    const sasl_callback_t *getpath_callback __attribute__((unused)),
    const sasl_callback_t *verifyfile_callback __attribute__((unused)))
{
    const add_plugin_list_t *ep;
    int r = SASL_OK;
    unsigned i;

    for (ep = entrypoints; ep->entryname; ep++) {
        if (!strcmp(ep->entryname, "sasl_server_plug_init")) {
            for (i = 0; i < n_server_plugins; i++) {
                const struct plugin *p = &server_plugins[i];
                r = sasl_server_add_plugin(p->name, p->server_init_fn);
            }
        }
        else if (!strcmp(ep->entryname, "sasl_client_plug_init")) {
            for (i = 0; i < n_client_plugins; i++) {
                const struct plugin *p = &client_plugins[i];
                r = sasl_client_add_plugin(p->name, p->client_init_fn);
            }
        }
        else if (!strcmp(ep->entryname, "sasl_auxprop_plug_init")) {
            for (i = 0; i < n_auxprop_plugins; i++) {
                const struct plugin *p = &auxprop_plugins[i];
                r = sasl_auxprop_add_plugin(p->name, p->auxprop_init_fn);
            }
        }
        else if (!strcmp(ep->entryname, "sasl_canonuser_init")) {
            for (i = 0; i < n_canonuser_plugins; i++) {
                const struct plugin *p = &canonuser_plugins[i];
                r = sasl_canonuser_add_plugin(p->name, p->canonuser_init_fn);
            }
        }
        else {
            return SASL_FAIL;
        }
    }

    return r;
}

EXPORTED int _sasl_get_plugin(
    const char *file __attribute__((unused)),
    const sasl_callback_t *verifyfile_cb __attribute__((unused)),
    void **libraryptr __attribute__((unused)))
{
    return SASL_FAIL;
}

EXPORTED int _sasl_locate_entry(
    void *library __attribute__((unused)),
    const char *entryname __attribute__((unused)),
    void **entry_point __attribute__((unused)))
{
    return SASL_FAIL;
}

EXPORTED int _sasl_done_with_plugins(void)
{
    return SASL_OK;
}
