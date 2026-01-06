/* auth.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "auth.h"
#include "libcyr_cfg.h"
#include "xmalloc.h"

struct auth_mech *auth_mechs[] = {
    &auth_unix,
    &auth_pts,
    &auth_mboxgroups,
#ifdef HAVE_GSSAPI_H
    &auth_krb5,
#endif
    NULL };

static struct auth_mech *auth_fromname(void)
{
    static struct auth_mech *auth;

    if (auth)
        return auth;

    const char *name = libcyrus_config_getstring(CYRUSOPT_AUTH_MECH);

    for (int i = 0; auth_mechs[i]; i++) {
        if (!strcmp(auth_mechs[i]->name, name)) {
            return auth = auth_mechs[i];
        }
    }

    char errbuf[1024];
    snprintf(errbuf, sizeof(errbuf),
             "Authorization mechanism %s not supported", name);
    fatal(errbuf, EX_CONFIG);
}

EXPORTED int auth_memberof(const struct auth_state *auth_state, const char *identifier)
{
    struct auth_mech *auth = auth_fromname();

    return auth->memberof(auth_state, identifier);
}

EXPORTED const char *auth_canonifyid(const char *identifier, size_t len)
{
    struct auth_mech *auth = auth_fromname();

    return auth->canonifyid(identifier, len);
}

EXPORTED struct auth_state *auth_newstate(const char *identifier)
{
    struct auth_mech *auth = auth_fromname();

    return auth->newstate(identifier);
}

EXPORTED void auth_freestate(struct auth_state *auth_state)
{
    struct auth_mech *auth = auth_fromname();

    if (auth_state) auth->freestate(auth_state);
}

EXPORTED strarray_t *auth_groups(const struct auth_state *auth_state)
{
    struct auth_mech *auth = auth_fromname();

    return auth->groups(auth_state);
}

EXPORTED void auth_refresh(struct auth_state *auth_state)
{
    struct auth_mech *auth = auth_fromname();

    if (auth->refresh) auth->refresh(auth_state);
}
