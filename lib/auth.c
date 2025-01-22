/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 */

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
