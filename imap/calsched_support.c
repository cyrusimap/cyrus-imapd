/* calsched_support.c -- utility functions for dealing with calendar scheduling
 *
 * Copyright (c) 1994-2022 Carnegie Mellon University.  All rights reserved.
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
#include <string.h>

#include "calsched_support.h"
#include "http_dav.h"
#include "mailbox.h"
#include "strarray.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"


EXPORTED int caldav_caluseraddr_read(const char *mboxname,
                                     const char *userid,
                                     struct caldav_caluseraddr *addr)
{
    static const char *annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";

    struct buf buf = BUF_INITIALIZER;

    int r = annotatemore_lookupmask(mboxname, annot, userid, &buf);
    if (r || !buf.len) {
        buf_free(&buf);
        return r ? r : IMAP_NOTFOUND;
    }

    size_t len = buf_len(&buf);
    char *val = buf_release(&buf);
    char *sep = val;
    long lpref = strtol(val, &sep, 10);
    if (sep != val && *sep == ';') {
        // splitm frees the buffer, so make the string
        // value start without the 'pref' field
        size_t i, j;
        for (i = sep + 1 - val, j = 0; i < len; i++, j++) {
            val[j] = val[i];
        }
        val[j] = '\0';
    }
    else lpref = INT_MAX;

    strarray_fini(&addr->uris);
    strarray_splitm(&addr->uris, val, ",", STRARRAY_TRIM);

    if (lpref < 0 || lpref > strarray_size(&addr->uris))
        addr->pref = strarray_size(&addr->uris);
    else
        addr->pref = (int)lpref;

    return 0;
}

EXPORTED int caldav_caluseraddr_write(struct mailbox *mbox,
                                      const char *userid,
                                      const struct caldav_caluseraddr *addr)
{
    static const char *annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";

    annotate_state_t *astate = NULL;
    struct buf buf = BUF_INITIALIZER;

    int r = mailbox_get_annotate_state(mbox, 0, &astate);
    if (r) goto done;

    if (strarray_size(&addr->uris)) {
        // format: (<pref>";")?addrs[0](","addrs[1..n-1])*
        buf_printf(&buf, "%d;", addr->pref);
        int i;
        for (i = 0; i < strarray_size(&addr->uris); i++) {
            if (i) buf_putc(&buf, ',');
            buf_appendcstr(&buf, strarray_nth(&addr->uris, i));
        }
    }

    r = annotate_state_writemask(astate, annot, userid, &buf);

done:
    buf_free(&buf);
    return r;
}

EXPORTED void caldav_caluseraddr_fini(struct caldav_caluseraddr *addr)
{
    if (addr) {
        strarray_fini(&addr->uris);
        addr->pref = 0;
    }
}

EXPORTED void get_schedule_addresses(const char *mboxname,
                                     const char *userid, strarray_t *addresses)
{
    struct buf buf = BUF_INITIALIZER;

    /* find schedule address based on the destination calendar's user */
    struct caldav_caluseraddr caluseraddr = CALDAV_CALUSERADDR_INITIALIZER;

    /* check calendar-user-address-set for target user's mailbox */
    int r = caldav_caluseraddr_read(mboxname, userid, &caluseraddr);
    if (r) {
        char *calhome = caldav_mboxname(userid, NULL);
        r = caldav_caluseraddr_read(calhome, userid, &caluseraddr);
        free(calhome);
    }

    if (!r && strarray_size(&caluseraddr.uris)) {
        int i;
        for (i = 0; i < strarray_size(&caluseraddr.uris); i++) {
            const char *item = strarray_nth(&caluseraddr.uris, i);
            if (!strncasecmp(item, "mailto:", 7)) item += 7;

            char *addr = xmlURIUnescapeString(item, strlen(item), NULL);
            strarray_addm(addresses, addr);
        }
    }
    else if (strchr(userid, '@')) {
        /* userid corresponding to target */
        strarray_add(addresses, userid);
    }
    else {
        /* append fully qualified userids */
        int i;

        for (i = 0; i < strarray_size(&config_cua_domains); i++) {
            const char *domain = strarray_nth(&config_cua_domains, i);

            buf_reset(&buf);
            buf_printf(&buf, "%s@%s", userid, domain);

            strarray_add(addresses, buf_cstring(&buf));
        }
    }

    caldav_caluseraddr_fini(&caluseraddr);

    buf_free(&buf);
}
