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
                                     strarray_t *addr)
{
    static const char *annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";

    struct buf buf = BUF_INITIALIZER;

    int r = annotatemore_lookupmask(mboxname, annot, userid, &buf);
    if (r || !buf.len) {
        buf_free(&buf);
        return r ? r : IMAP_NOTFOUND;
    }

    // In a previous JMAP for Calendars implementation, the annotation
    // value was of format:
    //
    //     (<pref>";")?addrs[0](","addrs[1..n-1])*
    //
    // where <pref> was an optional numeric index in the list of
    // addrs, indicating which of them is the preferred address.
    // The 'defaultParticipantIdentity' property that made use of
    // this <pref> field does not exist in the latest draft version,
    // and so we got rid of the <pref> field, too.
    const char *sep = strchr(buf_cstring(&buf), ';');
    // Just ignore the <pref> field in the annotation value.
    if (sep) {
        buf_remove(&buf, 0, sep + 1 - buf_base(&buf));
    }
    // Reset and split address list.
    strarray_truncate(addr, 0);
    strarray_splitm(addr, buf_release(&buf), ",", STRARRAY_TRIM);
    return 0;
}

EXPORTED int caldav_caluseraddr_write(struct mailbox *mbox,
                                      const char *userid,
                                      strarray_t *addrs)
{
    static const char *annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";

    annotate_state_t *astate = NULL;
    struct buf buf = BUF_INITIALIZER;

    int r = mailbox_get_annotate_state(mbox, 0, &astate);
    if (r) {
        goto done;
    }

    hash_table addrset = HASH_TABLE_INITIALIZER;
    construct_hash_table(&addrset, strarray_size(addrs) + 1, 0);
    struct buf normaddr = BUF_INITIALIZER;

    int i;
    for (i = 0; i < strarray_size(addrs); i++) {
        // Normalize URI scheme to lowercase.
        const char *addr = strarray_nth(addrs, i);
        const char *col = strchr(addr, ':');
        if (col && col > addr) {
            buf_reset(&normaddr);
            buf_appendmap(&normaddr, addr, col - addr);
            buf_lcase(&normaddr);
            buf_appendcstr(&normaddr, col);
        }
        else {
            buf_setcstr(&normaddr, addr);
        }

        // Deduplicate normalized URIs.
        if (hash_lookup(buf_cstring(&normaddr), &addrset)) {
            continue;
        }

        hash_insert(buf_cstring(&normaddr), (void *) 1, &addrset);

        // Append original URI to annotation value.
        if (i) {
            buf_putc(&buf, ',');
        }
        buf_appendcstr(&buf, addr);
    }

    buf_free(&normaddr);
    free_hash_table(&addrset, NULL);

    r = annotate_state_writemask(astate, annot, userid, &buf);

done:
    buf_free(&buf);
    return r;
}

EXPORTED void get_schedule_addresses(const char *mboxname,
                                     const char *userid,
                                     strarray_t *addresses)
{
    struct buf buf = BUF_INITIALIZER;

    /* check calendar-user-address-set for target user's mailbox */
    int r = caldav_caluseraddr_read(mboxname, userid, addresses);
    if (r) {
        char *calhome = caldav_mboxname(userid, NULL);
        r = caldav_caluseraddr_read(calhome, userid, addresses);
        free(calhome);
    }

    if (!r && strarray_size(addresses)) {
        int i;
        for (i = 0; i < strarray_size(addresses); i++) {
            const char *item = strarray_nth(addresses, i);
            if (!strncasecmp(item, "mailto:", 7)) {
                item += 7;
            }

            char *addr = xmlURIUnescapeString(item, strlen(item), NULL);
            strarray_setm(addresses, i, addr);
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

    buf_free(&buf);
}
