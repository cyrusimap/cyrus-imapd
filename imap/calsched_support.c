/* calsched_support.c - utility functions for dealing with calendar scheduling */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "calsched_support.h"
#include "http_dav.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
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
    if (sep) buf_remove(&buf, 0, sep + 1 - buf_base(&buf));
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
    if (r) goto done;

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
        if (hash_lookup(buf_cstring(&normaddr), &addrset))
            continue;

        hash_insert(buf_cstring(&normaddr), (void*)1, &addrset);

        // Append original URI to annotation value.
        if (i) buf_putc(&buf, ',');
        buf_appendcstr(&buf, addr);
    }

    buf_free(&normaddr);
    free_hash_table(&addrset, NULL);

    r = annotate_state_writemask(astate, annot, userid, &buf);

done:
    buf_free(&buf);
    return r;
}

/* Add to userids the userids whose default scheduling addresses (see
   get_schedule_addresses()) can include addr, whether or not they exist */
static void sched_address_userids(const char *addr, strarray_t *userids)
{
    if (!strncasecmp(addr, "mailto:", 7)) {
        addr += 7;
    }

    const char *at = strrchr(addr, '@');
    if (!at) {
        return;
    }

    const char *domain = at + 1;
    if (!strarray_contains_case(&config_cua_domains, domain)) {
        return;
    }

    /* user+detail@domain is an address of user and of user@domain */
    const char *plus = memchr(addr, '+', at - addr);
    size_t len = (plus ? plus : at) - addr;
    if (!len) {
        return;
    }

    struct buf buf = BUF_INITIALIZER;
    buf_setmap(&buf, addr, len);
    strarray_add(userids, buf_cstring(&buf));
    buf_printf(&buf, "@%s", domain);
    strarray_add(userids, buf_cstring(&buf));

    /* addresses compare without regard to case, userids may not */
    for (int i = 0, n = strarray_size(userids); i < n; i++) {
        buf_setcstr(&buf, strarray_nth(userids, i));
        strarray_add(userids, buf_lcase(&buf));
    }

    buf_free(&buf);
}

EXPORTED void sched_addresses_restrict(strarray_t *addresses,
                                       const char *userid,
                                       const char *ownerid)
{
    strarray_t addr_userids = STRARRAY_INITIALIZER;

    for (int i = strarray_size(addresses) - 1; i >= 0; i--) {
        strarray_truncate(&addr_userids, 0);
        sched_address_userids(strarray_nth(addresses, i), &addr_userids);

        if ((userid && strarray_contains_case(&addr_userids, userid))
            || (ownerid && strarray_contains_case(&addr_userids, ownerid)))
        {
            continue;
        }

        for (int j = 0; j < strarray_size(&addr_userids); j++) {
            char *inbox =
                mboxname_user_mbox(strarray_nth(&addr_userids, j), NULL);
            bool exists = !mboxlist_lookup(inbox, NULL, NULL);
            free(inbox);

            if (exists) {
                free(strarray_remove(addresses, i));
                break;
            }
        }
    }

    strarray_fini(&addr_userids);
}

EXPORTED void get_schedule_addresses(const char *mboxname,
                                     const char *userid, strarray_t *addresses)
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
            if (!strncasecmp(item, "mailto:", 7)) item += 7;

            char *addr = xmlURIUnescapeString(item, strlen(item), NULL);
            strarray_setm(addresses, i, addr);
        }

        /* the set can list anything: drop other users' addresses */
        char *ownerid = mboxname_to_userid(mboxname);
        sched_addresses_restrict(addresses, userid, ownerid);
        free(ownerid);
    }

    if (r || !strarray_size(addresses)) {
        if (strchr(userid, '@')) {
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
    }

    buf_free(&buf);
}
