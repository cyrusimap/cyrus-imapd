/* calsched_support.c - utility functions for dealing with calendar scheduling */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "caldav_db.h"
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

static int caladdress_mboxlist_lookup(const char *name, mbentry_t **mbentryp)
{
    return mboxlist_lookup(name, mbentryp, NULL);
}

EXPORTED char *caladdress_userid(const char *addr, bool defdomain_fallback,
                                 int (*mlookup)(const char *, mbentry_t **),
                                 mbentry_t **calhomep)
{
    char *userid = NULL;

    if (calhomep) *calhomep = NULL;
    if (!addr) return NULL;
    if (!mlookup) mlookup = &caladdress_mboxlist_lookup;

    if (!strncasecmp(addr, "mailto:", 7)) addr += 7;

    const char *at = strrchr(addr, '@');
    if (!at || !strarray_contains_case(&config_cua_domains, at + 1)) {
        return NULL;
    }

    /* user+detail@domain is delivered to user */
    const char *plus = memchr(addr, '+', at - addr);
    size_t len = (plus ? plus : at) - addr;
    if (!len) return NULL;

    /* with virtdomains, local@domain is that domain's user; a user in the
       default domain may also hold local@ in every calendar_user_address_set
       domain (see get_schedule_addresses()) */
    strarray_t tries = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    for (int lcase = 0; lcase < 2; lcase++) {
        if (config_virtdomains) {
            buf_setmap(&buf, addr, len);
            buf_printf(&buf, "@%s", at + 1);
            if (lcase) buf_lcase(&buf);
            strarray_add(&tries, buf_cstring(&buf));
        }
        if (!config_virtdomains || defdomain_fallback) {
            buf_setmap(&buf, addr, len);
            if (lcase) buf_lcase(&buf);
            strarray_add(&tries, buf_cstring(&buf));
        }
    }
    buf_free(&buf);

    for (int i = 0; !userid && i < strarray_size(&tries); i++) {
        mbname_t *mbname = mbname_from_userid(strarray_nth(&tries, i));
        char *calhome = caldav_mboxname(mbname_userid(mbname), NULL);
        mbentry_t *mbentry = NULL;

        if (!mlookup(calhome, &mbentry)) {
            userid = xstrdup(mbname_userid(mbname));
            if (calhomep) *calhomep = mbentry;
            else mboxlist_entry_free(&mbentry);
        }
        else if (!mboxlist_lookup(mbname_intname(mbname), NULL, NULL)) {
            /* a user with no calendars yet still owns the address */
            userid = xstrdup(mbname_userid(mbname));
        }

        free(calhome);
        mbname_free(&mbname);
    }

    strarray_fini(&tries);

    return userid;
}

static bool sched_same_user(const char *a, const char *b)
{
    if (!a || !b) return false;

    mbname_t *mbname = mbname_from_userid(b);
    bool same = !strcasecmpsafe(a, mbname_userid(mbname));
    mbname_free(&mbname);

    return same;
}

/* address -> its user, or "" for none; NULL outside a cached scope */
static hash_table *addrid_cache = NULL;

EXPORTED void sched_address_cache_begin(void)
{
    if (addrid_cache) return;

    addrid_cache = malloc_hash_table(0);
}

EXPORTED void sched_address_cache_end(void)
{
    if (!addrid_cache) return;

    release_hash_table(&addrid_cache, &free);
}

static char *sched_address_userid(const char *addr)
{
    if (!addrid_cache) return caladdress_userid(addr, true, NULL, NULL);

    const char *cached = hash_lookup(addr, addrid_cache);
    if (cached) return *cached ? xstrdup(cached) : NULL;

    char *addrid = caladdress_userid(addr, true, NULL, NULL);
    hash_insert(addr, xstrdup(addrid ? addrid : ""), addrid_cache);

    return addrid;
}

EXPORTED bool sched_address_permitted(const char *addr,
                                      const char *userid,
                                      const char *ownerid)
{
    char *addrid = sched_address_userid(addr);
    bool permitted = !addrid || sched_same_user(addrid, userid)
                             || sched_same_user(addrid, ownerid);

    free(addrid);
    return permitted;
}

EXPORTED void sched_addresses_restrict(strarray_t *addresses,
                                       const char *userid,
                                       const char *ownerid)
{
    for (int i = strarray_size(addresses) - 1; i >= 0; i--) {
        if (!sched_address_permitted(strarray_nth(addresses, i),
                                     userid, ownerid))
        {
            free(strarray_remove(addresses, i));
        }
    }
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
