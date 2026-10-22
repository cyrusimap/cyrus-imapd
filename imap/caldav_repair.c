/* caldav_repair.c - repair CalDAV database invariant violations */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <libical/ical.h>

#include "annotate.h"
#include "auth.h"
#include "caldav_db.h"
#include "caldav_repair.h"
#include "caldav_util.h"
#include "charset.h"
#include "dav_util.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "ical_support.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "message_guid.h"
#include "ptrarray.h"
#include "spool.h"
#include "strarray.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

/* Provenance of a resource that was split off under a new UID. */
#define XPROP_ORIGINAL_UID "X-CYRUS-ORIGINAL-UID"

/* What the repair does to one resource. */
enum repair_action {
    REPAIR_KEEP,    /* keeps its identity, absorbs the merged copies */
    REPAIR_MERGE,   /* folded into the kept resource, then expunged */
    REPAIR_REUID    /* split off under a new iCalendar UID */
};

/* One user's per-message calendar data, as stored in the annotation. */
struct repair_userdata {
    char *userid;
    struct buf value;
};

/* Any other per-message annotation. */
struct repair_annot {
    char *entry;
    char *userid;
    struct buf value;
};

/* One live ical_objs row of a conflicting group, with its content. */
struct repair_res {
    /* identity, from the database */
    char *mboxid;
    char *mboxname;
    char *resource;
    uint32_t imap_uid;
    modseq_t createdmodseq;
    unsigned comp_type;
    char *sched_tag;
    bool tzbyref;
    bool shared;

    /* content, read from the mailbox */
    icalcomponent *ical;
    strarray_t schedule_addresses;
    ptrarray_t userdata;        /* struct repair_userdata */
    strarray_t *flags;
    ptrarray_t annots;          /* struct repair_annot */

    /* filled in by plan_group() */
    enum repair_action action;
    char *conflict;             /* why it could not be merged, else NULL */
    unsigned nfolded;           /* components it contributes to the merge */
};

/* All live resources sharing one iCalendar UID. */
struct repair_group {
    char *ical_uid;
    ptrarray_t resources;       /* struct repair_res */
};

/* What plan_group() decided for one group. */
struct repair_plan {
    icalcomponent *ical;   /* the merged content for the kept resource */
    ptrarray_t userdata;   /* struct repair_userdata, borrowed */
    unsigned nmerged;      /* resources folded into the kept one */
    unsigned nsplit;       /* resources to be split off under a new UID */
};

#define REPAIR_PLAN_INITIALIZER { NULL, PTRARRAY_INITIALIZER, 0, 0 }

static void repair_userdata_free(struct repair_userdata *pud)
{
    if (!pud) return;
    free(pud->userid);
    buf_free(&pud->value);
    free(pud);
}

static void repair_annot_free(struct repair_annot *annot)
{
    if (!annot) return;
    free(annot->entry);
    free(annot->userid);
    buf_free(&annot->value);
    free(annot);
}

static void repair_res_free(struct repair_res *res)
{
    if (!res) return;

    free(res->mboxid);
    free(res->mboxname);
    free(res->resource);
    free(res->sched_tag);
    free(res->conflict);
    if (res->ical) icalcomponent_free(res->ical);
    strarray_fini(&res->schedule_addresses);

    struct repair_userdata *pud;
    while ((pud = ptrarray_pop(&res->userdata)))
        repair_userdata_free(pud);
    ptrarray_fini(&res->userdata);

    strarray_free(res->flags);

    struct repair_annot *annot;
    while ((annot = ptrarray_pop(&res->annots)))
        repair_annot_free(annot);
    ptrarray_fini(&res->annots);

    free(res);
}

static void repair_group_free(struct repair_group **groupp)
{
    struct repair_group *group = *groupp;

    if (!group) return;

    free(group->ical_uid);

    struct repair_res *res;
    while ((res = ptrarray_pop(&group->resources)))
        repair_res_free(res);
    ptrarray_fini(&group->resources);

    free(group);
    *groupp = NULL;
}

/*
 * Detection
 */

static int collect_cb(void *rock, struct caldav_data *cdata)
{
    ptrarray_t *groups = rock;
    struct repair_group *group = ptrarray_tail(groups);

    if (!group || strcmp(group->ical_uid, cdata->ical_uid)) {
        group = xzmalloc(sizeof(struct repair_group));
        group->ical_uid = xstrdup(cdata->ical_uid);
        ptrarray_append(groups, group);
    }

    struct repair_res *res = xzmalloc(sizeof(struct repair_res));
    res->mboxid = xstrdup(cdata->dav.mailbox);
    res->resource = xstrdup(cdata->dav.resource);
    res->imap_uid = cdata->dav.imap_uid;
    res->createdmodseq = cdata->dav.createdmodseq;
    res->comp_type = cdata->comp_type;
    res->sched_tag = xstrdupnull(cdata->sched_tag);
    res->tzbyref = cdata->comp_flags.tzbyref;
    res->shared = cdata->comp_flags.shared;
    ptrarray_append(&group->resources, res);

    return 0;
}

/* Deterministic order: the head of the list keeps its identity.  The lowest
 * createdmodseq keeps the JMAP id the client is likeliest to hold; imap_uid
 * and mailbox only break ties, so that a report and the repair it describes
 * agree. */
static int cmp_selection(const void **ap, const void **bp)
{
    const struct repair_res *a = *ap;
    const struct repair_res *b = *bp;

    if (!!a->sched_tag != !!b->sched_tag)
        return a->sched_tag ? -1 : 1;

    if (a->createdmodseq != b->createdmodseq)
        return a->createdmodseq < b->createdmodseq ? -1 : 1;

    if (a->imap_uid != b->imap_uid)
        return a->imap_uid < b->imap_uid ? -1 : 1;

    return strcmp(a->mboxid, b->mboxid);
}

/*
 * Occurrence keys
 */

/* An occurrence key is one (component kind, RECURRENCE-ID) pair, and names the
 * position a component occupies in its resource.  Every component of a group
 * shares the UID, so the keys are comparable across resources. */
static void occurrence_key(icalcomponent *comp, struct buf *key)
{
    buf_setcstr(key, icalcomponent_kind_to_string(icalcomponent_isa(comp)));
    buf_putc(key, '\t');

    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
    if (prop) {
        icalparameter *param =
            icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
        if (param) buf_appendcstr(key, icalparameter_get_tzid(param));
        buf_putc(key, '\t');
        buf_appendcstr(key, icalproperty_get_value_as_string(prop));
    }
}

static void occurrence_desc(icalcomponent *comp, struct buf *desc)
{
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);

    if (prop)
        buf_printf(desc, "instance %s", icalproperty_get_value_as_string(prop));
    else
        buf_setcstr(desc, "main component");
}

static void remove_properties(icalcomponent *comp, icalproperty_kind kind)
{
    icalproperty *prop, *next;

    for (prop = icalcomponent_get_first_property(comp, kind); prop; prop = next) {
        next = icalcomponent_get_next_property(comp, kind);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
}

/* Two components that are semantically equivalent routinely differ in bytes,
 * so compare normalized clones.  DTSTAMP, LAST-MODIFIED and SEQUENCE are
 * bookkeeping rather than content; validate_propupdates() already treats them
 * that way. */
static bool components_are_equal(icalcomponent *a, icalcomponent *b)
{
    icalcomponent *ca = icalcomponent_clone(a);
    icalcomponent *cb = icalcomponent_clone(b);

    static const icalproperty_kind volatile_props[] = {
        ICAL_DTSTAMP_PROPERTY,
        ICAL_LASTMODIFIED_PROPERTY,
        ICAL_SEQUENCE_PROPERTY
    };

    for (size_t i = 0; i < sizeof(volatile_props) / sizeof(volatile_props[0]);
         i++) {
        remove_properties(ca, volatile_props[i]);
        remove_properties(cb, volatile_props[i]);
    }

    icalcomponent_normalize_x(ca);
    icalcomponent_normalize_x(cb);

    char *sa = icalcomponent_as_ical_string_r(ca);
    char *sb = icalcomponent_as_ical_string_r(cb);
    bool equal = !strcmpnull(sa, sb);

    free(sa);
    free(sb);
    icalcomponent_free(ca);
    icalcomponent_free(cb);

    return equal;
}

static bool is_real_component(icalcomponent *comp)
{
    switch (icalcomponent_isa(comp)) {
    case ICAL_VEVENT_COMPONENT:
    case ICAL_VTODO_COMPONENT:
    case ICAL_VJOURNAL_COMPONENT:
    case ICAL_VFREEBUSY_COMPONENT:
    case ICAL_VAVAILABILITY_COMPONENT:
    case ICAL_VPOLL_COMPONENT:
        return true;
    default:
        return false;
    }
}

static void index_occurrences(icalcomponent *ical,
                              hash_table *occurrences)
{
    struct buf key = BUF_INITIALIZER;
    icalcomponent *comp;

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {

        if (!is_real_component(comp)) continue;

        occurrence_key(comp, &key);
        hash_insert(buf_cstring(&key), comp, occurrences);
    }

    buf_free(&key);
}

/*
 * Per-user data
 */

struct userdata_rock {
    ptrarray_t *userdata;
};

static int userdata_cb(const char *mboxname __attribute__((unused)),
                       uint32_t uid __attribute__((unused)),
                       const char *entry __attribute__((unused)),
                       const char *userid,
                       const struct buf *value,
                       const struct annotate_metadata *mdata
                           __attribute__((unused)),
                       void *rock)
{
    struct userdata_rock *urock = rock;

    if (!buf_len(value)) return 0;

    struct repair_userdata *pud = xzmalloc(sizeof(struct repair_userdata));
    pud->userid = xstrdup(userid);
    buf_copy(&pud->value, value);
    ptrarray_append(urock->userdata, pud);

    return 0;
}

static int annot_cb(const char *mboxname __attribute__((unused)),
                    uint32_t uid __attribute__((unused)),
                    const char *entry,
                    const char *userid,
                    const struct buf *value,
                    const struct annotate_metadata *mdata
                        __attribute__((unused)),
                    void *rock)
{
    ptrarray_t *annots = rock;

    /* store_resource() rewrites the shared modseq, so it never conflicts */
    if (!buf_len(value) || !strcmp(entry, PER_USER_CAL_DATA) ||
        !strcmp(entry, SHARED_MODSEQ))
        return 0;

    struct repair_annot *annot = xzmalloc(sizeof(struct repair_annot));
    annot->entry = xstrdup(entry);
    annot->userid = xstrdup(userid);
    buf_copy(&annot->value, value);
    ptrarray_append(annots, annot);

    return 0;
}

static bool has_annot(ptrarray_t *annots, const struct repair_annot *annot)
{
    for (int i = 0; i < ptrarray_size(annots); i++) {
        struct repair_annot *a = ptrarray_nth(annots, i);
        if (!strcmp(a->entry, annot->entry) &&
            !strcmp(a->userid, annot->userid) &&
            !buf_cmp(&a->value, &annot->value))
            return true;
    }

    return false;
}

static struct repair_userdata *find_userdata(ptrarray_t *userdata,
                                             const char *userid)
{
    for (int i = 0; i < ptrarray_size(userdata); i++) {
        struct repair_userdata *pud = ptrarray_nth(userdata, i);
        if (!strcmpsafe(pud->userid, userid)) return pud;
    }

    return NULL;
}

/* The VPATCH guid and the useDefaultAlerts flag are the whole content of the
 * per-user data; LASTMOD and MODSEQ are bookkeeping. */
static bool userdata_is_equal(const struct buf *a, const struct buf *b)
{
    struct icalsupport_personal_data pa = { 0 }, pb = { 0 };
    bool equal = false;

    if (icalsupport_decode_personal_data(a, &pa))
        goto done;
    if (icalsupport_decode_personal_data(b, &pb))
        goto done;

    equal = message_guid_equal(&pa.guid, &pb.guid) &&
            pa.usedefaultalerts == pb.usedefaultalerts;

done:
    icalsupport_personal_data_fini(&pa);
    icalsupport_personal_data_fini(&pb);

    return equal;
}

static bool userdata_is_valid(const struct buf *value)
{
    struct icalsupport_personal_data data = { 0 };
    bool valid = !icalsupport_decode_personal_data(value, &data);

    icalsupport_personal_data_fini(&data);

    return valid;
}

/*
 * Planning
 */

/* Fold one duplicate into the accumulated merge target, or say why it cannot
 * be folded.  Conflict is not decidable against the primary alone: two
 * duplicates may each be compatible with it and not with each other, so the
 * target grows as resources are folded in. */
static char *fold_resource(struct repair_res *dup,
                           struct repair_res *primary,
                           icalcomponent *target,
                           hash_table *occurrences,
                           ptrarray_t *target_userdata)
{
    icalcomponent *comp;
    struct buf key = BUF_INITIALIZER;
    struct buf reason = BUF_INITIALIZER;
    char *conflict = NULL;

    /* A single resource holding two component kinds is itself invalid, so
     * there is nothing to analyse per occurrence. */
    if (dup->comp_type != primary->comp_type) {
        conflict = xstrdup("component type");
        goto done;
    }

    /* The kept resource keeps only its own flags and annotations, so the
     * duplicate's must already be there. */
    for (int i = 0; i < strarray_size(dup->flags); i++) {
        const char *flag = strarray_nth(dup->flags, i);
        if (!strarray_contains_case(primary->flags, flag)) {
            buf_printf(&reason, "flag %s", flag);
            conflict = buf_release(&reason);
            goto done;
        }
    }

    for (int i = 0; i < ptrarray_size(&dup->annots); i++) {
        struct repair_annot *annot = ptrarray_nth(&dup->annots, i);
        if (!has_annot(&primary->annots, annot)) {
            buf_printf(&reason, "annotation %s", annot->entry);
            conflict = buf_release(&reason);
            goto done;
        }
    }

    for (comp = icalcomponent_get_first_component(dup->ical,
                                                  ICAL_ANY_COMPONENT);
         comp && !conflict;
         comp = icalcomponent_get_next_component(dup->ical,
                                                 ICAL_ANY_COMPONENT)) {

        if (!is_real_component(comp)) continue;

        occurrence_key(comp, &key);
        icalcomponent *tcomp = hash_lookup(buf_cstring(&key), occurrences);

        if (tcomp && !components_are_equal(tcomp, comp)) {
            occurrence_desc(comp, &reason);
            conflict = buf_release(&reason);
        }
    }
    if (conflict) goto done;

    for (int i = 0; i < ptrarray_size(&dup->userdata); i++) {
        struct repair_userdata *pud = ptrarray_nth(&dup->userdata, i);
        struct repair_userdata *tud =
            find_userdata(target_userdata, pud->userid);

        /* The merge has to re-encode data the target lacks, so data that
         * does not decode can only be kept by splitting its copy off. */
        if (tud ? !userdata_is_equal(&tud->value, &pud->value)
                : !userdata_is_valid(&pud->value)) {
            conflict = xstrdup("per-user data");
            goto done;
        }
    }

    /* No conflict: take every occurrence the target lacks, and every time zone
     * it does not already define. */
    for (comp = icalcomponent_get_first_component(dup->ical,
                                                  ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(dup->ical,
                                                 ICAL_ANY_COMPONENT)) {

        if (is_real_component(comp)) {
            occurrence_key(comp, &key);
            icalcomponent *tcomp = hash_lookup(buf_cstring(&key), occurrences);

            if (tcomp) {
                int sequence = icalcomponent_get_sequence(comp);
                if (sequence > icalcomponent_get_sequence(tcomp))
                    icalcomponent_set_sequence(tcomp, sequence);
            }
            else {
                tcomp = icalcomponent_clone(comp);
                icalcomponent_add_component(target, tcomp);
                hash_insert(buf_cstring(&key), tcomp, occurrences);
                dup->nfolded++;
            }
        }
        else if (icalcomponent_isa(comp) == ICAL_VTIMEZONE_COMPONENT) {
            icalproperty *prop =
                icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
            const char *tzid = prop ? icalproperty_get_tzid(prop) : NULL;

            if (tzid && !icalcomponent_get_timezone(target, tzid))
                icalcomponent_add_component(target, icalcomponent_clone(comp));
        }
    }

    for (int i = 0; i < ptrarray_size(&dup->userdata); i++) {
        struct repair_userdata *pud = ptrarray_nth(&dup->userdata, i);
        if (!find_userdata(target_userdata, pud->userid))
            ptrarray_append(target_userdata, pud);
    }

done:
    buf_free(&key);
    buf_free(&reason);
    return conflict;
}

/* Decide what becomes of each resource in a conflicting group.  Sorts them
 * into selection order and gives the primary REPAIR_KEEP; each duplicate is
 * folded into the accumulated merge target, or marked REPAIR_REUID with the
 * reason it could not be.  Reads nothing from a mailbox or a database, so a
 * report and the repair it describes run exactly the same decision. */
static void plan_group(struct repair_group *group, struct repair_plan *plan)
{
    hash_table occurrences = HASH_TABLE_INITIALIZER;

    ptrarray_sort(&group->resources, &cmp_selection);

    struct repair_res *primary = ptrarray_head(&group->resources);
    primary->action = REPAIR_KEEP;

    plan->ical = icalcomponent_clone(primary->ical);
    construct_hash_table(&occurrences, 32, 0);
    index_occurrences(plan->ical, &occurrences);

    for (int i = 0; i < ptrarray_size(&primary->userdata); i++)
        ptrarray_append(&plan->userdata, ptrarray_nth(&primary->userdata, i));

    for (int i = 1; i < ptrarray_size(&group->resources); i++) {
        struct repair_res *dup = ptrarray_nth(&group->resources, i);

        dup->conflict = fold_resource(dup, primary, plan->ical, &occurrences,
                                      &plan->userdata);
        if (dup->conflict) {
            dup->action = REPAIR_REUID;
            plan->nsplit++;
        }
        else {
            dup->action = REPAIR_MERGE;
            plan->nmerged++;
        }
    }

    free_hash_table(&occurrences, NULL);
}

static void repair_plan_fini(struct repair_plan *plan)
{
    if (plan->ical) icalcomponent_free(plan->ical);
    ptrarray_fini(&plan->userdata);
    memset(plan, 0, sizeof(struct repair_plan));
}

/*
 * Reading and writing resources
 */

static int load_resource(struct repair_res *res, const char *userid)
{
    struct mailbox *mailbox = NULL;
    struct index_record record;
    int r;

    r = mailbox_open_irl(res->mboxname, &mailbox);
    if (r) goto done;

    r = mailbox_find_index_record(mailbox, res->imap_uid, &record);
    if (r) goto done;

    res->ical = record_to_ical(mailbox, &record, &res->schedule_addresses);
    if (!res->ical) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }

    struct userdata_rock urock = { &res->userdata };
    r = annotatemore_findall_mailbox(mailbox, res->imap_uid, PER_USER_CAL_DATA,
                                     0, &userdata_cb, &urock, 0);
    if (r) goto done;

    r = annotatemore_findall_mailbox(mailbox, res->imap_uid, "*", 0, &annot_cb,
                                     &res->annots, 0);
    if (r) goto done;

    res->flags = mailbox_extract_flags(mailbox, &record, userid);

done:
    mailbox_close(&mailbox);
    return r;
}

/* The header-building slice of caldav_store_resource(), which dav_reconstruct
 * cannot reach: caldav_util.c is compiled per-binary into httpd and lmtpd, and
 * pulls in the whole HTTP stack.  These are the four Content-Disposition
 * parameters mailbox_update_caldav() reads back, plus enough of an RFC 5322
 * header for the message to look like any other calendar resource. */
static void build_headers(struct transaction_t *txn, icalcomponent *ical,
                          const char *resource, const char *sched_tag,
                          bool tzbyref, bool shared,
                          const strarray_t *schedule_addresses)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    char *mimehdr;

    buf_setcstr(&txn->buf, ICALENDAR_CONTENT_TYPE);
    buf_printf(&txn->buf, "; component=%s", icalcomponent_kind_to_string(kind));
    spool_replace_header(xstrdup("Content-Type"),
                         buf_release(&txn->buf), txn->req_hdrs);

    /* The iCalendar UID is in the resource name, so this parameter may be
       long and needs to get properly split per RFC 2231 */
    buf_setcstr(&txn->buf, "attachment");
    charset_append_mime_param(&txn->buf,
                              CHARSET_PARAM_XENCODE | CHARSET_PARAM_NEWLINE,
                              "filename", resource);

    if (sched_tag) buf_printf(&txn->buf, ";\r\n\tschedule-tag=%s", sched_tag);
    if (tzbyref) buf_printf(&txn->buf, ";\r\n\ttz-by-ref=true");
    if (shared) buf_printf(&txn->buf, ";\r\n\tper-user-data=true");
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    const char *summary = icalcomponent_get_summary(comp);
    if (summary) {
        mimehdr = charset_encode_mimeheader(summary, 0, 0);
        spool_replace_header(xstrdup("Subject"), mimehdr, txn->req_hdrs);
    }
    else {
        spool_replace_header(xstrdup("Subject"),
                             xstrdup(icalcomponent_kind_to_string(kind)),
                             txn->req_hdrs);
    }

    /* Use SHA1(uid)@servername as Message-ID */
    const char *uid = icalcomponent_get_uid(comp);
    struct message_guid uuid;
    message_guid_generate(&uuid, uid, strlen(uid));
    buf_printf(&txn->buf, "<%s@%s>",
               message_guid_encode(&uuid), config_servername);
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&txn->buf), txn->req_hdrs);

    if (strarray_size(schedule_addresses)) {
        char *value = strarray_join(schedule_addresses, ",");
        mimehdr = charset_encode_addrheader(value, 0, 0);
        spool_replace_header(xstrdup("X-Schedule-User-Address"),
                             mimehdr, txn->req_hdrs);
        free(value);
    }
}

static int store_resource(struct mailbox *mailbox, const char *userid,
                          const struct auth_state *authstate,
                          icalcomponent *ical, const char *resource,
                          struct index_record *oldrecord,
                          modseq_t createdmodseq, const char *sched_tag,
                          bool tzbyref, bool shared,
                          const strarray_t *schedule_addresses,
                          uint32_t *newuid)
{
    struct transaction_t txn;
    int r;

    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_hdrs = spool_new_hdrcache();
    txn.userid = userid;
    txn.authstate = authstate;

    build_headers(&txn, ical, resource, sched_tag, tzbyref, shared,
                  schedule_addresses);

    r = dav_store_resource(&txn, icalcomponent_as_ical_string(ical), 0,
                           mailbox, oldrecord, createdmodseq, NULL, NULL);
    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
        *newuid = mailbox->i.last_uid;
        r = 0;
    }
    else r = IMAP_IOERROR;

    /* A sharee's ETag is the later of their own data's modseq and this */
    if (!r && shared) {
        buf_reset(&txn.buf);
        buf_printf(&txn.buf, MODSEQ_FMT, mailbox->i.highestmodseq);
        r = mailbox_annotation_write(mailbox, *newuid, SHARED_MODSEQ, "",
                                     &txn.buf);
    }

    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);

    return r;
}

static int expunge_resource(struct repair_res *res)
{
    struct mailbox *mailbox = NULL;
    struct index_record record;
    int r;

    r = mailbox_open_iwl(res->mboxname, &mailbox);
    if (r) goto done;

    r = mailbox_find_index_record(mailbox, res->imap_uid, &record);
    if (r) goto done;

    record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
    r = mailbox_rewrite_index_record(mailbox, &record);

done:
    mailbox_close(&mailbox);
    return r;
}

static int rewrite_primary(struct repair_res *primary, const char *userid,
                           const struct auth_state *authstate,
                           icalcomponent *target, ptrarray_t *target_userdata)
{
    struct mailbox *mailbox = NULL;
    struct index_record record;
    uint32_t newuid = 0;
    int r;

    r = mailbox_open_iwl(primary->mboxname, &mailbox);
    if (r) goto done;

    r = mailbox_find_index_record(mailbox, primary->imap_uid, &record);
    if (r) goto done;

    /* Keep the createdmodseq: it is what the JMAP event id encodes.  Per-user
     * data is only read from a resource marked shared, so a merged copy's
     * data needs the mark even if the primary had none. */
    r = store_resource(mailbox, userid, authstate, target, primary->resource,
                       &record, record.createdmodseq, primary->sched_tag,
                       primary->tzbyref,
                       primary->shared || ptrarray_size(target_userdata),
                       &primary->schedule_addresses, &newuid);
    if (r) goto done;

    /* dav_store_resource() carried the primary's own annotations over.  The
     * per-user data taken from the merged duplicates has to be written out. */
    for (int i = 0; i < ptrarray_size(target_userdata) && !r; i++) {
        struct repair_userdata *pud = ptrarray_nth(target_userdata, i);

        if (find_userdata(&primary->userdata, pud->userid)) continue;

        /* plan_group() split off any copy whose data does not decode */
        struct icalsupport_personal_data pdata = { 0 };
        r = icalsupport_decode_personal_data(&pud->value, &pdata);
        if (r) r = IMAP_MAILBOX_BADFORMAT;

        struct index_record newrecord;
        if (!r) r = mailbox_find_index_record(mailbox, newuid, &newrecord);
        if (!r) {
            struct buf value = BUF_INITIALIZER;

            pdata.lastmod = time(NULL);
            pdata.modseq = newrecord.modseq;
            icalsupport_encode_personal_data(&value, &pdata);
            r = mailbox_annotation_write(mailbox, newuid, PER_USER_CAL_DATA,
                                         pud->userid, &value);
            buf_free(&value);
        }

        icalsupport_personal_data_fini(&pdata);
    }

done:
    mailbox_close(&mailbox);
    return r;
}

/* Per-user data addresses components by UID, in its VPATCH paths. */
static void reuid_vpatch(icalcomponent *vpatch, const char *ical_uid,
                         const char *newical_uid)
{
    struct buf path = BUF_INITIALIZER;
    char *match = strconcat("[UID=", ical_uid, "]", (char *) NULL);
    char *replace = strconcat("[UID=", newical_uid, "]", (char *) NULL);
    icalcomponent *patch;
    icalproperty *prop;

    for (patch = icalcomponent_get_first_component(vpatch,
                                                   ICAL_XPATCH_COMPONENT);
         patch;
         patch = icalcomponent_get_next_component(vpatch,
                                                  ICAL_XPATCH_COMPONENT)) {

        for (prop = icalcomponent_get_first_property(patch, ICAL_ANY_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(patch, ICAL_ANY_PROPERTY)) {

            switch (icalproperty_isa(prop)) {
            case ICAL_PATCHTARGET_PROPERTY:
                buf_setcstr(&path, icalproperty_get_patchtarget(prop));
                if (buf_replace_all(&path, match, replace))
                    icalproperty_set_patchtarget(prop, buf_cstring(&path));
                break;
            case ICAL_PATCHDELETE_PROPERTY:
                buf_setcstr(&path, icalproperty_get_patchdelete(prop));
                if (buf_replace_all(&path, match, replace))
                    icalproperty_set_patchdelete(prop, buf_cstring(&path));
                break;
            case ICAL_PATCHPARAMETER_PROPERTY:
                buf_setcstr(&path, icalproperty_get_patchparameter(prop));
                if (buf_replace_all(&path, match, replace))
                    icalproperty_set_patchparameter(prop, buf_cstring(&path));
                break;
            default:
                break;
            }
        }
    }

    buf_free(&path);
    free(match);
    free(replace);
}

/* dav_store_resource() carried the split copy's per-user data over as it was,
 * and its VPATCH paths still name the old UID. */
static int reuid_userdata(struct mailbox *mailbox, uint32_t newuid,
                          ptrarray_t *userdata, const char *ical_uid,
                          const char *newical_uid)
{
    struct index_record record;
    int r;

    r = mailbox_find_index_record(mailbox, newuid, &record);
    if (r) return r;

    for (int i = 0; i < ptrarray_size(userdata) && !r; i++) {
        struct repair_userdata *pud = ptrarray_nth(userdata, i);
        struct icalsupport_personal_data pdata = { 0 };

        /* Data that does not decode stays as it was, as nothing reads it */
        if (icalsupport_decode_personal_data(&pud->value, &pdata)) continue;

        struct buf value = BUF_INITIALIZER;

        reuid_vpatch(pdata.vpatch, ical_uid, newical_uid);
        pdata.lastmod = time(NULL);
        pdata.modseq = record.modseq;
        icalsupport_encode_personal_data(&value, &pdata);
        r = mailbox_annotation_write(mailbox, newuid, PER_USER_CAL_DATA,
                                     pud->userid, &value);

        buf_free(&value);
        icalsupport_personal_data_fini(&pdata);
    }

    return r;
}

/* A split copy is moved whole, including the components that would have
 * merged cleanly: folding in part of it would spread one resource's content
 * over two events, and leave the owner a fragment they never created. */
static int split_resource(struct repair_res *dup, const char *ical_uid,
                          const char *userid,
                          const struct auth_state *authstate)
{
    struct mailbox *mailbox = NULL;
    struct index_record record;
    icalcomponent *split = NULL;
    char *resource = NULL;
    uint32_t newuid = 0;
    char *newical_uid = xstrdup(makeuuid());
    int r;

    r = mailbox_open_iwl(dup->mboxname, &mailbox);
    if (r) goto done;

    r = mailbox_find_index_record(mailbox, dup->imap_uid, &record);
    if (r) goto done;

    split = icalcomponent_clone(dup->ical);

    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(split, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(split, ICAL_ANY_COMPONENT)) {

        if (!is_real_component(comp)) continue;

        icalcomponent_set_uid(comp, newical_uid);

        if (!icalcomponent_get_x_property_by_name(comp, XPROP_ORIGINAL_UID)) {
            icalproperty *prop = icalproperty_new_x(ical_uid);
            icalproperty_set_x_name(prop, XPROP_ORIGINAL_UID);
            icalcomponent_add_property(comp, prop);
        }
    }

    /* The resource name usually carries the UID, and then has to follow it */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%s.ics", ical_uid);
    if (!strcmp(dup->resource, buf_cstring(&buf)))
        resource = strconcat(newical_uid, ".ics", (char *) NULL);
    else
        resource = xstrdup(dup->resource);
    buf_free(&buf);

    /* createdmodseq 0 makes mailbox_append_index_record() derive one from the
     * new record's modseq.  The reported symptom is a createdmodseq
     * collision, not a UID collision, so re-UIDing alone would leave it. */
    r = store_resource(mailbox, userid, authstate, split, resource, &record,
                       /*createdmodseq*/ 0, dup->sched_tag, dup->tzbyref,
                       dup->shared, &dup->schedule_addresses, &newuid);
    if (r) goto done;

    r = reuid_userdata(mailbox, newuid, &dup->userdata, ical_uid, newical_uid);

done:
    if (split) icalcomponent_free(split);
    free(newical_uid);
    free(resource);
    mailbox_close(&mailbox);
    return r;
}

/*
 * Reporting
 */

static const char *action_verb(enum repair_action action)
{
    switch (action) {
    case REPAIR_KEEP:  return "keep";
    case REPAIR_MERGE: return "merge";
    default:           return "re-uid";
    }
}

/* Calendars read better by their own name than by their internal mailbox
 * name, and the calendar home prefix is the same for every row here. */
static const char *display_mboxname(const char *mboxname, const char *calhome)
{
    size_t len = strlen(calhome);

    if (!strncmp(mboxname, calhome, len) && mboxname[len] == '.')
        return mboxname + len + 1;

    return mboxname;
}

static void report_group(struct repair_group *group, const char *calhome)
{
    struct repair_res *primary = ptrarray_head(&group->resources);

    printf("UID %s: %d live resources, keep %s/%s\n",
           group->ical_uid, ptrarray_size(&group->resources),
           display_mboxname(primary->mboxname, calhome), primary->resource);

    for (int i = 0; i < ptrarray_size(&group->resources); i++) {
        struct repair_res *res = ptrarray_nth(&group->resources, i);
        struct buf detail = BUF_INITIALIZER;

        if (res->conflict)
            buf_printf(&detail, "  (conflict: %s)", res->conflict);
        else if (res->nfolded)
            buf_printf(&detail, "  (+%u component%s)", res->nfolded,
                       res->nfolded == 1 ? "" : "s");

        printf("  %-8s %s/%s  imap_uid=%u cmodseq=" MODSEQ_FMT " %s%s\n",
               action_verb(res->action),
               display_mboxname(res->mboxname, calhome), res->resource,
               res->imap_uid, res->createdmodseq,
               caldav_comp_type_as_string(res->comp_type),
               buf_cstring_or_empty(&detail));

        buf_free(&detail);
    }
}

static void log_resource(const char *userid, const char *ical_uid,
                         struct repair_res *res, bool dryrun)
{
    xsyslog_ev(LOG_NOTICE, "dav.repair.uid_conflict",
               lf_s("u.username", userid),
               lf_s("cal.uid", ical_uid),
               lf_s("dav.repair.action", action_verb(res->action)),
               lf_b("dav.repair.dryrun", dryrun),
               lf_intname("mbox.name", res->mboxname),
               lf_s("mbox.uniqueid", res->mboxid),
               lf_s("dav.resource", res->resource),
               lf_u("msg.imapuid", res->imap_uid));
}

/*
 * The pass
 */

static int repair_group(struct repair_group *group, const char *userid,
                        const struct auth_state *authstate, int flags,
                        const char *calhome, struct caldav_repair_stats *stats)
{
    struct repair_plan plan = REPAIR_PLAN_INITIALIZER;
    int r = 0;

    for (int i = 0; i < ptrarray_size(&group->resources); i++) {
        r = load_resource(ptrarray_nth(&group->resources, i), userid);
        if (r) goto done;
    }

    plan_group(group, &plan);
    stats->merged += plan.nmerged;
    stats->reuided += plan.nsplit;

    report_group(group, calhome);

    for (int i = 0; i < ptrarray_size(&group->resources); i++) {
        log_resource(userid, group->ical_uid, ptrarray_nth(&group->resources, i),
                     !(flags & DAV_REPAIR_REALLY));
    }

    if (!(flags & DAV_REPAIR_REALLY)) goto done;

    if (plan.nmerged) {
        r = rewrite_primary(ptrarray_head(&group->resources), userid,
                            authstate, plan.ical, &plan.userdata);
        if (r) goto done;
    }

    for (int i = 1; i < ptrarray_size(&group->resources) && !r; i++) {
        struct repair_res *dup = ptrarray_nth(&group->resources, i);

        if (dup->action == REPAIR_MERGE)
            r = expunge_resource(dup);
        else
            r = split_resource(dup, group->ical_uid, userid, authstate);
    }

done:
    repair_plan_fini(&plan);

    return r;
}

EXPORTED int caldav_repair_uid_conflicts(const char *userid, int flags,
                                         struct caldav_repair_stats *stats)
{
    struct caldav_db *caldavdb = NULL;
    struct auth_state *authstate = NULL;
    ptrarray_t groups = PTRARRAY_INITIALIZER;
    char *calhome = NULL;
    struct repair_group *group;
    int r;

    caldavdb = caldav_open_userid(userid);
    if (!caldavdb) return IMAP_IOERROR;

    r = caldav_foreach_uid_conflict(caldavdb, &collect_cb, &groups);
    if (r) goto done;

    if (!ptrarray_size(&groups)) goto done;

    authstate = auth_newstate(userid);
    calhome = caldav_mboxname(userid, NULL);

    for (int i = 0; i < ptrarray_size(&groups); i++) {
        group = ptrarray_nth(&groups, i);

        for (int j = 0; j < ptrarray_size(&group->resources); j++) {
            struct repair_res *res = ptrarray_nth(&group->resources, j);
            mbentry_t *mbentry = NULL;

            if (!mboxlist_lookup_by_uniqueid(res->mboxid, &mbentry, NULL))
                res->mboxname = xstrdup(mbentry->name);
            else
                res->mboxname = xstrdup(res->mboxid);
            mboxlist_entry_free(&mbentry);
        }

        stats->groups++;
    }

    for (int i = 0; i < ptrarray_size(&groups); i++) {
        group = ptrarray_nth(&groups, i);

        int r2 = repair_group(group, userid, authstate, flags, calhome, stats);
        if (r2) {
            xsyslog_ev(LOG_ERR, "dav.repair.uid_conflict.failed",
                       lf_s("u.username", userid),
                       lf_s("cal.uid", group->ical_uid),
                       lf_err("error", r2));
            stats->failed++;
        }
    }

done:
    while ((group = ptrarray_pop(&groups)))
        repair_group_free(&group);
    ptrarray_fini(&groups);

    auth_freestate(authstate);
    free(calhome);
    caldav_close(caldavdb);

    return r;
}
