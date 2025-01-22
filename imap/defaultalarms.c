#include "annotate.h"
#include "bsearch.h"
#include "caldav_util.h"
#include "defaultalarms.h"
#include "jmap_util.h"
#include "syslog.h"

#define CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATETIME \
    DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-datetime"

#define CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATE \
    DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-date"

#define JMAP_ANNOT_DEFAULTALERTS JMAP_ANNOT_NS "defaultalerts"

static void defaultalarms_record_fini(struct defaultalarms_record *rec)
{
    if (rec->ical) {
        icalcomponent_free(rec->ical);
        rec->ical = NULL;
    }

    message_guid_set_null(&rec->guid);
    free(rec->atag);
    rec->atag = NULL;
}

EXPORTED void defaultalarms_fini(struct defaultalarms *defalarms)
{
    if (defalarms) {
        defaultalarms_record_fini(&defalarms->with_time);
        defaultalarms_record_fini(&defalarms->with_date);
    }
}

enum internalize_flags {
    INTERNALIZE_DETERMINISTIC_UID = (1 << 0),
    INTERNALIZE_KEEP_APPLE        = (1 << 1),
};

static icalcomponent *internalize_alarms(icalcomponent *alarms, enum internalize_flags flags)
{
    icalcomponent *myalarms = icalcomponent_new(ICAL_XROOT_COMPONENT);
    struct buf buf = BUF_INITIALIZER;

    if (icalcomponent_isa(alarms) == ICAL_VALARM_COMPONENT) {
        icalcomponent_add_component(myalarms,
                icalcomponent_clone(alarms));
    }
    else {
        icalcomponent *valarm;
        for (valarm = icalcomponent_get_first_component(alarms,
                    ICAL_VALARM_COMPONENT);
             valarm;
             valarm = icalcomponent_get_next_component(alarms,
                    ICAL_VALARM_COMPONENT)) {
            icalcomponent_add_component(myalarms,
                    icalcomponent_clone(valarm));
        }
    }

    icalcomponent *valarm;
    for (valarm = icalcomponent_get_first_component(myalarms, ICAL_VALARM_COMPONENT);
         valarm;
         valarm = icalcomponent_get_next_component(myalarms, ICAL_VALARM_COMPONENT)) {

        if (!icalcomponent_get_x_property_by_name(valarm, "X-JMAP-DEFAULT-ALARM")) {
            icalproperty *prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, "X-JMAP-DEFAULT-ALARM");
            icalproperty_set_value(prop, icalvalue_new_boolean(1));
            icalcomponent_add_property(valarm, prop);
        }

        if (!(flags & INTERNALIZE_KEEP_APPLE)) {
            icalcomponent_remove_x_property_by_name(valarm, "X-APPLE-DEFAULT-ALARM");
        }

        if (!icalcomponent_get_uid(valarm)) {
            if (flags & INTERNALIZE_DETERMINISTIC_UID) {
                // that's just necessary for not-yet migrated legacy alarms
                icalcomponent *myalarm = icalcomponent_clone(valarm);
                icalcomponent_normalize(myalarm);
                buf_setcstr(&buf, icalcomponent_as_ical_string(myalarm));
                icalcomponent_free(myalarm);

                struct message_guid guid = MESSAGE_GUID_INITIALIZER;
                message_guid_generate(&guid, buf_base(&buf), buf_len(&buf));
                icalcomponent_set_uid(valarm, message_guid_encode(&guid));
            }
            else {
                buf_setcstr(&buf, makeuuid());
                icalcomponent_set_uid(valarm, buf_cstring(&buf));
            }
        }

        const char *jmapid = icalcomponent_get_jmapid(valarm);
        if (!jmapid) {
            jmapid = icalcomponent_get_uid(valarm);
            if (!jmap_is_valid_id(jmapid)) {
                buf_setcstr(&buf, makeuuid());
                jmapid = buf_cstring(&buf);
            }
            icalcomponent_set_jmapid(valarm, jmapid);
        }
    }

    icalcomponent_normalize_x(myalarms);

    if (!icalcomponent_get_first_component(myalarms, ICAL_VALARM_COMPONENT)) {
        icalcomponent_free(myalarms);
        myalarms = NULL;
    }

    buf_free(&buf);
    return myalarms;
}

static char *generate_atag(icalcomponent *comp)
{
    // requires comp to be normalized already

    struct buf buf = BUF_INITIALIZER;
    char *atag = NULL;

    icalcomponent *valarm;
    for (valarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         valarm;
         valarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {

        if (!icalcomponent_get_x_property_by_name(valarm, "X-JMAP-DEFAULT-ALARM"))
            continue;

        // UID contributes to the atag
        const char *uid = icalcomponent_get_uid(valarm);
        if (uid)
            buf_appendcstr(&buf, uid);

        // TRIGGER contributes to the atag
        icalproperty *prop =
            icalcomponent_get_first_property(valarm, ICAL_TRIGGER_PROPERTY);
        if (prop)
            buf_appendcstr(&buf, icalproperty_as_ical_string(prop));
    }

    if (buf_len(&buf)) {
        struct message_guid guid = MESSAGE_GUID_INITIALIZER;
        message_guid_generate(&guid, buf_base(&buf), buf_len(&buf));
        atag = xstrdup(message_guid_encode_short(&guid, 20));
    }

    buf_free(&buf);
    return atag;
}

static int get_alarms_dl(struct dlist *root, const char *name,
                         struct defaultalarms_record *rec)
{
    struct dlist *dl = NULL;
    if (!dlist_getlist(root, name, &dl))
        return 0;

    const char *guidrep = NULL;
    if (!dlist_getatom(dl, "GUID", &guidrep))
        return 0;

    const char *content = NULL;
    if (!dlist_getatom(dl, "CONTENT", &content))
        return 0;

    const char *atag = NULL;
    if (!dlist_getatom(dl, "ATAG", &atag))
        return 0;

    message_guid_decode(&rec->guid, guidrep);
    if (*content) {
        rec->ical = icalparser_parse_string(content);
        if (rec->ical == NULL)
            return 0;
    }
    rec->atag = xstrdupnull(atag);

    return 1;
}

static int load_legacy_alarms(const char *mboxname,
                              const char *userid,
                              const char *annot,
                              enum internalize_flags flags,
                              struct defaultalarms_record *rec,
                              struct buf *buf)
{
    buf_reset(buf);

    int r = annotatemore_lookup(mboxname, annot, userid, buf);
    if (!r && !buf_len(buf)) {
        // We stored CalDAV alarms as a shared annotation.
        char *ownerid = mboxname_to_userid(mboxname);
        if (!strcmpsafe(userid, ownerid)) {
            r = annotatemore_lookupmask(mboxname, annot, userid, buf);
        }
        free(ownerid);
    }
    if (r && r != CYRUSDB_NOTFOUND) return r;

    buf_trim(buf);
    if (!buf_len(buf))
        return 0;

    const char *content = NULL;
    const char *guidrep = NULL;

    struct dlist *dl = NULL;
    if (!dlist_parsemap(&dl, 1, buf_base(buf), buf_len(buf))) {
        if (!dlist_getatom(dl, "CONTENT", &content))
            return CYRUSDB_IOERROR;

        if (!dlist_getatom(dl, "GUID", &guidrep))
            return CYRUSDB_IOERROR;
    }
    else {
        content = buf_cstring(buf);
    }

    if (*content) {
        icalcomponent *alarms = icalparser_parse_string(content);
        if (alarms) {
            rec->ical = internalize_alarms(alarms, flags);
            icalcomponent_free(alarms);
        }

        if (guidrep) {
            message_guid_decode(&rec->guid, guidrep);
        }
        else {
            message_guid_generate(&rec->guid, content, strlen(content));
        }

        if (rec->ical) {
            rec->atag = generate_atag(rec->ical);
        }
    }

    dlist_free(&dl);
    return 0;
}

static int load_alarms(const char *mboxname,
                       const char *userid,
                       enum internalize_flags legacy_flags,
                       struct defaultalarms *defalarms)
{
    struct buf buf = BUF_INITIALIZER;
    defaultalarms_fini(defalarms);
    char *calhomename = caldav_mboxname(userid, NULL);

    const char *annot = JMAP_ANNOT_DEFAULTALERTS;
    int r = annotatemore_lookup(mboxname, annot, userid, &buf);
    if (!r && buf_len(&buf)) {
        struct dlist *root;
        if (!dlist_parsemap(&root, 1, buf_base(&buf), buf_len(&buf))) {
            if (!get_alarms_dl(root, "WITH_TIME", &defalarms->with_time) ||
                !get_alarms_dl(root, "WITH_DATE", &defalarms->with_date)) {

                xsyslog(LOG_ERR, "corrupt default alarm annotation value",
                        "mboxname=<%s> userid=<%s> annot=<%s> value=<%s>",
                        mboxname, userid, annot, buf_cstring(&buf));

                defaultalarms_fini(defalarms);
            }
        }
        dlist_free(&root);
    }
    else {
        // Any new JMAP calendar should at least have the zero
        // value set in their default alarm annotation. If there
        // is no annotation set, this indicates that this user's
        // calendars did not get migrated to JMAP calendar default
        // alerts. Fall back reading their CalDAV alarms.
        r = load_legacy_alarms(mboxname, userid,
                CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATETIME,
                legacy_flags, &defalarms->with_time, &buf);

        if (!r)
            r = load_legacy_alarms(mboxname, userid,
                    CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATE,
                    legacy_flags, &defalarms->with_date, &buf);

        if (r)
            defaultalarms_fini(defalarms);
    }

    free(calhomename);
    buf_free(&buf);
    return r;
}

EXPORTED int defaultalarms_load(const char *mboxname,
                                const char *userid,
                                struct defaultalarms *defalarms)
{
    return load_alarms(mboxname, userid,
            INTERNALIZE_DETERMINISTIC_UID|INTERNALIZE_KEEP_APPLE, defalarms);
}

static void set_alarms_dl(struct dlist *root, const char *name, icalcomponent *alarms)
{
    struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    struct buf content = BUF_INITIALIZER;
    char *atag = NULL;

    struct dlist *dl = dlist_newkvlist(root, name);

    if (alarms) {
        icalcomponent *myalarms = internalize_alarms(alarms, 0);
        if (myalarms) {
            buf_setcstr(&content, icalcomponent_as_ical_string(myalarms));
            message_guid_generate(&guid, buf_base(&content), buf_len(&content));
            atag = generate_atag(myalarms);
            icalcomponent_free(myalarms);
        }
    }

    dlist_setatom(dl, "CONTENT", buf_cstring(&content));
    dlist_setatom(dl, "GUID", message_guid_encode(&guid));
    dlist_setatom(dl, "ATAG", atag);

    buf_free(&content);
    free(atag);
}

static int defaultalarms_save_astate(annotate_state_t *astate,
                                     const char *userid,
                                     icalcomponent *with_time,
                                     icalcomponent *with_date)
{
    struct dlist *root = dlist_newkvlist(NULL, "DEFAULTALARMS");
    set_alarms_dl(root, "WITH_TIME", with_time);
    set_alarms_dl(root, "WITH_DATE", with_date);

    struct buf buf = BUF_INITIALIZER;
    dlist_printbuf(root, 1, &buf);

    int r = annotate_state_write(astate,
            JMAP_ANNOT_DEFAULTALERTS, userid, &buf);

    dlist_free(&root);
    buf_free(&buf);
    return r;
}

EXPORTED int defaultalarms_save(struct mailbox *mbox,
                                const char *userid,
                                icalcomponent *with_time,
                                icalcomponent *with_date)
{
    annotate_state_t *astate;

    int r = mailbox_get_annotate_state(mbox, 0, &astate);
    if (r) {
        xsyslog(LOG_ERR, "failed to get annotation state",
                "mboxname=<%s> err=<%s>",
                mailbox_name(mbox), error_message(r));
        return CYRUSDB_INTERNAL;
    }

    return defaultalarms_save_astate(astate, userid, with_time, with_date);
}

static int compare_valarm(const void **va, const void **vb)
{
    icalcomponent *a = (icalcomponent*)(*va);
    icalcomponent *b = (icalcomponent*)(*vb);

    // Regular alarms sort after snooze alarms
    int is_snooze_a =
        !!icalcomponent_get_first_property(a, ICAL_RELATEDTO_PROPERTY);
    int is_snooze_b =
        !!icalcomponent_get_first_property(b, ICAL_RELATEDTO_PROPERTY);
    if (is_snooze_a != is_snooze_b)
        return -(is_snooze_a - is_snooze_b);

    // Alarms with UID sort after alarms without UID
    int has_uid_a = !!icalcomponent_get_uid(a);
    int has_uid_b = !!icalcomponent_get_uid(b);
    if (has_uid_a != has_uid_b)
        return has_uid_a - has_uid_b;

    // Default alarms sort after non-default alarms
    int is_default_a =
        !!icalcomponent_get_x_property_by_name(a, "X-JMAP-DEFAULT-ALARM");
    int is_default_b =
        !!icalcomponent_get_x_property_by_name(b, "X-JMAP-DEFAULT-ALARM");
    if (is_default_a != is_default_b)
        return is_default_a - is_default_b;

    // Break ties by UID
    return strcmpsafe(icalcomponent_get_uid(a), icalcomponent_get_uid(b));
}

static void merge_alarms(icalcomponent *comp, icalcomponent *alarms)
{
    // Remove existing alarms
    ptrarray_t old_alarms = PTRARRAY_INITIALIZER;
    strarray_t related_uids = STRARRAY_INITIALIZER;

    icalcomponent *valarm, *nextalarm;
    for (valarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         valarm; valarm = nextalarm) {

        nextalarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);

        icalcomponent_remove_component(comp, valarm);
        ptrarray_append(&old_alarms, valarm);

        icalproperty *prop = icalcomponent_get_first_property(valarm, ICAL_RELATEDTO_PROPERTY);
        if (prop) {
            const char *related_uid = icalproperty_get_relatedto(prop);
            if (related_uid)
                strarray_append(&related_uids, related_uid);
        }
    }

    // Create copy of new default alarms, if any
    ptrarray_t new_alarms = PTRARRAY_INITIALIZER;
    if (alarms) {
        icalcomponent *valarm;
        for (valarm = icalcomponent_get_first_component(alarms, ICAL_VALARM_COMPONENT);
             valarm;
             valarm = icalcomponent_get_next_component(alarms, ICAL_VALARM_COMPONENT)) {

            icalcomponent *myalarm = icalcomponent_clone(valarm);
            ptrarray_append(&new_alarms, myalarm);

            /* Replace default description with component summary */
            const char *desc = icalcomponent_get_summary(comp);
            if (desc && *desc != '\0') {
                icalproperty *prop =
                    icalcomponent_get_first_property(myalarm, ICAL_DESCRIPTION_PROPERTY);
                if (prop) {
                    icalcomponent_remove_property(myalarm, prop);
                    icalproperty_free(prop);
                }
                prop = icalproperty_new_description(desc);
                icalcomponent_add_property(myalarm, prop);
            }
        }
    }

    strarray_sort(&related_uids, cmpstringp_raw);

    // Sort alarms, we'll pop from the arrays later.
    ptrarray_sort(&old_alarms, compare_valarm);
    ptrarray_sort(&new_alarms, compare_valarm);

    // Combine old and new alarms. All new alarms are default alarms.
    icalcomponent *old, *new;
    do {
        old = ptrarray_pop(&old_alarms);
        new = ptrarray_pop(&new_alarms);

        if (new) {
            // Add JMAP default alarm
            icalcomponent_add_component(comp, new);
            if (old) {
                const char *old_uid = icalcomponent_get_uid(old);
                const char *new_uid = icalcomponent_get_uid(new);
                if (!strcmpsafe(old_uid, new_uid)) {
                    // An alarm with the same UID already
                    // existed in the component. Use its new
                    // definition, but keep it acknowledged.
                    icalproperty *prop, *nextprop;
                    for (prop = icalcomponent_get_first_property(old,
                                ICAL_ACKNOWLEDGED_PROPERTY);
                         prop; prop = nextprop) {

                        nextprop = icalcomponent_get_next_property(old,
                                ICAL_ACKNOWLEDGED_PROPERTY);
                        icalcomponent_remove_property(old, prop);
                        icalcomponent_add_property(new, prop);
                    }

                    // Throw away old alarm
                    icalcomponent_free(old);
                    old = NULL;
                }
            }
        }

        if (old) {
            const char *old_uid = icalcomponent_get_uid(old);

            int is_default =
                !!icalcomponent_get_x_property_by_name(old, "X-JMAP-DEFAULT-ALARM");

            int is_apple = !is_default &&
                !!icalcomponent_get_x_property_by_name(old, "X-APPLE-DEFAULT-ALARM");

            int is_snoozed = old_uid &&
                strarray_contains(&related_uids, old_uid);

            int is_acked = !!icalcomponent_get_first_property(old,
                    ICAL_ACKNOWLEDGED_PROPERTY);

            int is_snooze = !!icalcomponent_get_first_property(old,
                    ICAL_RELATEDTO_PROPERTY);

            if (is_default) {
                // This is a stale default alarm.
                if (is_snoozed) {
                    // Some snooze alarm refers to this alarm. Keep it.
                    icalcomponent_add_component(comp, old);

                    // Make sure it can't trigger anymore.
                    icalproperty *trigger =
                        icalcomponent_get_first_property(old, ICAL_TRIGGER_PROPERTY);
                    if (trigger) {
                        // Use Apple's magic 5545 timestamp
                        struct icaltriggertype expired_trigger = {
                            .time = {
                                .year = 1976,
                                .month = 4,
                                .day = 1,
                                .hour = 0,
                                .minute = 55,
                                .second = 45,
                                .zone = icaltimezone_get_utc_timezone()
                            }
                        };
                        icalproperty_set_trigger(trigger, expired_trigger);
                    }

                    if (!is_acked) {
                        icalcomponent_add_property(old,
                                icalproperty_new_acknowledged(
                                    icaltime_current_time_with_zone(
                                        icaltimezone_get_utc_timezone())));
                    }
                }
                else {
                    // Remove obsolete default alarm
                    icalcomponent_free(old);
                }
            }
            else if (is_snoozed || is_snooze) {
                icalcomponent_add_component(comp, old);
            }
            else if (is_apple) {
                icalcomponent_add_component(comp, old);
            }
            else icalcomponent_free(old);
        }
    } while (old || new);

    ptrarray_fini(&old_alarms);
    ptrarray_fini(&new_alarms);
    strarray_fini(&related_uids);
}

EXPORTED void defaultalarms_insert(struct defaultalarms *defalarms,
                                   icalcomponent *ical,
                                   int set_atag)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    if (kind != ICAL_VEVENT_COMPONENT && kind != ICAL_VTODO_COMPONENT)
        return;

    for ( ; comp; comp = icalcomponent_get_next_component(ical, kind)) {

        if (!icalcomponent_get_usedefaultalerts(comp))
            continue;

        // Remove any atag that was set before
        icalcomponent_set_usedefaultalerts(comp, 1, NULL);

        struct defaultalarms_record *rec = icalcomponent_temporal_is_date(comp) ?
            &defalarms->with_date : &defalarms->with_time;

        if (set_atag)
            icalcomponent_set_usedefaultalerts(comp, 1, rec->atag);

        merge_alarms(comp, rec->ical);
    }
}

EXPORTED int defaultalarms_matches_atag(icalcomponent *comp, const char *atag)
{
    int matches_atag = 0;

    icalcomponent *mycomp = icalcomponent_clone(comp);
    icalcomponent_normalize_x(mycomp);
    char *myatag = generate_atag(mycomp);
    matches_atag = !strcmpsafe(myatag, atag);
    icalcomponent_free(mycomp);
    free(myatag);

    return matches_atag;
}

// Migration code starts - this should be required after version 3.9

static int migrate39_rewrite_peruser_data(struct mailbox *mbox,
                                          const char *userid,
                                          struct caldav_data *cdata,
                                          const char *annotval,
                                          struct defaultalarms *defalarms,
                                          int *rewrite,
                                          struct buf *buf)
{
    struct icalsupport_personal_data data = { 0 };
    struct buf value = BUF_INITIALIZER;
    buf_init_ro_cstr(&value, annotval);
    int r = 0;

    if (icalsupport_decode_personal_data(&value, &data)) {
        xsyslog(LOG_ERR, "invalid per-user data",
                "mboxname=<%s> imap_uid=<%d> userid=<%s>",
                mailbox_name(mbox), cdata->dav.imap_uid, userid);
        r = CYRUSDB_INTERNAL;
        goto done;
    }

    if (!data.usedefaultalerts)
        goto done;

    int is_date = strlen(cdata->dtstart) == 6;
    icalcomponent *alarms = is_date ?
        defalarms->with_date.ical : defalarms->with_time.ical;

    if (data.vpatch) {
        icalcomponent *patch, *nextpatch;
        for (patch = icalcomponent_get_first_component(data.vpatch,
                    ICAL_ANY_COMPONENT); patch; patch = nextpatch) {

            nextpatch = icalcomponent_get_next_component(data.vpatch,
                    ICAL_ANY_COMPONENT);

            icalproperty *prop = icalcomponent_get_first_property(patch,
                    ICAL_PATCHTARGET_PROPERTY);
            if (prop) {
                const char *tgt = icalproperty_get_patchtarget(prop);

                if (!strncasecmpsafe(tgt, "/VCALENDAR/VEVENT", 17) &&
                        !strchr(&tgt[17], '/') && !strchr(&tgt[17], '#')) {

                    icalcomponent_remove_x_property_by_name(patch,
                            "X-APPLE-DEFAULT-ALARM");
                    icalcomponent_remove_x_property_by_name(patch,
                            "X-JMAP-USEDEFAULTALERTS");

                    if (alarms) {
                        icalcomponent *valarm;
                        for (valarm = icalcomponent_get_first_component(alarms,
                                    ICAL_VALARM_COMPONENT);
                             valarm;
                             valarm = icalcomponent_get_next_component(alarms,
                                 ICAL_VALARM_COMPONENT)) {

                            icalcomponent_add_component(patch,
                                    icalcomponent_clone(valarm));
                        }
                    }

                    prop = icalcomponent_get_first_property(patch, ICAL_ANY_PROPERTY);
                    if ((icalproperty_isa(prop) == ICAL_PATCHTARGET_PROPERTY) &&
                        !icalcomponent_get_next_property(patch, ICAL_ANY_PROPERTY) &&
                        !icalcomponent_get_first_component(patch, ICAL_ANY_COMPONENT)) {

                        icalcomponent_remove_component(data.vpatch, patch);
                        icalcomponent_free(patch);
                    }
                }
            }
        }

        if (!icalcomponent_get_first_component(data.vpatch, ICAL_ANY_COMPONENT)) {
            icalcomponent_free(data.vpatch);
            data.vpatch = NULL;
        }

    }

    buf_reset(buf);

    if (data.vpatch) {
        data.usedefaultalerts = 0;
        data.modseq = mbox->i.highestmodseq;
        data.lastmod = time(NULL);

        icalcomponent_set_dtstamp(data.vpatch,
            icaltime_from_timet_with_zone(time(NULL), 0,
                icaltimezone_get_utc_timezone()));

        icalsupport_encode_personal_data(buf, &data);
    }

    *rewrite = 1;

done:
    icalsupport_personal_data_fini(&data);
    return r;
}

static int migrate39_find_peruser_cb(const char *mboxname __attribute__((unused)),
                           uint32_t uid __attribute__((unused)),
                           const char *entry __attribute__((unused)),
                           const char *userid,
                           const struct buf *value,
                           const struct annotate_metadata *mdata __attribute__((unused)),
                           void *vrock)
{
    if (buf_len(value))
        hash_insert(userid, xstrdup(buf_cstring(value)), (hash_table*)vrock);

    return 0;
}

HIDDEN void defaultalarms_migrate39(const mbentry_t *mbentry,
                                    enum defaultalarms_migrate39_flags flags,
                                    json_t **errp)
{
    struct defaultalarms defalarms = DEFAULTALARMS_INITIALIZER;
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    struct mailbox *mbox  = NULL;
    const char *ownerid = mbname_userid(mbname);
    struct buf buf = BUF_INITIALIZER;
    annotate_state_t *astate = NULL;
    json_t *err = NULL;
    json_t *caldav_alarm_err = json_object();
    json_t *sharee_err = json_object();

    int r = mailbox_open_iwl(mbentry->name, &mbox);
    if (r) {
        xsyslog(LOG_ERR, "could not open mailbox",
                "mboxname=<%s> err=<%s>",
                mbentry->name, cyrusdb_strerror(r));
        err = jmap_server_error(r);
        goto done;
    }

    // Load default alerts, either from JMAP or CalDAV
    r = load_alarms(mailbox_name(mbox), ownerid, 0, &defalarms);
    if (r) {
        xsyslog(LOG_ERR, "could not load default alarms",
                "mboxname=<%s> userid=<%s> err=<%s>",
                mailbox_name(mbox), ownerid, cyrusdb_strerror(r));
        err = jmap_server_error(r);
        goto done;
    }

    // We manage our own annotation state, because switching
    // the mailbox annotation state to mailbox scope is gnarly
    astate = annotate_state_new();
    if (!astate) {
        xsyslog(LOG_ERR, "could not get annotation state",
                "mboxname=<%s>", mailbox_name(mbox));
        r = CYRUSDB_INTERNAL;
        err = jmap_server_error(r);
        goto done;
    }
    annotate_state_set_mailbox(astate, mbox);

    // Set JMAP default alerts annotation if not already set
    r = annotatemore_lookup(mailbox_name(mbox),
            JMAP_ANNOT_DEFAULTALERTS, ownerid, &buf);
    if (!buf_len(&buf)) {
        r = defaultalarms_save_astate(astate, ownerid,
                defalarms.with_time.ical, defalarms.with_date.ical);
        if (r) {
            xsyslog(LOG_ERR, "could not set JMAP default alerts",
                    "mboxname=<%s> userid=<%s> err=<%s>",
                    mailbox_name(mbox), ownerid, cyrusdb_strerror(r));
            err = jmap_server_error(r);
            goto done;
        }
    }

    if (!(flags & DEFAULTALARMS_MIGRATE_KEEP_CALDAV_ALARMS)) {
        // Remove CalDAV alarms on calendar - they only got set by us
        buf_reset(&buf);

        const char *annot = CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATETIME;
        r = annotate_state_write(astate, annot, "", &buf);
        if (r) {
            xsyslog(LOG_ERR, "failed to remove annotation",
                    "mboxname=<%s> annot=<%s> err=<%s>",
                    mailbox_name(mbox), annot, cyrusdb_strerror(r));
            json_object_set_new(caldav_alarm_err, "withTime",
                    jmap_server_error(r));
        }

        annot = CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATE;
        r = annotate_state_write(astate, annot, "", &buf);
        if (r) {
            xsyslog(LOG_ERR, "failed to remove annotation",
                    "mboxname=<%s> annot=<%s> err=<%s>",
                    mailbox_name(mbox), annot, cyrusdb_strerror(r));

            json_object_set_new(caldav_alarm_err, "withoutTime",
                    jmap_server_error(r));
        }
    }

    r = annotate_state_commit(&astate);
    if (r) {
        xsyslog(LOG_ERR, "could not commit annotation state",
                "mboxname=<%s>", mailbox_name(mbox));
        err = jmap_server_error(r);
        goto done;
    }

    // Migrate sharee alerts

    struct caldav_db *caldav_db = caldav_open_mailbox(mbox);
    if (!caldav_db) {
        xsyslog(LOG_ERR, "could not open caldav.db", "mboxname=<%s>",
                mailbox_name(mbox));
        err = jmap_server_error(CYRUSDB_INTERNAL);
        goto done;
    }

    struct mailbox_iter *mit = mailbox_iter_init(mbox, 0, ITER_SKIP_UNLINKED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(mit))) {
        hash_table peruser = HASH_TABLE_INITIALIZER;
        construct_hash_table(&peruser, 32, 0);
        const struct index_record *record = msg_record(msg);
        annotatemore_findall_mailbox(mbox, record->uid, PER_USER_CAL_DATA,
                0, migrate39_find_peruser_cb, &peruser, ANNOTATE_TOMBSTONES);

        if (!hash_numrecords(&peruser)) {
            free_hash_table(&peruser, free);
            continue;
        }

        struct caldav_data *cdata;
        r = caldav_lookup_imapuid(caldav_db, mbentry, record->uid, &cdata, 1);
        if (r) {
            if (r == CYRUSDB_NOTFOUND) {
                xsyslog(LOG_INFO, "ignoring annotation tombstone in caldav.db",
                        "mboxname=<%s> imap_uid=<%d>",
                        mailbox_name(mbox), record->uid);
            }
            else {
                xsyslog(LOG_ERR, "can not load entry from caldav.db",
                        "mboxname=<%s> imap_uid=<%d> err=<%s>",
                        mailbox_name(mbox), record->uid, cyrusdb_strerror(r));
                free_hash_table(&peruser, free);

                buf_reset(&buf);
                buf_printf(&buf, "%d", record->uid);
                json_object_set_new(sharee_err, buf_cstring(&buf),
                        jmap_server_error(r));
            }
            continue;
        }

        hash_iter *hit = hash_table_iter(&peruser);
        while (hash_iter_next(hit)) {
            const char *userid = hash_iter_key(hit);
            char *annotval = hash_iter_val(hit);

            if (strcmp(userid, ownerid)) {
                int rewrite = 0;
                migrate39_rewrite_peruser_data(mbox, userid, cdata, annotval,
                        &defalarms, &rewrite, &buf);
                if (rewrite) {
                    r = mailbox_annotation_write(mbox, record->uid,
                            PER_USER_CAL_DATA, userid, &buf);
                    if (r) {
                        xsyslog(LOG_ERR, "could not rewrite per-user data",
                                "mboxname=<%s> imap_uid=<%d> userid=<%s> err=<%s>",
                                mailbox_name(mbox), record->uid,
                                userid, error_message(r));

                        buf_reset(&buf);
                        buf_printf(&buf, "%d/%s", record->uid, userid);
                        json_object_set_new(sharee_err, buf_cstring(&buf),
                                jmap_server_error(r));
                    }
                }
            }
        }
        hash_iter_free(&hit);

        free_hash_table(&peruser, free);
    }

    mailbox_iter_done(&mit);
    caldav_close(caldav_db);

done:
    if (json_object_size(caldav_alarm_err)) {
        if (!err) err = json_object();
        json_object_set_new(err, "caldavAlarmErrors", caldav_alarm_err);
    }
    else json_decref(caldav_alarm_err);

    if (json_object_size(sharee_err)) {
        if (!err) err = json_object();
        json_object_set_new(err, "shareeAlarmErrors", sharee_err);
    }
    else json_decref(sharee_err);

    *errp = err;

    if (astate) annotate_state_abort(&astate);
    defaultalarms_fini(&defalarms);
    mailbox_close(&mbox);
    mbname_free(&mbname);
    buf_free(&buf);
}
