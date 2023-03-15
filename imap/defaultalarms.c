#include "config.h"

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

#define JMAP_ANNOT_DEFAULTALERTS \
    DAV_ANNOT_NS "<" XML_NS_JMAPCAL ">defaultalerts"

EXPORTED void defaultalarms_fini(struct defaultalarms *defalarms)
{
    if (defalarms) {
        if (defalarms->with_time.ical) {
            icalcomponent_free(defalarms->with_time.ical);
            defalarms->with_time.ical = NULL;
        }

        if (defalarms->with_date.ical) {
            icalcomponent_free(defalarms->with_date.ical);
            defalarms->with_date.ical = NULL;
        }

        message_guid_set_null(&defalarms->with_time.guid);
        message_guid_set_null(&defalarms->with_date.guid);
    }
}

static int get_alarms_dl(struct dlist *root, const char *name,
                         icalcomponent **icalp,
                         struct message_guid *guid)
{
    struct dlist *dl = NULL;
    if (!dlist_getlist(root, name, &dl))
        return 0;

    const char *content = NULL;
    if (!dlist_getatom(dl, "CONTENT", &content))
        return 0;

    if (*content) {
        *icalp = icalparser_parse_string(content);
        if (*icalp == NULL)
            return 0;
    }

    const char *guidrep = NULL;
    if (!dlist_getatom(dl, "GUID", &guidrep))
        return 0;

    message_guid_decode(guid, guidrep);

    return 1;
}

static int load_legacy_alarms(const char *mboxname,
                              const char *userid,
                              const char *annot,
                              icalcomponent **icalp,
                              struct message_guid *guid,
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
    if (!dlist_parsemap(&dl, 1, 0, buf_base(buf), buf_len(buf))) {
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
            if (icalcomponent_isa(alarms) == ICAL_VALARM_COMPONENT) {
                icalcomponent *myalarms = alarms;
                myalarms = icalcomponent_new(ICAL_XROOT_COMPONENT);
                icalcomponent_add_component(myalarms, alarms);
                alarms = myalarms;
            }
            *icalp = alarms;
        }

        if (guidrep) {
            message_guid_decode(guid, guidrep);
        }
        else {
            message_guid_generate(guid, content, strlen(content));
        }
    }

    dlist_free(&dl);
    return 0;
}

EXPORTED int defaultalarms_load(const char *mboxname,
                                const char *userid,
                                struct defaultalarms *defalarms)
{
    struct buf buf = BUF_INITIALIZER;
    defaultalarms_fini(defalarms);
    char *calhomename = caldav_mboxname(userid, NULL);

    const char *annot = JMAP_ANNOT_DEFAULTALERTS;
    int r = annotatemore_lookup(mboxname, annot, userid, &buf);
    if (!r && buf_len(&buf)) {
        struct dlist *root;
        if (!dlist_parsemap(&root, 1, 0, buf_base(&buf), buf_len(&buf))) {
            if (!get_alarms_dl(root, "WITH_TIME",
                &defalarms->with_time.ical, &defalarms->with_time.guid) ||
                !get_alarms_dl(root, "WITH_DATE",
                &defalarms->with_date.ical, &defalarms->with_date.guid)) {

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
                &defalarms->with_time.ical,
                &defalarms->with_time.guid, &buf);

        if (!r)
            r = load_legacy_alarms(mboxname, userid,
                    CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATE,
                    &defalarms->with_date.ical,
                    &defalarms->with_date.guid, &buf);

        if (r)
            defaultalarms_fini(defalarms);
    }

    free(calhomename);
    buf_free(&buf);
    return r;
}

static void set_alarms_dl(struct dlist *root, const char *name,
                          icalcomponent *alarms, struct buf *buf)
{
    struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    buf_reset(buf);

    struct dlist *dl = dlist_newkvlist(root, name);

    if (alarms) {
        icalcomponent *myalarms = icalcomponent_new(ICAL_XROOT_COMPONENT);
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

        if (icalcomponent_get_first_component(myalarms, ICAL_VALARM_COMPONENT)) {
            buf_setcstr(buf, icalcomponent_as_ical_string(myalarms));
            icalcomponent_normalize_x(myalarms);
            message_guid_generate(&guid, buf_base(buf), buf_len(buf));
        }

        icalcomponent_free(myalarms);
    }

    dlist_setatom(dl, "CONTENT", buf_cstring(buf));
    dlist_setatom(dl, "GUID", message_guid_encode(&guid));
}

EXPORTED int defaultalarms_save(struct mailbox *mailbox,
                                const char *userid,
                                icalcomponent *with_time,
                                icalcomponent *with_date)
{
    struct dlist *root = dlist_newkvlist(NULL, "DEFAULTALARMS");
    struct buf buf = BUF_INITIALIZER;

    set_alarms_dl(root, "WITH_TIME", with_time, &buf);
    set_alarms_dl(root, "WITH_DATE", with_date, &buf);

    buf_reset(&buf);
    dlist_printbuf(root, 1, &buf);

    static const char *annot = JMAP_ANNOT_DEFAULTALERTS;
    annotate_state_t *astate;
    int r = mailbox_get_annotate_state(mailbox, 0, &astate);
    if (r) {
        xsyslog(LOG_ERR, "failed to get annotation state",
                "mboxname=<%s> err=<%s>",
                mailbox_name(mailbox), error_message(r));
        r = CYRUSDB_INTERNAL;
        goto done;
    }

    r = annotate_state_write(astate, annot, userid, &buf);
    if (r) {
        xsyslog(LOG_ERR, "failed to write annotation",
                "annot=<%s> err=<%s>", annot, cyrusdb_strerror(r));
        goto done;
    }

done:
    dlist_free(&root);
    buf_free(&buf);
    return r;
}

static void init_default_alarms(icalcomponent *alarms, int deterministic_uid)
{
    struct buf buf = BUF_INITIALIZER;

    icalcomponent *valarm;
    for (valarm = icalcomponent_get_first_component(alarms, ICAL_VALARM_COMPONENT);
         valarm;
         valarm = icalcomponent_get_next_component(alarms, ICAL_VALARM_COMPONENT)) {

        if (!icalcomponent_get_x_property_by_name(valarm, "X-JMAP-DEFAULT-ALARM")) {
            icalproperty *prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, "X-JMAP-DEFAULT-ALARM");
            icalproperty_set_value(prop, icalvalue_new_boolean(1));
            icalcomponent_add_property(valarm, prop);
        }

        if (!icalcomponent_get_uid(valarm)) {
            if (deterministic_uid) {
                icalcomponent *myalarm = icalcomponent_clone(valarm);
                icalcomponent_normalize(myalarm);
                buf_setcstr(&buf, icalcomponent_as_ical_string(myalarm));
                icalcomponent_free(myalarm);

                uint8_t digest[SHA1_DIGEST_LENGTH+1];
                xsha1(buf_base(&buf), buf_len(&buf), digest);
                digest[SHA1_DIGEST_LENGTH] = '\0';
                icalcomponent_set_uid(valarm, (const char*) digest);
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

    buf_free(&buf);
}

HIDDEN int defaultalarms_migrate(struct mailbox *mbox, const char *userid,
                                 int *did_migratep)
{
    struct defaultalarms defalarms = DEFAULTALARMS_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    *did_migratep = 0;

    static const char *annot = JMAP_ANNOT_DEFAULTALERTS;
    int r = annotatemore_lookup(mailbox_name(mbox), annot, userid, &buf);
    if (r || buf_len(&buf))
        goto done;

    r = load_legacy_alarms(mailbox_name(mbox), userid,
            CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATETIME,
            &defalarms.with_time.ical,
            &defalarms.with_time.guid, &buf);
    if (r) goto done;

    r = load_legacy_alarms(mailbox_name(mbox), userid,
            CALDAV_ANNOT_DEFAULTALARM_VEVENT_DATE,
            &defalarms.with_date.ical,
            &defalarms.with_date.guid, &buf);
    if (r) goto done;

    if (!defalarms.with_time.ical && !defalarms.with_date.ical) {
        // No default alarms defined. Skip writing empty
        // default alarms for calendar sharees.
        mbname_t *mbname = mbname_from_intname(mailbox_name(mbox));
        int is_owner = !strcmpsafe(mbname_userid(mbname), userid);
        mbname_free(&mbname);
        if (!is_owner) goto done;
    }

    // Initialize VALARMs to be proper JMAP default alarms
    init_default_alarms(defalarms.with_time.ical, 0);
    init_default_alarms(defalarms.with_date.ical, 0);

    r = defaultalarms_save(mbox, userid,
            defalarms.with_time.ical, defalarms.with_date.ical);

    *did_migratep = 1;

done:
    defaultalarms_fini(&defalarms);
    buf_free(&buf);
    return r;
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
    return strcmp(icalcomponent_get_uid(a), icalcomponent_get_uid(b));
}

static void merge_alarms(icalcomponent *comp, icalcomponent *alarms, int flags)
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
                strarray_find(&related_uids, old_uid, 0) >= 0;

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
            else if (flags & DEFAULTALARMS_KEEP_USER) {
                icalcomponent_add_component(comp, old);
            }
            else icalcomponent_free(old);
        }
    } while (old || new);

    ptrarray_fini(&old_alarms);
    ptrarray_fini(&new_alarms);
    strarray_fini(&related_uids);
}

EXPORTED void defaultalarms_insert(const struct defaultalarms *defalarms,
                                   icalcomponent *ical, int flags)
{
    if (!defalarms || (!defalarms->with_time.ical && !defalarms->with_date.ical))
        return;

    if (defalarms->with_time.ical)
        init_default_alarms(defalarms->with_time.ical, 1);

    if (defalarms->with_date.ical)
        init_default_alarms(defalarms->with_date.ical, 1);

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    if (kind != ICAL_VEVENT_COMPONENT && kind != ICAL_VTODO_COMPONENT)
        return;

    for ( ; comp; comp = icalcomponent_get_next_component(ical, kind)) {

        if (icalcomponent_get_usedefaultalerts(comp) <= 0 &&
                !(flags & DEFAULTALARMS_FORCE))
            continue;

        // Determine which default alarms to add
        int is_date;
        if (kind == ICAL_VTODO_COMPONENT) {
            if (icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY))
                is_date = icalcomponent_get_dtstart(comp).is_date;
            else if (icalcomponent_get_first_property(comp, ICAL_DUE_PROPERTY))
                is_date = icalcomponent_get_due(comp).is_date;
            else
                is_date = 1;
        }
        else is_date = icalcomponent_get_dtstart(comp).is_date;

        merge_alarms(comp, is_date ?
                defalarms->with_date.ical : defalarms->with_time.ical,
                flags);
    }
}
