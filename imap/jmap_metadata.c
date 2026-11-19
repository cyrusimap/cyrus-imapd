/* jmap_metadata.c -- JMAP Object Metadata (draft-ietf-jmap-metadata) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <string.h>

#include "annotate.h"
#include "caldav_db.h"
#include "charset.h"
#include "jmap_metadata.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/quota.h"

// clang-format off
static const struct {
    const char *name;
    const char *capability;
} metadata_types[] = {
    { "Mailbox",       JMAP_URN_MAIL      },
    { "Email",         JMAP_URN_MAIL      },
    { "Calendar",      JMAP_URN_CALENDARS },
    { "CalendarEvent", JMAP_URN_CALENDARS },
    { "AddressBook",   JMAP_URN_CONTACTS  },
    { "ContactCard",   JMAP_URN_CONTACTS  },
    { "SieveScript",   JMAP_URN_SIEVE     },
    { NULL,            NULL               }
};
// clang-format on

HIDDEN void jmap_metadata_init(jmap_settings_t *settings)
{
    json_object_set_new(settings->server_capabilities,
                        JMAP_URN_METADATA,
                        json_object());
}

HIDDEN void jmap_metadata_capabilities(json_t *account_capabilities)
{
    json_t *datatypes = json_object();

    for (size_t i = 0; metadata_types[i].name; i++) {
        if (!json_object_get(account_capabilities,
                             metadata_types[i].capability))
        {
            continue;
        }

        json_object_set_new(datatypes,
                            metadata_types[i].name,
                            json_pack("{s:[] s:b s:b s:i}",
                                      "namespaces",
                                      "supportsVendorNamespaces",
                                      1,
                                      "supportsPrivate",
                                      1,
                                      "maxDepth",
                                      JMAP_METADATA_MAXDEPTH));
    }

    if (json_object_size(datatypes)) {
        json_object_set_new(account_capabilities,
                            JMAP_URN_METADATA,
                            json_pack("{s:o}", "dataTypes", datatypes));
    }
    else {
        json_decref(datatypes);
    }
}

HIDDEN const char *jmap_metadata_datatype(jmap_req_t *req)
{
    const char *slash = req->method ? strchr(req->method, '/') : NULL;
    if (!slash) {
        return NULL;
    }

    size_t len = slash - req->method;
    for (size_t i = 0; metadata_types[i].name; i++) {
        if (strlen(metadata_types[i].name) == len
            && !strncmp(metadata_types[i].name, req->method, len))
        {
            return metadata_types[i].name;
        }
    }

    return NULL;
}

/* Namespaces */

static bool valid_label(const char *s, size_t len)
{
    if (!len || len > 63 || s[0] == '-' || s[len - 1] == '-') {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9')
              || s[i] == '-'))
        {
            return false;
        }
    }

    return true;
}

HIDDEN bool jmap_metadata_valid_namespace(const char *ns)
{
    size_t len = ns ? strlen(ns) : 0;
    if (!len) {
        return false;
    }

    if (!strchr(ns, '.')) {
        /* registered name */
        for (const char *p = ns; *p; p++) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')
                  || *p == '-' || *p == '_'))
            {
                return false;
            }
        }
        return true;
    }

    /* domain name, all labels in lowercase LDH form */
    if (len > 253) {
        return false;
    }
    const char *label = ns;
    for (const char *dot; (dot = strchr(label, '.')); label = dot + 1) {
        if (!valid_label(label, dot - label)) {
            return false;
        }
    }
    return valid_label(label, strlen(label));
}

/* No registered namespaces exist yet, so only vendor namespaces are
 * supported, on every listed data type. */
static bool namespace_supported(const char *ns)
{
    return jmap_metadata_valid_namespace(ns) && strchr(ns, '.') != NULL;
}

/* Binary values */

/* Return whether @p val is a Binary value: an object whose "@type" is
 * "Binary".  It may still be malformed. */
static bool is_binary(const json_t *val)
{
    return json_is_object(val)
           && !strcmpsafe(json_string_value(json_object_get(val, "@type")),
                          "Binary");
}

static int b64_index(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

/* Canonical padded base64 (RFC 4648, Sections 3.5 and 4) */
static bool valid_base64(const char *s)
{
    size_t len = strlen(s);
    if (len % 4) {
        return false;
    }

    size_t pad = 0;
    if (len && s[len - 1] == '=') {
        pad++;
    }
    if (len > 1 && s[len - 2] == '=') {
        pad++;
    }

    for (size_t i = 0; i < len - pad; i++) {
        if (b64_index(s[i]) < 0) {
            return false;
        }
    }

    /* the bits of the last character that padding leaves unused are 0 */
    if (pad) {
        int last = b64_index(s[len - pad - 1]);
        if (last & (pad == 1 ? 0x03 : 0x0f)) {
            return false;
        }
    }

    return true;
}

static bool valid_binary(const json_t *val)
{
    const char *b64 = json_string_value(json_object_get(val, "base64"));
    return json_object_size(val) == 2 && b64 && valid_base64(b64);
}

/* Return whether @p val contains a malformed Binary value */
static bool has_bad_binary(const json_t *val)
{
    if (is_binary(val)) {
        return !valid_binary(val);
    }

    if (json_is_object(val)) {
        const char *key;
        json_t *jval;
        json_object_foreach ((json_t *) val, key, jval) {
            if (has_bad_binary(jval)) {
                return true;
            }
        }
    }
    else if (json_is_array(val)) {
        size_t i;
        json_t *jval;
        json_array_foreach (val, i, jval) {
            if (has_bad_binary(jval)) {
                return true;
            }
        }
    }

    return false;
}

/* Depth as defined in draft-ietf-jmap-metadata, Section 2.1 */
static size_t json_depth(const json_t *val)
{
    size_t depth = 0;

    if (is_binary(val)) {
        return 0;
    }
    else if (json_is_object(val)) {
        const char *key;
        json_t *jval;
        json_object_foreach ((json_t *) val, key, jval) {
            size_t d = json_depth(jval);
            if (d > depth) {
                depth = d;
            }
        }
        depth++;
    }
    else if (json_is_array(val)) {
        size_t i;
        json_t *jval;
        json_array_foreach (val, i, jval) {
            size_t d = json_depth(jval);
            if (d > depth) {
                depth = d;
            }
        }
    }

    return depth;
}

/* Storage */

HIDDEN void jmap_metadata_fini(struct jmap_metadata *md)
{
    json_decref(md->shared);
    json_decref(md->private);
    memset(md, 0, sizeof(struct jmap_metadata));
}

HIDDEN void jmap_metadata_load(struct jmap_metadata *md,
                               const char *viewer,
                               const char *entry,
                               const char *userid,
                               const struct buf *value)
{
    size_t prefixlen = strlen(JMAP_METADATA_ANNOT);
    bool is_shared = !*userid;

    if (!is_shared && strcmpsafe(userid, viewer)) {
        return;
    }
    if (strncmp(entry, JMAP_METADATA_ANNOT, prefixlen)) {
        return;
    }

    const char *ns = entry + prefixlen;
    json_t *val = json_loadb(buf_base(value), buf_len(value), 0, NULL);
    if (!*ns || !json_is_object(val)) {
        xsyslog_ev(LOG_WARNING, "jmap.metadata.invalid",
                   lf_s("annot.entry", entry),
                   lf_s("u.username", userid));
        json_decref(val);
        return;
    }

    json_t **md_val = is_shared ? &md->shared : &md->private;
    if (!*md_val) {
        *md_val = json_object();
    }
    json_object_set_new(*md_val, ns, val);
}

struct lookup_rock
{
    const char *userid;
    struct jmap_metadata *md;
};

static int lookup_cb(const char *mboxname __attribute__((unused)),
                     uint32_t uid __attribute__((unused)),
                     const char *entry,
                     const char *userid,
                     const struct buf *value,
                     const struct annotate_metadata *mdata
                     __attribute__((unused)),
                     void *vrock)
{
    struct lookup_rock *rock = vrock;
    jmap_metadata_load(rock->md, rock->userid, entry, userid, value);
    return 0;
}

HIDDEN int jmap_metadata_lookup(jmap_req_t *req,
                                const struct mailbox *mailbox,
                                const mbentry_t *mbentry,
                                uint32_t uid,
                                struct jmap_metadata *md)
{
    return jmap_metadata_lookup_userid(req->userid, mailbox, mbentry, uid, md);
}

HIDDEN int jmap_metadata_lookup_userid(const char *userid,
                                       const struct mailbox *mailbox,
                                       const mbentry_t *mbentry,
                                       uint32_t uid,
                                       struct jmap_metadata *md)
{
    struct lookup_rock rock = { userid, md };
    int r;

    jmap_metadata_fini(md);

    if (mailbox) {
        r = annotatemore_findall_mailbox(mailbox,
                                         uid,
                                         JMAP_METADATA_PATTERN,
                                         0,
                                         lookup_cb,
                                         &rock,
                                         0);
    }
    else {
        r = annotatemore_findall_mbentry(mbentry,
                                         uid,
                                         JMAP_METADATA_PATTERN,
                                         0,
                                         lookup_cb,
                                         &rock,
                                         0);
    }

    if (!md->shared) {
        md->shared = json_object();
    }
    if (!md->private) {
        md->private = json_object();
    }

    return r;
}

/* The annotation storage that the namespaces of @p val take */
static quota_t value_size(const json_t *val)
{
    quota_t size = 0;
    const char *ns;
    json_t *nsval;

    json_object_foreach ((json_t *) val, ns, nsval) {
        char *s = json_dumps(nsval, JSON_COMPACT | JSON_SORT_KEYS);
        size += s ? strlen(s) : 0;
        free(s);
    }

    return size;
}

/* Write the namespaces of @p newval that differ from @p cur, and remove
 * those it lacks. */
static int write_namespaces(annotate_state_t *astate,
                            const char *userid,
                            const json_t *cur,
                            const json_t *newval,
                            modseq_t modseq)
{
    struct annotate_metadata mdata = { modseq, 0 };
    struct buf entry = BUF_INITIALIZER;
    struct buf value = BUF_INITIALIZER;
    const char *ns;
    json_t *nsval;
    int r = 0;

    json_object_foreach ((json_t *) cur, ns, nsval) {
        if (json_object_get(newval, ns)) {
            continue;
        }

        buf_setcstr(&entry, JMAP_METADATA_ANNOT);
        buf_appendcstr(&entry, ns);
        buf_reset(&value);
        r = annotate_state_writemdata(astate,
                                      buf_cstring(&entry),
                                      userid,
                                      &value,
                                      &mdata);
        if (r) {
            goto done;
        }
    }

    json_object_foreach ((json_t *) newval, ns, nsval) {
        if (json_equal(nsval, json_object_get(cur, ns))) {
            continue;
        }

        buf_setcstr(&entry, JMAP_METADATA_ANNOT);
        buf_appendcstr(&entry, ns);
        char *s = json_dumps(nsval, JSON_COMPACT | JSON_SORT_KEYS);
        buf_initm(&value, s, strlen(s));
        r = annotate_state_writemdata(astate,
                                      buf_cstring(&entry),
                                      userid,
                                      &value,
                                      &mdata);
        buf_free(&value);
        if (r) {
            goto done;
        }
    }

done:
    buf_free(&entry);
    buf_free(&value);
    return r;
}

HIDDEN int jmap_metadata_write(jmap_req_t *req,
                               struct mailbox *mailbox,
                               uint32_t uid,
                               const json_t *shared,
                               const json_t *private)
{
    struct jmap_metadata cur = JMAP_METADATA_INITIALIZER;
    struct index_record record;
    annotate_state_t *astate = NULL;
    int r;

    if (!shared && !private) {
        return 0;
    }

    if (uid) {
        r = mailbox_find_index_record(mailbox, uid, &record);
        if (r) {
            return r;
        }
    }

    r = jmap_metadata_lookup(req, mailbox, NULL, uid, &cur);
    if (r) {
        goto done;
    }

    /* Check the quota before changing anything */
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    qdiffs[QUOTA_ANNOTSTORAGE] = 0;
    if (shared) {
        qdiffs[QUOTA_ANNOTSTORAGE] +=
            value_size(shared) - value_size(cur.shared);
    }
    if (private) {
        qdiffs[QUOTA_ANNOTSTORAGE] +=
            value_size(private) - value_size(cur.private);
    }
    if (qdiffs[QUOTA_ANNOTSTORAGE] > 0) {
        r = mailbox_quota_check(mailbox, qdiffs);
        if (r) {
            goto done;
        }
    }

    r = mailbox_get_annotate_state(mailbox, uid, &astate);
    if (r) {
        goto done;
    }

    /* Advance the object's modseq first, then write the annotations
     * silently with that modseq */
    modseq_t modseq;
    if (uid) {
        r = mailbox_rewrite_index_record(mailbox, &record);
        if (r) {
            goto done;
        }
        modseq = record.modseq;
    }
    else {
        modseq = mailbox_modseq_dirty(mailbox);
    }

    if (shared) {
        r = write_namespaces(astate, "", cur.shared, shared, modseq);
        if (r) {
            goto done;
        }
    }
    if (private) {
        r = write_namespaces(astate, req->userid, cur.private, private, modseq);
        if (r) {
            goto done;
        }
    }

    /* The record's events changed too, though their iCalendar didn't */
    if (uid && mbtype_isa(mailbox_mbtype(mailbox)) == MBTYPE_CALENDAR) {
        struct caldav_db *db = caldav_open_mailbox(mailbox);
        struct caldav_data *cdata = NULL;
        if (!db) {
            r = IMAP_IOERROR;
            goto done;
        }
        r = caldav_lookup_imapuid(db, mailbox->mbentry, uid, &cdata, 0);
        if (!r) {
            r = caldav_touch_jscal(db, cdata);
        }
        else if (r == CYRUSDB_NOTFOUND) {
            r = 0;
        }
        caldav_close(db);
        if (r) {
            goto done;
        }
    }

    if (!uid) {
        r = mboxlist_update_foldermodseq(mailbox_name(mailbox), modseq);
        if (r) {
            goto done;
        }
        mailbox->mbentry->foldermodseq = modseq;
    }

done:
    if (r) {
        xsyslog_ev(r == IMAP_QUOTA_EXCEEDED ? LOG_INFO : LOG_ERR,
                   "jmap.metadata.write.failed",
                   lf_mailbox(mailbox),
                   lf_u("msg.imapuid", uid),
                   lf_s("error", error_message(r)));
    }
    jmap_metadata_fini(&cur);
    return r;
}

HIDDEN int jmap_metadata_check_quota(const char *mboxname,
                                     const json_t *shared,
                                     const json_t *private,
                                     const struct jmap_metadata *cur)
{
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    char root[MAX_MAILBOX_NAME + 1];

    if (!shared && !private) {
        return 0;
    }
    if (!quota_findroot(root, sizeof(root), mboxname)) {
        return 0;
    }

    qdiffs[QUOTA_ANNOTSTORAGE] = value_size(shared) + value_size(private);
    if (cur) {
        if (shared) {
            qdiffs[QUOTA_ANNOTSTORAGE] -= value_size(cur->shared);
        }
        if (private) {
            qdiffs[QUOTA_ANNOTSTORAGE] -= value_size(cur->private);
        }
    }

    return quota_check_useds(root, qdiffs);
}

HIDDEN json_t *jmap_metadata_take_props(json_t *obj)
{
    json_t *props = json_object();
    const char *key;
    json_t *val;
    void *tmp;

    json_object_foreach_safe (obj, tmp, key, val) {
        if (!strcmp(key, "metadata") || !strcmp(key, "privateMetadata")
            || !strncmp(key, "metadata/", 9)
            || !strncmp(key, "privateMetadata/", 16))
        {
            json_object_set(props, key, val);
            json_object_del(obj, key);
        }
    }

    return props;
}

HIDDEN void jmap_metadata_add_copied(jmap_req_t *req,
                                     const struct jmap_metadata *copied,
                                     json_t **shared,
                                     json_t **private)
{
    if (!copied) {
        return;
    }
    if (!*shared && json_object_size(copied->shared)) {
        *shared = json_incref(copied->shared);
    }
    if (!*private && json_object_size(copied->private)
        && jmap_is_using(req, JMAP_URN_METADATA))
    {
        *private = json_incref(copied->private);
    }
}

/* Foo/get */

static bool is_subselector(const char *prop, const char *root)
{
    size_t len = strlen(root);
    return !strncmp(prop, root, len) && prop[len] == '/';
}

HIDDEN bool jmap_metadata_wanted(hash_table *props)
{
    if (!props) {
        return false;
    }
    if (hash_lookup("metadata", props) || hash_lookup("privateMetadata", props))
    {
        return true;
    }

    hash_iter *iter = hash_table_iter(props);
    bool wanted = false;
    while (!wanted && hash_iter_next(iter)) {
        const char *prop = hash_iter_key(iter);
        wanted = is_subselector(prop, "metadata")
                 || is_subselector(prop, "privateMetadata");
    }
    hash_iter_free(&iter);

    return wanted;
}

static void get_one(hash_table *props,
                    json_t *obj,
                    const char *root,
                    const json_t *stored)
{
    if (hash_lookup(root, props)) {
        json_object_set_new(obj, root, json_deep_copy(stored));
        return;
    }

    json_t *val = NULL;
    hash_iter *iter = hash_table_iter(props);
    while (hash_iter_next(iter)) {
        const char *prop = hash_iter_key(iter);
        if (!is_subselector(prop, root)) {
            continue;
        }

        if (!val) {
            val = json_object();
        }

        const char *ns = prop + strlen(root) + 1;
        json_t *nsval = json_object_get(stored, ns);
        if (nsval) {
            json_object_set_new(val, ns, json_deep_copy(nsval));
        }
    }
    hash_iter_free(&iter);

    if (val) {
        json_object_set_new(obj, root, val);
    }
}

HIDDEN void jmap_metadata_get(hash_table *props,
                              json_t *obj,
                              const struct jmap_metadata *md)
{
    get_one(props, obj, "metadata", md->shared);
    get_one(props, obj, "privateMetadata", md->private);
}

/* Foo/set */

HIDDEN void jmap_metadata_set_fini(struct jmap_metadata_set *ms)
{
    json_decref(ms->shared);
    json_decref(ms->shared_patch);
    json_decref(ms->private);
    json_decref(ms->private_patch);
    memset(ms, 0, sizeof(struct jmap_metadata_set));
}

HIDDEN bool jmap_metadata_set_isempty(const struct jmap_metadata_set *ms)
{
    return !ms->shared && !ms->shared_patch && !ms->private
           && !ms->private_patch;
}

HIDDEN bool jmap_metadata_set_isshared(const struct jmap_metadata_set *ms)
{
    return ms->shared || ms->shared_patch;
}

static json_t *path_string(const char *root, const char *path)
{
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%s/%s", root, path);
    json_t *jpath = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return jpath;
}

static json_t *set_error(const char *type, json_t *props)
{
    if (props) {
        return json_pack("{s:s s:o}", "type", type, "properties", props);
    }
    return json_pack("{s:s}", "type", type);
}

/* A path within metadata: every "~" must start "~0" or "~1". */
static bool valid_pointer(const char *path)
{
    for (const char *p = path; (p = strchr(p, '~')); p += 2) {
        if (p[1] != '0' && p[1] != '1') {
            return false;
        }
    }
    return true;
}

/* Return the decoded namespace of a patch path "ns[/...]". */
static char *patch_namespace(const char *path)
{
    const char *slash = strchr(path, '/');
    return jmap_pointer_decode(path,
                               slash ? (size_t) (slash - path) : strlen(path));
}

HIDDEN json_t *jmap_metadata_set_parse(jmap_req_t *req,
                                       json_t *jobj,
                                       bool is_create,
                                       struct jmap_metadata_set *ms)
{
    static const char *roots[] = { "metadata", "privateMetadata", NULL };
    strarray_t keys = STRARRAY_INITIALIZER;
    json_t *err = NULL;
    const char *key;
    json_t *jval;

    json_object_foreach (jobj, key, jval) {
        for (int i = 0; roots[i]; i++) {
            if (!strcmp(key, roots[i]) || is_subselector(key, roots[i])) {
                strarray_append(&keys, key);
                break;
            }
        }
    }
    if (!strarray_size(&keys)) {
        goto done;
    }

    json_t *invalid = json_array();
    json_t *badpatch = json_array();
    bool using = jmap_is_using(req, JMAP_URN_METADATA);

    for (int k = 0; k < strarray_size(&keys); k++) {
        key = strarray_nth(&keys, k);
        jval = json_object_get(jobj, key);
        bool private = key[0] == 'p';
        const char *root = private ? "privateMetadata" : "metadata";
        json_t **full = private ? &ms->private : &ms->shared;
        json_t **patch = private ? &ms->private_patch : &ms->shared_patch;

        if (!using || (is_create && strcmp(key, root))) {
            json_array_append_new(invalid, json_string(key));
            continue;
        }

        if (!strcmp(key, root)) {
            /* In an update, null is equivalent to {} */
            if (json_is_null(jval) && !is_create) {
                *full = json_object();
            }
            else {
                *full = json_incref(jval);
            }
            continue;
        }

        const char *path = key + strlen(root) + 1;
        if (!valid_pointer(path)) {
            json_array_append_new(badpatch, json_string(key));
            continue;
        }
        if (!*patch) {
            *patch = json_object();
        }
        json_object_set(*patch, path, jval);
    }

    /* Patch paths below another patch path */
    struct buf prefix = BUF_INITIALIZER;
    for (int k = 0; k < strarray_size(&keys); k++) {
        const char *b = strarray_nth(&keys, k);
        const char *slash1 = strchr(b, '/');
        if (slash1 && !valid_pointer(slash1 + 1)) {
            continue; /* already reported */
        }
        buf_setcstr(&prefix, b);
        for (char *slash; (slash = strrchr(buf_cstring(&prefix), '/'));) {
            buf_truncate(&prefix, slash - buf_base(&prefix));
            if (json_object_get(jobj, buf_cstring(&prefix))) {
                json_array_append_new(badpatch, json_string(b));
                break;
            }
        }
    }
    buf_free(&prefix);

    for (int k = 0; k < strarray_size(&keys); k++) {
        json_object_del(jobj, strarray_nth(&keys, k));
    }

    if (json_array_size(invalid)) {
        err = set_error("invalidProperties", invalid);
        json_decref(badpatch);
    }
    else if (json_array_size(badpatch)) {
        err = set_error("invalidPatch", badpatch);
        json_decref(invalid);
    }
    else {
        json_decref(invalid);
        json_decref(badpatch);
    }

done:
    strarray_fini(&keys);
    return err;
}

/* Check a complete metadata value against the stored one. */
static void check_full(const char *root,
                       const json_t *val,
                       const json_t *stored,
                       bool is_create,
                       json_t *invalid)
{
    if (!json_is_object(val)) {
        json_array_append_new(invalid, json_string(root));
        return;
    }

    const char *ns;
    json_t *nsval;
    json_object_foreach ((json_t *) val, ns, nsval) {
        bool ok;
        if (namespace_supported(ns)) {
            ok = json_is_object(nsval);
        }
        else {
            ok = !is_create && json_equal(nsval, json_object_get(stored, ns));
        }

        if (!ok) {
            char *enc = jmap_pointer_encode(ns);
            json_array_append_new(invalid, path_string(root, enc));
            free(enc);
        }
    }
}

/* Check the namespace of each patch path. */
static void check_patch(const char *root, const json_t *patch, json_t *invalid)
{
    const char *path;
    json_t *val;

    json_object_foreach ((json_t *) patch, path, val) {
        char *ns = patch_namespace(path);
        bool whole = !strchr(path, '/');
        bool ok;

        if (!namespace_supported(ns)) {
            /* data can always be migrated off an unsupported namespace */
            ok =
                whole && json_is_null(val) && jmap_metadata_valid_namespace(ns);
        }
        else {
            ok = !whole || json_is_null(val) || json_is_object(val);
        }

        if (!ok) {
            json_array_append_new(invalid, path_string(root, path));
        }
        free(ns);
    }
}

/* Check the depth of every namespace the update writes. */
static void check_depth(const char *root,
                        const json_t *newval,
                        const json_t *stored,
                        json_t *invalid)
{
    const char *ns;
    json_t *nsval;

    json_object_foreach ((json_t *) newval, ns, nsval) {
        if (json_equal(nsval, json_object_get(stored, ns))) {
            continue;
        }
        if (json_depth(nsval) > JMAP_METADATA_MAXDEPTH) {
            char *enc = jmap_pointer_encode(ns);
            json_array_append_new(invalid, path_string(root, enc));
            free(enc);
        }
    }
}

/* Check that no patch path goes through a Binary value. */
static void check_patch_binary(const char *root,
                               const json_t *patch,
                               const json_t *stored,
                               json_t *badpatch)
{
    const char *path;
    json_t *val;

    json_object_foreach ((json_t *) patch, path, val) {
        const json_t *it = stored;
        const char *base = path;
        const char *slash;

        while (json_is_object(it) && (slash = strchr(base, '/'))) {
            char *ref = jmap_pointer_decode(base, slash - base);
            it = json_object_get(it, ref);
            free(ref);
            if (is_binary(it)) {
                json_array_append_new(badpatch, path_string(root, path));
                break;
            }
            base = slash + 1;
        }
    }
}

/* Check every namespace the update writes for malformed Binary values.
 * A namespace value is itself never a Binary value. */
static void check_binary(const char *root,
                         const json_t *newval,
                         const json_t *stored,
                         json_t *invalid)
{
    const char *ns;
    json_t *nsval;

    json_object_foreach ((json_t *) newval, ns, nsval) {
        if (json_equal(nsval, json_object_get(stored, ns))) {
            continue;
        }
        if (is_binary(nsval) || has_bad_binary(nsval)) {
            char *enc = jmap_pointer_encode(ns);
            json_array_append_new(invalid, path_string(root, enc));
            free(enc);
        }
    }
}

static json_t *apply_one(const char *root,
                         const json_t *full,
                         const json_t *patch,
                         const json_t *stored,
                         json_t *badpatch)
{
    if (full) {
        return json_deep_copy(full);
    }
    if (!patch) {
        return NULL;
    }

    size_t nbad = json_array_size(badpatch);
    check_patch_binary(root, patch, stored, badpatch);
    if (json_array_size(badpatch) > nbad) {
        return NULL;
    }

    json_t *newval = json_deep_copy(stored);
    json_t *invalid = json_array();
    jmap_patchobject_applym(newval, (json_t *) patch, invalid, 0);

    size_t i;
    json_t *jpath;
    json_array_foreach (invalid, i, jpath) {
        json_array_append_new(badpatch,
                              path_string(root, json_string_value(jpath)));
    }
    json_decref(invalid);

    return newval;
}

HIDDEN json_t *jmap_metadata_set_apply(const struct jmap_metadata_set *ms,
                                       bool may_write,
                                       const struct jmap_metadata *cur,
                                       json_t **new_shared,
                                       json_t **new_private)
{
    json_t *err = NULL;
    json_t *invalid = json_array();
    json_t *badpatch = json_array();
    bool is_create = cur->shared == NULL;
    json_t *empty = json_object();
    const json_t *cur_shared = cur->shared ? cur->shared : empty;
    const json_t *cur_private = cur->private ? cur->private : empty;

    *new_shared = *new_private = NULL;

    /* Rule 1: rights */
    if (jmap_metadata_set_isshared(ms) && !may_write) {
        err = set_error("forbidden", NULL);
        goto done;
    }

    /* Rule 3: namespaces */
    if (ms->shared) {
        check_full("metadata", ms->shared, cur_shared, is_create, invalid);
    }
    if (ms->private) {
        check_full("privateMetadata",
                   ms->private,
                   cur_private,
                   is_create,
                   invalid);
    }
    if (ms->shared_patch) {
        check_patch("metadata", ms->shared_patch, invalid);
    }
    if (ms->private_patch) {
        check_patch("privateMetadata", ms->private_patch, invalid);
    }
    if (json_array_size(invalid)) {
        err = set_error("invalidProperties", json_incref(invalid));
        goto done;
    }

    /* Patch errors that depend on the stored values */
    *new_shared = apply_one("metadata",
                            ms->shared,
                            ms->shared_patch,
                            cur_shared,
                            badpatch);
    *new_private = apply_one("privateMetadata",
                             ms->private,
                             ms->private_patch,
                             cur_private,
                             badpatch);
    if (json_array_size(badpatch)) {
        err = set_error("invalidPatch", json_incref(badpatch));
        goto done;
    }

    /* Rule 4: depth */
    if (*new_shared) {
        check_depth("metadata", *new_shared, cur_shared, invalid);
    }
    if (*new_private) {
        check_depth("privateMetadata", *new_private, cur_private, invalid);
    }
    if (json_array_size(invalid)) {
        err = set_error("invalidProperties", json_incref(invalid));
        goto done;
    }

    /* Rule 5: Binary values */
    if (*new_shared) {
        check_binary("metadata", *new_shared, cur_shared, invalid);
    }
    if (*new_private) {
        check_binary("privateMetadata", *new_private, cur_private, invalid);
    }
    if (json_array_size(invalid)) {
        err = set_error("invalidProperties", json_incref(invalid));
        goto done;
    }

    /* Skip writes that change nothing */
    if (!is_create && *new_shared && json_equal(*new_shared, cur_shared)) {
        json_decref(*new_shared);
        *new_shared = NULL;
    }
    if (!is_create && *new_private && json_equal(*new_private, cur_private)) {
        json_decref(*new_private);
        *new_private = NULL;
    }

done:
    if (err) {
        json_decref(*new_shared);
        json_decref(*new_private);
        *new_shared = *new_private = NULL;
    }
    json_decref(invalid);
    json_decref(badpatch);
    json_decref(empty);
    return err;
}

HIDDEN json_t *jmap_metadata_set_error(int r)
{
    if (r == IMAP_QUOTA_EXCEEDED) {
        return json_pack("{s:s}", "type", "overQuota");
    }
    return jmap_server_error(r);
}

/* Rights */

struct sharee_rock
{
    const char *sharee;
    int rights;
};

static void sharee_cb(const char *sharee, int rights, void *vrock)
{
    struct sharee_rock *rock = vrock;
    if (!strcmp(sharee, rock->sharee)) {
        rock->rights = rights;
    }
}

HIDDEN const char *jmap_metadata_sharewith_conflict(
    const mbentry_t *mbentry,
    json_t *shareWith,
    bool overwrite,
    int (*patchrights)(int, json_t *),
    json_t *(*tojmap)(int) )
{
    const char *sharee;
    json_t *jrights;

    json_object_foreach (shareWith, sharee, jrights) {
        if (!json_object_get(jrights, "maySetMetadata")) {
            continue;
        }

        struct sharee_rock rock = { sharee, 0 };
        if (mbentry && !overwrite) {
            jmap_foreach_sharee(mbentry, sharee_cb, &rock);
        }

        json_t *want = tojmap(rock.rights);
        json_object_update(want, jrights);
        json_t *have = tojmap(patchrights(rock.rights, jrights));

        bool ok = true;
        const char *right;
        json_t *jval;
        json_object_foreach (have, right, jval) {
            if (!json_equal(jval, json_object_get(want, right))) {
                ok = false;
            }
        }
        json_decref(want);
        json_decref(have);

        if (!ok) {
            return sharee;
        }
    }

    return NULL;
}

HIDDEN void jmap_metadata_sharewith_validate(struct jmap_parser *parser,
                                             const mbentry_t *mbentry,
                                             json_t *shareWith,
                                             bool overwrite,
                                             int (*patchrights)(int, json_t *),
                                             json_t *(*tojmap)(int) )
{
    const char *sharee = jmap_metadata_sharewith_conflict(mbentry,
                                                          shareWith,
                                                          overwrite,
                                                          patchrights,
                                                          tojmap);
    if (sharee) {
        jmap_parser_push(parser, "shareWith");
        jmap_parser_push(parser, sharee);
        jmap_parser_invalid(parser, "maySetMetadata");
        jmap_parser_pop(parser);
        jmap_parser_pop(parser);
    }
}

/* Foo/query */

// clang-format off
static const struct {
    const char *name;
    bool private;
    enum { MD_EXISTS, MD_CONTAINS, MD_EQUALS } op;
} metadata_filters[] = {
    { "metadataExists",              false, MD_EXISTS   },
    { "privateMetadataExists",       true,  MD_EXISTS   },
    { "metadataTextContains",        false, MD_CONTAINS },
    { "privateMetadataTextContains", true,  MD_CONTAINS },
    { "metadataTextEquals",          false, MD_EQUALS   },
    { "privateMetadataTextEquals",   true,  MD_EQUALS   },
    { NULL,                          false, MD_EXISTS   }
};
// clang-format on

static int filter_index(const char *field)
{
    for (int i = 0; metadata_filters[i].name; i++) {
        if (!strcmp(field, metadata_filters[i].name)) {
            return i;
        }
    }
    return -1;
}

HIDDEN bool jmap_metadata_is_filter(const char *field)
{
    return filter_index(field) >= 0;
}

HIDDEN void jmap_metadata_filter_validate(jmap_req_t *req,
                                          struct jmap_parser *parser,
                                          json_t *filter)
{
    for (int i = 0; metadata_filters[i].name; i++) {
        const char *field = metadata_filters[i].name;
        json_t *arg = json_object_get(filter, field);
        if (!arg) {
            continue;
        }

        if (!jmap_is_using(req, JMAP_URN_METADATA)) {
            jmap_parser_invalid(parser, field);
            continue;
        }

        const char *path;
        if (metadata_filters[i].op == MD_EXISTS) {
            path = json_string_value(arg);
        }
        else {
            path = json_string_value(json_object_get(arg, "path"));
            if (!json_is_object(arg)
                || !json_is_string(json_object_get(arg, "value"))
                || json_object_size(arg) != 2)
            {
                path = NULL;
            }
        }

        if (!path || !valid_pointer(path)) {
            jmap_parser_invalid(parser, field);
        }
    }
}

HIDDEN bool jmap_metadata_filter_uses(const json_t *filter)
{
    json_t *conditions = json_object_get(filter, "conditions");
    if (json_is_array(conditions)) {
        size_t i;
        json_t *cond;
        json_array_foreach (conditions, i, cond) {
            if (jmap_metadata_filter_uses(cond)) {
                return true;
            }
        }
        return false;
    }

    for (int i = 0; metadata_filters[i].name; i++) {
        if (json_object_get(filter, metadata_filters[i].name)) {
            return true;
        }
    }
    return false;
}

/* Resolve "ns[/json-pointer]" within a metadata object.  Only object
 * members are addressed; an array, scalar or Binary value on the way
 * yields NULL. */
static const json_t *resolve_path(const json_t *md, const char *path)
{
    const json_t *it = md;
    const char *base = path;

    for (;;) {
        const char *slash = strchr(base, '/');
        size_t len = slash ? (size_t) (slash - base) : strlen(base);
        char *ref = jmap_pointer_decode(base, len);

        it = json_is_object(it) && (it == md || !is_binary(it))
                 ? json_object_get(it, ref)
                 : NULL;
        free(ref);

        if (!it || !slash) {
            return it;
        }
        base = slash + 1;
    }
}

static bool match_one(int op, const json_t *md, const json_t *arg)
{
    if (op == MD_EXISTS) {
        const char *path = json_string_value(arg);
        const json_t *val = resolve_path(md, path);

        /* a namespace set to {} does not exist */
        if (!strchr(path, '/') && json_is_object(val) && !json_object_size(val))
        {
            return false;
        }
        return val != NULL;
    }

    const json_t *val =
        resolve_path(md, json_string_value(json_object_get(arg, "path")));
    const char *want = json_string_value(json_object_get(arg, "value"));
    const char *have = json_string_value(val);
    if (!have || !want) {
        return false;
    }

    if (op == MD_EQUALS) {
        return !strcmp(have, want);
    }

    char *h = unicode_casemap(have, -1);
    char *w = unicode_casemap(want, -1);
    bool match = h && w && strstr(h, w);
    free(h);
    free(w);
    return match;
}

HIDDEN int jmap_metadata_lookup_filter(const char *userid,
                                       const struct mailbox *mailbox,
                                       const mbentry_t *mbentry,
                                       uint32_t uid,
                                       const json_t *cond,
                                       struct jmap_metadata *md)
{
    struct lookup_rock rock = { userid, md };
    strarray_t entries = STRARRAY_INITIALIZER;
    int r = 0;

    jmap_metadata_fini(md);

    for (int i = 0; !r && metadata_filters[i].name; i++) {
        json_t *arg = json_object_get(cond, metadata_filters[i].name);
        const char *path =
            metadata_filters[i].op == MD_EXISTS
                ? json_string_value(arg)
                : json_string_value(json_object_get(arg, "path"));
        if (!path) {
            continue;
        }

        char *ns = patch_namespace(path);
        if (jmap_metadata_valid_namespace(ns)) {
            char *entry = strconcat(JMAP_METADATA_ANNOT, ns, (char *) NULL);
            if (strarray_find(&entries, entry, 0) < 0) {
                r = mailbox ? annotatemore_findall_mailbox(mailbox,
                                                           uid,
                                                           entry,
                                                           0,
                                                           lookup_cb,
                                                           &rock,
                                                           0)
                            : annotatemore_findall_mbentry(mbentry,
                                                           uid,
                                                           entry,
                                                           0,
                                                           lookup_cb,
                                                           &rock,
                                                           0);
                strarray_appendm(&entries, entry);
            }
            else {
                free(entry);
            }
        }
        free(ns);
    }
    strarray_fini(&entries);

    if (!md->shared) {
        md->shared = json_object();
    }
    if (!md->private) {
        md->private = json_object();
    }
    return r;
}

HIDDEN bool jmap_metadata_filter_match(const json_t *cond,
                                       const struct jmap_metadata *md)
{
    for (int i = 0; metadata_filters[i].name; i++) {
        json_t *arg = json_object_get(cond, metadata_filters[i].name);
        if (!arg) {
            continue;
        }

        const json_t *val =
            metadata_filters[i].private ? md->private : md->shared;
        if (!match_one(metadata_filters[i].op, val, arg)) {
            return false;
        }
    }
    return true;
}
