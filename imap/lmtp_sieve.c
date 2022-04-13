/* lmtp_sieve.c -- Sieve implementation for lmtpd
 *
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "auth.h"
#include "duplicate.h"
#include "global.h"
#include "imapurl.h"
#include "lmtpd.h"
#include "lmtp_sieve.h"
#include "lmtpengine.h"
#include "map.h"
#include "notify.h"
#include "prometheus.h"
#include "prot.h"
#include "times.h"
#include "sieve_db.h"
#include "sievedir.h"
#include "smtpclient.h"
#include "strhash.h"
#include "tok.h"
#include "user.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/lmtp_err.h"

static int sieve_usehomedir = 0;
static const char *sieve_dir = NULL;

/* data per script */
typedef struct script_data {
    const mbname_t *mbname;
    const struct auth_state *authstate;
    const struct namespace *ns;
} script_data_t;

static int autosieve_createfolder(const char *userid, const struct auth_state *auth_state,
                                  const char *internalname, int createsievefolder);
static deliver_data_t *setup_special_delivery(deliver_data_t *mydata,
                                              struct buf *headers);
static void cleanup_special_delivery(deliver_data_t *mydata);

static char *make_sieve_db(const char *user)
{
    static char buf[MAX_MAILBOX_PATH+1];

    buf[0] = '.';
    buf[1] = '\0';
    strlcat(buf, user, sizeof(buf));
    strlcat(buf, ".sieve.", sizeof(buf));

    return buf;
}

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = ((deliver_data_t *) v)->m;

    if (phead==NULL) return SIEVE_FAIL;
    *body = msg_getheader(m, phead);

    if (*body) {
        return SIEVE_OK;
    } else {
        return SIEVE_FAIL;
    }
}

static void getheaders_cb(const char *name, const char *value,
                          const char *raw, void *rock)
{
    struct buf *contents = (struct buf *) rock;

    if (raw) buf_appendcstr(contents, raw);
    else buf_printf(contents, "%s: %s\r\n", name, value);
}

static int getheadersection(void *mc, struct buf **contents)
{
    message_data_t *m = ((deliver_data_t *) mc)->m;

    *contents = buf_new();

    spool_enum_hdrcache(m->hdrcache, &getheaders_cb, *contents);

    return SIEVE_OK;
}

/* adds the header "head" with body "body" to msg */
static int addheader(void *mc, const char *head, const char *body, int index)
{
    message_data_t *m = ((deliver_data_t *) mc)->m;

    if (head == NULL || body == NULL) return SIEVE_FAIL;

    if (index < 0)
        spool_append_header(xstrdup(head), xstrdup(body), m->hdrcache);
    else
        spool_prepend_header(xstrdup(head), xstrdup(body), m->hdrcache);

    return SIEVE_OK;
}

/* deletes (instance "index" of) the header "head" from msg */
static int deleteheader(void *mc, const char *head, int index)
{
    message_data_t *m = ((deliver_data_t *) mc)->m;

    if (head == NULL) return SIEVE_FAIL;

    if (!index) spool_remove_header(xstrdup(head), m->hdrcache);
    else spool_remove_header_instance(xstrdup(head), index, m->hdrcache);

    return SIEVE_OK;
}

static int getmailboxexists(void *sc, const char *extname)
{
    script_data_t *sd = (script_data_t *)sc;
    char *intname = mboxname_from_externalUTF8(extname, sd->ns,
                                               mbname_userid(sd->mbname));
    int r = mboxlist_lookup(intname, NULL, NULL);
    free(intname);
    return r ? 0 : 1; /* 0 => exists */
}

static int getmailboxidexists(void *sc, const char *extname)
{
    script_data_t *sd = (script_data_t *)sc;
    const char *userid = mbname_userid(sd->mbname);
    char *intname = mboxlist_find_uniqueid(extname, userid, sd->authstate);
    int exists = 0;

    if (intname && !mboxname_isnondeliverymailbox(intname, 0)) {
        exists = 1;
    }

    free(intname);
    return exists;
}

static int getspecialuseexists(void *sc, const char *extname, strarray_t *uses)
{
    script_data_t *sd = (script_data_t *)sc;
    const char *userid = mbname_userid(sd->mbname);
    int i, r = 1;

    if (extname) {
        char *intname = mboxname_from_externalUTF8(extname, sd->ns, userid);
        struct buf attrib = BUF_INITIALIZER;

        annotatemore_lookup(intname, "/specialuse", userid, &attrib);

        /* \\Inbox is magical */
        if (mboxname_isusermailbox(intname, 1) &&
            mboxname_userownsmailbox(userid, intname)) {
            if (buf_len(&attrib)) buf_putc(&attrib, ' ');
            buf_appendcstr(&attrib, "\\Inbox");
        }

        if (buf_len(&attrib)) {
            strarray_t *haystack = strarray_split(buf_cstring(&attrib), " ", 0);

            for (i = 0; i < strarray_size(uses); i++) {
                if (strarray_find_case(haystack, strarray_nth(uses, i), 0) < 0) {
                    r = 0;
                    break;
                }
            }
            strarray_free(haystack);
        }
        else r = 0;

        buf_free(&attrib);
        free(intname);
    }
    else {
        for (i = 0; i < strarray_size(uses); i++) {
            char *intname = mboxlist_find_specialuse(strarray_nth(uses, i), userid);
            if (!intname) r = 0;
            free(intname);
            if (!r) break;
        }
    }

    return r;
}

static int getmetadata(void *sc, const char *extname, const char *keyname, char **res)
{
    script_data_t *sd = (script_data_t *)sc;
    struct buf attrib = BUF_INITIALIZER;
    char *intname = !extname ? xstrdup("") :
        mboxname_from_externalUTF8(extname, sd->ns, mbname_userid(sd->mbname));
    int r;
    if (!strncmp(keyname, "/private/", 9)) {
        r = annotatemore_lookup(intname, keyname+8, mbname_userid(sd->mbname), &attrib);
    }
    else if (!strncmp(keyname, "/shared/", 8)) {
        r = annotatemore_lookup(intname, keyname+7, "", &attrib);
    }
    else {
        r = IMAP_MAILBOX_NONEXISTENT;
    }
    *res = (r || !attrib.len) ? NULL : buf_release(&attrib);
    free(intname);
    buf_free(&attrib);
    return r ? 0 : 1;
}

static int getfname(void *v, const char **fnamep)
{
    deliver_data_t *d = (deliver_data_t *)v;
    *fnamep = NULL;
    if (d->stage)
        *fnamep = append_stagefname(d->stage);
    /* XXX GLOBAL STUFF HERE */
    return 0;
}

static int getsize(void *mc, int *size)
{
    message_data_t *m = ((deliver_data_t *) mc)->m;

    *size = msg_getsize(m);
    return SIEVE_OK;
}

/* we use the temp field in message_data to avoid having to malloc memory
   to return, and we also can't expose our the recipients to the message */
static int getenvelope(void *mc, const char *field, const char ***contents)
{
    deliver_data_t *mydata = (deliver_data_t *) mc;
    message_data_t *m = mydata->m;

    if (!strcasecmp(field, "from")) {
        *contents = mydata->temp;
        mydata->temp[0] = m->return_path;
        mydata->temp[1] = NULL;
        return SIEVE_OK;
    } else if (!strcasecmp(field, "to")) {
        *contents = mydata->temp;
        mydata->temp[0] = msg_getrcptall(m, mydata->cur_rcpt);
        mydata->temp[1] = NULL;
        return SIEVE_OK;
    } else if (!strcasecmp(field, "auth") && mydata->authuser) {
        *contents = mydata->temp;
        mydata->temp[0] = mydata->authuser;
        mydata->temp[1] = NULL;
        return SIEVE_OK;
    } else {
        *contents = NULL;
        return SIEVE_FAIL;
    }
}

static int getenvironment(void *sc __attribute__((unused)),
                          const char *keyname, char **res)
{
    *res = NULL;

    switch (*keyname) {
    case 'd':
        if (!strcmp(keyname, "domain")) {
            const char *domain = strchr(config_servername, '.');

            if (domain) domain++;
            else domain = "";

            *res = xstrdup(domain);
        }
        break;

    case 'h':
        if (!strcmp(keyname, "host")) *res = xstrdup(config_servername);
        break;

    case 'l':
        if (!strcmp(keyname, "location")) *res = xstrdup("MDA");
        break;

    case 'n':
        if (!strcmp(keyname, "name")) *res = xstrdup("Cyrus LMTP");
        break;

    case 'p':
        if (!strcmp(keyname, "phase")) *res = xstrdup("during");
        break;

    case 'r':
        if (!strncmp(keyname, "remote-", 7)) {
            const char *localip, *remoteip,
                *remotehost = get_clienthost(0, &localip, &remoteip);

            if (!strcmp(keyname+7, "host"))
                *res = xstrndup(remotehost, strcspn(remotehost, " ["));
            else if (remoteip && !strcmp(keyname+7, "ip"))
                *res = xstrndup(remoteip, strcspn(remoteip, ";"));
        }
        break;

    case 'v':
        if (!strcmp(keyname, "version")) *res = xstrdup(CYRUS_VERSION);
        break;
    }

    return (*res ? SIEVE_OK : SIEVE_FAIL);
}

static int getbody(void *mc, const char **content_types,
                   sieve_bodypart_t ***parts)
{
    deliver_data_t *mydata = (deliver_data_t *) mc;
    message_data_t *m = mydata->m;
    int r = 0;

    if (!mydata->content->body) {
        /* parse the message body if we haven't already */
        r = message_parse_file_buf(m->f, &mydata->content->map,
                                   &mydata->content->body, NULL);
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    if (!r) message_fetch_part(mydata->content, content_types,
                               (struct bodypart ***) parts);
    return (!r ? SIEVE_OK : SIEVE_FAIL);
}


static int sieve_find_script(const char *user, const char *domain,
                             const char *script, char *fname, size_t size);

static int getinclude(void *sc, const char *script, int isglobal,
                      char *fname, size_t size)
{
    script_data_t *sdata = (script_data_t *) sc;
    struct stat sbuf;
    int r;

    if (strstr(script, "../")) {
        syslog(LOG_NOTICE, "Illegal script name '%s' for user '%s'",
               script, mbname_userid(sdata->mbname));
        return SIEVE_FAIL;
    }

    r = sieve_find_script(isglobal ? NULL : mbname_localpart(sdata->mbname),
                          mbname_domain(sdata->mbname), script, fname, size);

    if (!r && isglobal && mbname_domain(sdata->mbname) && stat(fname, &sbuf) != 0) {
        /* if the domain-specific global script doesn't exist,
           try a server-wide global script */
        r = sieve_find_script(NULL, NULL, script, fname, size);
    }

    return r;
}

static int global_outgoing_count = 0;

static int send_rejection(const char *userid,
                          const char *origid,
                          const char *rejto,
                          const char *origreceip,
                          const char *mailreceip,
                          const char *reason,
                          struct protstream *file)
{
    char buf[8192], *namebuf;
    int i, r = 0;
    time_t t;
    char datestr[RFC5322_DATETIME_MAX+1];
    pid_t p;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    struct buf msgbuf = BUF_INITIALIZER;
    smtp_envelope_t sm_env = SMTP_ENVELOPE_INITIALIZER;
    smtpclient_t *sm = NULL;

    /* Initialize SMTP envelope */
    smtp_envelope_set_from(&sm_env, "");
    smtp_envelope_add_rcpt(&sm_env, rejto);

    /* Build message */
    t = time(NULL);
    p = getpid();
    snprintf(buf, sizeof(buf), "<cmu-sieve-%d-%d-%d@%s>", (int) p, (int) t,
             global_outgoing_count++, config_servername);

    namebuf = make_sieve_db(mailreceip);

    time_to_rfc5322(t, datestr, sizeof(datestr));

    dkey.id = buf;
    dkey.to = namebuf;
    dkey.date = datestr;
    duplicate_mark(&dkey, t, 0);

    buf_printf(&msgbuf, "Message-ID: %s\r\n", buf);
    buf_printf(&msgbuf, "Date: %s\r\n", datestr);

    buf_printf(&msgbuf, "X-Sieve: %s\r\n", SIEVE_VERSION);
    buf_appendcstr(&msgbuf, "X-Sieve-Action: reject\r\n");
    buf_printf(&msgbuf, "From: Mail Sieve Subsystem <%s>\r\n",
            config_getstring(IMAPOPT_POSTMASTER));
    buf_printf(&msgbuf, "To: <%s>\r\n", rejto);
    buf_printf(&msgbuf, "MIME-Version: 1.0\r\n");
    buf_printf(&msgbuf, "Content-Type: "
            "multipart/report; report-type=disposition-notification;"
            "\r\n\tboundary=\"%d/%s\"\r\n", (int) p, config_servername);
    buf_printf(&msgbuf, "Subject: Automatically rejected mail\r\n");
    buf_printf(&msgbuf, "Auto-Submitted: auto-replied (rejected)\r\n");
    buf_printf(&msgbuf, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* this is the human readable status report */
    buf_printf(&msgbuf, "--%d/%s\r\n", (int) p, config_servername);
    buf_printf(&msgbuf, "Content-Type: text/plain; charset=utf-8\r\n");
    buf_printf(&msgbuf, "Content-Disposition: inline\r\n");
    buf_printf(&msgbuf, "Content-Transfer-Encoding: 8bit\r\n\r\n");

    buf_printf(&msgbuf, "Your message was automatically rejected by Sieve, a mail\r\n"
            "filtering language.\r\n\r\n");
    buf_printf(&msgbuf, "The following reason was given:\r\n%s\r\n\r\n", reason);

    /* this is the MDN status report */
    buf_printf(&msgbuf, "--%d/%s\r\n"
            "Content-Type: message/disposition-notification\r\n\r\n",
            (int) p, config_servername);
    buf_printf(&msgbuf, "Reporting-UA: %s; Cyrus %s/%s\r\n",
            config_servername, CYRUS_VERSION, SIEVE_VERSION);
    if (origreceip)
        buf_printf(&msgbuf, "Original-Recipient: rfc822; %s\r\n", origreceip);
    buf_printf(&msgbuf, "Final-Recipient: rfc822; %s\r\n", mailreceip);
    if (origid)
        buf_printf(&msgbuf, "Original-Message-ID: %s\r\n", origid);
    buf_printf(&msgbuf, "Disposition: "
            "automatic-action/MDN-sent-automatically; deleted\r\n");
    buf_printf(&msgbuf, "\r\n");

    /* this is the original message */
    buf_printf(&msgbuf, "--%d/%s\r\nContent-Type: message/rfc822\r\n\r\n",
            (int) p, config_servername);
    prot_rewind(file);
    while ((i = prot_read(file, buf, sizeof(buf))) > 0) {
        buf_appendmap(&msgbuf, buf, i);
    }
    buf_printf(&msgbuf, "\r\n\r\n");
    buf_printf(&msgbuf, "--%d/%s--\r\n", (int) p, config_servername);

    /* Send the mail */
    sm = NULL;
    r = smtpclient_open(&sm);
    if (!r) {
        smtpclient_set_auth(sm, userid);
        r = smtpclient_send(sm, &sm_env, &msgbuf);
    }
    if (r) {
        syslog(LOG_ERR, "sieve: send_rejection: SMTP error: %s",
                error_message(r));
    }
    smtpclient_close(&sm);

    smtp_envelope_fini(&sm_env);
    buf_free(&msgbuf);
    return r;
}

#ifdef USE_SRS
#include <srs2.h>

static srs_t *srs_engine = NULL;

#define SRS_INIT_FAIL_UNLESS(x)                 \
    if ((srs_status = (x)) != SRS_SUCCESS) {    \
        goto END;                               \
    }

void sieve_srs_init(void)
{
    const char *srs_domain = config_getstring(IMAPOPT_SRS_DOMAIN);
    char *saved_secrets = NULL;
    int srs_status = SRS_SUCCESS;

    if (!srs_engine && srs_domain && *srs_domain) {
        /* SRS enabled and not yet initialized */
        int srs_alwaysrewrite = config_getswitch(IMAPOPT_SRS_ALWAYSREWRITE);
        int srs_hashlength = config_getint(IMAPOPT_SRS_HASHLENGTH);
        const char *srs_separator = config_getstring(IMAPOPT_SRS_SEPARATOR);
        const char *srs_secrets = config_getstring(IMAPOPT_SRS_SECRETS);

        SRS_INIT_FAIL_UNLESS(srs_set_malloc((srs_malloc_t)xmalloc,
                                            (srs_realloc_t)xrealloc,
                                            (srs_free_t)free));

        srs_engine = srs_new();
        SRS_INIT_FAIL_UNLESS(srs_set_alwaysrewrite(srs_engine,
                                                   srs_alwaysrewrite));

        if (srs_hashlength > 0) {
            SRS_INIT_FAIL_UNLESS(srs_set_hashlength(srs_engine,
                                                    srs_hashlength));
        }
        if (srs_separator) {
            SRS_INIT_FAIL_UNLESS(srs_set_separator(srs_engine,
                                                   srs_separator[0]));
        }

        if (srs_secrets) {
            char *secret = NULL;

            saved_secrets = xstrdup(srs_secrets);
            secret = strtok(saved_secrets, ", \t\r\n");
            while (secret) {
                SRS_INIT_FAIL_UNLESS(srs_add_secret(srs_engine, secret));
                secret = strtok(NULL, ", \t\r\n");
            }
        }
    }

  END:
    if (saved_secrets) free(saved_secrets);

    if (srs_status != SRS_SUCCESS) {
        sieve_srs_free();

        syslog(LOG_ERR, "sieve SRS configuration error: %s",
               srs_strerror(srs_status));
    }
}

void sieve_srs_free(void)
{
    if (srs_engine) {
        srs_free(srs_engine);
        srs_engine = NULL;
    }
}

/**
 * Performs SRS forward rewriting.
 * If rewriting failed, or SRS is disabled, NULL pointer is returned. Otherwise
 * caller is responsible of freeing the resulting address.
 *
 * @param return_path   address to rewrite
 * @return rewritten address, or NULL
 */
static char *sieve_srs_forward(char *return_path)
{
    const char *srs_domain = config_getstring(IMAPOPT_SRS_DOMAIN);
    char *srs_return_path = NULL;
    int srs_status;

    if (!srs_engine) {
        /* SRS not enabled */
        return NULL;
    }

    srs_status = srs_forward_alloc(srs_engine, &srs_return_path,
                                   return_path, srs_domain);

    if (srs_status != SRS_SUCCESS) {
        syslog(LOG_ERR, "sieve SRS forward failed (%s, %s): %s",
               return_path, srs_domain, srs_strerror(srs_status));
        if (srs_return_path) {
            free(srs_return_path);
            srs_return_path = NULL;
        }
    }

    return srs_return_path;
}

#else /* !USE_SRS */

void sieve_srs_init(void) { return; }
void sieve_srs_free(void) { return; }

static char *sieve_srs_forward(char *return_path __attribute__((unused)))
{
    return NULL;
}

#endif /* USE_SRS */

#ifdef WITH_DAV
#include <libxml/uri.h>

static mbentry_t *get_addrbook_mbentry(const char *list, const char *userid)
{
    const char *addrbook_urn_full = "urn:ietf:params:sieve:addrbook:";
    const char *addrbook_urn_abbrev = ":addrbook:";
    char *abook = NULL, *mboxname = NULL;
    mbentry_t *mbentry = NULL;

    /* percent-decode list URI */
    char *uri = xmlURIUnescapeString(list, strlen(list), NULL);

    if (!strncmp(uri, addrbook_urn_full, strlen(addrbook_urn_full))) {
        abook = xstrdup(uri + strlen(addrbook_urn_full));
    }
    else if (!strncmp(uri, addrbook_urn_abbrev, strlen(addrbook_urn_abbrev))) {
        abook = xstrdup(uri + strlen(addrbook_urn_abbrev));
    }

    free(uri);

    if (!abook) return NULL;

    /* MUST match default addressbook case-insensitively */
    if (!strcasecmp(abook, "Default")) {
        abook[0] = 'D';
        lcase(abook+1);
    }

    /* construct mailbox name of addressbook */
    mboxname = carddav_mboxname(userid, abook);
    free(abook);

    /* see if addressbook mailbox exists */
    mboxlist_lookup(mboxname, &mbentry, NULL);
    free(mboxname);

    return mbentry;
}

static int listvalidator(void *ic, const char *list)
{
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    mbentry_t *mbentry = get_addrbook_mbentry(list, ctx->userid);
    int ret = mbentry ? SIEVE_OK : SIEVE_FAIL;

    mboxlist_entry_free(&mbentry);

    return ret;
}

static int listcompare(const char *text, size_t tlen __attribute__((unused)),
                       const char *list, strarray_t *match_vars, void *rock)
{
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) rock;
    mbentry_t *mbentry = get_addrbook_mbentry(list, ctx->userid);
    int ret = 0;

    if (!mbentry) return 0;

    if (!ctx->carddavdb) {
        /* open user's CardDAV DB */
        ctx->carddavdb = carddav_open_userid(ctx->userid);
    }
    if (ctx->carddavdb) {
        /* search for email address in addressbook */
        strarray_t *uids =
            carddav_getemail2details(ctx->carddavdb, text, mbentry, NULL);
        ret = strarray_size(uids);

        strarray_free(uids);
    }

    if (ret && match_vars) {
        /* found a match - set $0 */
        strarray_add(match_vars, text);
    }

    mboxlist_entry_free(&mbentry);

    return ret;
}

static int list_addresses(void *rock, struct carddav_data *cdata)
{
    smtp_envelope_t *sm_env = rock;
    int i;

    /* XXX  Lookup up emails for vcard */
    if (!cdata->emails) return 0;
    for (i = 0; i < strarray_size(cdata->emails); i++) {
        /* Find preferred address */
        smtp_envelope_add_rcpt(sm_env, strarray_nth(cdata->emails, i));
    }

    return 0;
}
#endif /* WITH_DAV */

static int send_forward(sieve_redirect_context_t *rc,
                        struct sieve_interp_ctx *ctx,
                        char *return_path,
                        struct protstream *file)
{
    int r = 0;
    char buf[1024];
    int body = 0, skip;
    char *srs_return_path = NULL;
    smtp_envelope_t sm_env = SMTP_ENVELOPE_INITIALIZER;
    struct buf msgbuf = BUF_INITIALIZER;
    smtpclient_t *sm = NULL;

    srs_return_path = sieve_srs_forward(return_path);
    if (srs_return_path) {
        smtp_envelope_set_from(&sm_env, srs_return_path);
    }
    else if (return_path && *return_path) {
        smtp_envelope_set_from(&sm_env, return_path);
    }
    else {
        smtp_envelope_set_from(&sm_env, "");
    }

    if (rc->is_ext_list) {
#ifdef WITH_DAV
        mbentry_t *mbentry = get_addrbook_mbentry(rc->addr, ctx->userid);

        if (mbentry && !ctx->carddavdb) {
            /* open user's CardDAV DB */
            ctx->carddavdb = carddav_open_userid(ctx->userid);
        }
        if (!(mbentry && ctx->carddavdb)) {
            r = SIEVE_FAIL;
            mboxlist_entry_free(&mbentry);
            goto done;
        }
        carddav_foreach(ctx->carddavdb, mbentry, &list_addresses, &sm_env);
        mboxlist_entry_free(&mbentry);
#endif
    }
    else {
        smtp_envelope_add_rcpt(&sm_env, rc->addr);
    }

    if (srs_return_path) free(srs_return_path);

    buf_setcstr(&msgbuf, "X-Sieve-Action: redirect\r\n");

    prot_rewind(file);
    while (prot_fgets(buf, sizeof(buf), file)) {
        if (!body && buf[0] == '\r' && buf[1] == '\n') {
            /* blank line between header and body */
            body = 1;
        }

        skip = 0;
        if (!body) {
            if (!strncasecmp(buf, "Return-Path:", 12)) {
                /* strip the Return-Path */
                skip = 1;
            }
        }

        do {
            if (!skip) buf_appendcstr(&msgbuf, buf);
        } while (buf[strlen(buf)-1] != '\n' &&
                 prot_fgets(buf, sizeof(buf), file));
    }

    r = smtpclient_open(&sm);
    if (r) goto done;

    smtpclient_set_auth(sm, ctx->userid);
    smtpclient_set_notify(sm, rc->dsn_notify);
    smtpclient_set_ret(sm, rc->dsn_ret);
    smtpclient_set_by(sm, rc->deliverby);
    r = smtpclient_send(sm, &sm_env, &msgbuf);
    smtpclient_close(&sm);

done:
    smtp_envelope_fini(&sm_env);
    buf_free(&msgbuf);
    return r;
}


static int sieve_redirect(void *ac, void *ic,
                          void *sc, void *mc, const char **errmsg)
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mdata = (deliver_data_t *) mc;
    message_data_t *m = mdata->m;
    char buf[8192], *sievedb = NULL;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    int res;

    /* if we have a msgid, we can track our redirects */
    if (m->id) {
        snprintf(buf, sizeof(buf), "%s-%s", m->id, rc->addr);
        sievedb = make_sieve_db(mbname_recipient(sd->mbname, ((deliver_data_t *) mc)->ns));

        dkey.id = buf;
        dkey.to = sievedb;
        dkey.date = ((deliver_data_t *) mc)->m->date;
        /* ok, let's see if we've redirected this message before */
        if (duplicate_check(&dkey)) {
            duplicate_log(&dkey, "redirect");
            return SIEVE_OK;
        }
    }

    if (rc->headers) {
        mdata = setup_special_delivery(mdata, rc->headers);
        if (!mdata) return SIEVE_FAIL;
        else m = mdata->m;
    }

    res = send_forward(rc, ctx, m->return_path, m->data);

    if (rc->headers) cleanup_special_delivery(mdata);

    if (res == 0) {
        /* mark this message as redirected */
        if (sievedb) duplicate_mark(&dkey, time(NULL), 0);

        prometheus_increment(CYRUS_LMTP_SIEVE_REDIRECT_TOTAL);
        syslog(LOG_INFO, "sieve redirected: %s to: %s",
               m->id ? m->id : "<nomsgid>", rc->addr);
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: redirect sessionid=<%s> message-id=%s target=<%s> userid=<%s>",
                   session_id(), m->id ? m->id : "<nomsgid>", rc->addr, ctx->userid);
        return SIEVE_OK;
    } else {
        if (res == -1) {
            *errmsg = "Could not spawn sendmail process";
        } else {
            *errmsg = error_message(res);
        }
        return SIEVE_FAIL;
    }
}

static int sieve_discard(void *ac __attribute__((unused)),
                         void *ic __attribute__((unused)),
                         void *sc __attribute__((unused)),
                         void *mc,
                         const char **errmsg __attribute__((unused)))
{
    message_data_t *md = ((deliver_data_t *) mc)->m;

    prometheus_increment(CYRUS_LMTP_SIEVE_DISCARD_TOTAL);

    /* ok, we won't file it, but log it */
    syslog(LOG_INFO, "sieve discarded: %s",
           md->id ? md->id : "<nomsgid>");
    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: discard sessionid=<%s> message-id=%s",
               session_id(), md->id ? md->id : "<nomsgid>");

    return SIEVE_OK;
}

static int sieve_reject(void *ac, void *ic,
                        void *sc, void *mc, const char **errmsg)
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mydata = (deliver_data_t *) mc;
    message_data_t *md = mydata->m;
    const char **body;
    const char *origreceip;
    int res, need_encode = 0;

    /* Per RFC 5429, reject can do LMTP reject if reason string is US-ASCII */
    const char *cp;
    for (cp = rc->msg; *cp; cp++) {
        if (!isascii(*cp)) {
            need_encode = 1;
            break;
        }
    }

    if (rc->is_extended || (config_getswitch(IMAPOPT_SIEVE_USE_LMTP_REJECT) && !need_encode)) {
        char *msg = need_encode ?
            charset_qpencode_mimebody(rc->msg, strlen(rc->msg), 0, NULL) :
            xstrdup(rc->msg);
        strarray_t *resp = strarray_new();
        struct buf buf = BUF_INITIALIZER;
        const char *cur, *next;
        tok_t tok;

        tok_initm(&tok, msg, "\r\n", 0);
        for (cur = tok_next(&tok); (next = tok_next(&tok)); cur = next) {
            buf_printf(&buf, "550-5.7.1 %s\r\n", cur);
            strarray_appendm(resp, buf_release(&buf));
        }
        buf_printf(&buf, "550 5.7.1 %s\r\n", cur);
        strarray_appendm(resp, buf_release(&buf));
        free(msg);

        msg_setrcpt_status(md, mydata->cur_rcpt, LMTP_MESSAGE_REJECTED, resp);

        prometheus_increment(CYRUS_LMTP_SIEVE_REJECT_TOTAL);
        syslog(LOG_INFO, "sieve LMTP rejected: %s",
               md->id ? md->id : "<nomsgid>");
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: LMTP reject sessionid=<%s> message-id=%s userid=<%s>",
                   session_id(), md->id ? md->id : "<nomsgid>", ctx->userid);

        return SIEVE_OK;
    }

    if (md->return_path == NULL) {
        /* return message to who?!? */
        *errmsg = "No return-path for reply";
        return SIEVE_FAIL;
    }

    if (strlen(md->return_path) == 0) {
        syslog(LOG_INFO, "sieve: discarded reject to <> for %s id %s",
               mbname_userid(sd->mbname), md->id ? md->id : "<nomsgid>");
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: discard-reject sessionid=<%s> message-id=%s userid=<%s>",
                   session_id(), md->id ? md->id : "<nomsgid>", ctx->userid);
        return SIEVE_OK;
    }

    body = msg_getheader(md, "original-recipient");
    origreceip = body ? body[0] : NULL;
    if ((res = send_rejection(ctx->userid, md->id, md->return_path,
                              origreceip, mbname_recipient(sd->mbname, ((deliver_data_t *) mc)->ns),
                              rc->msg, md->data)) == 0) {
        prometheus_increment(CYRUS_LMTP_SIEVE_REJECT_TOTAL);
        syslog(LOG_INFO, "sieve rejected: %s to: %s",
               md->id ? md->id : "<nomsgid>", md->return_path);
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: reject sessionid=<%s> message-id=%s target=<%s> userid=<%s>",
                   session_id(), md->id ? md->id : "<nomsgid>", md->return_path,
                   ctx->userid);
        return SIEVE_OK;
    } else {
        if (res == -1) {
            *errmsg = "Could not spawn sendmail process";
        } else {
            *errmsg = error_message(res);
        }
        return SIEVE_FAIL;
    }
}

static deliver_data_t *setup_special_delivery(deliver_data_t *mydata,
                                              struct buf *headers)
{
    static deliver_data_t dd;
    static message_data_t md;
    static struct message_content mc;

    memcpy(&dd, mydata, sizeof(deliver_data_t));
    dd.m = memcpy(&md, mydata->m, sizeof(message_data_t));
    dd.content = &mc;
    memset(&mc, 0, sizeof(struct message_content));

    /* build the mailboxname from the recipient address */
    const mbname_t *origmbname = msg_getrcpt(mydata->m, mydata->cur_rcpt);

    /* do the userid */
    mbname_t *mbname = mbname_dup(origmbname);
    if (mbname_userid(mbname)) {
        mbname_truncate_boxes(mbname, 0);
    }

    const char *intname = mbname_intname(mbname);
    md.f = append_newstage(intname, time(0),
                           strhash(intname) /* unique msgnum for modified msg */,
                           &dd.stage);
    if (md.f) {
        char buf[4096];

        /* write updated message headers */
        fwrite(buf_base(headers), buf_len(headers), 1, md.f);

        /* get offset of message body */
        md.body_offset = ftell(md.f);

        /* write message body */
        fseek(mydata->m->f, mydata->m->body_offset, SEEK_SET);
        while (fgets(buf, sizeof(buf), mydata->m->f)) fputs(buf, md.f);
        fflush(md.f);

        /* XXX  do we look for updated Date and Message-ID? */
        md.size = ftell(md.f);
        md.data = prot_new(fileno(md.f), 0);

        mydata = &dd;
    }
    else mydata = NULL;

    mbname_free(&mbname);

    return mydata;
}

static void cleanup_special_delivery(deliver_data_t *mydata)
{
    fclose(mydata->m->f);
    prot_free(mydata->m->data);
#ifdef WITH_JMAP
    jmap_email_matchmime_free(&mydata->content->matchmime);
#endif
    append_removestage(mydata->stage);
    buf_free(&mydata->content->map);
    if (mydata->content->body) {
        message_free_body(mydata->content->body);
        free(mydata->content->body);
    }
}

static int sieve_fileinto(void *ac,
                          void *ic __attribute__((unused)),
                          void *sc,
                          void *mc,
                          const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mdata = (deliver_data_t *) mc;
    int ret = IMAP_MAILBOX_NONEXISTENT;

    const char *userid = mbname_userid(sd->mbname);
    char *intname = NULL;

    if (fc->resolved_mailbox) {
        intname = xstrdup(fc->resolved_mailbox);
    }
    else {
        if (fc->mailboxid) {
            intname = mboxlist_find_uniqueid(fc->mailboxid, userid, sd->authstate);
            if (intname && mboxname_isnondeliverymailbox(intname, 0)) {
                free(intname);
                intname = NULL;
            }
        }
        if (!intname) {
            if (fc->specialuse) {
                intname = mboxname_from_external(fc->specialuse, sd->ns, userid);
                ret = mboxlist_lookup(intname, NULL, NULL);
                if (ret) free(intname);
            }
            if (ret) {
                intname = mboxname_from_externalUTF8(fc->mailbox, sd->ns, userid);
            }
        }
    }

    // didn't resolve a name, this will always fail
    if (!intname) goto done;

    if (!mdata) {
        /* just doing destination mailbox resolution */
        if (fc->resolved_mailbox) free(intname);
        else fc->resolved_mailbox = intname;
        return SIEVE_OK;
    }


    message_data_t *md = mdata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mdata->cur_rcpt);
    struct imap4flags imap4flags = { fc->imapflags, sd->authstate };

    if (fc->headers) {
        mdata = setup_special_delivery(mdata, fc->headers);
        if (!mdata) {
            ret = SIEVE_FAIL;
            goto done;
        }
        else md = mdata->m;
    }

    ret = deliver_mailbox(md->f, mdata->content, mdata->stage, md->size,
                          &imap4flags, NULL, userid, sd->authstate, md->id,
                          userid, mdata->notifyheader,
                          intname, md->date, 0 /*savedate*/, quotaoverride, 0);

    if (ret == IMAP_MAILBOX_NONEXISTENT) {
        /* if "plus" folder under INBOX, then try to create it */
        ret = autosieve_createfolder(userid, sd->authstate,
                                     intname, fc->do_create);

        /* Try to deliver the mail again. */
        if (!ret) {
            if (fc->specialuse) {
                /* Attempt to add special-use flag to newly created mailbox */
                struct buf specialuse = BUF_INITIALIZER;
                int r = specialuse_validate(NULL, userid, fc->specialuse, &specialuse, 0);

                if (!r) {
                    annotatemore_write(intname, "/specialuse",
                                       userid, &specialuse);
                }
                buf_free(&specialuse);
            }

            ret = deliver_mailbox(md->f, mdata->content, mdata->stage, md->size,
                                  &imap4flags, NULL, userid, sd->authstate, md->id,
                                  userid, mdata->notifyheader,
                                  intname, md->date, 0 /*savedate*/, quotaoverride, 0);
        }
    }

    if (fc->headers) cleanup_special_delivery(mdata);

done:
    if (!ret) {
        prometheus_increment(CYRUS_LMTP_SIEVE_FILEINTO_TOTAL);
        ret = SIEVE_OK;
    } else {
        *errmsg = error_message(ret);
        ret = SIEVE_FAIL;
    }

    free(intname);

    return ret;
}

#ifdef HAVE_ICAL
#include <jansson.h>
#include "ical_support.h"

static void add_keywords(strarray_t *flags, json_t *set_keywords, int add)
{
    int i;

    for (i = 0; i < strarray_size(flags); i++) {
        const char *flag = strarray_nth(flags, i);

        if (!strcasecmp(flag, "\\Seen")) flag = "$Seen";
        else if (!strcasecmp(flag, "\\Flagged")) flag = "$Flagged";
        else if (!strcasecmp(flag, "\\Answered")) flag = "$Answered";
        else if (!strcasecmp(flag, "\\Draft")) flag = "$Draft";

        json_object_set_new(set_keywords, flag,
                            add ? json_true() : json_false());
    }
}

static int sieve_snooze(void *ac,
                        void *ic __attribute__((unused)),
                        void *sc,
                        void *mc,
                        const char **errmsg __attribute__((unused)))
{
    sieve_snooze_context_t *sn = (sieve_snooze_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mdata = (deliver_data_t *) mc;
    message_data_t *md = mdata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mdata->cur_rcpt);
    const char *userid = mbname_userid(sd->mbname);
    int ret = IMAP_MAILBOX_NONEXISTENT;

    if (sn->headers) {
        mdata = setup_special_delivery(mdata, sn->headers);
        if (!mdata) return SIEVE_FAIL;
        else md = mdata->m;
    }

    char *intname = mboxlist_find_specialuse("\\Snoozed", userid);
    if (!intname) goto done;

    /* Determine until time */
    time_t now = time(NULL), until;
    struct tm *tm = localtime(&now);
    struct icaltimetype tt;
    icaltimezone *tz = NULL;
    unsigned wday, today_sec;
    int day_inc = -1;
    unsigned t;
    char tbuf[26];

    if (sn->tzid) {
        tz = icaltimezone_get_builtin_timezone_from_tzid(sn->tzid);

        if (!tz) tz = icaltimezone_get_builtin_timezone(sn->tzid);
        if (!tz) goto done;

        tt = icaltime_current_time_with_zone(tz);
        wday = icaltime_day_of_week(tt) - 1;
        today_sec = 3600 * tt.hour + 60 * tt.minute + tt.second;
    }
    else {
        wday = tm->tm_wday;
        today_sec = 3600 * tm->tm_hour + 60 * tm->tm_min + tm->tm_sec;
    }

    if (sn->days & (1 << wday)) {
        /* We have times for today - see if a future one is still available */
        size_t i;
        for (i = 0; i < arrayu64_size(sn->times); i++) {
            t = arrayu64_nth(sn->times, i);
            if (t >= today_sec) {
                day_inc = 0;
                break;
            }
        }
    }
    if (day_inc == -1) {
        /* Use first time on next available day */
        t = arrayu64_nth(sn->times, 0);

        /* Find next available day */
        int i;
        for (i = wday + 1; i < 14; i++) {
            if (sn->days & (1 << (i % 7))) {
                day_inc = i - wday;
                break;
            }
        }
    }

    if (tz) {
        icaltime_adjust(&tt, day_inc, -tt.hour, -tt.minute, -tt.second + t);
        until = icaltime_as_timet_with_zone(tt, tz);
    }
    else {
        tm->tm_mday += day_inc;
        tm->tm_hour = t / 3600;
        tm->tm_min = (t % 3600) / 60;
        tm->tm_sec = t % 60;
        until = mktime(tm);
    }

    time_to_iso8601(until, tbuf, sizeof(tbuf), 1);

    /* Create snoozeDetails annotation */
    json_t *snoozed = json_pack("{s:s}", "until", tbuf);

    if (sn->awaken_mbox || sn->awaken_mboxid || sn->awaken_spluse) {
        char *awaken = NULL;
        const char *awakenid = NULL;
        mbentry_t *mbentry = NULL;

        if (sn->awaken_mboxid) {
            awaken = mboxlist_find_uniqueid(sn->awaken_mboxid,
                                            userid, sd->authstate);
            if (awaken) awakenid = sn->awaken_mboxid;
        }
        if (!awakenid && sn->awaken_spluse) {
            awaken = mboxlist_find_specialuse(sn->awaken_spluse, userid);
            if (awaken) {
                ret = mboxlist_lookup(awaken, &mbentry, NULL);
                if (!ret) awakenid = mbentry->uniqueid;
            }
        }
        if (!awakenid && sn->awaken_mbox) {
            awaken = mboxname_from_external(sn->awaken_mbox, sd->ns, userid);
            ret = mboxlist_lookup(awaken, &mbentry, NULL);
            if (ret == IMAP_MAILBOX_NONEXISTENT) {
                ret = autosieve_createfolder(userid, sd->authstate,
                                             awaken, sn->do_create);

                if (!ret) ret = mboxlist_lookup(awaken, &mbentry, NULL);
                if (!ret && sn->awaken_spluse) {
                    /* Attempt to add special-use flag to newly created mailbox */
                    struct buf specialuse = BUF_INITIALIZER;
                    int r2 = specialuse_validate(NULL, userid,
                                                 sn->awaken_spluse, &specialuse, 0);

                    if (!r2) {
                        annotatemore_write(awaken, "/specialuse",
                                           userid, &specialuse);
                    }
                    buf_free(&specialuse);
                }
            }
            if (!ret) awakenid = mbentry->uniqueid;
        }

        if (awakenid) {
            json_object_set_new(snoozed, "moveToMailboxId",
                                json_string(awakenid));
        }

        mboxlist_entry_free(&mbentry);
        free(awaken);
    }

    if (sn->addflags || sn->removeflags) {
        json_t *set_keywords = json_object();

        if (sn->addflags) {
            add_keywords(sn->addflags, set_keywords, 1);
        }
        if (sn->removeflags) {
            add_keywords(sn->removeflags, set_keywords, 0);
        }

        json_object_set_new(snoozed, "setKeywords", set_keywords);
    }

    struct entryattlist *annots = NULL;
    const char *annot = IMAP_ANNOT_NS "snoozed";
    const char *attrib = "value.shared";
    struct buf buf = BUF_INITIALIZER;
    char *json = json_dumps(snoozed, JSON_COMPACT|JSON_SORT_KEYS);

    json_decref(snoozed);
    buf_initm(&buf, json, strlen(json));
    setentryatt(&annots, annot, attrib, &buf);
    buf_free(&buf);

    /* Add \snoozed pseudo-flag */
    strarray_t *imapflags = strarray_dup(sn->imapflags);
    strarray_add(imapflags, "\\snoozed");

    struct imap4flags imap4flags = { imapflags, sd->authstate };
    ret = deliver_mailbox(md->f, mdata->content, mdata->stage, md->size,
                          &imap4flags, annots, userid, sd->authstate, md->id,
                          userid, mdata->notifyheader,
                          intname, md->date, until, quotaoverride, 0);

    strarray_free(imapflags);
    freeentryatts(annots);

done:
    if (sn->headers) cleanup_special_delivery(mdata);

    if (!ret) {
        prometheus_increment(CYRUS_LMTP_SIEVE_SNOOZE_TOTAL);
        ret = SIEVE_OK;
    } else {
        *errmsg = error_message(ret);
        ret = SIEVE_FAIL;
    }

    free(intname);

    return ret;
}

#ifdef WITH_DAV
#include "caldav_util.h"
#include "http_caldav_sched.h"

char *httpd_userid = NULL;  // due to caldav_util.h including httpd.h
struct namespace_t namespace_calendar = { .allow = ALLOW_USERDATA | ALLOW_CAL_NOTZ };

static int sieve_imip(void *ac, void *ic, void *sc, void *mc,
                      const char **errmsg __attribute__((unused)))
{
    sieve_imip_context_t *imip = (sieve_imip_context_t *) ac;
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mydata = (deliver_data_t *) mc;
    message_data_t *m = mydata->m;
    icalcomponent *itip = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL, *organizer = NULL;
    const char *originator = NULL, *recipient = NULL;
    strarray_t sched_addresses = STRARRAY_INITIALIZER;
    unsigned sched_flags = 0;
    struct bodypart **parts = NULL;
    int ret = 0;

    prometheus_increment(CYRUS_LMTP_SIEVE_IMIP_TOTAL);

    buf_setcstr(&imip->outcome, "no_action");
    buf_reset(&imip->errstr);

    if (caldav_create_defaultcalendars(ctx->userid,
                                       &lmtpd_namespace, sd->authstate, NULL)) {
        buf_setcstr(&imip->outcome, "error");
        buf_setcstr(&imip->errstr, "could not autoprovision calendars");
        goto done;
    }

    /* parse the message body if we haven't already */
    if (!mydata->content->body &&
        message_parse_file_buf(m->f, &mydata->content->map,
                               &mydata->content->body, NULL)) {
        buf_setcstr(&imip->errstr, "unable to parse iMIP message");
        goto done;
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    const char *content_types[] = { "text/calendar", NULL };
    message_fetch_part(mydata->content, content_types, &parts);
    if (parts && parts[0]) {
        struct buf buf = BUF_INITIALIZER;

        buf_init_ro_cstr(&buf, parts[0]->decoded_body);
        itip = ical_string_as_icalcomponent(&buf);
        buf_free(&buf);
    }

    if (!itip) {
        buf_setcstr(&imip->errstr, "unable to find & parse text/calendar part");
        goto done;
    }

    meth = icalcomponent_get_method(itip);
    if (meth == ICAL_METHOD_NONE) {
        buf_setcstr(&imip->errstr, "missing METHOD property");
        goto done;
    }

    icalrestriction_check(itip);
    if (get_icalcomponent_errstr(itip)) {
        buf_setcstr(&imip->outcome, "error");
        buf_setcstr(&imip->errstr, "invalid iCalendar data");
        goto done;
    }

    comp = icalcomponent_get_first_real_component(itip);
    if (!comp) {
        buf_setcstr(&imip->outcome, "error");
        buf_setcstr(&imip->errstr, "no component to schedule");
        goto done;
    }

    kind = icalcomponent_isa(comp);
    uid = icalcomponent_get_uid(comp);
    if (!uid) {
        buf_setcstr(&imip->outcome, "error");
        buf_setcstr(&imip->errstr, "missing UID property");
        goto done;
    }

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (!prop) {
        buf_setcstr(&imip->outcome, "error");
        buf_setcstr(&imip->errstr, "missing ORGANIZER property");
        goto done;
    }
    organizer = icalproperty_get_organizer(prop);

    if (strchr(ctx->userid, '@')) {
        strarray_add(&sched_addresses, ctx->userid);
    }
    else {
        const char *domains;
        char *domain;
        tok_t tok;

        domains = config_getstring(IMAPOPT_CALENDAR_USER_ADDRESS_SET);
        if (!domains) domains = config_defdomain;
        if (!domains) domains = config_servername;

        tok_init(&tok, domains, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        while ((domain = tok_next(&tok))) {
            strarray_appendm(&sched_addresses,
                             strconcat(ctx->userid, "@", domain, NULL));
        }
        tok_fini(&tok);
    }

    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
    case ICAL_VTODO_COMPONENT:
    case ICAL_VPOLL_COMPONENT:
        switch (meth) {
        case ICAL_METHOD_POLLSTATUS:
        case ICAL_METHOD_ADD:
            if (kind == ICAL_VPOLL_COMPONENT) {
                if (meth == ICAL_METHOD_ADD) goto unsupported_method;
            }
            else if (meth == ICAL_METHOD_POLLSTATUS) goto unsupported_method;

            GCC_FALLTHROUGH

        case ICAL_METHOD_CANCEL:
            if (imip->invites_only) {
                buf_setcstr(&imip->errstr, "configured to NOT process updates");
                goto done;
            }

            if (imip->delete_canceled) sched_flags |= SCHEDFLAG_DELETE_CANCELED;

            GCC_FALLTHROUGH

        case ICAL_METHOD_REQUEST:
            originator = organizer;

#if 0
            /* Find invitee that matches owner of script */
            for (prop = icalcomponent_get_first_invitee(comp); prop;
                 prop = icalcomponent_get_next_invitee(comp)) {
                const char *invitee = icalproperty_get_invitee(prop);
                if (!strncasecmp(invitee, "mailto:", 7)) invitee += 7;
                int n = strarray_find(&sched_addresses, invitee, 0);
                if (n >= 0) {
                    recipient = strarray_nth(&sched_addresses, n);
                    break;
                }
            }
#else
            /* XXX  For now, assume an invitee matches owner of script */
            recipient = strarray_nth(&sched_addresses, 0);
#endif
            if (!recipient) {
                buf_setcstr(&imip->outcome, "error");
                buf_setcstr(&imip->errstr,
                            "could not find matching ATTENDEE property");
                goto done;
            }

            if (imip->updates_only) sched_flags |= SCHEDFLAG_UPDATES_ONLY;
            else if (imip->invites_only) sched_flags |= SCHEDFLAG_INVITES_ONLY;
            break;

        case ICAL_METHOD_REPLY:
            if (imip->invites_only) {
                buf_setcstr(&imip->errstr, "configured to NOT process replies");
                goto done;
            }

#if 0
            /* TODO: Organizer better match owner of script */
            recipient = organizer;
#else
            /* XXX  For now, assume organizer matches owner of script */
            recipient = strarray_nth(&sched_addresses, 0);
#endif
            prop = icalcomponent_get_first_invitee(comp);
            if (!prop) {
                buf_setcstr(&imip->outcome, "error");
                buf_setcstr(&imip->errstr, "missing ATTENDEE property");
                goto done;
            }
            originator = icalproperty_get_invitee(prop);

            sched_flags |= SCHEDFLAG_IS_REPLY;
            break;

        unsupported_method:
        default:
            /* Unsupported method */
            buf_setcstr(&imip->outcome, "error");
            buf_printf(&imip->errstr, "unsupported method: '%s'",
                       icalproperty_method_to_string(meth));
            goto done;
        }
        break;

    default:
        /* Unsupported component */
        buf_setcstr(&imip->outcome, "error");
        buf_printf(&imip->errstr, "unsupported component: '%s'",
                   icalcomponent_kind_to_string(kind));
        goto done;
    }

    struct sched_data sched_data =
        { sched_flags, itip, NULL, NULL,
          ICAL_SCHEDULEFORCESEND_NONE, &sched_addresses, imip->calendarid, NULL };
    struct caldav_sched_param sched_param = {
        (char *) ctx->userid, NULL, 0, 0, 1, NULL
    };

    int r = sched_deliver_local(ctx->userid, originator, recipient,
                                mydata->content->body->from,
                                &sched_param, &sched_data,
                                (struct auth_state *) sd->authstate,
                                NULL, NULL);
    switch (r) {
    case SCHED_DELIVER_ERROR:
        buf_setcstr(&imip->outcome, "error");
        buf_printf(&imip->errstr, "failed to deliver iMIP message: %s",
                   sched_data.status ? sched_data.status : "");
        break;
    case SCHED_DELIVER_NOACTION:
        buf_setcstr(&imip->outcome, "no_action");
        break;
    case SCHED_DELIVER_ADDED:
        buf_setcstr(&imip->outcome, "added");
        break;
    default:
        buf_setcstr(&imip->outcome, "updated");
        break;
    }

    syslog(LOG_INFO, "sieve iMIP processed: %s: %s",
           m->id ? m->id : "<nomsgid>", buf_cstring(&imip->errstr));
    if (config_auditlog)
        syslog(LOG_NOTICE,
               "auditlog: processed iMIP sessionid=<%s> message-id=%s: %s",
               session_id(), m->id ? m->id : "<nomsgid>",
               buf_cstring(&imip->errstr));

  done:
    syslog(LOG_DEBUG, "sieve iMIP: %s: %s (%s)",
           m->id ? m->id : "<nomsgid>",
           buf_cstring(&imip->outcome), buf_cstring(&imip->errstr));

    strarray_fini(&sched_addresses);
    if (parts) {
        struct bodypart **part;

        for (part = parts; *part; part++) {
            free(*part);
        }
        free(parts);

        if (itip) icalcomponent_free(itip);
    }

    return ret;
}
#endif /* WITH_DAV */
#endif /* HAVE_ICAL */

static int sieve_keep(void *ac,
                      void *ic __attribute__((unused)),
                      void *sc, void *mc, const char **errmsg)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mydata = (deliver_data_t *) mc;
    int ret = IMAP_MAILBOX_NONEXISTENT;

    const char *userid = mbname_userid(sd->mbname);
    char *intname = NULL;

    if (kc->resolved_mailbox) {
        intname = xstrdup(kc->resolved_mailbox);
    }
    else {
        if (!userid) {
            /* shared mailbox request */
            ret = mboxlist_lookup(mbname_intname(sd->mbname), NULL, NULL);
            if (!ret) intname = xstrdup(mbname_intname(sd->mbname));
        }
        else {
            mbname_t *mbname = mbname_dup(sd->mbname);

            if (strarray_size(mbname_boxes(mbname))) {
                ret = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
                if (ret &&
                    config_getswitch(IMAPOPT_LMTP_FUZZY_MAILBOX_MATCH) &&
                    fuzzy_match(mbname)) {
                    /* try delivery to a fuzzy matched mailbox */
                    ret = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
                }
            }
            if (ret) {
                /* normal delivery to INBOX */
                mbname_truncate_boxes(mbname, 0);
                ret = 0;
            }

            intname = xstrdup(mbname_intname(mbname));
            mbname_free(&mbname);
        }
    }

    // didn't resolve a name, this will always fail
    if (!intname) goto done;

    if (!mydata) {
        /* just doing destination mailbox resolution */
        if (kc->resolved_mailbox) free(intname);
        else kc->resolved_mailbox = intname;
        return SIEVE_OK;
    }


    message_data_t *md = mydata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mydata->cur_rcpt);
    struct imap4flags imap4flags = { kc->imapflags, sd->authstate };
    const char *authuser = mydata->authuser;
    const struct auth_state *authstate = mydata->authstate;
    struct auth_state *freeme = NULL;
    int acloverride = 0;

    if (kc->headers) {
        mydata = setup_special_delivery(mydata, kc->headers);
        if (!mydata) {
            ret = SIEVE_FAIL;
            goto done;
        }
        else md = mydata->m;
    }

    if (mboxname_isusermailbox(intname, 1)) {
        authstate = freeme = auth_newstate(userid);
        authuser = userid;
        acloverride = 1;
    }

    ret = deliver_mailbox(md->f, mydata->content, mydata->stage, md->size,
                          &imap4flags, NULL, authuser, authstate, md->id,
                          userid, mydata->notifyheader, intname, md->date,
                          0 /*savedate*/, quotaoverride, acloverride);

    if (freeme) auth_freestate(freeme);

    if (kc->headers) cleanup_special_delivery(mydata);
 
  done:
    if (!ret) {
        prometheus_increment(CYRUS_LMTP_SIEVE_KEEP_TOTAL);
        ret = SIEVE_OK;
    } else {
        *errmsg = error_message(ret);
        ret = SIEVE_FAIL;
    }

    free(intname);

    return ret;
}

static int sieve_notify(void *ac,
                        void *interp_context __attribute__((unused)),
                        void *script_context,
                        void *mc __attribute__((unused)),
                        const char **errmsg __attribute__((unused)))
{
    const char *notifier = config_getstring(IMAPOPT_SIEVENOTIFIER);

    if (notifier) {
        sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
        script_data_t *sd = (script_data_t *) script_context;
        int nopt = strarray_size(nc->options);

        prometheus_increment(CYRUS_LMTP_SIEVE_NOTIFY_TOTAL);

        /* "default" is a magic value that implies the default */
        notify(!strcmp("default",nc->method) ? notifier : nc->method,
               "SIEVE", nc->priority, mbname_userid(sd->mbname), NULL,
               nopt, (const char **) nc->options->data, nc->message, nc->fname);
    }

    return SIEVE_OK;
}

static const char hex[] = "0123456789ABCDEF";

static int autorespond(void *ac,
                       void *ic __attribute__((unused)),
                       void *sc,
                       void *mc __attribute__((unused)),
                       const char **errmsg __attribute__((unused)))
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    time_t t, now;
    int ret;
    int i;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    char *id;

    prometheus_increment(CYRUS_LMTP_SIEVE_AUTORESPOND_TOTAL);

    now = time(NULL);

    /* ok, let's see if we've responded before */
    id = xmalloc(SIEVE_HASHLEN*2 + 1);
    for (i = 0; i < SIEVE_HASHLEN; i++) {
        id[i*2+0] = hex[arc->hash[i] / 16];
        id[i*2+1] = hex[arc->hash[i] % 16];
    }
    id[SIEVE_HASHLEN*2] = '\0';
    dkey.id = id;
    dkey.to = mbname_userid(sd->mbname);
    dkey.date = "";  /* no date on these, ID is custom */
    t = duplicate_check(&dkey);
    if (t) {
        if (now >= t) {
            /* yay, we can respond again! */
            ret = SIEVE_OK;
        } else {
            ret = SIEVE_DONE;
        }
    } else {
        /* never responded before */
        ret = SIEVE_OK;
    }

    if (ret == SIEVE_OK) {
        duplicate_mark(&dkey, now + arc->seconds, 0);
    }

    free(id);

    return ret;
}

static void do_fcc(script_data_t *sdata, sieve_fileinto_context_t *fcc,
                   struct buf *msg)
{
    struct appendstate as;
    const char *userid;
    char *intname = NULL;
    int r = 0;

    userid = mbname_userid(sdata->mbname);

    if (fcc->mailboxid) {
        intname = mboxlist_find_uniqueid(fcc->mailboxid, userid,
                                         sdata->authstate);
        if (intname && mboxname_isnondeliverymailbox(intname, 0)) {
            free(intname);
            intname = NULL;
        }
    }
    if (!intname && fcc->specialuse) {
        intname = mboxlist_find_specialuse(fcc->specialuse, userid);
    }
    if (!intname) {
        intname = mboxname_from_externalUTF8(fcc->mailbox, sdata->ns, userid);

        r = mboxlist_lookup(intname, NULL, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            r = autosieve_createfolder(userid, sdata->authstate,
                                       intname, fcc->do_create);

            if (!r && fcc->specialuse) {
                /* Attempt to add special-use flag to newly created mailbox */
                struct buf specialuse = BUF_INITIALIZER;
                int r2 = specialuse_validate(NULL, userid,
                                             fcc->specialuse, &specialuse, 0);

                if (!r2) {
                    annotatemore_write(intname, "/specialuse",
                                       userid, &specialuse);
                }
                buf_free(&specialuse);
            }
        }
    }
    if (!r) {
        r = append_setup(&as, intname, userid, sdata->authstate,
                         0, NULL, NULL, 0, EVENT_MESSAGE_APPEND);
    }
    if (!r) {
        struct stagemsg *stage;
        /* post-date by 1 sec in an effort to have
           the FCC threaded AFTER the incoming message */
        time_t internaldate = time(NULL) + 1;
        FILE *f = append_newstage(intname, internaldate,
                                  strhash(intname) /* unique msgnum for reply */,
                                  &stage);
        if (f) {
            struct body *body = NULL;

            fwrite(buf_base(msg), buf_len(msg), 1, f);
            fclose(f);

            r = append_fromstage(&as, &body, stage,
                                 internaldate, /* createdmodseq */ 0,
                                 fcc->imapflags, 0, /* annotations */ NULL);
            if (!r) r = append_commit(&as);

            if (body) {
                message_free_body(body);
                free(body);
            }

            append_removestage(stage);
        }
        if (r || !f) append_abort(&as);
    }

    if (r) {
        syslog(LOG_NOTICE, "sieve fcc '%s' failed: %s",
               fcc->mailbox, error_message(r));
    }

    free(intname);
}

static int send_response(void *ac, void *ic,
                         void *sc, void *mc, const char **errmsg)
{
    char outmsgid[8192], *sievedb, *subj;
    int i, sl, ret, r;
    time_t t;
    char datestr[RFC5322_DATETIME_MAX+1];
    pid_t p;
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *md = ((deliver_data_t *) mc)->m;
    script_data_t *sdata = (script_data_t *) sc;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    struct buf msgbuf = BUF_INITIALIZER;
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    smtp_envelope_t sm_env = SMTP_ENVELOPE_INITIALIZER;
    smtpclient_t *sm = NULL;

    smtp_envelope_set_from(&sm_env, "");
    smtp_envelope_add_rcpt(&sm_env, src->addr);

    t = time(NULL);
    p = getpid();
    snprintf(outmsgid, sizeof(outmsgid), "<cmu-sieve-%d-%d-%d@%s>",
             (int) p, (int) t, global_outgoing_count++, config_servername);

    buf_printf(&msgbuf, "Message-ID: %s\r\n", outmsgid);

    time_to_rfc5322(t, datestr, sizeof(datestr));
    buf_printf(&msgbuf, "Date: %s\r\n", datestr);

    buf_printf(&msgbuf, "X-Sieve: %s\r\n", SIEVE_VERSION);
    buf_appendcstr(&msgbuf, "X-Sieve-Action: vacation\r\n");

    if (strchr(src->fromaddr, '<'))
        buf_printf(&msgbuf, "From: %s\r\n", src->fromaddr);
    else
        buf_printf(&msgbuf, "From: <%s>\r\n", src->fromaddr);

    buf_printf(&msgbuf, "To: <%s>\r\n", src->addr);
    /* check that subject is sane */
    sl = strlen(src->subj);
    for (i = 0; i < sl; i++)
        if (Uiscntrl(src->subj[i])) {
            src->subj[i] = '\0';
            break;
        }
    subj = charset_encode_mimeheader(src->subj, strlen(src->subj), 0);
    buf_printf(&msgbuf, "Subject:%s %s\r\n",  /* fold before long header body */
               strlen(subj) > 69 ? "\r\n" : "", subj);
    free(subj);
    if (md->id) buf_printf(&msgbuf, "In-Reply-To: %s\r\n", md->id);
    buf_appendcstr(&msgbuf, "Auto-Submitted: auto-replied (vacation)\r\n");
    buf_appendcstr(&msgbuf, "MIME-Version: 1.0\r\n");

    if (src->mime) {
        /* Assume that the body is a fully-formed MIME entity */
        /* XXX  Should we try to verify it as such? */
    } else {
        /* Add Content-* headers for the plaintext body */
        buf_appendcstr(&msgbuf, "Content-Type: text/plain; charset=utf-8\r\n");
        buf_appendcstr(&msgbuf, "Content-Transfer-Encoding: 8bit\r\n");
        buf_appendcstr(&msgbuf, "\r\n");
    }

    buf_appendcstr(&msgbuf, src->msg);
    buf_appendcstr(&msgbuf, "\r\n");

    r = smtpclient_open(&sm);
    if (!r) {
        smtpclient_set_auth(sm, ctx->userid);
        r = smtpclient_send(sm, &sm_env, &msgbuf);
    }
    smtpclient_close(&sm);

    if (r == 0) {
        sievedb = make_sieve_db(mbname_recipient(sdata->mbname, ((deliver_data_t *) mc)->ns));

        dkey.id = outmsgid;
        dkey.to = sievedb;
        dkey.date = ((deliver_data_t *) mc)->m->date;
        duplicate_mark(&dkey, t, 0);

        if (src->fcc.mailbox) {
            do_fcc(sdata, &src->fcc, &msgbuf);
        }

        prometheus_increment(CYRUS_LMTP_SIEVE_AUTORESPOND_SENT_TOTAL);

        ret = SIEVE_OK;
    } else {
        *errmsg = error_message(r);
        ret = SIEVE_FAIL;
    }

    buf_free(&msgbuf);
    smtp_envelope_fini(&sm_env);

    return ret;
}

/* vacation support */
static sieve_vacation_t vacation = {
    1 * DAY2SEC,                /* min response */
    31 * DAY2SEC,               /* max response */
    &autorespond,               /* autorespond() */
    &send_response,             /* send_response() */
};

static int sieve_duplicate_check(void *dc,
                                 void *ic __attribute__((unused)),
                                 void *sc,
                                 void *mc __attribute__((unused)),
                                 const char **errmsg __attribute__((unused)))
{
    sieve_duplicate_context_t *dtc = (sieve_duplicate_context_t *) dc;
    script_data_t *sd = (script_data_t *) sc;
    time_t t, now = time(NULL);
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;

    dkey.id = dtc->id;
    dkey.to = make_sieve_db(mbname_userid(sd->mbname));
    dkey.date = "";  /* no date on these, ID is custom */
    t = duplicate_check(&dkey);

    if (t && now < t) {
        /* active tracking record */
        duplicate_log(&dkey, "sieve-duplicate");
        return 1;
    }

    /* no active tracking record */
    return 0;
}

static int sieve_duplicate_track(void *dc,
                                 void *ic __attribute__((unused)),
                                 void *sc,
                                 void *mc __attribute__((unused)),
                                 const char **errmsg __attribute__((unused)))
{
    sieve_duplicate_context_t *dtc = (sieve_duplicate_context_t *) dc;
    script_data_t *sd = (script_data_t *) sc;
    time_t now = time(NULL);
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;

    dkey.id = dtc->id;
    dkey.to = make_sieve_db(mbname_userid(sd->mbname));
    dkey.date = "";  /* no date on these, ID is custom */
    duplicate_mark(&dkey, now + dtc->seconds, 0);

    return SIEVE_OK;
}

/* duplicate support */
static sieve_duplicate_t duplicate = {
    0, /* max expiration */
    &sieve_duplicate_check,
    &sieve_duplicate_track,
};

#ifdef WITH_JMAP
#include "jmap_mail_query.h"

static int jmapquery(void *ic, void *sc, void *mc, const char *json)
{
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *m = ((deliver_data_t *) mc)->m;
    struct message_content *content = ((deliver_data_t *) mc)->content;
    const char *userid = mbname_userid(sd->mbname);
    json_error_t jerr;
    json_t *jfilter, *err = NULL;
    int matches = 0;

    /* Create filter from json */
    jfilter = json_loads(json, 0, &jerr);
    if (!jfilter) return 0;

    if (!content->matchmime) {
        if (!content->body) {
            /* parse the message body if we haven't already */
            int r = message_parse_file_buf(m->f, &content->map,
                                           &content->body, NULL);
            if (r) {
                json_decref(jfilter);
                return 0;
            }
        }
        /* build the query filter */
        content->matchmime = jmap_email_matchmime_new(&content->map, &err);
    }

    /* Run query */
    if (content->matchmime && !err)
        matches = jmap_email_matchmime(content->matchmime, jfilter, ctx->cstate, userid,
                sd->authstate, sd->ns, time(NULL), &err);

    if (err) {
        const char *type = json_string_value(json_object_get(err, "type"));
        char *errstr = json_dumps(err, JSON_COMPACT);
        int priority = LOG_NOTICE;

        if (strcmpsafe(type, "invalidArguments")) {
            priority = LOG_ERR;
        }

        syslog(priority, "sieve: jmapquery error: %s", errstr);

        free(errstr);
        json_decref(err);
    }

    json_decref(jfilter);

    return matches;
}
#endif

static int sieve_parse_error_handler(int lineno, const char *msg,
                                     void *ic __attribute__((unused)),
                                     void *sc)
{
    script_data_t *sd = (script_data_t *) sc;

    syslog(LOG_INFO, "sieve parse error for %s: line %d: %s",
           mbname_userid(sd->mbname), lineno, msg);

    return SIEVE_OK;
}

static int sieve_execute_error_handler(const char *msg,
                                       void *ic  __attribute__((unused)),
                                       void *sc, void *mc)
{
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = ((deliver_data_t *) mc)->m;

    syslog(LOG_INFO, "sieve runtime error for %s id %s: %s",
           mbname_userid(sd->mbname), md->id ? md->id : "(null)", msg);

    return SIEVE_OK;
}

void sieve_log(void *sc, void *mc, const char *text)
{
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = ((deliver_data_t *) mc)->m;

    syslog(LOG_INFO, "sieve log: userid=%s messageid=%s text=%s",
           mbname_userid(sd->mbname), md->id ? md->id : "(null)", text);
}

sieve_interp_t *setup_sieve(struct sieve_interp_ctx *ctx)
{
    sieve_interp_t *interp = NULL;
    int res;
    static strarray_t mark = STRARRAY_INITIALIZER;
    static strarray_t methods = STRARRAY_INITIALIZER;

    if (!mark.count)
        strarray_append(&mark, "\\flagged");

    if (!methods.count) {
        /* XXX  is there an imapd.conf option for this? */
        strarray_append(&methods, "mailto:");
    }

    sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);
    if (!sieve_usehomedir) {
        sieve_dir = config_getstring(IMAPOPT_SIEVEDIR);
    } else {
        sieve_dir = NULL;
    }

    interp = sieve_interp_alloc(ctx);
    assert(interp != NULL);

    sieve_register_redirect(interp, &sieve_redirect);
    sieve_register_discard(interp, &sieve_discard);
    sieve_register_reject(interp, &sieve_reject);
    sieve_register_fileinto(interp, &sieve_fileinto);
    sieve_register_keep(interp, &sieve_keep);
    sieve_register_notify(interp, &sieve_notify, &methods);
    sieve_register_size(interp, &getsize);
    sieve_register_mailboxexists(interp, &getmailboxexists);
    sieve_register_mailboxidexists(interp, &getmailboxidexists);
    sieve_register_specialuseexists(interp, &getspecialuseexists);
    sieve_register_metadata(interp, &getmetadata);
    sieve_register_header(interp, &getheader);
    sieve_register_headersection(interp, &getheadersection);
    sieve_register_addheader(interp, &addheader);
    sieve_register_deleteheader(interp, &deleteheader);
    sieve_register_fname(interp, &getfname);

    sieve_register_envelope(interp, &getenvelope);
    sieve_register_environment(interp, &getenvironment);
    sieve_register_body(interp, &getbody);
    sieve_register_include(interp, &getinclude);

    sieve_register_logger(interp, &sieve_log); 

    res = sieve_register_vacation(interp, &vacation);
    if (res != SIEVE_OK) {
        syslog(LOG_ERR, "sieve_register_vacation() returns %d", res);
        fatal("sieve_register_vacation()", EX_SOFTWARE);
    }

    duplicate.max_expiration =
        config_getduration(IMAPOPT_SIEVE_DUPLICATE_MAX_EXPIRATION, 's');
    res = sieve_register_duplicate(interp, &duplicate);
    if (res != SIEVE_OK) {
        syslog(LOG_ERR, "sieve_register_duplicate() returns %d", res);
        fatal("sieve_register_duplicate()", EX_SOFTWARE);
    }

#ifdef WITH_DAV
    sieve_register_extlists(interp, &listvalidator, &listcompare);
#endif
#ifdef WITH_JMAP
    sieve_register_jmapquery(interp, &jmapquery);
#endif
#ifdef HAVE_ICAL
    /* need timezones for sieve snooze */
    ical_support_init();
    sieve_register_snooze(interp, &sieve_snooze);
#ifdef WITH_DAV
    sieve_register_imip(interp, &sieve_imip);
#endif
#endif /* HAVE_ICAL */
    sieve_register_parse_error(interp, &sieve_parse_error_handler);
    sieve_register_execute_error(interp, &sieve_execute_error_handler);

    return interp;
}

static int sieve_find_script(const char *user, const char *domain,
                             const char *script, char *fname, size_t size)
{
    if (!user && !script) {
        return -1;
    }

    if (user && strlen(user) > 900) {
        return -1;
    }

    if (sieve_usehomedir && user) { /* look in homedir */
        struct passwd *pent = getpwnam(user);

        if (pent == NULL) {
            return -1;
        }

        /* check ~USERNAME/.sieve */
        snprintf(fname, size, "%s/%s", pent->pw_dir, script ? script : ".sieve");

        return 0;
    }

    /* look in sieve_dir */
    struct buf buf = BUF_INITIALIZER;

    if (user) buf_setcstr(&buf, user);
    if (domain) buf_printf(&buf, "@%s", domain);

    const char *userid = buf_cstring(&buf);
    const char *sievedir = user_sieve_path(userid);

    if (!script) { /* default script */
        script = sievedir_get_active(sievedir);

        if (!script) return 0;  /* no default */
    }

    snprintf(fname, size, "%s/%s.bc", sievedir, script);

    sieve_script_rebuild(userid, sievedir, script);

    buf_free(&buf);

    return 0;
}

int run_sieve(const mbname_t *mbname, sieve_interp_t *interp, deliver_data_t *msgdata)
{
    struct buf attrib = BUF_INITIALIZER;
    const char *script = NULL;
    char fname[MAX_MAILBOX_PATH+1];
    sieve_execute_t *bc = NULL;
    script_data_t sdata;
    int r = 0;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    struct auth_state *freeauthstate = NULL;

    if (!mbname_userid(mbname)) {
        if (annotatemore_lookup(mbname_intname(mbname),
                                IMAP_ANNOT_NS "sieve", "",
                                &attrib) != 0 || !attrib.s) {
            /* no sieve script annotation */
            return 1; /* do normal delivery actions */
        }

        script = buf_cstring(&attrib);
    }

    if (sieve_find_script(mbname_localpart(mbname), mbname_domain(mbname),
                          script, fname, sizeof(fname)) != 0 ||
        sieve_script_load(fname, &bc) != SIEVE_OK) {
        buf_free(&attrib);
        /* no sieve script */
        return 1; /* do normal delivery actions */
    }
    buf_free(&attrib);
    script = NULL;

    sdata.mbname = mbname;
    sdata.ns = msgdata->ns;

    if (mbname_userid(mbname)) {
        sdata.authstate = freeauthstate = auth_newstate(mbname_userid(mbname));
    }
    else {
        sdata.authstate = msgdata->authstate;
    }

    r = sieve_execute_bytecode(bc, interp,
                               (void *) &sdata, (void *) msgdata);

    if ((r == SIEVE_OK) && (msgdata->m->id)) {
        const char *sdb = make_sieve_db(mbname_recipient(mbname, sdata.ns));

        dkey.id = msgdata->m->id;
        dkey.to = sdb;
        dkey.date = msgdata->m->date;
        duplicate_mark(&dkey, time(NULL), 0);
    }

    /* free everything */
    if (freeauthstate) auth_freestate(freeauthstate);
    sieve_script_unload(&bc);

    /* if there was an error, r is non-zero and
       we'll do normal delivery */
    return r;
}


#define SEP "|"

static int autosieve_createfolder(const char *userid, const struct auth_state *auth_state,
                                  const char *internalname, int createsievefolder)
{
    const char *subf ;
    int r = 0;
    int n;

    /* Check if internalname or userid are NULL */
    if (userid == NULL || internalname == NULL)
        return IMAP_MAILBOX_NONEXISTENT;

    syslog(LOG_DEBUG, "autosievefolder: autosieve_createfolder() was called for user %s, folder %s",
           userid, internalname);

    if (config_getswitch(IMAPOPT_ANYSIEVEFOLDER)) {
        createsievefolder = 1;
    }
    else if ((subf = config_getstring(IMAPOPT_AUTOCREATE_SIEVE_FOLDERS)) != NULL) {
        strarray_t *create = strarray_split(subf, SEP, STRARRAY_TRIM);

        for (n = 0; n < create->count; n++) {
            const char *name = strarray_nth(create, n);
            char *foldername = mboxname_user_mbox(userid, name);

            if (!strcmp(foldername, internalname))
                createsievefolder = 1;

            free(foldername);
            if (createsievefolder) break;
        }

        strarray_free(create);
    }

    // unless configured to create it, drop out now
    if (!createsievefolder) return IMAP_MAILBOX_NONEXISTENT;

    // lock the namespace and check again before trying to create
    struct mboxlock *namespacelock = mboxname_usernamespacelock(internalname);

    // did we lose the race?
    r = mboxlist_lookup(internalname, 0, 0);
    if (r != IMAP_MAILBOX_NONEXISTENT) goto done;

    mbentry_t mbentry = MBENTRY_INITIALIZER;
    mbentry.name = (char *) internalname;
    mbentry.mbtype = MBTYPE_EMAIL;

    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                               0/*isadmin*/, userid, auth_state,
                               MBOXLIST_CREATE_NOTIFY, NULL/*mailboxptr*/);
    if (r) {
        syslog(LOG_ERR, "autosievefolder: User %s, folder %s creation failed. %s",
               userid, internalname, error_message(r));
        goto done;
    }

    mboxlist_changesub(internalname, userid, auth_state, 1, 1, 1);
    syslog(LOG_DEBUG, "autosievefolder: User %s, folder %s creation succeeded",
           userid, internalname);

done:
    mboxname_release(&namespacelock);
    return r;
}

