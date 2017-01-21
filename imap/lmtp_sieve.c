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
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "auth.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "lmtpd.h"
#include "lmtp_sieve.h"
#include "lmtpengine.h"
#include "map.h"
#include "notify.h"
#include "prot.h"
#include "times.h"
#include "sieve/sieve_interface.h"
#include "smtpclient.h"
#include "strhash.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/lmtp_err.h"
#include "imap/lmtpstats.h"

static int sieve_usehomedir = 0;
static const char *sieve_dir = NULL;

/* data per script */
typedef struct script_data {
    const mbname_t *mbname;
    const struct auth_state *authstate;
    const struct namespace *ns;

    int edited_header;
} script_data_t;

static int autosieve_createfolder(const char *userid, const struct auth_state *auth_state,
                                  const char *internalname, int createsievefolder);
static deliver_data_t *setup_special_delivery(deliver_data_t *mydata);
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

/* adds the header "head" with body "body" to msg */
static int addheader(void *sc, void *mc,
                     const char *head, const char *body, int index)
{
    script_data_t *sd = (script_data_t *)sc;
    message_data_t *m = ((deliver_data_t *) mc)->m;

    if (head == NULL || body == NULL) return SIEVE_FAIL;

    if (index < 0)
        spool_append_header(xstrdup(head), xstrdup(body), m->hdrcache);
    else
        spool_prepend_header(xstrdup(head), xstrdup(body), m->hdrcache);

    sd->edited_header = 1;

    return SIEVE_OK;
}

/* deletes (instance "index" of) the header "head" from msg */
static int deleteheader(void *sc, void *mc, const char *head, int index)
{
    script_data_t *sd = (script_data_t *)sc;
    message_data_t *m = ((deliver_data_t *) mc)->m;

    if (head == NULL) return SIEVE_FAIL;

    if (!index) spool_remove_header(xstrdup(head), m->hdrcache);
    else spool_remove_header_instance(xstrdup(head), index, m->hdrcache);

    sd->edited_header = 1;

    return SIEVE_OK;
}

static int getmailboxexists(void *sc, const char *extname)
{
    script_data_t *sd = (script_data_t *)sc;
    char *intname = mboxname_from_external(extname, sd->ns, mbname_userid(sd->mbname));
    int r = mboxlist_lookup(intname, NULL, NULL);
    free(intname);
    return r ? 0 : 1; /* 0 => exists */
}

static int getmetadata(void *sc, const char *extname, const char *keyname, char **res)
{
    script_data_t *sd = (script_data_t *)sc;
    struct buf attrib = BUF_INITIALIZER;
    char *intname = extname ? mboxname_from_external(extname, sd->ns, mbname_userid(sd->mbname)) : xstrdup("");
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
   to return, and we also can't expose our the receipients to the message */
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

static int getbody(void *mc, const char **content_types,
                   sieve_bodypart_t ***parts)
{
    deliver_data_t *mydata = (deliver_data_t *) mc;
    message_data_t *m = mydata->m;
    int r = 0;

    if (!mydata->content->body) {
        /* parse the message body if we haven't already */
        r = message_parse_file(m->f, &mydata->content->base,
                               &mydata->content->len, &mydata->content->body);
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

static int send_rejection(const char *origid,
                          const char *rejto,
                          const char *origreceip,
                          const char *mailreceip,
                          const char *reason,
                          struct protstream *file)
{
    FILE *sm;
    const char *smbuf[10];
    char buf[8192], *namebuf;
    int i, sm_stat;
    time_t t;
    char datestr[RFC822_DATETIME_MAX+1];
    pid_t sm_pid, p;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;

    smbuf[0] = "sendmail";
    smbuf[1] = "-i";            /* ignore dots */
    smbuf[2] = "-f";
    smbuf[3] = "<>";
    smbuf[4] = "--";
    smbuf[5] = rejto;
    smbuf[6] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
    if (sm == NULL) {
        return -1;
    }

    t = time(NULL);
    p = getpid();
    snprintf(buf, sizeof(buf), "<cmu-sieve-%d-%d-%d@%s>", (int) p, (int) t,
             global_outgoing_count++, config_servername);

    namebuf = make_sieve_db(mailreceip);

    time_to_rfc822(t, datestr, sizeof(datestr));

    dkey.id = buf;
    dkey.to = namebuf;
    dkey.date = datestr;
    duplicate_mark(&dkey, t, 0);

    fprintf(sm, "Message-ID: %s\r\n", buf);
    fprintf(sm, "Date: %s\r\n", datestr);

    fprintf(sm, "X-Sieve: %s\r\n", SIEVE_VERSION);
    fprintf(sm, "From: Mail Sieve Subsystem <%s>\r\n",
            config_getstring(IMAPOPT_POSTMASTER));
    fprintf(sm, "To: <%s>\r\n", rejto);
    fprintf(sm, "MIME-Version: 1.0\r\n");
    fprintf(sm, "Content-Type: "
            "multipart/report; report-type=disposition-notification;"
            "\r\n\tboundary=\"%d/%s\"\r\n", (int) p, config_servername);
    fprintf(sm, "Subject: Automatically rejected mail\r\n");
    fprintf(sm, "Auto-Submitted: auto-replied (rejected)\r\n");
    fprintf(sm, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* this is the human readable status report */
    fprintf(sm, "--%d/%s\r\n", (int) p, config_servername);
    fprintf(sm, "Content-Type: text/plain; charset=utf-8\r\n");
    fprintf(sm, "Content-Disposition: inline\r\n");
    fprintf(sm, "Content-Transfer-Encoding: 8bit\r\n\r\n");

    fprintf(sm, "Your message was automatically rejected by Sieve, a mail\r\n"
            "filtering language.\r\n\r\n");
    fprintf(sm, "The following reason was given:\r\n%s\r\n\r\n", reason);

    /* this is the MDN status report */
    fprintf(sm, "--%d/%s\r\n"
            "Content-Type: message/disposition-notification\r\n\r\n",
            (int) p, config_servername);
    fprintf(sm, "Reporting-UA: %s; Cyrus %s/%s\r\n",
            config_servername, cyrus_version(), SIEVE_VERSION);
    if (origreceip)
        fprintf(sm, "Original-Recipient: rfc822; %s\r\n", origreceip);
    fprintf(sm, "Final-Recipient: rfc822; %s\r\n", mailreceip);
    if (origid)
        fprintf(sm, "Original-Message-ID: %s\r\n", origid);
    fprintf(sm, "Disposition: "
            "automatic-action/MDN-sent-automatically; deleted\r\n");
    fprintf(sm, "\r\n");

    /* this is the original message */
    fprintf(sm, "--%d/%s\r\nContent-Type: message/rfc822\r\n\r\n",
            (int) p, config_servername);
    prot_rewind(file);
    while ((i = prot_read(file, buf, sizeof(buf))) > 0) {
        fwrite(buf, i, 1, sm);
    }
    fprintf(sm, "\r\n\r\n");
    fprintf(sm, "--%d/%s--\r\n", (int) p, config_servername);

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    return sm_stat;     /* sendmail exit value */
}

#ifdef WITH_DAV
#include <libxml/uri.h>

static char *get_addrbook_mboxname(const char *list, const char *userid)
{
    const char *addrbook_urn_full = "urn:ietf:params:sieve:addrbook:";
    const char *addrbook_urn_abbrev = ":addrbook:";
    char *abook = NULL, *mboxname = NULL;

    /* percent-decode list URI */
    char *uri = xmlURIUnescapeString(list, strlen(list), NULL);

    if (!strncmp(uri, addrbook_urn_full, strlen(addrbook_urn_full))) {
        abook = xstrdup(uri + strlen(addrbook_urn_full));
    }
    else if (!strncmp(uri, addrbook_urn_abbrev, strlen(addrbook_urn_abbrev))) {
        abook = xstrdup(uri + strlen(addrbook_urn_abbrev));
    }

    free(uri);

    /* MUST match default addressbook case-insensitively */
    if (!strcasecmp(abook, "Default")) {
        abook[0] = 'D';
        lcase(abook+1);
    }

    /* construct mailbox name of addressbook */
    mboxname = carddav_mboxname(userid, abook);

    /* see if addressbook mailbox exists */
    if (mboxlist_lookup(mboxname, NULL, NULL) == 0) return mboxname;
    else {
        free(mboxname);
        return NULL;
    }
}

static int listvalidator(void *ic, const char *list)
{
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    char *abook = get_addrbook_mboxname(list, ctx->userid);
    int ret = abook ? SIEVE_OK : SIEVE_FAIL;

    free(abook);

    return ret;
}

static int listcompare(const char *text, size_t tlen __attribute__((unused)),
                       const char *list, strarray_t *match_vars, void *rock)
{
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) rock;
    char *abook = get_addrbook_mboxname(list, ctx->userid);
    int ret = 0;

    if (!abook) return 0;

    if (!ctx->carddavdb) {
        /* open user's CardDAV DB */
        ctx->carddavdb = carddav_open_userid(ctx->userid);
    }
    if (ctx->carddavdb) {
        /* search for email address in addressbook */
        strarray_t *uids =
            carddav_getemail2uids(ctx->carddavdb, text, abook);
        ret = strarray_size(uids);

        strarray_free(uids);
    }

    if (ret && match_vars) {
        /* found a match - set $0 */
        strarray_add(match_vars, text);
    }

    free(abook);

    return ret;
}

static int list_addresses(void *rock, struct carddav_data *cdata)
{
    strarray_t *smbuf = (strarray_t *) rock;
    int i;

    /* XXX  Lookup up emails for vcard */
    if (!cdata->emails) return 0;
    for (i = 0; i < strarray_size(cdata->emails); i++) {
        /* Find preferred address */
        strarray_append(smbuf, strarray_nth(cdata->emails, i));
    }

    return 0;
}
#endif /* WITH_DAV */

static int send_forward(sieve_redirect_context_t *rc,
                        struct sieve_interp_ctx *ctx,
                        char *return_path,
                        struct protstream *file)
{
    FILE *sm;
    strarray_t smbuf = STRARRAY_INITIALIZER;
    int sm_stat;
    char buf[1024];
    pid_t sm_pid;
    int body = 0, skip;

    /* build argv[] for sendmail */
    strarray_append(&smbuf, "sendmail");
    strarray_append(&smbuf, "-i");            /* ignore dots */
    strarray_append(&smbuf, "-f");
    strarray_append(&smbuf, return_path && *return_path ? return_path : "<>");
    strarray_append(&smbuf, "--");
    if (rc->is_ext_list) {
#ifdef WITH_DAV
        char *abook = get_addrbook_mboxname(rc->addr, ctx->userid);

        if (abook && !ctx->carddavdb) {
            /* open user's CardDAV DB */
            ctx->carddavdb = carddav_open_userid(ctx->userid);
        }
        if (!(abook && ctx->carddavdb)) {
            strarray_fini(&smbuf);
            return SIEVE_FAIL;
        }
        carddav_foreach(ctx->carddavdb, abook, &list_addresses, &smbuf); 
        free(abook);
#endif
    }
    else strarray_append(&smbuf, rc->addr);
    strarray_appendm(&smbuf, NULL);

    sm_pid = open_sendmail((const char **) smbuf.data, &sm);
    strarray_fini(&smbuf);

    if (sm == NULL) {
        return -1;
    }

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
            if (!skip) fwrite(buf, strlen(buf), 1, sm);
        } while (buf[strlen(buf)-1] != '\n' &&
                 prot_fgets(buf, sizeof(buf), file));
    }

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    return sm_stat;     /* sendmail exit value */
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
        sievedb = make_sieve_db(mbname_userid(sd->mbname));

        dkey.id = buf;
        dkey.to = sievedb;
        dkey.date = ((deliver_data_t *) mc)->m->date;
        /* ok, let's see if we've redirected this message before */
        if (duplicate_check(&dkey)) {
            duplicate_log(&dkey, "redirect");
            return SIEVE_OK;
        }
    }

    if (sd->edited_header) {
        mdata = setup_special_delivery(mdata);
        if (!mdata) return SIEVE_FAIL;
        else m = mdata->m;
    }

    res = send_forward(rc, ctx, m->return_path, m->data);

    if (sd->edited_header) cleanup_special_delivery(mdata);

    if (res == 0) {
        /* mark this message as redirected */
        if (sievedb) duplicate_mark(&dkey, time(NULL), 0);

        snmp_increment(SIEVE_REDIRECT, 1);
        syslog(LOG_INFO, "sieve redirected: %s to: %s",
               m->id ? m->id : "<nomsgid>", rc->addr);
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: redirect sessionid=<%s> message-id=%s target=<%s>",
                   session_id(), m->id ? m->id : "<nomsgid>", rc->addr);
        return SIEVE_OK;
    } else {
        if (res == -1) {
            *errmsg = "Could not spawn sendmail process";
        } else {
            *errmsg = sendmail_errstr(res);
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

    snmp_increment(SIEVE_DISCARD, 1);

    /* ok, we won't file it, but log it */
    syslog(LOG_INFO, "sieve discarded: %s",
           md->id ? md->id : "<nomsgid>");
    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: discard sessionid=<%s> message-id=%s",
               session_id(), md->id ? md->id : "<nomsgid>");

    return SIEVE_OK;
}

static int sieve_reject(void *ac,
                        void *ic __attribute__((unused)),
                        void *sc, void *mc, const char **errmsg)
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
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

    if (rc->is_extended || !need_encode) {
        char *msg = need_encode ?
            charset_qpencode_mimebody(rc->msg, strlen(rc->msg), NULL) :
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

        snmp_increment(SIEVE_REJECT, 1);
        syslog(LOG_INFO, "sieve LMTP rejected: %s",
               md->id ? md->id : "<nomsgid>");
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: LMTP reject sessionid=<%s> message-id=%s",
                   session_id(), md->id ? md->id : "<nomsgid>");

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
                   "auditlog: discard-reject sessionid=<%s> message-id=%s",
                   session_id(), md->id ? md->id : "<nomsgid>");
        return SIEVE_OK;
    }

    body = msg_getheader(md, "original-recipient");
    origreceip = body ? body[0] : NULL;
    if ((res = send_rejection(md->id, md->return_path,
                              origreceip, mbname_userid(sd->mbname),
                              rc->msg, md->data)) == 0) {
        snmp_increment(SIEVE_REJECT, 1);
        syslog(LOG_INFO, "sieve rejected: %s to: %s",
               md->id ? md->id : "<nomsgid>", md->return_path);
        if (config_auditlog)
            syslog(LOG_NOTICE,
                   "auditlog: reject sessionid=<%s> message-id=%s target=<%s>",
                   session_id(), md->id ? md->id : "<nomsgid>", md->return_path);
        return SIEVE_OK;
    } else {
        if (res == -1) {
            *errmsg = "Could not spawn sendmail process";
        } else {
            *errmsg = sendmail_errstr(res);
        }
        return SIEVE_FAIL;
    }
}

static void dump_header(const char *name, const char *value, void *rock)
{
    /* Q-encode the value */
    char *mimehdr = charset_encode_mimeheader(value, strlen(value));
    char *freeme = mimehdr;
    size_t maxlen = 78 - (strlen(name) + 2);

    /* write header name */
    fprintf((FILE *) rock, "%s: ", name);

    /* fold value */
    /* XXX  Do we want/need to do smarter folding on structured headers? */
    while (strlen(mimehdr) > maxlen) {
        char *p;

        /* look for first whitespace prior to maxlen */
        for (p = mimehdr + maxlen; p > mimehdr; p--) {
            if (*p == ' ' || *p == '\t') {
                *p = '\t';  /* make sure its a TAB */
                break;
            }
        }
        if (p == mimehdr) break;

        /* write chunk of value + fold */
        fprintf((FILE *) rock, "%.*s\r\n", (int) (p - mimehdr), mimehdr);

        mimehdr = p;
        maxlen = 78;
    }

    /* write remainder of value */
    fprintf((FILE *) rock, "%s\r\n", mimehdr);

    free(freeme);
}

static deliver_data_t *setup_special_delivery(deliver_data_t *mydata)
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
        spool_enum_hdrcache(mydata->m->hdrcache, &dump_header, md.f);

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
    append_removestage(mydata->stage);
    if (mydata->content->base) {
        map_free(&mydata->content->base, &mydata->content->len);
        if (mydata->content->body) {
            message_free_body(mydata->content->body);
            free(mydata->content->body);
        }
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
    message_data_t *md = mdata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mdata->cur_rcpt);
    char namebuf[MAX_MAILBOX_BUFFER];
    int ret;

    char *intname = mboxname_from_external(fc->mailbox, sd->ns, mbname_userid(sd->mbname));
    strncpy(namebuf, intname, sizeof(namebuf));
    free(intname);

    if (sd->edited_header) {
        mdata = setup_special_delivery(mdata);
        if (!mdata) return SIEVE_FAIL;
        else md = mdata->m;
    }

    ret = deliver_mailbox(md->f, mdata->content, mdata->stage, md->size,
                          fc->imapflags,
                          mbname_userid(sd->mbname), sd->authstate, md->id,
                          mbname_userid(sd->mbname), mdata->notifyheader,
                          namebuf, md->date, quotaoverride, 0);

    if (ret == IMAP_MAILBOX_NONEXISTENT) {
        /* if "plus" folder under INBOX, then try to create it */
        ret = autosieve_createfolder(mbname_userid(sd->mbname), sd->authstate, namebuf, fc->do_create);

        /* Try to deliver the mail again. */
        if (!ret)
            ret = deliver_mailbox(md->f, mdata->content, mdata->stage, md->size,
                                  fc->imapflags,
                                  mbname_userid(sd->mbname), sd->authstate, md->id,
                                  mbname_userid(sd->mbname), mdata->notifyheader,
                                  namebuf, md->date, quotaoverride, 0);
    }

    if (sd->edited_header) cleanup_special_delivery(mdata);

    if (!ret) {
        snmp_increment(SIEVE_FILEINTO, 1);
        return SIEVE_OK;
    } else {
        *errmsg = error_message(ret);
        return SIEVE_FAIL;
    }
}

static int sieve_keep(void *ac,
                      void *ic __attribute__((unused)),
                      void *sc, void *mc, const char **errmsg)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    deliver_data_t *mydata = (deliver_data_t *) mc;
    int ret;

    if (sd->edited_header) {
        mydata = setup_special_delivery(mydata);
        if (!mydata) return SIEVE_FAIL;
    }

    ret = deliver_local(mydata, kc->imapflags, sd->mbname);

    if (sd->edited_header) cleanup_special_delivery(mydata);
 
    if (!ret) {
        snmp_increment(SIEVE_KEEP, 1);
        return SIEVE_OK;
    } else {
        *errmsg = error_message(ret);
        return SIEVE_FAIL;
    }
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
        int nopt = 0;

        snmp_increment(SIEVE_NOTIFY, 1);

        /* count options */
        while (nc->options[nopt]) nopt++;

        /* "default" is a magic value that implies the default */
        notify(!strcmp("default",nc->method) ? notifier : nc->method,
               "SIEVE", nc->priority, mbname_userid(sd->mbname), NULL,
               nopt, nc->options, nc->message, nc->fname);
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

    snmp_increment(SIEVE_VACATION_TOTAL, 1);

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

static int send_response(void *ac,
                         void *ic __attribute__((unused)),
                         void *sc, void *mc, const char **errmsg)
{
    FILE *sm;
    const char *smbuf[10];
    char outmsgid[8192], *sievedb, *subj;
    int i, sl, sm_stat;
    time_t t;
    char datestr[RFC822_DATETIME_MAX+1];
    pid_t sm_pid, p;
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *md = ((deliver_data_t *) mc)->m;
    script_data_t *sdata = (script_data_t *) sc;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;

    smbuf[0] = "sendmail";
    smbuf[1] = "-i";            /* ignore dots */
    smbuf[2] = "-f";
    smbuf[3] = "<>";
    smbuf[4] = "--";
    smbuf[5] = src->addr;
    smbuf[6] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
    if (sm == NULL) {
        *errmsg = "Could not spawn sendmail process";
        return -1;
    }

    t = time(NULL);
    p = getpid();
    snprintf(outmsgid, sizeof(outmsgid), "<cmu-sieve-%d-%d-%d@%s>",
             (int) p, (int) t, global_outgoing_count++, config_servername);

    fprintf(sm, "Message-ID: %s\r\n", outmsgid);

    time_to_rfc822(t, datestr, sizeof(datestr));
    fprintf(sm, "Date: %s\r\n", datestr);

    fprintf(sm, "X-Sieve: %s\r\n", SIEVE_VERSION);
    fprintf(sm, "From: <%s>\r\n", src->fromaddr);
    fprintf(sm, "To: <%s>\r\n", src->addr);
    /* check that subject is sane */
    sl = strlen(src->subj);
    for (i = 0; i < sl; i++)
        if (Uiscntrl(src->subj[i])) {
            src->subj[i] = '\0';
            break;
        }
    subj = charset_encode_mimeheader(src->subj, strlen(src->subj));
    fprintf(sm, "Subject: %s\r\n", subj);
    free(subj);
    if (md->id) fprintf(sm, "In-Reply-To: %s\r\n", md->id);
    fprintf(sm, "Auto-Submitted: auto-replied (vacation)\r\n");
    fprintf(sm, "MIME-Version: 1.0\r\n");
    if (src->mime) {
        fprintf(sm, "Content-Type: multipart/mixed;"
                "\r\n\tboundary=\"%d/%s\"\r\n", (int) p, config_servername);
        fprintf(sm, "\r\nThis is a MIME-encapsulated message\r\n\r\n");
        fprintf(sm, "--%d/%s\r\n", (int) p, config_servername);
    } else {
        fprintf(sm, "Content-Type: text/plain; charset=utf-8\r\n");
        fprintf(sm, "Content-Transfer-Encoding: 8bit\r\n");
        fprintf(sm, "\r\n");
    }

    fprintf(sm, "%s\r\n", src->msg);

    if (src->mime) {
        fprintf(sm, "\r\n--%d/%s--\r\n", (int) p, config_servername);
    }
    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    if (sm_stat == 0) { /* sendmail exit value */
        sievedb = make_sieve_db(mbname_userid(sdata->mbname));

        dkey.id = outmsgid;
        dkey.to = sievedb;
        dkey.date = ((deliver_data_t *) mc)->m->date;
        duplicate_mark(&dkey, t, 0);

        snmp_increment(SIEVE_VACATION_REPLIED, 1);

        return SIEVE_OK;
    } else {
        *errmsg = sendmail_errstr(sm_stat);
        return SIEVE_FAIL;
    }
}

/* vacation support */
static sieve_vacation_t vacation = {
    1 * DAY2SEC,                /* min response */
    31 * DAY2SEC,               /* max response */
    &autorespond,               /* autorespond() */
    &send_response,             /* send_response() */
};

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

sieve_interp_t *setup_sieve(struct sieve_interp_ctx *ctx)
{
    sieve_interp_t *interp = NULL;
    int res;
    static strarray_t mark = STRARRAY_INITIALIZER;

    if (!mark.count)
        strarray_append(&mark, "\\flagged");

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
    sieve_register_imapflags(interp, &mark);
    sieve_register_notify(interp, &sieve_notify);
    sieve_register_size(interp, &getsize);
    sieve_register_mailboxexists(interp, &getmailboxexists);
    sieve_register_metadata(interp, &getmetadata);
    sieve_register_header(interp, &getheader);
    sieve_register_addheader(interp, &addheader);
    sieve_register_deleteheader(interp, &deleteheader);
    sieve_register_fname(interp, &getfname);

    sieve_register_envelope(interp, &getenvelope);
    sieve_register_body(interp, &getbody);
    sieve_register_include(interp, &getinclude);

    res = sieve_register_vacation(interp, &vacation);
    if (res != SIEVE_OK) {
        syslog(LOG_ERR, "sieve_register_vacation() returns %d\n", res);
        fatal("sieve_register_vacation()", EC_SOFTWARE);
    }
#ifdef WITH_DAV
    sieve_register_listvalidator(interp, &listvalidator);
    sieve_register_listcompare(interp, &listcompare);
#endif
    sieve_register_parse_error(interp, &sieve_parse_error_handler);
    sieve_register_execute_error(interp, &sieve_execute_error_handler);

    return interp;
}

static void _rm_dots(char *p)
{
    for (; *p; p++) {
        if (*p == '.') *p = '^';
    }
}

static int sieve_find_script(const char *user, const char *domain,
                             const char *script, char *fname, size_t size)
{
    char *ext = NULL;

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
    } else { /* look in sieve_dir */
        size_t len = strlcpy(fname, sieve_dir, size);

        if (domain) {
            char dhash = (char) dir_hash_c(domain, config_fulldirhash);
            len += snprintf(fname+len, size-len, "%s%c/%s",
                            FNAME_DOMAINDIR, dhash, domain);
        }

        if (!user) { /* global script */
            len = strlcat(fname, "/global/", size);
        }
        else {
            char hash = (char) dir_hash_c(user, config_fulldirhash);
            char *usercopy = xstrdup(user);  // stupid hashing of names, we SHOULD just allow dots on disk
            _rm_dots(usercopy);
            len += snprintf(fname+len, size-len, "/%c/%s/", hash, usercopy);
            free(usercopy);

            if (!script) { /* default script */
                char *bc_fname;

                strlcat(fname, "defaultbc", size);

                bc_fname = sieve_getdefaultbcfname(fname);
                if (bc_fname) {
                    sieve_rebuild(NULL, bc_fname, 0, NULL);
                    free(bc_fname);
                }

                return 0;
            }
        }

        snprintf(fname+len, size-len, "%s.bc", script);
    }

    /* don't do this for ~username ones */
    ext = strrchr(fname, '.');
    if (ext && !strcmp(ext, ".bc"))
        sieve_rebuild(NULL, fname, 0, NULL);

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
    sdata.edited_header = 0;

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

    if (createsievefolder) {
        /* Folder is already in internal namespace format */
        r = mboxlist_createmailbox(internalname, 0, NULL,
                                   1, userid, auth_state, 0, 0, 0, 1, NULL);
        if (!r) {
            mboxlist_changesub(internalname, userid, auth_state, 1, 1, 1);
            syslog(LOG_DEBUG, "autosievefolder: User %s, folder %s creation succeeded",
                   userid, internalname);
            return 0;
        } else {
            syslog(LOG_ERR, "autosievefolder: User %s, folder %s creation failed. %s",
                   userid, internalname, error_message(r));
            return r;
        }
    }

    return IMAP_MAILBOX_NONEXISTENT;
}

