/* lmtpengine.c: LMTP protocol engine
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "times.h"
#include "global.h"
#include "exitcodes.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "version.h"
#include "tok.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/lmtp_err.h"
#include "imap/lmtpstats.h"
#include "imap/mupdate_err.h"

#include "lmtpengine.h"
#include "tls.h"
#include "telemetry.h"

#define RCPT_GROW 30

/* data per message */
struct address_data {
    mbname_t *mbname;
    int ignorequota;
    int status;
    char *status_msg;
};

struct clientdata {
    struct protstream *pin;
    struct protstream *pout;
    int fd;

    const char *clienthost;
    char lhlo_param[250];

    sasl_conn_t *conn;

    enum {
        TLSCERT_AUTHED = -2,  /* -2: TLS cert auth'd, but no AUTH issued */
        EXTERNAL_AUTHED = -1, /* -1: external auth'd, but no AUTH issued */
        NOAUTH = 0,
        DIDAUTH = 1
    } authenticated;

#ifdef HAVE_SSL
    SSL *tls_conn;
#endif /* HAVE_SSL */
    int starttls_done;
};

/* defined in lmtpd.c or lmtpproxyd.c */
extern int deliver_logfd;

extern int saslserver(sasl_conn_t *conn, const char *mech,
                      const char *init_resp, const char *resp_prefix,
                      const char *continuation, const char *empty_chal,
                      struct protstream *pin, struct protstream *pout,
                      int *sasl_result, char **success_data);

static struct {
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};


#ifdef USING_SNMPGEN
/* round to nearest 1024 bytes and return number of Kbytes.
 used for SNMP updates. */
static int roundToK(int x)
{
    double rd = (x*1.0)/1024.0;
    int ri = x/1024;

    if (rd-ri < 0.5)
        return ri;
    else
        return ri+1;
}
#else
#define roundToK(x)
#endif /* USING_SNMPGEN */

static void send_lmtp_error(struct protstream *pout, int r, const char *msg)
{
    int code = r;

    switch (r) {
    case LMTP_MESSAGE_REJECTED:
        if (msg) {
            const char *cur, *next;
            tok_t tok;

            tok_initm(&tok, charset_qpencode_mimebody(msg, strlen(msg), NULL),
                      "\r\n", TOK_FREEBUFFER);
            for (cur = tok_next(&tok); (next = tok_next(&tok)); cur = next) {
                prot_printf(pout, "550-5.7.1 %s\r\n", cur);
            }
            prot_printf(pout, "550 5.7.1 %s\r\n", cur);
            tok_fini(&tok);
            return;
        }
        break;

    case 0:
        code = LMTP_OK;
        break;

    case IMAP_SERVER_UNAVAILABLE:
    case MUPDATE_NOCONN:
    case MUPDATE_NOAUTH:
    case MUPDATE_TIMEOUT:
    case MUPDATE_PROTOCOL_ERROR:
        code = LMTP_SERVER_FAILURE;
        break;

    case IMAP_NOSPACE:
        code = LMTP_SERVER_FULL;
        break;

    case IMAP_PERMISSION_DENIED:
        if (LMTP_LONG_ERROR_MSGS) {
            prot_printf(pout, error_message(LMTP_NOT_AUTHORIZED_LONG),
                        config_getstring(IMAPOPT_POSTMASTER));
        }
        code = LMTP_NOT_AUTHORIZED;
        break;

    case IMAP_QUOTA_EXCEEDED:
        if(config_getswitch(IMAPOPT_LMTP_OVER_QUOTA_PERM_FAILURE)) {
            /* Not Default - Perm Failure */
            code = LMTP_MAILBOX_FULL_PERM;
        } else {
            /* Default - Temp Failure */
            code = LMTP_MAILBOX_FULL;
        }
        break;

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
        code = LMTP_MAILBOX_ERROR;
        break;

    case IMAP_MAILBOX_MOVED:
    case IMAP_MAILBOX_RESERVED:
    case IMAP_MAILBOX_DISABLED:
        code = LMTP_MAILBOX_DISABLED;
        break;

    case IMAP_MESSAGE_CONTAINSNULL:
    case IMAP_MESSAGE_CONTAINSNL:
    case IMAP_MESSAGE_CONTAINS8BIT:
    case IMAP_MESSAGE_BADHEADER:
    case IMAP_MESSAGE_NOBLANKLINE:
        code = LMTP_MESSAGE_INVALID;
        break;

    case IMAP_MAILBOX_NONEXISTENT:
        /* XXX Might have been moved to other server */
        if (LMTP_LONG_ERROR_MSGS) {
            prot_puts(pout, error_message(LMTP_USER_UNKNOWN_LONG));
        }
        code = LMTP_USER_UNKNOWN;
        break;

    case IMAP_PROTOCOL_BAD_PARAMETERS:
        code = LMTP_PROTOCOL_ERROR;
        break;

    case IMAP_IOERROR:
    case IMAP_AGAIN:
    case MUPDATE_BADPARAM:
    default:
        /* Some error we're not expecting. */
        code = LMTP_SYSTEM_ERROR;
        break;
    }

    prot_printf(pout, error_message(code), error_message(r), session_id());
    prot_puts(pout, "\r\n");
}

/* ----- this section defines functions on message_data_t.
   ----- access functions and the like, etc. */

/* returns non-zero on failure */
static int msg_new(message_data_t **m, const struct namespace *ns)
{
    message_data_t *ret = (message_data_t *) xmalloc(sizeof(message_data_t));

    ret->data = NULL;
    ret->f = NULL;
    ret->id = NULL;
    ret->size = 0;
    ret->return_path = NULL;
    ret->rcpt = NULL;
    ret->rcpt_num = 0;
    ret->date = NULL;

    ret->authuser = NULL;
    ret->authstate = NULL;

    ret->rock = NULL;

    ret->hdrcache = spool_new_hdrcache();

    ret->ns = ns;

    *m = ret;
    return 0;
}

static void msg_free(message_data_t *m)
{
    int i;

    if (m->data) {
        prot_free(m->data);
    }
    if (m->f) {
        fclose(m->f);
    }
    if (m->id) {
        free(m->id);
    }

    if (m->return_path) {
        free(m->return_path);
    }
    if (m->rcpt) {
        for (i = 0; i < m->rcpt_num; i++) {
            mbname_free(&m->rcpt[i]->mbname);
            free(m->rcpt[i]->status_msg);
            free(m->rcpt[i]);
        }
        free(m->rcpt);
    }
    if (m->date) {
      free(m->date);
     }

    if (m->authuser) {
        free(m->authuser);
        if (m->authstate) auth_freestate(m->authstate);
    }

    spool_free_hdrcache(m->hdrcache);

    free(m);
}

const char **msg_getheader(message_data_t *m, const char *phead)
{
    assert(m && phead);

    return spool_getheader(m->hdrcache, phead);
}

int msg_getsize(message_data_t *m)
{
    return m->size;
}

int msg_getnumrcpt(message_data_t *m)
{
    return m->rcpt_num;
}

const mbname_t *msg_getrcpt(message_data_t *m, int rcpt_num)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    return m->rcpt[rcpt_num]->mbname;
}

const char *msg_getrcptall(message_data_t *m, int rcpt_num)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    return mbname_recipient(m->rcpt[rcpt_num]->mbname, m->ns);
}

int msg_getrcpt_ignorequota(message_data_t *m, int rcpt_num)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    return m->rcpt[rcpt_num]->ignorequota;
}

/* set a recipient status; 'r' should be an IMAP error code that will be
   translated into an LMTP status code */
void msg_setrcpt_status(message_data_t *m, int rcpt_num, int r, const char *msg)
{
    assert(0 <= rcpt_num && rcpt_num < m->rcpt_num);
    if (!m->rcpt[rcpt_num]->status) {
        m->rcpt[rcpt_num]->status = r;
        m->rcpt[rcpt_num]->status_msg = xstrdupnull(msg);
    }
}

void *msg_getrock(message_data_t *m)
{
    return m->rock;
}

void msg_setrock(message_data_t *m, void *rock)
{
    m->rock = rock;
}

/* return a malloc'd string representing the authorized user.
 advance 'strp' over the parameter */
static char *parseautheq(char **strp)
{
    char *ret;
    char *str;
    char *s = *strp;

    if (!strcmp(s, "<>")) {
        *strp = s + 2;
        return NULL;
    }

    ret = (char *) xmalloc(strlen(s)+1);
    ret[0]='\0';
    str = ret;

    if (*s == '<') s++;         /* we'll be liberal and accept "<foo>" */
    while (1)
    {
        /* hexchar */
        if (*s == '+')
        {
            int lup;
            *str = '\0';
            s++;

            for (lup=0;lup<2;lup++)
            {
                if ((*s>='0') && (*s<='9'))
                    (*str) = (*str) & (*s - '0');
                else if ((*s>='A') && (*s<='F'))
                    (*str) = (*str) & (*s - 'A' + 10);
                else {
                    free(ret);
                    *strp = s;
                    return NULL;
                }
                if (lup==0)
                {
                    (*str) = (*str) << 4;
                    s++;
                }
            }
            str++;

        } else if ((*s >= '!') && (*s <='~') && (*s!='+') && (*s!='=')) {
            /* ascii char */
            *str = *s;
            str++;
        } else {
            /* bad char or end-of-line */
            break;
        }
        s++;
    }

    *strp = s;
    if (*s && (*s!=' ')) { free(ret); return NULL; }

    *str = '\0';

    /* take off trailing '>' */
    if ((str!=ret) && ( *(str-1)=='>'))
    {
        *(str-1) = '\0';
    }

    return ret;
}

/* return malloc'd string containing the address */
static char *parseaddr(char *s)
{
    char *p;
    int lmtp_strict_rfc2821 = config_getswitch(IMAPOPT_LMTP_STRICT_RFC2821);

    p = s;

    if (*p++ != '<') return 0;

    /* at-domain-list */
    while (*p == '@') {
        p++;
        if (*p == '[') {
            p++;
            while (Uisdigit(*p) || *p == '.') p++;
            if (*p++ != ']') return 0;
        }
        else {
            while (Uisalnum(*p) || *p == '.' || *p == '-') p++;
        }
        if (*p == ',' && p[1] == '@') p++;
        else if (*p == ':' && p[1] != '@') p++;
        else return 0;
    }

    /* local-part */
    if (*p == '\"') {
        p++;
        while (*p && *p != '\"') {
            if (*p == '\\') {
                if (!*++p) return 0;
            }
            p++;
        }
        if (!*p++) return 0;
    }
    else {
        while (*p && *p != '@' && *p != '>') {
            if (*p == '\\') {
                if (!*++p) return 0;
            }
            else {
                if (*p & 128 && !lmtp_strict_rfc2821) {
                    /* this prevents us from becoming a backscatter
                       source if our MTA allows 8bit in local-part
                       of adresses. */
                    *p = 'X';
                }
                if (*p <= ' ' || (*p & 128) ||
                    strchr("<>()[]\\,;:\"", *p)) return 0;
            }
            p++;
        }
    }

    /* @domain */
    if (*p == '@') {
        p++;
        if (*p == '[') {
            p++;
            while (Uisdigit(*p) || *p == '.') p++;
            if (*p++ != ']') return 0;
        }
        else {
            while (Uisalnum(*p) || *p == '.' || *p == '-') p++;
        }
    }

    if (*p++ != '>') return 0;
    if (*p && *p != ' ') return 0;

    return xstrndup(s, p - s);
}

/* clean off the <> from the return path */
static void clean_retpath(char *rpath)
{
    int sl;

    /* Remove any angle brackets around return path */
    if (*rpath == '<') {
        sl = strlen(rpath);
        /* use strlen(rpath) so we move the NUL too */
        memmove(rpath, rpath+1, sl);
        sl--; /* string is one shorter now */
        if (rpath[sl-1] == '>') {
            rpath[sl-1] = '\0';
        }
    }
}

/*
 * Destructively remove any whitespace and 822 comments
 * from string pointed to by 'buf'.  Does not handle continuation header
 * lines.
 */
static void clean822space(char *buf)
{
    char *from=buf, *to=buf;
    int c;
    int commentlevel = 0;

    while ((c = *from++)!=0) {
        switch (c) {
        case '\r':
        case '\n':
        case '\0':
            *to = '\0';
            return;

        case ' ':
        case '\t':
            continue;

        case '(':
            commentlevel++;
            break;

        case ')':
            if (commentlevel) commentlevel--;
            break;

        case '\\':
            if (commentlevel && *from) from++;
            /* FALL THROUGH */

        default:
            if (!commentlevel) *to++ = c;
            break;
        }
    }
}

/*
 * file in the message structure 'm' from 'pin', assuming a dot-stuffed
 * stream a la lmtp.
 *
 * returns 0 on success, imap error code on failure
 */
static int savemsg(struct clientdata *cd,
                   const struct lmtp_func *func,
                   message_data_t *m)
{
    FILE *f;
    struct stat sbuf;
    const char **body;
    int r;
    int nrcpts = m->rcpt_num;
    time_t now = time(NULL);
    static unsigned msgid_count = 0;
    char datestr[RFC822_DATETIME_MAX+1], tls_info[250] = "";
    const char *skipheaders[] = {
        "Return-Path",  /* need to remove (we add our own) */
        NULL
    };
    char *addbody, *fold[5], *p;
    int addlen, nfold, i;

    /* Copy to spool file */
    f = func->spoolfile(m);
    if (!f) {
        prot_printf(cd->pout,
                    "451 4.3.%c cannot create temporary file: %s\r\n",
                    (
#ifdef EDQUOT
                        errno == EDQUOT ||
#endif
                        errno == ENOSPC) ? '1' : '2',
                    error_message(errno));
        return IMAP_IOERROR;
    }

    prot_printf(cd->pout, "354 go ahead\r\n");

    if (m->return_path && func->addretpath) { /* add the return path */
        char *rpath = m->return_path;
        const char *hostname = 0;

        clean_retpath(rpath);
        /* Append our hostname if there's no domain in address */
        hostname = NULL;
        if (!strchr(rpath, '@') && strlen(rpath) > 0) {
            hostname = config_servername;
        }

        addlen = 2 + strlen(rpath) + (hostname ? 1 + strlen(hostname) : 0);
        addbody = xmalloc(addlen + 1);
        sprintf(addbody, "<%s%s%s>",
                rpath, hostname ? "@" : "", hostname ? hostname : "");
        fprintf(f, "Return-Path: %s\r\n", addbody);
        spool_cache_header(xstrdup("Return-Path"), addbody, m->hdrcache);
    }

    /* add a received header */
    time_to_rfc822(now, datestr, sizeof(datestr));
    addlen = 8 + strlen(cd->lhlo_param) + strlen(cd->clienthost);
    if (m->authuser) addlen += 28 + strlen(m->authuser) + 5; /* +5 for ssf */
    addlen += 25 + strlen(config_servername) + strlen(cyrus_version());
#ifdef HAVE_SSL
    if (cd->tls_conn) {
        addlen += 3 + tls_get_info(cd->tls_conn, tls_info, sizeof(tls_info));
    }
#endif
    addlen += 2 + strlen(datestr);
    p = addbody = xmalloc(addlen + 1);

    nfold = 0;
    p += sprintf(p, "from %s (%s)", cd->lhlo_param, cd->clienthost);
    fold[nfold++] = p;
    if (m->authuser) {
        const void *ssfp;
        sasl_ssf_t ssf;
        sasl_getprop(cd->conn, SASL_SSF, &ssfp);
        ssf = *((sasl_ssf_t *) ssfp);
        p += sprintf(p, " (authenticated user=%s bits=%d)", m->authuser, ssf);
        fold[nfold++] = p;
    }

    /* We are always atleast "with LMTPA" -- no unauth delivery */
    p += sprintf(p, " by %s", config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        p += sprintf(p, " (Cyrus %s)", cyrus_version());
    }
    p += sprintf(p, " with LMTP%s%s",
                 cd->starttls_done ? "S" : "",
                 cd->authenticated != NOAUTH ? "A" : "");

    if (*tls_info) {
        fold[nfold++] = p;
        p += sprintf(p, " (%s)", tls_info);
    }

    strcat(p++, ";");
    fold[nfold++] = p;
    p += sprintf(p, " %s", datestr);

    fprintf(f, "Received: ");
    for (i = 0, p = addbody; i < nfold; p = fold[i], i++) {
        fprintf(f, "%.*s\r\n\t", (int) (fold[i] - p), p);
    }
    fprintf(f, "%s\r\n", p);
    spool_cache_header(xstrdup("Received"), addbody, m->hdrcache);

    char *sid = xstrdup(session_id());
    fprintf(f, "X-Cyrus-Session-Id: %s\r\n", sid);
    spool_cache_header(xstrdup("X-Cyrus-Session-Id"), sid, m->hdrcache);

    /* add any requested headers */
    if (func->addheaders) {
        struct addheader *h;
        for (h = func->addheaders; h && h->name; h++) {
            fprintf(f, "%s: %s\r\n", h->name, h->body);
            spool_cache_header(xstrdup(h->name), xstrdup(h->body), m->hdrcache);
        }
    }

    /* fill the cache */
    r = spool_fill_hdrcache(cd->pin, f, m->hdrcache, skipheaders);

    /* now, using our header cache, fill in the data that we want */

    /* first check x-me-message-id, then resent-message-id */
    if ((body = msg_getheader(m, "x-me-message-id")) && body[0][0]) {
        m->id = xstrdup(body[0]);
    } else if ((body = msg_getheader(m, "resent-message-id")) && body[0][0]) {
        m->id = xstrdup(body[0]);
    } else if ((body = msg_getheader(m, "message-id")) && body[0][0]) {
        m->id = xstrdup(body[0]);
    } else if (body) {
        r = IMAP_MESSAGE_BADHEADER;  /* empty message-id */
    } else {
        /* no message-id, create one */
        pid_t p = getpid();

        m->id = xmalloc(40 + strlen(config_servername));
        sprintf(m->id, "<cmu-lmtpd-%d-%d-%u@%s>", p, (int) now,
                msgid_count++, config_servername);
        fprintf(f, "Message-ID: %s\r\n", m->id);
        spool_cache_header(xstrdup("Message-ID"), xstrdup(m->id), m->hdrcache);
    }

    /* get date */
    if (!(body = spool_getheader(m->hdrcache, "date"))) {
        /* no date, create one */
        addbody = xstrdup(datestr);
        m->date = xstrdup(datestr);
        fprintf(f, "Date: %s\r\n", addbody);
        spool_cache_header(xstrdup("Date"), addbody, m->hdrcache);
    }
    else {
        m->date = xstrdup(body[0]);
    }

    if (!m->return_path &&
        (body = msg_getheader(m, "return-path"))) {
        /* let's grab return_path */
        m->return_path = xstrdup(body[0]);
        clean822space(m->return_path);
        clean_retpath(m->return_path);
    }

    /* get offset of message body */
    m->body_offset = ftell(f);

    r |= spool_copy_msg(cd->pin, f);
    if (r) {
        fclose(f);
        if (func->removespool) {
            /* remove the spool'd message */
            func->removespool(m);
        }
        while (nrcpts--) {
            send_lmtp_error(cd->pout, r, NULL);
        }
        return r;
    }

    fflush(f);
    if (ferror(f)) {
        while (nrcpts--) {
            prot_printf(cd->pout,
               "451 4.3.%c cannot copy message to temporary file: %s\r\n",
                   (
#ifdef EDQUOT
                    errno == EDQUOT ||
#endif
                    errno == ENOSPC) ? '1' : '2',
                   error_message(errno));
        }
        fclose(f);
        if (func->removespool) func->removespool(m);
        return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
        while (nrcpts--) {
            prot_printf(cd->pout,
                        "451 4.3.2 cannot stat message temporary file: %s\r\n",
                        error_message(errno));
        }
        fclose(f);
        if (func->removespool) func->removespool(m);
        return IMAP_IOERROR;
    }
    m->size = sbuf.st_size;
    m->f = f;
    m->data = prot_new(fileno(f), 0);

    return 0;
}

/* see if 'addr' exists. if so, fill in 'ad' appropriately.
   on success, return NULL.
   on failure, return the error. */
static int process_recipient(char *addr,
                             int ignorequota,
                             int (*verify_user)(const mbname_t *mbname,
                                                quota_t, quota_t,
                                                struct auth_state *),
                             message_data_t *msg)
{
    assert(addr != NULL && msg != NULL);

    if (*addr == '<') addr++;

    /* Skip at-domain-list */
    if (*addr == '@') {
        addr = strchr(addr, ':');
        if (!addr)
            return IMAP_PROTOCOL_BAD_PARAMETERS;
        addr++;
    }

    mbname_t *mbname = NULL;

    size_t sl = strlen(addr);
    if (addr[sl-1] == '>') sl--;

    if (sl) {
        char *rcpt = xstrndup(addr, sl);
        mbname = mbname_from_recipient(rcpt, msg->ns);
        free(rcpt);

        int forcedowncase = config_getswitch(IMAPOPT_LMTP_DOWNCASE_RCPT);
        if (forcedowncase) mbname_downcaseuser(mbname);

        /* strip username if postuser */
        if (!strcmpsafe(mbname_userid(mbname), config_getstring(IMAPOPT_POSTUSER))) {
            mbname_set_localpart(mbname, NULL);
            mbname_set_domain(mbname, NULL);
        }

        if (verify_user(mbname,
                        (quota_t) (ignorequota ? -1 : msg->size),
                        ignorequota ? -1 : 1, msg->authstate)) {
            mbname_free(&mbname);
        }
    }

    if (!mbname) {
        const char *catchall = config_getstring(IMAPOPT_LMTP_CATCHALL_MAILBOX);
        if (catchall) {
            mbname = mbname_from_userid(catchall);
            if (verify_user(mbname,
                            ignorequota ? -1 : msg->size,
                            ignorequota ? -1 : 1, msg->authstate)) {
                mbname_free(&mbname);
            }
        }
    }

    if (!mbname) {
        /* we lost */
        return IMAP_MAILBOX_NONEXISTENT;
    }

    address_data_t *ret = (address_data_t *) xzmalloc(sizeof(address_data_t));
    ret->mbname = mbname;
    ret->ignorequota = ignorequota;
    msg->rcpt[msg->rcpt_num] = ret;

    return 0;
}

static int localauth_mechlist_override(
    void *context __attribute__((unused)),
    const char *plugin_name __attribute__((unused)),
    const char *option,
    const char **result,
    unsigned *len)
{
    /* If we are doing local auth, we only support EXTERNAL */
    if (strcmp(option,"mech_list")==0)
    {
        *result = "EXTERNAL";
        if (len)
            *len = strlen(*result);
        return SASL_OK;
    }

    /* if we don't find the option,
       this should percolate to the global getopt */
    return SASL_FAIL;
}

static struct sasl_callback localauth_override_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &localauth_mechlist_override, NULL },
    { SASL_CB_LIST_END, NULL, NULL },
};

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("lmtp", config_servername,
                         NULL, NULL, NULL,
                         NULL, 0, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
                          saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;

    if(saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
                          saslprops.iplocalport);
    if(ret != SASL_OK) return ret;

    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
       ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    }
    if(ret != SASL_OK) return ret;

    if(saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

void lmtpmode(struct lmtp_func *func,
              struct protstream *pin,
              struct protstream *pout,
              int fd)
{
    message_data_t *msg = NULL;
    int max_msgsize;
    char buf[4096];
    char *p;
    int r;
    struct clientdata cd;

    const char *localip, *remoteip;

    sasl_ssf_t ssf;
    char *auth_id;

    sasl_security_properties_t *secprops = NULL;

    /* setup the clientdata structure */
    cd.pin = pin;
    cd.pout = pout;
    cd.fd = fd;
    cd.clienthost = "";
    cd.lhlo_param[0] = '\0';
    cd.authenticated =  NOAUTH;
#ifdef HAVE_SSL
    cd.tls_conn = NULL;
#endif
    cd.starttls_done = 0;

    max_msgsize = config_getint(IMAPOPT_MAXMESSAGESIZE);

    /* If max_msgsize is 0, allow any size */
    if(!max_msgsize) max_msgsize = INT_MAX;

    msg_new(&msg, func->namespace);

    /* don't leak old connections */
    if(saslprops.iplocalport) {
        free(saslprops.iplocalport);
        saslprops.iplocalport = NULL;
    }
    if(saslprops.ipremoteport) {
        free(saslprops.ipremoteport);
        saslprops.ipremoteport = NULL;
    }

    /* determine who we're talking to */
    cd.clienthost = get_clienthost(fd, &localip, &remoteip);
    if (!strcmp(cd.clienthost, UNIX_SOCKET)) {
        /* we're not connected to a internet socket! */
        func->preauth = 1;
    }

    syslog(LOG_DEBUG, "connection from %s%s",
           cd.clienthost,
           func->preauth ? " preauth'd as postman" : "");

    /* Setup SASL to go.  We need to do this *after* we decide if
     *  we are preauthed or not. */
    if (sasl_server_new("lmtp", config_servername, NULL, NULL,
                        NULL, (func->preauth ? localauth_override_cb : NULL),
                        0, &cd.conn) != SASL_OK) {
        fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    /* set my allowable security properties */
    /* ANONYMOUS is silly because we allow that anyway */
    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    sasl_setprop(cd.conn, SASL_SEC_PROPS, secprops);

    if (func->preauth) {
        cd.authenticated = EXTERNAL_AUTHED;     /* we'll allow commands,
                                                   but we still accept
                                                   the AUTH command */
        ssf = 2;
        auth_id = "postman";
        if (sasl_setprop(cd.conn, SASL_SSF_EXTERNAL, &ssf) != SASL_OK)
            fatal("Failed to set SASL property", EC_TEMPFAIL);
        if (sasl_setprop(cd.conn, SASL_AUTH_EXTERNAL, auth_id) != SASL_OK)
            fatal("Failed to set SASL property", EC_TEMPFAIL);

        deliver_logfd = telemetry_log(auth_id, pin, pout, 0);
    } else {
        if(localip) sasl_setprop(cd.conn, SASL_IPLOCALPORT,  &localip );
        if(remoteip) sasl_setprop(cd.conn, SASL_IPREMOTEPORT, &remoteip);
    }

    prot_printf(pout, "220 %s", config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        prot_printf(pout, " Cyrus LMTP %s", cyrus_version());
    }
    prot_printf(pout, " server ready\r\n");

    for (;;) {
    nextcmd:
      signals_poll();

      if (!prot_fgets(buf, sizeof(buf), pin)) {
          const char *err = prot_error(pin);

          if (err != NULL) {
              prot_printf(pout, "421 4.4.1 bye %s\r\n", err);
              prot_flush(pout);
          }
          goto cleanup;
      }
      p = buf + strlen(buf) - 1;
      if (p >= buf && *p == '\n') *p-- = '\0';
      if (p >= buf && *p == '\r') *p-- = '\0';

      /* Only allow LHLO/NOOP/QUIT when there is a shutdown file */
      if (!strchr("LlNnQq", buf[0]) &&
          shutdown_file(buf, sizeof(buf))) {

          prot_printf(pout, "421 4.3.2 %s\r\n", buf);
          prot_flush(pout);

          func->shutdown(0);
      }

      if (config_getswitch(IMAPOPT_CHATTY))
        syslog(LOG_NOTICE, "command: %s", buf);

      switch (buf[0]) {
      case 'a':
      case 'A':
          if (!strncasecmp(buf, "auth ", 5)) {
              char mech[128];
              int sasl_result;
              const void *val;
              const char *user;

              if (cd.authenticated > 0) {
                  prot_printf(pout,
                              "503 5.5.0 already authenticated\r\n");
                  continue;
              }
              if (msg->rcpt_num != 0) {
                  prot_printf(pout,
                              "503 5.5.0 AUTH not permitted now\r\n");
                  continue;
              }

              /* ok, what mechanism ? */
              p = buf + 5;
              while ((*p != ' ') && (*p != '\0')) {
                  p++;
              }
              if (*p == ' ') {
                  *p = '\0';
                  p++;
              } else {
                  p = NULL;
              }
              strlcpy(mech, buf + 5, sizeof(mech));

              r = saslserver(cd.conn, mech, p, "", "334 ", "",
                             pin, pout, &sasl_result, NULL);

              if (r) {
                  const char *errorstring = NULL;

                  switch (r) {
                  case IMAP_SASL_CANCEL:
                      prot_printf(pout,
                                  "501 5.5.4 client canceled authentication\r\n");
                      break;
                  case IMAP_SASL_PROTERR:
                      errorstring = prot_error(pin);

                      prot_printf(pout,
                                  "501 5.5.4 Error reading client response: %s\r\n",
                                  errorstring ? errorstring : "");
                      break;
                  default:
                      if (sasl_result == SASL_NOMECH) {
                          prot_printf(pout,
                                      "504 Unrecognized authentication type.\r\n");
                          continue;
                      }
                      else {
                          syslog(LOG_ERR, "badlogin: %s %s %s",
                                 cd.clienthost, mech, sasl_errdetail(cd.conn));

                          snmp_increment_args(AUTHENTICATION_NO, 1,
                                              VARIABLE_AUTH, hash_simple(mech),
                                              VARIABLE_LISTEND);

                          prot_printf(pout, "501 5.5.4 %s\r\n",
                                      sasl_errstring((r == SASL_NOUSER ?
                                                      SASL_BADAUTH : r),
                                                     NULL, NULL));
                      }
                  }

                  reset_saslconn(&cd.conn);
                  continue;
              }
              r = sasl_getprop(cd.conn, SASL_USERNAME, &val);
              if (r != SASL_OK) {
                  prot_printf(pout, "501 5.5.4 SASL Error\r\n");
                  reset_saslconn(&cd.conn);
                  goto nextcmd;
              }
              user = (const char *) val;

              r = sasl_getprop(cd.conn, SASL_SSF, &val);
              if (r != SASL_OK) {
                  prot_printf(pout, "501 5.5.4 SASL Error\r\n");
                  reset_saslconn(&cd.conn);
                  goto nextcmd;
              }
              saslprops.ssf = *((sasl_ssf_t *) val);

              /* Create telemetry log */
              deliver_logfd = telemetry_log(user, pin, pout, 0);

              /* authenticated successfully! */
              snmp_increment_args(AUTHENTICATION_YES,1,
                                  VARIABLE_AUTH, hash_simple(mech),
                                  VARIABLE_LISTEND);
              syslog(LOG_NOTICE, "login: %s %s %s%s %s",
                     cd.clienthost, user, mech,
                     cd.starttls_done ? "+TLS" : "", "User logged in");

              cd.authenticated = DIDAUTH;
              prot_printf(pout, "235 Authenticated!\r\n");

              /* set protection layers */
              prot_setsasl(pin,  cd.conn);
              prot_setsasl(pout, cd.conn);
              continue;
          }
          goto syntaxerr;

      case 'd':
      case 'D':
            if (!strcasecmp(buf, "data")) {
                int delivered = 0;
                int j;

                if (!msg->rcpt_num) {
                    prot_printf(pout, "503 5.5.1 No recipients\r\n");
                    continue;
                }
                /* copy message from input to msg structure */
                r = savemsg(&cd, func, msg);
                if (r) {
                    goto rset;
                }

                if (msg->size > max_msgsize) {
                    prot_printf(pout,
                                "552 5.2.3 Message size (%d) exceeds fixed "
                                "maximum message size (%d)\r\n",
                                msg->size, max_msgsize);
                    continue;
                }

                snmp_increment(mtaReceivedMessages, 1);
                snmp_increment(mtaReceivedVolume, roundToK(msg->size));
                snmp_increment(mtaReceivedRecipients, msg->rcpt_num);

                /* do delivery, report status */
                func->deliver(msg, msg->authuser, msg->authstate, msg->ns);
                for (j = 0; j < msg->rcpt_num; j++) {
                    if (!msg->rcpt[j]->status) delivered++;
                    send_lmtp_error(pout, msg->rcpt[j]->status,
                                    msg->rcpt[j]->status_msg);
                }

                snmp_increment(mtaTransmittedMessages, delivered);
                snmp_increment(mtaTransmittedVolume,
                               roundToK(delivered * msg->size));
                goto rset;
            }
            goto syntaxerr;

      case 'l':
      case 'L':
          if (!strncasecmp(buf, "lhlo ", 5)) {
              int mechcount;
              const char *mechs;

              prot_printf(pout, "250-%s\r\n"
                          "250-8BITMIME\r\n"
                          "250-ENHANCEDSTATUSCODES\r\n"
                          "250-PIPELINING\r\n",
                          config_servername);
              if (max_msgsize < INT_MAX)
                  prot_printf(pout, "250-SIZE %d\r\n", max_msgsize);
              else
                  prot_printf(pout, "250-SIZE\r\n");
              if (tls_enabled() && !cd.starttls_done &&
                  cd.authenticated == NOAUTH) {
                  prot_printf(pout, "250-STARTTLS\r\n");
              }
              if ((cd.authenticated <= 0) &&
                  sasl_listmech(cd.conn, NULL, "AUTH ", " ", "", &mechs,
                                NULL, &mechcount) == SASL_OK &&
                  mechcount > 0) {
                  prot_printf(pout,"250-%s\r\n", mechs);
              }
              prot_printf(pout, "250-IGNOREQUOTA\r\n");
              prot_printf(pout, "250 Ok SESSIONID=<%s>\r\n", session_id());

              strlcpy(cd.lhlo_param, buf + 5, sizeof(cd.lhlo_param));

              session_new_id();
              continue;
          }
          goto syntaxerr;

      case 'm':
      case 'M':
            if (!cd.authenticated) {
                if (config_getswitch(IMAPOPT_SOFT_NOAUTH)) {
                    prot_printf(pout, "430 Authentication required\r\n");
                } else {
                    prot_printf(pout, "530 Authentication required\r\n");
                }
                continue;
            }

            if (!strncasecmp(buf, "mail ", 5)) {
                char *tmp;
                if (msg->return_path) {
                    prot_printf(pout,
                                "503 5.5.1 Nested MAIL command\r\n");
                    continue;
                }
                /* +5 to get past "mail "
                 * +10 to get past "mail from:" */
                if (strncasecmp(buf+5, "from:", 5) != 0 ||
                    !(msg->return_path = parseaddr(buf+10))) {
                    prot_printf(pout,
                                "501 5.5.4 Syntax error in parameters\r\n");
                    continue;
                }
                tmp = buf+10+strlen(msg->return_path);

                /* is any other whitespace allow seperating? */
                while (*tmp == ' ') {
                    tmp++;
                    switch (*tmp) {
                    case 'a': case 'A':
                        if (strncasecmp(tmp, "auth=", 5) != 0) {
                            goto badparam;
                        }
                        tmp += 5;
                        msg->authuser = parseautheq(&tmp);
                        if (msg->authuser) {
                            msg->authstate = auth_newstate(msg->authuser);
                        } else {
                            /* do we want to bounce mail because of this? */
                            /* i guess not. accept with no auth user */
                            msg->authstate = NULL;
                        }
                        break;

                    case 'b': case 'B':
                        if (strncasecmp(tmp, "body=", 5) != 0) {
                            goto badparam;
                        }
                        tmp += 5;
                        /* just verify it's one of
                           body-value ::= "7BIT" / "8BITMIME" */
                        if (!strncasecmp(tmp, "7bit", 4)) {
                            tmp += 4;
                        } else if (!strncasecmp(tmp, "8bitmime", 8)) {
                            tmp += 8;
                        } else {
                            prot_printf(pout,
                              "501 5.5.4 Unrecognized BODY type\r\n");
                            goto nextcmd;
                        }
                        break;

                    case 's': case 'S':
                        if (strncasecmp(tmp, "size=", 5) != 0) {
                            goto badparam;
                        }
                        tmp += 5;
                        /* make sure we have a value */
                        if (!Uisdigit(*tmp)) {
                                prot_printf(pout,
                                            "501 5.5.2 SIZE requires a value\r\n");
                                goto nextcmd;
                        }
                        msg->size = strtoul(tmp, &p, 10);
                        tmp = p;
                        /* make sure the value is in range */
                        if (errno == ERANGE || msg->size < 0 ||
                            msg->size > max_msgsize) {
                            prot_printf(pout,
                                        "552 5.2.3 Message SIZE exceeds fixed "
                                        "maximum message size (%d)\r\n",
                                        max_msgsize);
                            goto nextcmd;
                        }
                        break;

                    default:
                    badparam:
                        prot_printf(pout,
                                    "501 5.5.4 Unrecognized parameters\r\n");
                        goto nextcmd;
                    }
                }
                if (*tmp != '\0') {
                    prot_printf(pout,
                                "501 5.5.4 Syntax error in parameters\r\n");
                    continue;
                }

                prot_printf(pout, "250 2.1.0 ok\r\n");
                continue;
            }
            goto syntaxerr;

      case 'n':
      case 'N':
            if (!strcasecmp(buf, "noop")) {
                prot_printf(pout,"250 2.0.0 ok\r\n");
                continue;
            }
            goto syntaxerr;

      case 'q':
      case 'Q':
            if (!strcasecmp(buf, "quit")) {
                prot_printf(pout,"221 2.0.0 bye\r\n");
                prot_flush(pout);
                goto cleanup;
            }
            goto syntaxerr;

      case 'r':
      case 'R':
            if (!strncasecmp(buf, "rcpt ", 5)) {
                char *rcpt = NULL;
                int ignorequota = 0;
                char *tmp;

                if (!msg->return_path) {
                    prot_printf(pout, "503 5.5.1 Need MAIL command\r\n");
                    continue;
                }
                if (!(msg->rcpt_num % RCPT_GROW)) { /* time to alloc more */
                    msg->rcpt = (address_data_t **)
                        xrealloc(msg->rcpt, (msg->rcpt_num + RCPT_GROW + 1) *
                                 sizeof(address_data_t *));
                }
                /* +5 to get past "rcpt "
                 * +8 to get past "rcpt to:" */
                if (strncasecmp(buf+5, "to:", 3) != 0 ||
                    !(rcpt = parseaddr(buf+8))) {
                    prot_printf(pout,
                                "501 5.5.4 Syntax error in parameters\r\n");
                    continue;
                }

                tmp = buf+8+strlen(rcpt);
                while (*tmp == ' ') {
                    tmp++;
                    switch (*tmp) {
                    case 'i': case 'I':
                        if (strncasecmp(tmp, "ignorequota", 12) != 0) {
                            goto badrparam;
                        }
                        tmp += 12;
                        ignorequota = 1;
                        break;

                    default:
                    badrparam:
                        prot_printf(pout,
                                    "501 5.5.4 Unrecognized parameters\r\n");
                        goto nextcmd;
                    }
                }
                if (*tmp != '\0') {
                    prot_printf(pout,
                                "501 5.5.4 Syntax error in parameters\r\n");
                    continue;
                }

                r = process_recipient(rcpt,
                                      ignorequota,
                                      func->verify_user,
                                      msg);
                if (rcpt) free(rcpt); /* malloc'd in parseaddr() */
                if (r) {
                    send_lmtp_error(pout, r, NULL);
                    continue;
                }
                msg->rcpt_num++;
                msg->rcpt[msg->rcpt_num] = NULL;
                prot_printf(pout, "250 2.1.5 ok\r\n");
                continue;
            }
            else if (!strcasecmp(buf, "rset")) {
                session_new_id();
                prot_printf(pout, "250 2.0.0 Ok SESSIONID=<%s>\r\n", session_id());

              rset:
                if (msg) msg_free(msg);
                msg_new(&msg, func->namespace);

                continue;
            }
            goto syntaxerr;

      case 's':
      case 'S':
#ifdef HAVE_SSL
            if (!strcasecmp(buf, "starttls") && tls_enabled() &&
                !func->preauth) { /* don't need TLS for preauth'd connect */
                int *layerp;
                sasl_ssf_t ssf;
                char *auth_id;

                /* XXX  discard any input pipelined after STARTTLS */
                prot_flush(pin);

                /* SASL and openssl have different ideas
                   about whether ssf is signed */
                layerp = (int *) &ssf;

                if (cd.starttls_done == 1) {
                    prot_printf(pout, "454 4.3.3 %s\r\n",
                                "Already successfully executed STARTTLS");
                    continue;
                }
                if (msg->rcpt_num != 0) {
                    prot_printf(pout,
                                "503 5.5.0 STARTTLS not permitted now\r\n");
                    continue;
                }

                r=tls_init_serverengine("lmtp",
                                        5,   /* depth to verify */
                                        1,   /* can client auth? */
                                        NULL);

                if (r == -1) {

                    syslog(LOG_ERR, "[lmtpd] error initializing TLS");

                    prot_printf(pout, "454 4.3.3 %s\r\n", "Error initializing TLS");
                    continue;
                }

                prot_printf(pout, "220 %s\r\n", "Begin TLS negotiation now");
                /* must flush our buffers before starting tls */
                prot_flush(pout);

                r=tls_start_servertls(0, /* read */
                                      1, /* write */
                                      360, /* 6 minutes */
                                      layerp,
                                      &auth_id,
                                      &(cd.tls_conn));

                /* if error */
                if (r==-1) {
                    prot_printf(pout, "454 4.3.3 STARTTLS failed\r\n");
                    syslog(LOG_NOTICE, "[lmtpd] STARTTLS failed: %s", cd.clienthost);
                    continue;
                }

                /* tell SASL about the negotiated layer */
                r=sasl_setprop(cd.conn, SASL_SSF_EXTERNAL, &ssf);
                if (r != SASL_OK)
                    fatal("sasl_setprop(SASL_SSF_EXTERNAL) failed: STARTTLS",
                          EC_TEMPFAIL);
                saslprops.ssf = ssf;

                r=sasl_setprop(cd.conn, SASL_AUTH_EXTERNAL, auth_id);
                if (r != SASL_OK)
                    fatal("sasl_setprop(SASL_AUTH_EXTERNAL) failed: STARTTLS",
                          EC_TEMPFAIL);
                if(saslprops.authid) {
                    free(saslprops.authid);
                    saslprops.authid = NULL;
                }
                if(auth_id) {
                    saslprops.authid = xstrdup(auth_id);
                    cd.authenticated = TLSCERT_AUTHED;
                }

                /* tell the prot layer about our new layers */
                prot_settls(pin, cd.tls_conn);
                prot_settls(pout, cd.tls_conn);

                cd.starttls_done = 1;

                continue;
            }
#endif /* HAVE_SSL*/
            goto syntaxerr;

      case 'v':
      case 'V':
            if (!strncasecmp(buf, "vrfy ", 5)) {
                prot_printf(pout,
                            "252 2.3.3 try RCPT to attempt delivery\r\n");
                continue;
            }
            goto syntaxerr;

      default:
      syntaxerr:
            prot_printf(pout, "500 5.5.2 Syntax error\r\n");
            continue;
      }
    }

 cleanup:
    /* free resources and return; this connection has been closed */

    if (msg) msg_free(msg);

    /* security */
    if (cd.conn) sasl_dispose(&cd.conn);

    cd.starttls_done = 0;
#ifdef HAVE_SSL
    if (cd.tls_conn) {
        tls_reset_servertls(&cd.tls_conn);
        cd.tls_conn = NULL;
    }
#endif
}

/************** client-side LMTP ****************/

#define ISGOOD(r) (((r) / 100) == 2)
#define TEMPFAIL(r) (((r) / 100) == 4)
#define PERMFAIL(r) (((r) / 100) == 5)
#define ISCONT(s) (s && (s[3] == '-'))

static int revconvert_lmtp(const char *code)
{
    int c = atoi(code);
    switch (c) {
    case 250:
    case 251:
        return 0;
    case 451:
        if (code[4] == '4' && code[6] == '3') {
            if (code[8] == '0') {
                return IMAP_IOERROR;
            } else if (code[8] == '1') {
                return IMAP_NOSPACE;
            } else {
                return IMAP_IOERROR;
            }
        }
        else if (code[4] == '4' && code [6] == '4') {
            return IMAP_SERVER_UNAVAILABLE;
        }
        else if (code[4] == '4' && code[6] == '2') {
            if (code[8] == '1') {
                return IMAP_MAILBOX_MOVED;
            } else {
                return IMAP_MAILBOX_BADFORMAT;
            }
        }
        else {
            return IMAP_IOERROR;
        }
    case 452:
        return IMAP_QUOTA_EXCEEDED;
    case 550:
        if (code[4] == '5' && code[6] == '7') {
            return IMAP_PERMISSION_DENIED;
        } else if (code[4] == '5' && code[6] == '1') {
            return IMAP_MAILBOX_NONEXISTENT;
        }
        return IMAP_PERMISSION_DENIED;
    case 552:
        if (code[6] == '2') {
            return IMAP_QUOTA_EXCEEDED;
        } else if (code[6] == '3') {
            return IMAP_MESSAGE_TOO_LARGE;
        }
        return IMAP_QUOTA_EXCEEDED;
    case 554:
        return IMAP_MESSAGE_BADHEADER; /* sigh, pick one */

    default:
        if (ISGOOD(c)) return 0;
        else if (TEMPFAIL(c)) return IMAP_AGAIN;
        else if (PERMFAIL(c)) return IMAP_PROTOCOL_ERROR;
        else return IMAP_AGAIN;
    }
}

static int ask_code(const char *s)
{
    int ret = 0;

    if (s==NULL) return -1;

    if (strlen(s) < 3) return -1;

    /* check to make sure 0-2 are digits */
    if ((Uisdigit(s[0])==0) ||
        (Uisdigit(s[1])==0) ||
        (Uisdigit(s[2])==0))
    {
        return -1;
    }

    ret = ((s[0]-'0')*100)+((s[1]-'0')*10)+(s[2]-'0');

    return ret;
}

/* getlastresp reads from 'pin' until we get an LMTP that isn't a continuation.
   it puts it in 'buf', which must be at least 'len' big.

   '*code' will contain the integer three digit response code.
   if a read failed, '*code == 400', a temporary failure.

   returns an IMAP error code. */
static int getlastresp(char *buf, int len, int *code, struct protstream *pin)
{
    do {
        if (!prot_fgets(buf, len, pin)) {
            *code = 400;
            return IMAP_SERVER_UNAVAILABLE;
        }
    } while (ISCONT(buf));
    *code = ask_code(buf);

    return 0;
}

static void pushmsg(struct protstream *in, struct protstream *out,
                    int isdotstuffed)
{
    char buf[8192], *p;
    int lastline_hadendline = 1;

    /* -2: Might need room to add a \r\n\0 set */
    while (prot_fgets(buf, sizeof(buf)-2, in)) {
        /* dot stuff */
        if (!isdotstuffed && (lastline_hadendline == 1) && (buf[0]=='.')) {
            (void)prot_putc('.', out);
        }
        p = buf + strlen(buf) - 1;
        if (*p == '\n') {
            if (p == buf || p[-1] != '\r') {
                p[0] = '\r';
                p[1] = '\n';
                p[2] = '\0';
            }
            lastline_hadendline = 1;
        }
        else if (*p == '\r') {
            if (buf[0] == '\r' && buf[1] == '\0') {
                /* The message contained \r\0, and fgets is confusing us.
                   XXX ignored
                 */
                lastline_hadendline = 1;
            } else {
                /*
                 * We were unlucky enough to get a CR just before we ran
                 * out of buffer--put it back.
                 */
                prot_ungetc('\r', in);
                *p = '\0';
                lastline_hadendline = 0;
            }
        } else {
            lastline_hadendline = 0;
        }

        /* Remove any lone CR characters */
        while ((p = strchr(buf, '\r')) && p[1] != '\n') {
            /* Src/Target overlap, use memmove */
            /* strlen(p) will result in copying the NUL byte as well */
            memmove(p, p+1, strlen(p));
        }

        prot_write(out, buf, strlen(buf));
    }

    if (!isdotstuffed) {
        /* signify end of message */
        if (!lastline_hadendline) {
            prot_printf(out, "\r\n");
        }
        prot_printf(out, ".\r\n");
    }
}

int lmtp_runtxn(struct backend *conn, struct lmtp_txn *txn)
{
    int j, code, r = 0;
    char buf[8192], rsessionid[MAX_SESSIONID_SIZE];
    int onegood;

    assert(conn && txn);
    /* pipelining v. no pipelining? */

    /* here's the straightforward non-pipelining version */

    /* rset */
    prot_printf(conn->out, "RSET\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->in);
    if (!ISGOOD(code)) {
        goto failall;
    }

    if (config_auditlog) {
        parse_sessionid(buf, rsessionid);
        syslog(LOG_NOTICE, "auditlog: proxy sessionid=<%s> remote=<%s>", session_id(), rsessionid);
    }

    /* mail from */
    if (!txn->from) {
        prot_printf(conn->out, "MAIL FROM:<>");
    } else if (txn->from[0] == '<') {
        prot_printf(conn->out, "MAIL FROM:%s", txn->from);
    } else {
        prot_printf(conn->out, "MAIL FROM:<%s>", txn->from);
    }
    if (CAPA(conn, CAPA_AUTH)) {
        prot_printf(conn->out, " AUTH=%s",
                    txn->auth && txn->auth[0] ? txn->auth : "<>");
    }
    prot_printf(conn->out, "\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->in);
    if (!ISGOOD(code)) {
        goto failall;
    }

    /* rcpt to */
    onegood = 0;
    for (j = 0; j < txn->rcpt_num; j++) {
        prot_printf(conn->out, "RCPT TO:<%s>", txn->rcpt[j].addr);
        if (txn->rcpt[j].ignorequota && CAPA(conn, CAPA_IGNOREQUOTA)) {
            prot_printf(conn->out, " IGNOREQUOTA");
        }
        prot_printf(conn->out, "\r\n");
        r = getlastresp(buf, sizeof(buf)-1, &code, conn->in);
        if (r) {
            goto failall;
        }
        txn->rcpt[j].r = revconvert_lmtp(buf);
        if (ISGOOD(code)) {
            onegood = 1;
            txn->rcpt[j].result = RCPT_GOOD;
        } else if (TEMPFAIL(code)) {
            txn->rcpt[j].result = RCPT_TEMPFAIL;
        } else if (PERMFAIL(code)) {
            if(txn->tempfail_unknown_mailbox &&
               txn->rcpt[j].r == IMAP_MAILBOX_NONEXISTENT) {
                /* If there is a nonexistant error, we have been told
                 * to mask it (e.g. proxy got out-of-date mupdate data) */
                txn->rcpt[j].result = RCPT_TEMPFAIL;
                txn->rcpt[j].r = IMAP_AGAIN;
            } else {
                txn->rcpt[j].result = RCPT_PERMFAIL;
            }
        } else {
            /* yikes?!? */
            code = 400;
            goto failall;
        }
    }
    if (!onegood) {
        /* all recipients failed! */
        return 0;
    }

    /* data */
    prot_printf(conn->out, "DATA\r\n");
    r = getlastresp(buf, sizeof(buf)-1, &code, conn->in);
    if (r) {
        goto failall;
    }
    if (code != 354) {
        /* erg? */
        if (ISGOOD(code)) code = 400;
        r = IMAP_PROTOCOL_ERROR;
        goto failall;
    }

    /* send the data, dot-stuffing as needed */
    pushmsg(txn->data, conn->out, txn->isdotstuffed);

    /* read the response codes, one for each accepted RCPT TO */
    for (j = 0; j < txn->rcpt_num; j++) {
        if (txn->rcpt[j].result == RCPT_GOOD) {
            /* expecting a status code for this recipient */
            r = getlastresp(buf, sizeof(buf)-1, &code, conn->in);
            if (r) {
                /* technically, some recipients might've succeeded here,
                   but we'll be paranoid */
                goto failall;
            }
            txn->rcpt[j].r = revconvert_lmtp(buf);
            if (ISGOOD(code)) {
                onegood = 1;
                txn->rcpt[j].result = RCPT_GOOD;
            } else if (TEMPFAIL(code)) {
                txn->rcpt[j].result = RCPT_TEMPFAIL;
            } else if (PERMFAIL(code)) {
                txn->rcpt[j].result = RCPT_PERMFAIL;
            } else {
                /* yikes?!? */
                txn->rcpt[j].result = RCPT_TEMPFAIL;
            }
        }
    }

    /* done with txn */
    return 0;

 failall:
    /* something fatal happened during the transaction; we should assign
       'code' to all recipients and return */
    for (j = 0; j < txn->rcpt_num; j++) {
        if (ISGOOD(code)) {
            txn->rcpt[j].r = 0;
            txn->rcpt[j].result = RCPT_GOOD;
        } else if (TEMPFAIL(code)) {
            txn->rcpt[j].r = IMAP_AGAIN;
            txn->rcpt[j].result = RCPT_TEMPFAIL;
        } else if (PERMFAIL(code)) {
            txn->rcpt[j].r = IMAP_PROTOCOL_ERROR;
            txn->rcpt[j].result = RCPT_PERMFAIL;
        } else {
            /* code should have been a valid number */
            abort();
        }
    }

    /* return overall error code already set */
    return r;
}
