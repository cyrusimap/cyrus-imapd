/* attachextract.c -- Routines for extracting text from attachments
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

#include <string.h>
#include <syslog.h>

#include "backend.h"
#include "global.h"
#include "http_client.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "attachextract.h"

struct extractor_ctx {
    struct protstream *clientin;
    char *hostname;
    char *path;
    struct backend *be;
};

static struct extractor_ctx *global_extractor = NULL;

static void extractor_disconnect(struct extractor_ctx *ext)
{
    if (!ext) return;

    struct backend *be = ext->be;
    syslog(LOG_DEBUG, "extractor_disconnect(%p)", be);

    if (!be || (be->sock == -1)) {
        /* already disconnected */
        return;
    }

    /* need to logout of server */
    backend_disconnect(be);

    /* remove the timeout */
    if (be->timeout) prot_removewaitevent(be->clientin, be->timeout);
    be->timeout = NULL;
    be->clientin = NULL;
}

static struct prot_waitevent *
extractor_timeout(struct protstream *s __attribute__((unused)),
                  struct prot_waitevent *ev __attribute__((unused)),
                  void *rock)
{
    struct extractor_ctx *ext = rock;

    syslog(LOG_DEBUG, "extractor_timeout(%p)", ext);

    /* too long since we last used the extractor - disconnect */
    extractor_disconnect(ext);

    return NULL;
}


#define IDLE_TIMEOUT (5 * 60)  /* 5 min */

static int login(struct backend *s __attribute__((unused)),
                 const char *userid __attribute__((unused)),
                 sasl_callback_t *cb __attribute__((unused)),
                 const char **status __attribute__((unused)),
                 int noauth __attribute__((unused)))
{
    return 0;
}

static int ping(struct backend *s __attribute__((unused)),
                const char *userid __attribute__((unused)))
{
    return 0;
}

static int logout(struct backend *s __attribute__((unused)))
{
    return 0;
}


static struct protocol_t http =
{ "http", "HTTP", TYPE_SPEC, { .spec = { &login, &ping, &logout } } };

static int extractor_connect(struct extractor_ctx *ext)
{
    struct backend *be;
    time_t now = time(NULL);

    syslog(LOG_DEBUG, "extractor_connect()");

    be = ext->be;
    if (be && be->sock != -1) {
        // extend the timeout
        if (be->timeout) be->timeout->mark = now + IDLE_TIMEOUT;
        return 0;
    }

    // clean up any existing connection
    extractor_disconnect(ext);
    be = ext->be = backend_connect(be, ext->hostname,
                                   &http, NULL, NULL, NULL, -1);

    if (!be) {
        syslog(LOG_ERR, "extract_connect: failed to connect to %s",
               ext->hostname);
        return IMAP_IOERROR;
    }

    if (ext->clientin) {
        /* add a default timeout */
        be->clientin = ext->clientin;
        be->timeout = prot_addwaitevent(ext->clientin,
                                        now + IDLE_TIMEOUT,
                                        extractor_timeout, ext);
    }

    return 0;
}

EXPORTED int attachextract_extract(const struct attachextract_record *rec,
                                   const struct buf *data,
                                   int encoding,
                                   const char *charset,
                                   struct buf *text)
{
    struct backend *be;
    struct buf decbuf = BUF_INITIALIZER;
    struct buf ctypehdr = BUF_INITIALIZER;
    hdrcache_t hdrs = NULL;
    struct body_t body = { 0, 0, 0, 0, 0, BUF_INITIALIZER };
    const char *guidstr, *errstr = NULL;
    size_t hostlen;
    const char **hdr, *p;

    /* Capture HTTP response directly in target buffer */
    body.payload = *text;

    if (!global_extractor) {
        /* This is a legitimate case for sieve and lmtpd (so we don't need
         * to spam the logs! */
        xsyslog(LOG_DEBUG, "ignoring uninitialized extractor", NULL);
        return 0;
    }

    if (!rec->type || !rec->subtype) {
        xsyslog(LOG_DEBUG, "ignoring incomplete MIME type",
                "type=<%s> subtype<%s>",
               rec->type ? rec->type : "<null>",
               rec->subtype ? rec->subtype : "<null>");
        return 0;
    }

    if (message_guid_isnull(&rec->guid)) {
        xsyslog(LOG_DEBUG, "ignoring null guid", "mime_type=<%s/%s>",
               rec->type, rec->subtype);
        return 0;
    }

    struct extractor_ctx *ext = global_extractor;
    int r = extractor_connect(ext);
    if (r) return r;
    be = ext->be;

    hostlen = strcspn(ext->hostname, "/");
    guidstr = message_guid_encode(&rec->guid);

    /* try to fetch previously extracted text */
    unsigned statuscode = 0;
    prot_printf(be->out,
                "GET %s/%s %s\r\n"
                "Host: %.*s\r\n"
                "User-Agent: Cyrus/%s\r\n"
                "Connection: Keep-Alive\r\n"
                "Keep-Alive: timeout=%u\r\n"
                "Accept: text/plain\r\n"
                "X-Truncate-Length: " SIZE_T_FMT "\r\n"
                "\r\n",
                ext->path, guidstr, HTTP_VERSION,
                (int) hostlen, be->hostname, CYRUS_VERSION,
                IDLE_TIMEOUT, config_search_maxsize);
    prot_flush(be->out);

    /* Read GET response */
    do {
        r = http_read_response(be, METH_GET,
                               &statuscode, &hdrs, &body, &errstr);
        if (r) {
            syslog(LOG_ERR,
                   "extract_attachment: failed to read response for GET %s/%s",
                   ext->path, guidstr);
            statuscode = 599;
        }
    } while (statuscode < 200);

    syslog(LOG_DEBUG, "extract_attachment: GET %s/%s: got status %u",
           ext->path, guidstr, statuscode);

    if (statuscode == 200) goto gotdata;

    // otherwise we're going to try three times to PUT this request to the server!

    /* Decode data */
    if (encoding) {
        if (charset_decode(&decbuf, buf_base(data), buf_len(data), encoding)) {
            syslog(LOG_ERR, "extract_attachment: failed to decode data");
            r = IMAP_IOERROR;
            goto done;
        }
        data = &decbuf;
    }

    /* Build Content-Type */
    buf_printf(&ctypehdr, "%s/%s", rec->type, rec->subtype);
    if (charset) {
        buf_printf(&ctypehdr, ";charset=%s", charset);
    }

    int retry;
    for (retry = 0; retry < 3; retry++) {
        if (retry) {
            // second and third time around, sleep and reconnect
            sleep(retry);
            extractor_disconnect(ext);
            r = extractor_connect(ext);
            if (r) continue;
            be = ext->be;
        }

        /* Send attachment to service for text extraction */
        prot_printf(be->out,
                    "PUT %s/%s %s\r\n"
                    "Host: %.*s\r\n"
                    "User-Agent: Cyrus/%s\r\n"
                    "Connection: Keep-Alive\r\n"
                    "Keep-Alive: timeout=%u\r\n"
                    "Accept: text/plain\r\n"
                    "Content-Type: %s\r\n"
                    "Content-Length: " SIZE_T_FMT "\r\n"
                    "X-Truncate-Length: " SIZE_T_FMT "\r\n"
                    "\r\n",
                    ext->path, guidstr, HTTP_VERSION,
                    (int) hostlen, be->hostname, CYRUS_VERSION, IDLE_TIMEOUT,
                    buf_cstring(&ctypehdr), buf_len(data), config_search_maxsize);
        prot_putbuf(be->out, data);
        prot_flush(be->out);

        /* Read PUT response */
        body.flags = 0;
        do {
            r = http_read_response(be, METH_PUT,
                                   &statuscode, &hdrs, &body, &errstr);
            if (r) {
                syslog(LOG_ERR,
                       "extract_attachment: failed to read response for PUT %s/%s",
                       ext->path, guidstr);
                statuscode = 599;
            }
        } while (statuscode < 200);

        syslog(LOG_DEBUG, "extract_attachment: PUT %s/%s: got status %u",
               ext->path, guidstr, statuscode);

        if (statuscode == 200 || statuscode == 201) {
            // we got a result, yay
            goto gotdata;
        }

        if (statuscode >= 400 && statuscode <= 499) {
            /* indexer can't extract this for some reason, never try again */
            goto done;
        }

        /* any other status code is an error */
        syslog(LOG_ERR, "extract GOT STATUSCODE %d with timeout %d: %s", statuscode, IDLE_TIMEOUT, errstr);
    }

    // dropped out of the loop?  Then we failed!
    r = IMAP_IOERROR;
    goto done;

gotdata:
    /* Abide by server's timeout, if any */
    if ((hdr = spool_getheader(hdrs, "Keep-Alive")) &&
        (p = strstr(hdr[0], "timeout="))) {
        int timeout = atoi(p+8);
        if (be->timeout) be->timeout->mark = time(NULL) + timeout;
    }

done:
    spool_free_hdrcache(hdrs);
    *text = body.payload;
    buf_free(&ctypehdr);
    buf_free(&decbuf);
    return r;
}

EXPORTED void attachextract_init(struct protstream *clientin)
{
    const char *exturl =
         config_getstring(IMAPOPT_SEARCH_ATTACHMENT_EXTRACTOR_URL);
    if (!exturl) return;

    syslog(LOG_DEBUG, "extractor_init(%p)", clientin);

    char scheme[6], server[100], path[256], *p;
    unsigned https, port;

    /* Parse URL (cheesy parser without having to use libxml2) */
    int n = sscanf(exturl, "%5[^:]://%99[^/]%255[^\n]",
                   scheme, server, path);
    if (n != 3 ||
        strncmp(lcase(scheme), "http", 4) || (scheme[4] && scheme[4] != 's')) {
        syslog(LOG_ERR,
               "extract_attachment: unexpected non-HTTP URL %s", exturl);
        return;
    }

    /* Normalize URL parts */
    https = (scheme[4] == 's');
    if (*(p = path + strlen(path) - 1) == '/') *p = '\0';
    if ((p = strrchr(server, ':'))) {
        *p++ = '\0';
        port = atoi(p);
    }
    else port = https ? 443 : 80;

    /* Build servername, port, and options */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%s:%u%s/noauth", server, port, https ? "/tls" : "");

    global_extractor = xzmalloc(sizeof(struct extractor_ctx));
    global_extractor->clientin = clientin;
    global_extractor->path = xstrdup(path);
    global_extractor->hostname = buf_release(&buf);
}

EXPORTED void attachextract_destroy(void)
{
    struct extractor_ctx *ext = global_extractor;

    syslog(LOG_DEBUG, "extractor_destroy(%p)", ext);

    if (!ext) return;

    extractor_disconnect(ext);
    free(ext->be);
    free(ext->hostname);
    free(ext->path);
    free(ext);

    global_extractor = NULL;
}


EXPORTED int attachextract_supports_type(const char *type, const char *subtype)
{
    if (!strcasecmpsafe(type, "APPLICATION")) {
        if (!strcasecmpsafe(subtype, "ICS")) {
            // this gets handled like text/calendar
            return 0;
        }
        else if (!strcasecmpsafe(subtype, "PKCS7-MIME") ||
            !strcasecmpsafe(subtype, "PKCS7-ENCRYPTED") ||
            !strcasecmpsafe(subtype, "PKCS7-SIGNATURE") ||
            !strcasecmpsafe(subtype, "PGP-SIGNATURE") ||
            !strcasecmpsafe(subtype, "PGP-KEYS") ||
            !strcasecmpsafe(subtype, "PGP-ENCRYPTED")) {
            // these are encrypted fields which aren't worth indexing
            return 0;
        }
        else return 1;
    }
    else return !strcasecmpsafe(type, "TEXT");
}



