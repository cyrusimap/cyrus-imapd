/* attachextract.c - Routines for extracting text from attachments */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <string.h>
#include <syslog.h>

#include "backend.h"
#include "global.h"
#include "http_client.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "xunlink.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "attachextract.h"

struct extractor_ctx {
    struct protstream *clientin;
    char *hostname;
    char *path;
    struct backend *be;
};

static char *attachextract_cachedir = NULL;
static int attachextract_cacheonly = 0;
static unsigned attachextract_idle_timeout = 5 * 60;
static unsigned attachextract_request_timeout = 5 * 60;

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
extractor_idle_timeout_cb(struct protstream *s __attribute__((unused)),
                          struct prot_waitevent *ev __attribute__((unused)),
                          void *rock)
{
    struct extractor_ctx *ext = rock;

    syslog(LOG_DEBUG, "extractor_idle_timeout(%p)", ext);

    /* too long since we last used the extractor - disconnect */
    extractor_disconnect(ext);

    return NULL;
}

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

static const struct tls_alpn_t http_alpn_map[] = {
    { "http/1.1", NULL, NULL },
    { "",         NULL, NULL },
};

static struct protocol_t http =
{ "http", "HTTP", http_alpn_map, TYPE_SPEC,
  { .spec = { &login, &ping, &logout } }
};

static int extractor_connect(struct extractor_ctx *ext)
{
    struct backend *be;
    time_t now = time(NULL);

    syslog(LOG_DEBUG, "extractor_connect()");

    be = ext->be;
    if (be && be->sock != -1) {
        // extend the timeout
        if (be->timeout) {
            be->timeout->mark = now + attachextract_idle_timeout;
            xsyslog(LOG_DEBUG, "keep using socket with timeout mark",
                    "sockfd=<%d> timeout_mark=<" TIME_T_FMT ">",
                    be->sock, be->timeout->mark);
        }
        else {
            xsyslog(LOG_DEBUG, "keep using socket",
                    "sockfd=<%d>", be->sock);
        }
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

    // set request timeout
    prot_settimeout(be->in, attachextract_request_timeout);

    if (ext->clientin) {
        /* set idle timeout */
        be->clientin = ext->clientin;
        be->timeout = prot_addwaitevent(ext->clientin,
                now + attachextract_idle_timeout, extractor_idle_timeout_cb, ext);
    }

    return 0;
}

static int extractor_httpreq(struct extractor_ctx *ext,
                             const char *method,
                             const char *guidstr,
                             const char *req_ctype,
                             const struct buf *req_body,
                             unsigned *res_statuscode,
                             struct body_t *res_body)
{
    struct buf req_buf = BUF_INITIALIZER;
    size_t hostlen = strcspn(ext->hostname, "/");
    hdrcache_t res_hdrs = NULL;
    const char **hdr;
    *res_statuscode = HTTP_BAD_GATEWAY;
    int r = IMAP_INTERNAL;
    struct buf url_buf = BUF_INITIALIZER;
    buf_printf(&url_buf, "%s/%s", ext->path, guidstr);
    const char *url = buf_cstring(&url_buf);

    xsyslog(LOG_DEBUG, "starting HTTP request",
            "method=<%s> guid=<%s>", method, guidstr);

    // Prepare request
    buf_printf(&req_buf,
            "%s %s %s\r\n"
            "Host: %.*s\r\n"
            "User-Agent: Cyrus/%s\r\n"
            "Connection: Keep-Alive\r\n"
            "Keep-Alive: timeout=%u\r\n"
            "Accept: text/plain\r\n"
            "X-Truncate-Length: " SIZE_T_FMT "\r\n",
            method, url, HTTP_VERSION,
            (int) hostlen, ext->hostname, CYRUS_VERSION,
            attachextract_idle_timeout, config_search_maxsize);

    if (req_body) {
        buf_printf(&req_buf,
                "Content-Type: %s\r\n",
                req_ctype ? req_ctype : "application/octet-stream");

        buf_printf(&req_buf,
                "Content-Length: " SIZE_T_FMT "\r\n",
                buf_len(req_body));
    }

    buf_appendcstr(&req_buf, "\r\n");

    int retry = 0;
    do {
        // Connect to backend
        r = extractor_connect(ext);
        if (r) goto done;

        struct backend *be = ext->be;

        // Send request
        prot_settimeout(be->in, attachextract_idle_timeout);

        r = prot_putbuf(be->out, &req_buf);

        if (!r && req_body)
            r = prot_putbuf(be->out, req_body);

        if (!r)
            r = prot_flush(be->out);

        if (r == EOF) {
            r = IMAP_IOERROR;
            xsyslog(LOG_DEBUG,
                    "failed to send HTTP request",
                    "method=<%s> url=<%s> err=<%s>",
                    method, url, error_message(r));
            extractor_disconnect(ext);
            retry++;
            continue;
        }

        // Read response
        const char *res_err = NULL;
        *res_statuscode = 599;
        uint64_t prev_bytes_in = be->in->bytes_in;

        do {
            r = http_read_response(be,
                    !strcmp(method, "GET") ? METH_GET : METH_PUT,
                    res_statuscode, &res_hdrs, res_body, &res_err);
        } while (*res_statuscode < 200 && !r);

        // Reconnect if the socket is closed
        if (r == HTTP_BAD_GATEWAY &&
                be->in->eof && prev_bytes_in == be->in->bytes_in &&
                time(NULL) < be->in->timeout_mark) {
            xsyslog(LOG_DEBUG,
                    "no bytes read from socket - retrying",
                    "method=<%s> url=<%s>", method, url);
            extractor_disconnect(ext);
            retry++;
        }
        // Reconnect if the connection expired
        else if (r == HTTP_TIMEOUT &&
                (res_hdrs &&
                 (hdr = spool_getheader(res_hdrs, "Connection")) &&
                 !strcasecmpsafe(hdr[0], "close") &&
                 time(NULL) < be->in->timeout_mark)) {
            xsyslog(LOG_DEBUG,
                    "keep-alive connection got closed - retrying",
                    "method=<%s> url=<%s>", method, url);
            extractor_disconnect(ext);
            retry++;
        }
        // Handle response
        else {
            if (r) {
                xsyslog(LOG_ERR,
                        "failed to read HTTP response",
                        "method=<%s> url=<%s> res_err=<%s> err=<%s>",
                        method, url, res_err, error_message(r));
                *res_statuscode = 599;
            }
            else xsyslog(
                    (*res_statuscode == 200 || *res_statuscode == 201 ||
                     *res_statuscode == 404) ? LOG_DEBUG : LOG_WARNING,
                    "got HTTP response", "method=<%s> url=<%s> statuscode=<%d>",
                    method, url, *res_statuscode);

            if (*res_statuscode == 200 || *res_statuscode == 201) {
                /* Abide by server's timeout, if any */
                const char *p;
                if (res_hdrs &&
                        (hdr = spool_getheader(res_hdrs, "Keep-Alive")) &&
                        (p = strstr(hdr[0], "timeout="))) {
                    int timeout = atoi(p+8);
                    if (be->timeout) be->timeout->mark = time(NULL) + timeout;
                }
            }
            retry = 0;
        }
    } while (retry && retry < 3);

done:
    xsyslog(LOG_DEBUG, "ending HTTP request",
            "method=<%s> guid=<%s> statuscode=<%d> r=<%s>",
            method, guidstr, *res_statuscode, error_message(r));

    if (r) {
        xsyslog(LOG_WARNING, "failed HTTP request - resetting connection",
                "method=<%s> guid=<%s> statuscode=<%d> r=<%s>",
                method, guidstr, *res_statuscode, error_message(r));
        extractor_disconnect(ext);
    }

    spool_free_hdrcache(res_hdrs);
    buf_free(&req_buf);
    buf_free(&url_buf);
    return r;
}


static void generate_record_id(struct buf *id, const struct attachextract_record *rec)
{
    // encode content guid
    buf_putc(id, 'G');
    buf_appendcstr(id, message_guid_encode(&rec->guid));

    // encode media type, make sure it's safe to use as file name
    buf_putc(id, '-');
    const char *types[2] = { rec->type, rec->subtype };
    for (int i = 0; i < 2; i++) {

        if (i) buf_putc(id, '_');

        for (const char *s = types[i]; *s; s++) {
            if (('a' <= *s && *s <= 'z') ||
                ('A' <= *s && *s <= 'Z') ||
                ('0' <= *s && *s <= '9')) {
                buf_putc(id, TOLOWER(*s));
            }
            else {
                buf_putc(id, '%');
                buf_printf(id, "%02x", (unsigned char) *s);
            }
        }
    }
}

EXPORTED int attachextract_extract(const struct attachextract_record *axrec,
                                   const struct buf *data,
                                   int encoding,
                                   struct buf *text)
{
    struct extractor_ctx *ext = global_extractor;
    struct body_t body = { 0, 0, 0, 0, 0, BUF_INITIALIZER };
    const char *guidstr = message_guid_encode(&axrec->guid);
    char *cachefname = NULL;
    char *ctype = NULL;
    struct buf buf = BUF_INITIALIZER;
    unsigned statuscode = 0;
    int is_cached = 0;
    int retry;
    int r = 0;

    if (!global_extractor) {
        /* This is a legitimate case for sieve and lmtpd (so we don't need
         * to spam the logs! */
        xsyslog(LOG_DEBUG, "ignoring uninitialized extractor", NULL);
        return 0;
    }

    if (!axrec->type || !axrec->subtype) {
        xsyslog(LOG_DEBUG, "ignoring incomplete MIME type",
                "type=<%s> subtype<%s>",
               axrec->type ? axrec->type : "<null>",
               axrec->subtype ? axrec->subtype : "<null>");
        return IMAP_NOTFOUND;
    }

    if (message_guid_isnull(&axrec->guid)) {
        xsyslog(LOG_DEBUG, "ignoring null guid", "mime_type=<%s/%s>",
               axrec->type, axrec->subtype);
        return 0;
    }

    if (attachextract_cachedir) {
        generate_record_id(&buf, axrec);
        cachefname = strconcat(attachextract_cachedir, "/", buf_cstring(&buf), NULL);
        buf_reset(&buf);
    }
    else if (attachextract_cacheonly) {
        xsyslog(LOG_ERR,
                "cache-only flag is set, but no cache directory is configured", NULL);
        r = IMAP_NOTFOUND;
        goto done;
    }

    /* Build Content-Type */
    buf_printf(&buf, "%s/%s", axrec->type, axrec->subtype);
    ctype = buf_release(&buf);

    /* Fetch from cache */
    if (cachefname) {
        int fd = open(cachefname, O_RDONLY);
        if (fd != -1) {
            struct buf cache_data = BUF_INITIALIZER;
            buf_refresh_mmap(&cache_data, 1, fd, cachefname, MAP_UNKNOWN_LEN, NULL);
            buf_copy(text, &cache_data);
            buf_free(&cache_data);
            close(fd);

            xsyslog(LOG_DEBUG, "read from cache",
                    "cachefname=<%s>", cachefname);
            is_cached = 1;
            goto gotdata;
        }
        else {
            xsyslog(LOG_DEBUG, "not found in cache",
                    "cachefname=<%s>", cachefname);
        }
    }

    if (attachextract_cacheonly) {
        xsyslog(LOG_DEBUG,
                "cache-only flag is set, will not call extractor", NULL);
        r = IMAP_NOTFOUND;
        goto done;
    }

    /* Fetch from network */
    r = extractor_httpreq(ext, "GET", guidstr, NULL, NULL, &statuscode, &body);

    if (statuscode == 200) {
        buf_copy(text, &body.payload);
        goto gotdata;
    }
    else if (statuscode == 422) {
        // handle unprocessable content like empty file
        buf_reset(text);
        goto gotdata;
    }

    if (statuscode == 599) goto done;

    // otherwise we're going to try three times to PUT this request to the server!

    /* Decode data */
    if (encoding) {
        if (charset_decode(&buf, buf_base(data), buf_len(data), encoding)) {
            syslog(LOG_ERR, "extract_attachment: failed to decode data");
            r = IMAP_IOERROR;
            goto done;
        }
        data = &buf;
    }

    for (retry = 0; retry < 3; retry++) {
        if (retry) {
            // second and third time around, sleep
            sleep(retry);
        }

        /* Send attachment to service for text extraction */
        r = extractor_httpreq(ext, "PUT", guidstr, ctype, data,
                &statuscode, &body);
        if (r == IMAP_IOERROR) goto done;

        if (statuscode == 200 || statuscode == 201) {
            // we got a result, yay
            buf_copy(text, &body.payload);
            goto gotdata;
        }
        else if (statuscode == 422) {
            // handle unprocessable content like empty file
            buf_reset(text);
            goto gotdata;
        }

        if ((statuscode >= 400 && statuscode <= 499) || statuscode == 599) {
            /* indexer can't extract this for some reason, never try again */
            goto done;
        }

        // Keep trying
    }

    // dropped out of the loop?  Then we failed!
    xsyslog(LOG_ERR, "exhausted retry attempts - giving up",
            "retry=<%d>", retry);
    r = IMAP_IOERROR;
    goto done;

gotdata:
    xsyslog(LOG_DEBUG, is_cached ?
            "read cached attachment extract" :
            "extracted text from attachment",
            "guid=<%s> content_type=<%s> size=<%zu>",
            guidstr, ctype, buf_len(text));

    if (!is_cached && cachefname) {
        /* Add to cache */
        char *tempfname = strconcat(cachefname, ".download.XXXXXX", NULL);
        int fd = mkstemp(tempfname);
        if (fd != -1) {
            int wr = retry_write(fd, buf_base(text), buf_len(text));
            close(fd);

            if (wr == -1) {
                xsyslog(LOG_WARNING, "failed to write temp file",
                        "tempfname=<%s>", tempfname);
            }
            else {
                if (cyrus_rename(tempfname, cachefname)) {
                    xsyslog(LOG_WARNING, "failed to rename tempfile to cache file",
                            "tempfname=<%s> cachefname=<%s>",
                            tempfname, cachefname);
                }
                else xsyslog(LOG_DEBUG, "wrote to cache",
                            "cachefname=<%s>", cachefname);
            }

            xunlink(tempfname);
        }
        else xsyslog(LOG_WARNING, "could not create temp file",
                    "tempfname=<%s>", tempfname);
        free(tempfname);
    }

done:
    if (statuscode == 599) {
        extractor_disconnect(ext);
    }
    free(cachefname);
    buf_free(&body.payload);
    buf_free(&buf);
    free(ctype);
    return r;
}

EXPORTED void attachextract_init(struct protstream *clientin)
{
    syslog(LOG_DEBUG, "extractor_init(%p)", clientin);

    /* Read config */
    attachextract_idle_timeout =
        config_getduration(IMAPOPT_SEARCH_ATTACHMENT_EXTRACTOR_IDLE_TIMEOUT, 's');

    attachextract_request_timeout =
        config_getduration(IMAPOPT_SEARCH_ATTACHMENT_EXTRACTOR_REQUEST_TIMEOUT, 's');

    if (attachextract_idle_timeout < attachextract_request_timeout)
        attachextract_idle_timeout = attachextract_request_timeout;

    const char *exturl =
         config_getstring(IMAPOPT_SEARCH_ATTACHMENT_EXTRACTOR_URL);
    if (!exturl) return;

    /* Initialize extractor URL */
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

EXPORTED void attachextract_set_cachedir(const char *cachedir)
{
    char *old_cachedir = attachextract_cachedir;
    attachextract_cachedir = xstrdupnull(cachedir);
    xsyslog(LOG_DEBUG, "updated attachextract cache directory",
            "old_cachedir=<%s> new_cachedir=<%s>", old_cachedir, cachedir);
    free(old_cachedir);
}

EXPORTED const char *attachextract_get_cachedir(void)
{
    return attachextract_cachedir;
}

EXPORTED void attachextract_set_cacheonly(int cacheonly)
{
    int old_cacheonly = attachextract_cacheonly;
    attachextract_cacheonly = cacheonly;
    xsyslog(LOG_DEBUG, "updated attachextract cache-only flag",
            "old_cacheonly=<%d> new_cacheonly=<%d>", old_cacheonly, cacheonly);
}

EXPORTED int attachextract_get_cacheonly(void)
{
    return attachextract_cacheonly;
}
