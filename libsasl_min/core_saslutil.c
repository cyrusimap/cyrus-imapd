/* core_saslutil.c - SASL utilities */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/core_saslint.h"

#include "libsasl_min/saslutil.h"

#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*  Contains:
 *
 * sasl_decode64
 * sasl_encode64
 * sasl_mkchal
 * sasl_utf8verify
 * sasl_erasebuffer
 */

char *encode_table;
char *decode_table;

#define CHAR64(c) (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

static char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    "??????????????????????????????????????????????????????????????????????????"
    "?????????????????????????????????????????????????????????????????";

static signed char index_64[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
    -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

/* base64 encode
 *  in      -- input data
 *  inlen   -- input data length
 *  out     -- output buffer (will be NUL terminated)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen  -- gets actual length of output buffer (optional)
 *
 * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
 */

EXPORTED int sasl_encode64(const char *_in,
                           unsigned inlen,
                           char *_out,
                           unsigned outmax,
                           unsigned *outlen)
{
    const unsigned char *in = (const unsigned char *) _in;
    unsigned char *out = (unsigned char *) _out;
    unsigned char oval;
    unsigned olen;

    /* check params */
    if ((inlen > 0) && (in == NULL)) {
        return SASL_BADPARAM;
    }

    /* Will it fit? */
    olen = (inlen + 2) / 3 * 4;
    if (outlen) {
        *outlen = olen;
    }
    if (outmax <= olen) {
        return SASL_BUFOVER;
    }

    /* Do the work... */
    while (inlen >= 3) {
        /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        *out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = basis_64[in[2] & 0x3f];
        in += 3;
        inlen -= 3;
    }
    if (inlen > 0) {
        /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        oval = (in[0] << 4) & 0x30;
        if (inlen > 1) {
            oval |= in[1] >> 4;
        }
        *out++ = basis_64[oval];
        *out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }

    *out = '\0';

    return SASL_OK;
}

/* base64 decode
 *  in     -- input data
 *  inlen  -- length of input data
 *  out    -- output data (may be same as in, must have enough space)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen -- actual output length
 *
 * returns:
 * SASL_BADPROT on bad base64,
 * SASL_BUFOVER if result won't fit,
 * SASL_CONTINUE on a partial block,
 * SASL_OK on success
 */

EXPORTED int sasl_decode64(
    const char *in,
    unsigned inlen,
    char *out,
    unsigned outmax, /* size of the buffer, not counting the NUL */
    unsigned *outlen)
{
    unsigned len = 0;
    unsigned j;
    int c[4];
    int saw_equal = 0;

    /* check parameters */
    if (out == NULL) {
        return SASL_FAIL;
    }

    if (inlen > 0 && *in == '\r') {
        return SASL_FAIL;
    }

    while (inlen > 3) {
        /* No data is valid after an '=' character */
        if (saw_equal) {
            return SASL_BADPROT;
        }

        for (j = 0; j < 4; j++) {
            c[j] = in[0];
            in++;
            inlen--;
        }

        if (CHAR64(c[0]) == -1 || CHAR64(c[1]) == -1) {
            return SASL_BADPROT;
        }
        if (c[2] != '=' && CHAR64(c[2]) == -1) {
            return SASL_BADPROT;
        }
        if (c[3] != '=' && CHAR64(c[3]) == -1) {
            return SASL_BADPROT;
        }
        /* No data is valid after a '=' character, unless it is another '=' */
        if (c[2] == '=' && c[3] != '=') {
            return SASL_BADPROT;
        }
        if (c[2] == '=' || c[3] == '=') {
            saw_equal = 1;
        }

        *out++ = (CHAR64(c[0]) << 2) | (CHAR64(c[1]) >> 4);
        if (++len >= outmax) {
            return SASL_BUFOVER;
        }
        if (c[2] != '=') {
            *out++ = ((CHAR64(c[1]) << 4) & 0xf0) | (CHAR64(c[2]) >> 2);
            if (++len >= outmax) {
                return SASL_BUFOVER;
            }
            if (c[3] != '=') {
                *out++ = ((CHAR64(c[2]) << 6) & 0xc0) | CHAR64(c[3]);
                if (++len >= outmax) {
                    return SASL_BUFOVER;
                }
            }
        }
    }

    *out = '\0'; /* NUL terminate the output string */

    if (outlen) {
        *outlen = len;
    }

    if (inlen != 0) {
        if (saw_equal) {
            /* Unless there is CRLF at the end? */
            return SASL_BADPROT;
        }
        else {
            return (SASL_CONTINUE);
        }
    }

    return SASL_OK;
}

/* make a challenge string (NUL terminated)
 *  buf      -- buffer for result
 *  maxlen   -- max length of result
 *  hostflag -- 0 = don't include hostname, 1 = include hostname
 * returns final length or 0 if not enough space
 */

EXPORTED int sasl_mkchal(sasl_conn_t *conn,
                         char *buf,
                         unsigned maxlen,
                         unsigned hostflag)
{
    unsigned long randnum;
    time_t now;
    unsigned len;

    len = 4           /* <.>\0 */
          + (2 * 20); /* 2 numbers, 20 => max size of 64bit
                       * ulong in base 10 */
    if (hostflag && conn->serverFQDN) {
        len += (unsigned) strlen(conn->serverFQDN) + 1 /* for the @ */;
    }

    if (maxlen < len) {
        return 0;
    }

    if (1 != RAND_bytes((unsigned char *) &randnum, sizeof(randnum))) {
        /* couldn't get random data!
         * cyrus-sasl pretends failure to obtain a random number is a
         * not-enough-memory problem, so we'll do the same for now
         */
         return 0;
    }

    time(&now);

    if (hostflag && conn->serverFQDN) {
        snprintf(
            buf,
            maxlen,
            "<%lu.%lu@%s>",
            randnum,
            (unsigned long) now,
            conn->serverFQDN); /* don't care much about time 32bit overlap */
    }
    else {
        snprintf(buf, maxlen, "<%lu.%lu>", randnum, (unsigned long) now);
    }

    return (int) strlen(buf);
}

/* borrowed from larry. probably works :)
 * probably is also in acap server somewhere
 */
EXPORTED int sasl_utf8verify(const char *str, unsigned len)
{
    unsigned i;
    for (i = 0; i < len; i++) {
        /* how many octets? */
        int seqlen = 0;
        while (str[i] & (0x80 >> seqlen)) {
            ++seqlen;
        }
        if (seqlen == 0) {
            continue; /* this is a valid US-ASCII char */
        }
        if (seqlen == 1) {
            return SASL_BADPROT; /* this shouldn't happen here */
        }
        if (seqlen > 6) {
            return SASL_BADPROT; /* illegal */
        }
        while (--seqlen) {
            if ((str[++i] & 0xC0) != 0x80) {
                return SASL_BADPROT; /* needed a 10 octet */
            }
        }
    }
    return SASL_OK;
}

EXPORTED void sasl_erasebuffer(char *buf, unsigned len)
{
    memset(buf, 0, len);
}

/* Lowercase string in place */
EXPORTED char *sasl_strlower(char *val)
{
    int i;

    if (val == NULL) {
        return (NULL);
    }

    /* don't use tolower(), as it is locale dependent */

    for (i = 0; val[i] != '\0'; i++) {
        if (val[i] >= 'A' && val[i] <= 'Z') {
            val[i] = val[i] - 'A' + 'a';
        }
    }

    return (val);
}

/* A version of gethostname that tries hard to return a FQDN */
EXPORTED int get_fqhostname(char *name, unsigned namelen, int abort_if_no_fqdn)
{
    int return_value;
    struct addrinfo hints;
    struct addrinfo *result;

    return_value = gethostname(name, namelen);
    name[namelen - 1] = '\0'; /* insure string is always 0 terminated*/
    if (return_value != 0) {
        return (return_value);
    }

    if (strchr(name, '.') != NULL) {
        goto LOWERCASE;
    }

    /* gethostname hasn't returned a FQDN, we have to canonify it ourselves */
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM; /* TCP only */
    /* A value of zero for ai_protocol indicates the caller will accept any protocol. or IPPROTO_TCP? */
    hints.ai_protocol = 0; /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
    hints.ai_addrlen = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    if (getaddrinfo(name,
                    NULL, /* don't care abour service/port */
                    &hints,
                    &result)
        != 0)
    {
        if (abort_if_no_fqdn) {
            /* errno on Unix, WSASetLastError on Windows are already done by the function */
            return (-1);
        }
        else {
            goto LOWERCASE;
        }
    }

    if (result == NULL || result->ai_canonname == NULL
        || strchr(result->ai_canonname, '.') == NULL
        || strlen(result->ai_canonname) > namelen - 1)
    {
        freeaddrinfo(result);
        if (abort_if_no_fqdn) {
#if defined(ENODATA)
            errno = ENODATA;
#elif defined(EADDRNOTAVAIL)
            errno = EADDRNOTAVAIL;
#endif
            return (-1);
        }
        else {
            goto LOWERCASE;
        }
    }

    strncpy(name, result->ai_canonname, namelen);
    name[namelen - 1] = '\0'; /* insure string is always 0 terminated*/
    freeaddrinfo(result);

LOWERCASE:
    sasl_strlower(name);
    return (0);
}
