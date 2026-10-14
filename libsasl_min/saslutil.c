/* saslutil.c
 * Rob Siemborski
 * Tim Martin
 */
/*
 * Copyright (c) 1998-2016 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
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

#include "libsasl_min/saslutil.h"
#include "libsasl_min/saslint.h"

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
 * sasl_randcreate
 * sasl_randfree
 * sasl_randseed
 * sasl_rand
 * sasl_churn
 * sasl_erasebuffer
 */

char *encode_table;
char *decode_table;

#define RPOOL_SIZE 3
struct sasl_rand_s
{
    unsigned short pool[RPOOL_SIZE];
    /* since the init time might be really bad let's make this lazy */
    int initialized;
};

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
    sasl_rand_t *pool = NULL;
    unsigned long randnum;
    int ret;
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

    ret = sasl_randcreate(&pool);
    if (ret != SASL_OK) {
        return 0; /* xxx sasl return code? */
    }

    sasl_rand(pool, (char *) &randnum, sizeof(randnum));
    sasl_randfree(&pool);

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

/*
 * To see why this is really bad see RFC 1750
 *
 * unfortunatly there currently is no way to make
 * cryptographically secure pseudo random numbers
 * without specialized hardware etc...
 * thus, this is for nonce use only
 */
EXPORTED void getranddata(unsigned short ret[RPOOL_SIZE])
{
    long curtime;

    memset(ret, 0, RPOOL_SIZE * sizeof(unsigned short));

#ifdef DEV_RANDOM
    {
        int fd;

        fd = open(DEV_RANDOM, O_RDONLY);
        if (fd != -1) {
            unsigned char *buf = (unsigned char *) ret;
            ssize_t bytesread = 0;
            size_t bytesleft = RPOOL_SIZE * sizeof(unsigned short);

            do {
                bytesread = read(fd, buf, bytesleft);
                if (bytesread == -1 && errno == EINTR) {
                    continue;
                }
                else if (bytesread <= 0) {
                    break;
                }
                bytesleft -= bytesread;
                buf += bytesread;
            } while (bytesleft != 0);

            close(fd);
        }
    }
#endif

#ifdef HAVE_GETPID
    ret[0] ^= (unsigned short) getpid();
#endif

#ifdef HAVE_GETTIMEOFDAY
    {
        struct timeval tv;

        /* xxx autoconf macro */
# ifdef _SVID_GETTOD
        if (!gettimeofday(&tv))
# else
        if (!gettimeofday(&tv, NULL))
# endif
        {
            /* longs are guaranteed to be at least 32 bits; we need
               16 bits in each short */
            ret[0] ^= (unsigned short) (tv.tv_sec & 0xFFFF);
            ret[1] ^= (unsigned short) (clock() & 0xFFFF);
            ret[1] ^= (unsigned short) (tv.tv_usec >> 16);
            ret[2] ^= (unsigned short) (tv.tv_usec & 0xFFFF);
            return;
        }
    }
#endif /* HAVE_GETTIMEOFDAY */

    /* if all else fails just use time() */
    curtime = (long) time(NULL); /* better be at least 32 bits */

    ret[0] ^= (unsigned short) (curtime >> 16);
    ret[1] ^= (unsigned short) (curtime & 0xFFFF);
    ret[2] ^= (unsigned short) (clock() & 0xFFFF);

    return;
}

EXPORTED int sasl_randcreate(sasl_rand_t **rpool)
{
    (*rpool) = sasl_ALLOC(sizeof(sasl_rand_t));
    if ((*rpool) == NULL) {
        return SASL_NOMEM;
    }

    /* init is lazy */
    (*rpool)->initialized = 0;

    return SASL_OK;
}

EXPORTED void sasl_randfree(sasl_rand_t **rpool)
{
    sasl_FREE(*rpool);
}

EXPORTED void sasl_randseed(sasl_rand_t *rpool, const char *seed, unsigned len)
{
    /* is it acceptable to just use the 1st 3 char's given??? */
    unsigned int lup;

    /* check params */
    if (seed == NULL) {
        return;
    }
    if (rpool == NULL) {
        return;
    }

    rpool->initialized = 1;

    if (len > sizeof(unsigned short) * RPOOL_SIZE) {
        len = sizeof(unsigned short) * RPOOL_SIZE;
    }

    for (lup = 0; lup < len; lup += 2) {
        rpool->pool[lup / 2] = (seed[lup] << 8) + seed[lup + 1];
    }
}

static void randinit(sasl_rand_t *rpool)
{
    if (!rpool) {
        return;
    }

    if (!rpool->initialized) {
        getranddata(rpool->pool);
        rpool->initialized = 1;
# ifndef HAVE_JRAND48
        {
            /* xxx varies by platform */
            unsigned int *foo = (unsigned int *) rpool->pool;
            srandom(*foo);
        }
# endif /* HAVE_JRAND48 */
    }
}

EXPORTED void sasl_rand(sasl_rand_t *rpool, char *buf, unsigned len)
{
    unsigned int lup;

    /* check params */
    if (!rpool || !buf) {
        return;
    }

    /* init if necessary */
    randinit(rpool);

    for (lup = 0; lup < len; lup++) {
# ifdef HAVE_JRAND48
        buf[lup] = (char) (jrand48(rpool->pool) >> 8);
# else
        buf[lup] = (char) (random() >> 8);
# endif /* HAVE_JRAND48 */
    }
}

/* this function is just a bad idea all around, since we're not trying to
   implement a true random number generator */
EXPORTED void sasl_churn(sasl_rand_t *rpool, const char *data, unsigned len)
{
    unsigned int lup;

    /* check params */
    if (!rpool || !data) {
        return;
    }

    /* init if necessary */
    randinit(rpool);

    for (lup = 0; lup < len; lup++) {
        rpool->pool[lup % RPOOL_SIZE] ^= data[lup];
    }
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
