/* sessionid.c - Session ID management */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "lib/sessionid.h"

#include "lib/libconfig.h"

#include <string.h>
#include <unistd.h>

#include <openssl/rand.h>

static char session_id_buf[MAX_SESSIONID_SIZE];
static int session_id_time = 0;
static int session_id_count = 0;

static char trace_id_buf[MAX_TRACEID_SIZE];

/* Set up the Session ID Buffer */
EXPORTED void session_new_id(void)
{
    const char *base;
    int now = time(NULL);
    if (now != session_id_time) {
        session_id_time = now;
        session_id_count = 0;
    }
    ++session_id_count;
    base = config_getstring(IMAPOPT_SYSLOG_PREFIX);
    if (!base) base = config_servername;

    unsigned long long random;
    RAND_bytes((unsigned char *) &random, sizeof(random));
    snprintf(session_id_buf, MAX_SESSIONID_SIZE, "%.128s-%d-%d-%d-%llu",
             base, session_id_time, getpid(), session_id_count, random);
}

/* Return the session id */
EXPORTED const char *session_id(void)
{
    if (!session_id_count)
        session_new_id();
    return (const char *)session_id_buf;
}

/* Do we have a session id? */
EXPORTED bool session_have_id(void)
{
    return session_id_count && session_id_buf[0];
}

/* Reset session id state (needed for unit tests) */
EXPORTED void session_clear_id(void)
{
    memset(session_id_buf, 0, sizeof(session_id_buf));
    session_id_time = 0;
    session_id_count = 0;
}

/* parse sessionid out of protocol answers */
EXPORTED void parse_sessionid(const char *str, char *sessionid)
{
    char *sp, *ep;
    int len;

    if ((str) && (sp = strstr(str, "SESSIONID=<")) && (ep = strchr(sp, '>')))
    {
        sp += 11;
        len = ep - sp;
        if (len < MAX_SESSIONID_SIZE)
        {
            strncpy(sessionid, sp, len);
            ep = sessionid + len;
            *ep = '\0';
        }
        else
            strcpy(sessionid, "invalid");
    }
    else
        strcpy(sessionid, "unknown");
}

EXPORTED int trace_set_id(const char *traceid, size_t len)
{
    if (traceid && traceid[0]) {
        if (!len) len = strlen(traceid);

        if (len >= MAX_TRACEID_SIZE
            || len > strspn(traceid, TRACE_ID_GOODCHARS))
        {
            return -1;
        }

        snprintf(trace_id_buf, sizeof(trace_id_buf), "%.*s",
                 (int) len, traceid);
        return 0;
    }
    else {
        memset(trace_id_buf, 0, sizeof(trace_id_buf));
        return 0;
    }
}

EXPORTED const char *trace_id(void)
{
    return trace_id_buf[0] ? trace_id_buf : NULL;
}
