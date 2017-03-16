/*
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

/* cyrus includes */
#include "assert.h"
#include "exitcodes.h"
#include "global.h"
#include "sync_log.h"
#include "sysexits.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "http_jmap.h"

/* modes */
enum { UNKNOWN, LOOKUP, DELETE, FLAG, UNFLAG };

int verbose = 0;

int mode = UNKNOWN;

struct mode_data {
    struct buf buf;
    char flags;
};

static int usage(const char *name)
        __attribute__((noreturn));

static void dump_token(const struct jmapauth_token *tok)
{
    char datetime[RFC3339_DATETIME_MAX+1];

    char *tokenid = jmapauth_tokenid(tok);
    printf("%s :\n", tokenid);
    printf("  userid  : %s\n", tok->userid);
    printf("  version : %d\n", tok->version);
    printf("  kind    : %c\n", tok->kind);

    time_to_rfc3339(tok->lastuse, datetime, RFC3339_DATETIME_MAX);
    datetime[RFC3339_DATETIME_MAX] = '\0';
    printf("  lastuse : %s\n", datetime);

    printf("  flagged : %s\n", tok->flags ? "yes" : "no");
    printf("  data    : %.*s\n", (int) tok->datalen, (char*) tok->data);

    free(tokenid);
}

static int flag_token(struct db *db, struct jmapauth_token *tok,
                      struct mode_data *mdata, struct txn **tidptr)
{
    if (verbose) {
        char *tokenid = jmapauth_tokenid(tok);
        fprintf(stderr, "flagging token %s of user %s\n", tokenid, tok->userid);
        free(tokenid);
    }

    /* Preserve token data across database operations */
    buf_reset(&mdata->buf);
    buf_appendmap(&mdata->buf, tok->data, tok->datalen);
    tok->data = buf_base(&mdata->buf);
    tok->datalen = buf_len(&mdata->buf);

    /* Set flags */
    tok->flags = mdata->flags;

    return jmapauth_store(db, tok, tidptr);
}

static int do_lookup(struct db *db __attribute__((unused)),
                     struct jmapauth_token *tok,
                     void* rock __attribute__((unused)),
                     struct txn **tidptr __attribute__((unused)))
{
    dump_token(tok);
    return 0;
}

static int do_delete(struct db *db,
                     struct jmapauth_token *tok,
                     void* rock __attribute__((unused)),
                     struct txn **tidptr)
{
    char *tokenid = jmapauth_tokenid(tok);
    int r;

    if (verbose) {
        fprintf(stderr, "deleting token %s of user %s\n", tokenid, tok->userid);
    }
    r = jmapauth_delete(db, tokenid, tidptr);
    free(tokenid);
    return r;
}

static int do_flag(struct db *db,
                   struct jmapauth_token *tok,
                   void* rock,
                   struct txn **tidptr)
{
    return flag_token(db, tok, rock, tidptr);
}

static time_t parse_lastuse(const char *arg)
{
    time_t lastuse, now = time( NULL);
    struct tm since = *localtime(&now);
    uint32_t dur = 0;
    const char *p = NULL;
    int r;

    r = parseuint32(arg, &p, &dur);
    if (r) {
        return 0;
    }

    if (p && *p && ((*p != 'm' && *p != 'h') || *(p+1))) {
        return 0;
    }

    switch (*p) {
        case 'm':
            since.tm_min -= dur;
            break;
        case 'h':
            since.tm_hour -= dur;
            break;
        default:
            since.tm_sec -= dur;
    }

    lastuse = mktime(&since);
    if (lastuse == (time_t)-1) {
        return 0;
    }

    return lastuse;
}

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    const char *userid = NULL;
    const char *tokenid = NULL;
    const char *fname = NULL;
    char kind = 0;
    int expired = 0;
    time_t lastuse = 0;
    struct mode_data mdata = { BUF_INITIALIZER, 0 };
    int r = 0;

    if ((geteuid()) == 0 && (become_cyrus(/*ismaster*/0) != 0)) {
        fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((c = getopt(argc, argv, "C:dD:fFk:lt:u:vx")) != EOF) {
        switch (c) {
            case 'C': /* alt config file */
                alt_config = optarg;
                break;
            case 'd':
                if (mode != UNKNOWN)
                    usage(argv[0]);
                mode = DELETE;
                break;
            case 'D':
                fname = optarg;
                break;
            case 'f':
                if (mode != UNKNOWN)
                    usage(argv[0]);
                mode = FLAG;
                mdata.flags = 1;
                break;
            case 'F':
                if (mode != UNKNOWN)
                    usage(argv[0]);
                mode = UNFLAG;
                mdata.flags = 0;
                break;
            case 'k':
                if (kind || !optarg) usage(argv[0]);
                if (!strcmp(optarg, "L"))
                    kind = JMAPAUTH_LOGINID_KIND;
                else if (!strcmp(optarg, "A"))
                    kind = JMAPAUTH_ACCESS_KIND;
                else
                    usage(argv[0]);
                break;
            case 'l':
                if (mode != UNKNOWN)
                    usage(argv[0]);
                mode = LOOKUP;
                break;
            case 't':
                tokenid = optarg;
                break;
            case 'u':
                lastuse = parse_lastuse(optarg);
                if (lastuse == 0) usage(argv[0]);
                break;
            case 'v':
                verbose++;
                break;
            case 'x':
                expired = 1;
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    if (mode == UNKNOWN)
        usage(argv[0]);

    if (optind == argc-1)
        userid = argv[optind];
    else if (optind == argc)
        userid = NULL;
    else
        usage(argv[0]);

    if (tokenid && userid) {
        fprintf(stderr, "error: -t must not be combined with username\n");
        usage(argv[0]);
    }

    cyrus_init(alt_config, "ctl_jmapauth", 0, 0);

    mboxlist_init(0);
    mboxlist_open(NULL);

    sync_log_init();

    struct db *db = NULL;

    r = jmapauth_open(&db, 0, fname);
    if (r) {
        fprintf(stderr, "jmapauth_open: %s\n", cyrusdb_strerror(r));
        goto done;
    }

    if (tokenid) {
        /* Operate on a single token */
        if (mode == LOOKUP) {
            struct jmapauth_token *tok;
            r = jmapauth_fetch(db, tokenid, &tok, 0, NULL);
            if (r) {
                fprintf(stderr, "jmapauth_fetch: %s\n", cyrusdb_strerror(r));
                goto done;
            }
            dump_token(tok);
            jmapauth_token_free(tok);
        }
        else if (mode == DELETE) {
            if (verbose) {
                fprintf(stderr, "Deleting token %s", tokenid);
            }
            r = jmapauth_delete(db, tokenid,  NULL);
            if (r) {
                fprintf(stderr, "jmapauth_delete: %s\n", cyrusdb_strerror(r));
                goto done;
            }
        }
        else if (mode == FLAG || mode == UNFLAG) {
            struct jmapauth_token *tok;
            struct txn *tid = NULL;

            /* Fetch token */
            r = jmapauth_fetch(db, tokenid, &tok, 0, &tid);
            if (r) {
                fprintf(stderr, "jmapauth_fetch: %s\n", cyrusdb_strerror(r));
                goto done;
            }

            /* Flag token */
            r = flag_token(db, tok, &mdata, &tid);
            if (r) {
                cyrusdb_abort(db, tid);
                fprintf(stderr, "flag_token %s\n", cyrusdb_strerror(r));
                goto done;
            }

            /* Commit transaction */
            r = cyrusdb_commit(db, tid);
            if (r) {
                cyrusdb_abort(db, tid);
                fprintf(stderr, "cyrusdb_commit: %s\n", cyrusdb_strerror(r));
                goto done;
            }
        }
    } else {
        /* Determine db callback */
        jmapauth_find_proc_t proc = NULL;
        switch (mode) {
            case DELETE:
                proc = do_delete;
                break;
            case FLAG:
            case UNFLAG:
                proc = do_flag;
                break;
            case LOOKUP:
                proc = do_lookup;
                break;
            default:
                /* never reached */
                usage(argv[0]);
        }

        /* Operate on multiple tokens, either bound to a userid or all */
        r = jmapauth_find(db, userid, expired, lastuse, kind, proc, &mdata, NULL);
        if (r) {
            fprintf(stderr, "jmapauth_find: %s\n", cyrusdb_strerror(r));
            goto done;
        }
    }

    r = jmapauth_close(db);
    if (r) {
        fprintf(stderr, "jmapauth_close: %s\n", cyrusdb_strerror(r));
        goto done;
    }

done:
    if (r && db) jmapauth_close(db);
    sync_log_done();

    mboxlist_close();
    mboxlist_done();

    cyrus_done();

    buf_free(&mdata.buf);
    return r;
}

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [options] [command] [criteria] [username]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "options are:\n");
    fprintf(stderr, "    -v         be verbose\n");
    fprintf(stderr, "    -C config  use alternate config file\n");
    fprintf(stderr, "    -D dbfile  use dbfile as jmapauth database\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "command is one of:\n");
    fprintf(stderr, "    -l         lookup tokens (default)\n");
    fprintf(stderr, "    -d         delete tokens\n");
    fprintf(stderr, "    -f         flag tokens\n");
    fprintf(stderr, "    -F         unflag tokens\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "criteria is a combination of:\n");
    fprintf(stderr, "    -k A,L     find access tokens 'A' or login ids 'L' (default all)\n");
    fprintf(stderr, "    -x         find expired tokens. Tokens expiry dates are determined according\n"
                    "               to their corresponding ttl parameters in imapd.conf\n");
    fprintf(stderr, "    -u <dur>   find tokens that haven't been used in the last <dur> time units\n"
                    "               <dur> must be a positive integer, optionally followed by either\n"
                    "               'm' or 'h' for minutes and hours, respectively. Default is seconds.\n");
    fprintf(stderr, "    or\n");
    fprintf(stderr, "    -t id      find token with id\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "username:      limit search to tokens for username (default all)\n");
    exit(EC_USAGE);
}
