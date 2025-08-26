/* cyr_dbtool.c -- manage Cyrus databases
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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "assert.h"
#include "cyrusdb.h"
#include "global.h"
#include "mailbox.h"
#include "util.h"
#include "retry.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define STACKSIZE 64000
static char stack[STACKSIZE+1];

static int outfd;

static struct db *db = NULL;
static struct txn **tidp = NULL;

static int read_key_value(char **keyptr, size_t *keylen, char **valptr, size_t *vallen) {
  int c,res,inkey;
  res = 0;
  inkey = 1;
  *keyptr = stack;
  *keylen = 0;
  *vallen = 0;
  while( (c = getchar()) != EOF ) {
    if (c == '\n') break;
    if ((c == '\t') && inkey) {
      inkey = 0;
      *valptr = stack + *keylen + 1;
    } else {
      if (inkey) {
        (*keyptr)[(*keylen)++] = c;
        res = 1;
      } else {
        (*valptr)[(*vallen)++] = c;
      }
    }
    if (*keylen + *vallen >= STACKSIZE - 1) {
      printf("Error, stack overflow\n");
      fatal("stack overflow", EX_DATAERR);
    }
  }
  (*keyptr)[*keylen] = '\0';
  if (inkey) {
    *valptr = *keyptr + *keylen;
  } else {
    (*valptr)[*vallen] = '\0';
  }
  return res;
}

static int printer_cb(void *rock __attribute__((unused)),
    const char *key, size_t keylen,
    const char *data, size_t datalen)
{
    struct iovec io[4];
    io[0].iov_base = (char *) key;
    io[0].iov_len = keylen;
    io[1].iov_base = (char *) "\t";
    io[1].iov_len = 1;
    io[2].iov_base = (char *) data;
    io[2].iov_len = datalen;
    io[3].iov_base = (char *) "\n";
    io[3].iov_len = 1;
    retry_writev(outfd, io, 4);
    return 0;
}

/* use IMAP literals for all communications */
static int aprinter_cb(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen)
{
    struct protstream *out = (struct protstream *)rock;

    prot_printamap(out, key, keylen);
    prot_putc(' ', out);
    prot_printamap(out, data, datalen);
    prot_putc('\n', out);

    return 0;
}

static void batch_commands(struct db *db)
{
    struct buf cmd = BUF_INITIALIZER;
    struct buf key = BUF_INITIALIZER;
    struct buf val = BUF_INITIALIZER;
    struct txn *tid = NULL;
    struct protstream *in = prot_new(0, 0); // stdin
    struct protstream *out = prot_new(1, 1); // stdout
    int line = 0;
    int c = '-';
    int r = 0;

    prot_setisclient(in, 1);

    while (1) {
        buf_reset(&cmd);
        buf_reset(&key);
        buf_reset(&val);
        line++;
        c = getword(in, &cmd);
        if (c == EOF) break;

        if (c == ' ')
            c = getbastring(in, NULL, &key);
        if (c == ' ')
            c = getbastring(in, NULL, &val);
        if (c == '\r') c = prot_getc(in);
        if (c != '\n') {
            r = IMAP_PROTOCOL_BAD_PARAMETERS;
            goto done;
        }

        if (cmd.len) {
            /* got a command! */
            if (!strcmp(cmd.s, "BEGIN")) {
                if (tidp) {
                    r = IMAP_MAILBOX_LOCKED;
                    goto done;
                }
                tidp = &tid;
            }
            else if (!strcmp(cmd.s, "SHOW")) {
                r = cyrusdb_foreach(db, key.s, key.len, NULL, aprinter_cb, out, tidp);
                if (r) goto done;
                prot_flush(out);
            }
            else if (!strcmp(cmd.s, "SET")) {
                r = cyrusdb_store(db, key.s, key.len, val.s, val.len, tidp);
                if (r) goto done;
            }
            else if (!strcmp(cmd.s, "GET")) {
                const char *res;
                size_t reslen;
                r = cyrusdb_fetch(db, key.s, key.len, &res, &reslen, tidp);
                switch (r) {
                case 0:
                    aprinter_cb(out, key.s, key.len, res, reslen);
                    prot_flush(out);
                    break;
                case CYRUSDB_NOTFOUND:
                    r = 0;
                    break;
                default:
                    goto done;
                }
            }
            else if (!strcmp(cmd.s, "DELETE")) {
                r = cyrusdb_delete(db, key.s, key.len, tidp, 1);
                if (r) goto done;
            }
            else if (!strcmp(cmd.s, "COMMIT")) {
                if (!tidp) {
                    r = IMAP_NOTFOUND;
                    goto done;
                }
                r = cyrusdb_commit(db, *tidp);
                if (r) goto done;
                tid = NULL;
                tidp = NULL;
            }
            else if (!strcmp(cmd.s, "ABORT")) {
                if (!tidp) {
                    r = IMAP_NOTFOUND;
                    goto done;
                }
                r = cyrusdb_abort(db, *tidp);
                if (r) goto done;
                tid = NULL;
                tidp = NULL;
            }
            else {
                r = IMAP_MAILBOX_NONEXISTENT;
                goto done;
            }
        }
    }

done:
    if (r) {
        if (*tidp) cyrusdb_abort(db, *tidp);
        fprintf(stderr, "FAILED: line %d at cmd %.*s with error %s\n",
                line, (int)cmd.len, cmd.s, error_message(r));
    }

    prot_free(in);
    prot_free(out);

    buf_free(&cmd);
    buf_free(&key);
    buf_free(&val);
}

int main(int argc, char *argv[])
{
    const char *fname;
    const char *action;
    char *key = NULL;
    char *value = NULL;
    int i,r;
    size_t keylen = 0, vallen = 0, reslen = 0;
    int opt,loop;
    char *alt_config = NULL;
    const char *res = NULL;
    int is_get = 0;
    int is_set = 0;
    int is_delete = 0;
    int use_stdin = 0;
    int db_flags = 0;
    struct txn *tid = NULL;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:NRSTcnt";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "convert", no_argument, NULL, 'c' },
        { "no-checksum", no_argument, NULL, 'N' },
        { "create", no_argument, NULL, 'n' },
        { "readonly", no_argument, NULL, 'R' },
        { "no-sync", no_argument, NULL, 'S' },
        { "use-transaction", no_argument, NULL, 'T' },
        { "no-transaction", no_argument, NULL, 't' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'c':
            db_flags |= CYRUSDB_CONVERT;
            break;
        case 'N':
            db_flags |= CYRUSDB_NOCRC;
            break;
        case 'n': /* create new */
            db_flags |= CYRUSDB_CREATE;
            break;
        case 'R':
            db_flags |= CYRUSDB_SHARED;
            break;
        case 'S':
            db_flags |= CYRUSDB_NOSYNC;
            break;
        case 'T':
            tidp = &tid;
            break;
        case 't': /* legacy - now the default, but don't break existing users */
            tidp = NULL;
            break;
        }
    }

    if ((argc - optind) < 3) {
        char sep;
        strarray_t *backends = cyrusdb_backends();

        fprintf(stderr, "Usage: %s [-C altconfig] <db file> <db backend> <action> [<key>] [<value>]\n", argv[0]);
        fprintf(stderr, "Usable Backends");

        for(i=0, sep = ':'; i < backends->count; i++) {
            fprintf(stderr, "%c %s", sep, strarray_nth(backends, i));
            sep = ',';
        }
        strarray_free(backends);

        fprintf(stderr, "\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -c     convert database to named backend if not already\n");
        fprintf(stderr, "  -N     minimise use of checksums (don't check on read, create nochecksum if supported)\n");
        fprintf(stderr, "  -n     create the database if it doesn't exist\n");
        fprintf(stderr, "  -R     open the database readonly (won't create a new DB)\n");
        fprintf(stderr, "  -S     don't fsync writes (dangerous)\n");
        fprintf(stderr, "  -T     use a single transaction for the action\n");
        fprintf(stderr, "  -t     don't use a transaction (default)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Actions:\n");
        fprintf(stderr, "* show [<prefix>]\n");
        fprintf(stderr, "* get <key>\n");
        fprintf(stderr, "* set <key> <value>\n");
        fprintf(stderr, "* delete <key>\n");
        fprintf(stderr, "* dump - internal format dump\n");
        fprintf(stderr, "* consistent - check consistency (if supported)\n");
        fprintf(stderr, "* repack - repack/checkpoint the DB (if supported)\n");
        fprintf(stderr, "* damage - start a commit then die during\n");
        fprintf(stderr, "* batch - read from stdin and execute commands\n");
        fprintf(stderr, "You may omit key or key/value and specify one per line on stdin\n");
        fprintf(stderr, "keys are terminated by tab or newline, values are terminated by newline\n");
        exit(-1);
    }

    fname = argv[optind];
    action = argv[optind+2];

    if(fname[0] != '/') {
        printf("\nSorry, you cannot use this tool with relative path names.\n"
               "This is because some database backends do not\n"
               "always do what you would expect with them.\n"
               "\nPlease use absolute pathnames instead.\n\n");
        exit(EX_OSERR);
    }

    outfd = fileno(stdout);

    cyrus_init(alt_config, "cyr_dbtool", 0, 0);

    r = cyrusdb_lockopen(argv[optind+1], fname, db_flags, &db, tidp);
    if(r != CYRUSDB_OK)
        fatal("can't open database", EX_TEMPFAIL);

    if (( is_get = !strcmp(action, "get"))  ||
      (is_delete = !strcmp(action, "delete")) ||
      (is_set = !strcmp(action, "set")) ) {
        use_stdin = ( (argc - optind) < 4 );
        if (use_stdin) {
          loop = read_key_value( &key, &keylen, &value, &vallen );
        } else {
          key = argv[optind+3];
          keylen = strlen(key);
          if (is_set) {
            value = argv[optind+4];
            vallen = strlen(value);
          }
          loop = 1;
        }
        while ( loop ) {
          if (is_get) {
            r = cyrusdb_fetch(db, key, keylen, &res, &reslen, tidp);
            if (r) break;
            printf("%.*s\n", (int)reslen, res);
          } else if (is_set) {
            r = cyrusdb_store(db, key, keylen, value, vallen, tidp);
            if (r) break;
          } else if (is_delete) {
            r = cyrusdb_delete(db, key, keylen, tidp, 1);
            if (r) break;
          }
          loop = 0;
          if ( use_stdin ) {
            loop = read_key_value( &key, &keylen, &value, &vallen );
          }
        }
    } else if (!strcmp(action, "batch")) {
        batch_commands(db);
    } else if (!strcmp(action, "show")) {
        if ((argc - optind) < 4) {
            r = cyrusdb_foreach(db, "", 0, NULL, printer_cb, NULL, tidp);
        } else {
            key = argv[optind+3];
            keylen = strlen(key);
            r = cyrusdb_foreach(db, key, keylen, NULL, printer_cb, NULL, tidp);
        }
    } else if (!strcmp(action, "dump")) {
        int level = 1;
        if ((argc - optind) > 3)
            level = atoi(argv[optind+3]);
        r = cyrusdb_dump(db, level);
    } else if (!strcmp(action, "consistent")) {
        if (cyrusdb_consistent(db)) {
            printf("No, not consistent\n");
        } else {
            printf("Yes, consistent\n");
        }
    } else if (!strcmp(action, "repack")) {
        r = cyrusdb_repack(db);
    } else if (!strcmp(action, "damage")) {
        if (!tidp) tidp = &tid;
        cyrusdb_store(db, "INVALID", 7, "CRASHME", 7, tidp);
        assert(!*tidp);
    } else {
        printf("Unknown action %s\n", action);
    }

    if (tidp) {
        if (r) {
            printf("ABORTING: %s\n", cyrusdb_strerror(r));
            r = cyrusdb_abort(db, *tidp);
            if (r) printf("ERROR ON ABORT: %s\n", cyrusdb_strerror(r));
        }
        else {
            r = cyrusdb_commit(db, *tidp);
            if (r) printf("ERROR ON COMMIT: %s\n", cyrusdb_strerror(r));
        }
    }

    cyrusdb_close(db);

    cyrus_done();

    return r ? 1 : 0;
}
