/*
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

/* cyrus includes */
#include "assert.h"
#include "bsearch.h"
#include "global.h"
#include "index.h"
#include "search_engines.h"
#include "conversations.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int usage(const char *name);

int verbose = 0;
static enum { PART_TREE, TEXT_SECTIONS, TEXT_RECEIVER } dump_mode = PART_TREE;

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static void dump_octets(FILE *fp, const char *base, unsigned int len)
{
    unsigned int i;

    while (len > 0) {
        fputs("    ", fp);
        for (i = 0 ; i < 16 && i < len ; i++)
            fprintf(fp, "%02x ", ((unsigned char *)base)[i]);
        for (; i < 16 ; i++)
            fputs("   ", fp);
        fputs("   ", fp);
        for (i = 0 ; i < 16 && i < len ; i++)
            fputc((isprint(base[i]) && !isspace(base[i]) ? base[i] : '.'), fp);
        fputc('\n', fp);

        i = (len > 16 ? 16 : len);
        len -= i;
        base += i;
    }
}

static void dump_buf(FILE *fp, const struct buf *data)
{
#define MAX_TEXT    512
    if (verbose || data->len <= MAX_TEXT) {
        dump_octets(fp, data->s, data->len);
    }
    else {
        dump_octets(fp, data->s, MAX_TEXT/2);
        fputs("    ...\n", fp);
        dump_octets(fp, data->s + data->len - MAX_TEXT/2, MAX_TEXT/2);
    }
#undef MAX_TEXT
}

static int dump_one_section(int partno, charset_t charset, int encoding,
                            const char *type __attribute__((unused)),
                            const char *subtype,
                            const struct param *type_params __attribute__((unused)),
                            const char *disposition __attribute__((unused)),
                            const struct param *disposition_params __attribute__((unused)),
                            const struct message_guid *content_guid __attribute__((unused)),
                            const char *part __attribute__((unused)),
                            struct buf *data,
                            void *rock __attribute__((unused)))
{
#define MAX_TEXT    512
    printf("SECTION partno=%d length=%llu subtype=%s charset=%s encoding=%s\n",
            partno, (unsigned long long)data->len, subtype, charset_alias_name(charset), encoding_name(encoding));
    dump_buf(stdout, data);
    return 0;
#undef MAX_TEXT
}

static int dump_text_sections(message_t *message)
{
    return message_foreach_section(message, dump_one_section, NULL);
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static int dump_message(message_t *message)
{
    return dump_text_sections(message);
}

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    const char *filename = NULL;
    const char *mboxname = NULL;
    int recno = 1;
    int record_flag = 0;
    int r = 0;

    while ((c = getopt(argc, argv, "Rf:m:pr:stvC:")) != EOF) {
        switch (c) {

        case 'f':
            filename = optarg;
            break;

        case 'm':
            mboxname = optarg;
            break;

        case 'p':
            dump_mode = PART_TREE;
            break;

        case 'r':
            recno = atoi(optarg);
            if (recno <= 0)
                usage(argv[0]);
            break;

        case 's':
            dump_mode = TEXT_SECTIONS;
            break;

        case 't':
            dump_mode = TEXT_RECEIVER;
            break;

        case 'v':
            verbose++;
            break;

        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'R':
            record_flag = 1;
            break;

        default:
            usage(argv[0]);
            break;
        }
    }

    if (optind != argc)
        usage(argv[0]);
    if (mboxname && filename)
        usage(argv[0]);

    cyrus_init(alt_config, "message_test", 0, CONFIG_NEED_PARTITION_DATA);

    if (mboxname && record_flag) {
        struct mailbox *mailbox = NULL;
        struct index_record record;
        message_t *message = NULL;

        r = mailbox_open_irl(mboxname, &mailbox);
        if (r) {
            fprintf(stderr, "Failed to open mailbox %s: %s\n",
                    mboxname, error_message(r));
            return 1;
        }

        memset(&record, 0, sizeof(struct index_record));
        record.recno = recno;
        r = mailbox_reload_index_record(mailbox, &record);
        if (r) {
            fprintf(stderr, "Failed to read index record %u of %s: %s\n",
                    recno, mboxname, error_message(r));
            return 1;
        }

        message = message_new_from_record(mailbox, &record);
        r = dump_message(message);
        if (r) {
            fprintf(stderr, "Error dumping message: %s\n",
                    error_message(r));
            return 1;
        }

        message_unref(&message);
        mailbox_close(&mailbox);
    }
    else if (mboxname) {
        struct mailbox *mailbox = NULL;
        message_t *message = NULL;

        r = mailbox_open_irl(mboxname, &mailbox);
        if (r) {
            fprintf(stderr, "Failed to open mailbox %s: %s\n",
                    mboxname, error_message(r));
            return 1;
        }

        message = message_new_from_mailbox(mailbox, recno);
        r = dump_message(message);
        if (r) {
            fprintf(stderr, "Error dumping message: %s\n",
                    error_message(r));
            return 1;
        }

        message_unref(&message);
        mailbox_close(&mailbox);
    }
    else if (filename) {
        message_t *message = NULL;

        message = message_new_from_filename(filename);
        r = dump_message(message);
        if (r) {
            fprintf(stderr, "Error dumping message: %s\n",
                    error_message(r));
            return 1;
        }

        message_unref(&message);
    }
    else {
        message_t *message = NULL;
        int c;
        struct buf buf = BUF_INITIALIZER;

        while ((c = fgetc(stdin)) != EOF)
            buf_putc(&buf, c);
        message = message_new_from_data(buf.s, buf.len);
        dump_message(message);
        if (r) {
            fprintf(stderr, "Error dumping message: %s\n",
                    error_message(r));
            return 1;
        }

        message_unref(&message);
        buf_free(&buf);
    }

    cyrus_done();

    return r;
}

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [format-options] -m mailbox [-r recno] [-R]\n", name);
    fprintf(stderr, "       %s [format-options] -f filename\n", name);
    fprintf(stderr, "       %s [format-options] < message\n", name);
    fprintf(stderr, "format-options :=\n");
    fprintf(stderr, "-p         dump message part tree\n");
    fprintf(stderr, "-s         dump text sections\n");
    fprintf(stderr, "-t         dump output from search text receiver\n");
    exit(EX_USAGE);
}

EXPORTED void fatal(const char* s, int code)
{
    fprintf(stderr, "message_test: %s\n", s);
    cyrus_done();
    exit(code);
}


