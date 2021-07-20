/* cyr_sequence.c -- manipulate sequences
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "sequence.h"
#include "global.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [-C altconfig] [-m maxval] command sequence [args]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " - parsed               => dump a parsed view of the list structure\n");
    fprintf(stderr, " - compress             => dump a compressed list\n");
    fprintf(stderr, " - ismember [num...]    => is num in the list for each num\n");
    fprintf(stderr, " - members              => all list members in order\n");
    fprintf(stderr, " - create [-s] [items]  => generate a new list from the items\n");
    fprintf(stderr, "                           - prefix numbers with '~' for remove\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    const char *alt_config = NULL;
    unsigned maxval = 0;
    int flags = SEQ_MERGE;
    struct seqset *seq = NULL;
    int opt;
    unsigned num;
    char *res;
    const char *origlist = NULL;

    while ((opt = getopt(argc, argv, "C:m:o:s")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'm': /* maxval */
            parseuint32(optarg, NULL, &maxval);
            break;
        case 'o':
            origlist = optarg;
            break;
        case 's':
            flags = SEQ_SPARSE;
        }
    }

    if ((argc - optind) < 1) usage(argv[0]);


    cyrus_init(alt_config, "cyr_sequence", 0, 0);

    /* special case */
    if (!strcmp(argv[optind], "create")) {
        int i;
        seq = seqset_init(maxval, flags);
        for (i = optind + 1; i < argc; i++) {
            char *ptr = argv[i];
            int isadd = 1;
            if (*ptr == '~') {
                isadd = 0;
                ptr++;
            }
            if (parseuint32(ptr, NULL, &num))
                printf("%s NAN\n", argv[i]);
            else
                seqset_add(seq, num, isadd);
        }
        if (origlist) {
            unsigned oldmax = seq_lastnum(origlist);
            if (oldmax > maxval) {
                struct seqset *origseq = seqset_parse(origlist, NULL, oldmax);
                unsigned val;
                for (val = maxval + 1; val <= oldmax; val++)
                    seqset_add(seq, val, seqset_ismember(origseq, val));
                seqset_free(origseq);
            }
        }
        res = seqset_cstring(seq);
        printf("%s\n", res);
        free(res);
    }
    else if (!strcmp(argv[optind], "parsed")) {
        unsigned i;
        seq = seqset_parse(argv[optind+1], NULL, maxval);
        printf("Sections: " SIZE_T_FMT "\n", seq->len);
        for (i = 0; i < seq->len; i++) {
            if (seq->set[i].high == UINT_MAX)
                printf(" [%u, *]\n", seq->set[i].low);
            else
                printf(" [%u, %u]\n", seq->set[i].low, seq->set[i].high);
        }
    }
    else if (!strcmp(argv[optind], "compress")) {
        seq = seqset_parse(argv[optind+1], NULL, maxval);
        res = seqset_cstring(seq);
        printf("%s\n", res);
        free(res);
    }
    else if (!strcmp(argv[optind], "members")) {
        seq = seqset_parse(argv[optind+1], NULL, maxval);
        while ((num = seqset_getnext(seq))) {
            printf("%u\n", num);
        }
    }
    else if (!strcmp(argv[optind], "join")) {
        struct seqset *seq2;
        seq = seqset_parse(argv[optind+1], NULL, maxval);
        seq2 = seqset_parse(argv[optind+2], NULL, maxval);
        seqset_join(seq, seq2);
        res = seqset_cstring(seq);
        printf("%s\n", res);
        free(res);
    }
    else if (!strcmp(argv[optind], "ismember")) {
        int i;
        seq = seqset_parse(argv[optind+1], NULL, maxval);
        for (i = optind + 2; i < argc; i++) {
            if (parseuint32(argv[i], NULL, &num))
                printf("%s NAN\n", argv[i]);
            else
                printf("%d %s\n", num, seqset_ismember(seq, num) ? "Yes" : "No");
        }
    }
    else {
        printf("Unknown command %s", argv[optind]);
    }

    seqset_free(seq);

    cyrus_done();

    return 0;
}
