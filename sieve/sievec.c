/* sievec.c -- compile a sieve script to bytecode manually */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sieve_interface.h"
#include <syslog.h>
#include <sysexits.h>

#include "libconfig.h"
#include "xmalloc.h"

#include "script.h"
#include "util.h"
#include "assert.h"
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TIMSIEVE_FAIL -1
#define TIMSIEVE_OK 0

int main(int argc, char **argv)
{
    FILE *instream;
    char *err = NULL;
    sieve_script_t *s = NULL;
    bytecode_info_t *bc = NULL;
    int opt, fd, usage_error = 0;
    char *alt_config = NULL;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        default:
            usage_error = 1;
            break;
        }
    }

    if (usage_error || (argc - optind) < 2) {
        fprintf(stderr, "Syntax: %s [-C <altconfig>] <filename> <outputfile>\n",
               argv[0]);
        exit(1);
    }

    instream = !strcmp(argv[optind], "-") ? stdin : fopen(argv[optind], "r");
    if(instream == NULL) {
        fprintf(stderr, "Unable to open %s for reading\n", argv[optind]);
        exit(1);
    }

    /* Load configuration file. */
    config_read(alt_config, 0);

    if(sieve_script_parse_only(instream, &err, &s) != SIEVE_OK) {
        if(err) {
            fprintf(stderr, "Unable to parse script: %s\n", err);
        } else {
            fprintf(stderr, "Unable to parse script.\n");
        }
        sieve_script_free(&s);

        exit(1);
    }

    /* Now, generate the bytecode */
    if(sieve_generate_bytecode(&bc, s) == -1) {
        fprintf(stderr, "bytecode generate failed\n");
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        exit(1);
    }

    /* Now, open the new file */
    fd = open(argv[++optind], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        fprintf(stderr, "couldn't open bytecode output file\n");
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        exit(1);
    }

    /* Now, emit the bytecode */
    if(sieve_emit_bytecode(fd, bc) == -1) {
        fprintf(stderr, "bytecode emit failed\n");
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        exit(1);
    }

    close(fd);

    sieve_free_bytecode(&bc);
    sieve_script_free(&s);

    return 0;
}

EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s (%d)\r\n", s, code);

    if (code != EX_PROTOCOL && config_fatals_abort) abort();

    exit(code);
}
