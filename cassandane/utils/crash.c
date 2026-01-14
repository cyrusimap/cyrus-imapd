/* crash.c: deliberately crash to get a core file */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const size_t default_alloc = 10 * 1024 * 1024;  /* 10MB */

int main(int argc, char **argv)
{
    size_t alloc = default_alloc;
    char *ptr = NULL;

    if (argc > 1) {
        alloc = strtoull(argv[1], NULL, 10);
    }

    printf("allocating %zu bytes\n", alloc);

    /* big allocation to help detect core truncation */
    ptr = malloc(alloc);
    (void) ptr;

    sleep(1);
    abort();

    /* never get here */
    return 0;
}
