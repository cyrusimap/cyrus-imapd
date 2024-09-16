/* crash.c: deliberately crash to get a core file
 *
 * Copyright (c) 2017 FastMail Pty. Ltd.  All rights reserved.
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
 * 3. The name "FastMail" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *        FastMail Pty. Ltd.
 *        Level 1, 91 William St
 *        Melbourne 3000
 *        Victoria
 *        Australia
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by FastMail Pty. Ltd."
 *
 * FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

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
