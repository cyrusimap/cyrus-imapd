/* notify_null.c -- NULL notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "notify_null.h"

#include <string.h>

char* notify_null(const char *class __attribute__((unused)),
                  const char *priority __attribute__((unused)),
                  const char *user __attribute__((unused)),
                  const char *mailbox __attribute__((unused)),
                  int nopt __attribute__((unused)),
                  char **options __attribute__((unused)),
                  const char *message __attribute__((unused)),
                  const char *fname __attribute__((unused)))
{
    return strdup("OK null notification successful");
}
