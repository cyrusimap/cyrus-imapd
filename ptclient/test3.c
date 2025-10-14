/*
 * test ptsmodule_standard_root_dn
 * gcc -I.. -I ../lib ../lib/.libs/util.o ../lib/.libs/xmalloc.o ../lib/.libs/map_shared.o ../lib/.libs/retry.o ../lib/.libs/assert.o test3.c -lz -lpcre2-posix
 */
#include <assert.h>
#include <stdio.h>
#include <syslog.h>

#include "util.h"
#include "xmalloc.h"

// ptsmodule_standard_root_dn is declared static, so we need to include its
// source rather than just linking with the object it's in
#define PTSM_OK 0
static int ptsmodule_standard_root_dn(const char *domain, const char **result)
{
    const char *dc_sep = ",dc=";
    char *domain_copy;
    char *part, *tok_state;
    struct buf buf = BUF_INITIALIZER;

    assert(domain != NULL && domain[0] != '\0');

    syslog(LOG_DEBUG,
           "ptsmodule_standard_root_dn called for domain %s",
           domain);

    /* Each dot is to be replaced with ',dc='.
     * We also need a leading 'dc=' at the start.
     */
    domain_copy = xstrdup(domain);
    part = strtok_r(domain_copy, ".", &tok_state);
    buf_setcstr(&buf, "dc=");

    while (part != NULL) {
        syslog(LOG_DEBUG, "Root DN now %s", buf_cstring(&buf));

        buf_appendcstr(&buf, part);
        syslog(LOG_DEBUG, "Root DN now %s", buf_cstring(&buf));

        part = strtok_r(NULL, ".", &tok_state);

        if (part != NULL) {
            buf_appendcstr(&buf, dc_sep);
        }
    }

    free(domain_copy);

    syslog(LOG_DEBUG, "Root DN now %s", buf_cstring(&buf));

    *result = buf_release(&buf);

    syslog(LOG_DEBUG, "Root DN now %s", *result);

    return PTSM_OK;
}

void fatal(const char *s, int code)
{
    fprintf(stderr, "fatal error: %s\n", s);
    exit(code);
}

int main(int argc, const char **argv)
{
    int errors = 0;
    int i;

    for (i = 1; i < argc; i++) {
        const char *domain = argv[i];
        char *result;

        printf("generating standard root dn from domain '%s'...\n", domain);
        int r = ptsmodule_standard_root_dn(domain, &result);

        if (0 == r) {
            printf(" => '%s'\n", result);
            free(result);
        }
        else {
            fprintf(stderr,
                    "error: ptsmodule_standard_root_dn returned %i\n",
                    r);
            errors++;
        }
    }

    return errors;
}
