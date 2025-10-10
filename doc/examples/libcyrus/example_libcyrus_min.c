/* example for linking against libcyrus_min.so
 *
 * compile and run something like:
 *
   export LD_LIBRARY_PATH=/path/to/cyrus/lib
   export PKG_CONFIG_PATH=/path/to/cyrus/lib/pkgconfig
   export CFLAGS=-Wall -Wextra -Werror -g -O0 $(pkg-config --cflags libcyrus_min)
   export LDFLAGS=$(pkg-config --libs-only-L --libs-only-other libcyrus_min)
   export LDLIBS=$(pkg-config --libs-only-l libcyrus_min)
   make example_libcyrus_min
   ./example_libcyrus_min
 */

/* DEPS: libcyrus_min */

#include "arrayu64.h"
#include "assert.h"
#include "buf.h"
#include "dynarray.h"
#include "hash.h"
#include "hashset.h"
#include "hashu64.h"
#include "imapopts.h"
#include "libconfig.h"
#include "mpool.h"
#include "proc.h"
#include "retry.h"
#include "smallarrayu64.h"
#include "strarray.h"
#include "strhash.h"
#include "tok.h"
#include "xmalloc.h"
#include "xunlink.h"
#include "xsha1.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

void fatal(const char *s, int code)
{
    fputs(s, stderr);
    exit(code);
}

void usage(void)
{
    fputs("usage", stderr);
    exit(EX_USAGE);
}

void test_arrayu64(void)
{
    arrayu64_t a = ARRAYU64_INITIALIZER;
    uint64_t u;

    for (u = 0; u < 20; u++) {
        arrayu64_append(&a, u);
    }

    arrayu64_truncate(&a, 0);
    arrayu64_fini(&a);

    puts("arrayu64 ok");
}

void test_buf(void)
{
    struct buf buf = BUF_INITIALIZER;

    buf_appendcstr(&buf, "hello");
    buf_free(&buf);

    puts("buf ok");
}

void test_dynarray(void)
{
    uint64_t u;
    dynarray_t d = DYNARRAY_INITIALIZER(sizeof(u));

    for (u = 0; u < 20; u++) {
        dynarray_append(&d, &u);
    }

    dynarray_truncate(&d, 0);
    dynarray_fini(&d);

    puts("dynarray ok");
}

void test_hash(void)
{
    struct hash_table ht = HASH_TABLE_INITIALIZER;
    uintptr_t u;

    construct_hash_table(&ht, 20, 0);

    for (u = 0; u < 20; u++) {
        char key[128] = "";
        snprintf(key, sizeof key, "%" PRIuPTR, u);
        hash_insert(key, (void *) u, &ht);
    }

    free_hash_table(&ht, NULL);

    puts("hash ok");
}

void test_hashset(void)
{
    struct hashset *hs;
    uint64_t u;

    hs = hashset_new(sizeof(u));

    for (u = 0; u < 20; u++) {
        hashset_add(hs, &u);
    }

    hashset_free(&hs);

    puts("hashset ok");
}

void test_hashu64(void)
{
    struct hashu64_table ht = HASHU64_TABLE_INITIALIZER;
    uint64_t u;

    construct_hashu64_table(&ht, 20, 0);

    for (u = 0; u < 20; u++) {
        hashu64_insert(u, (void *) u, &ht);
    }

    free_hashu64_table(&ht, NULL);

    puts("hashu64 ok");
}

void test_mpool(void)
{
    struct mpool *mpool;
    unsigned u;

    mpool = new_mpool(1024);

    for (u = 0; u < 20; u++) {
        unsigned *not_lost = mpool_malloc(mpool, sizeof(unsigned));

        *not_lost = u;
    }

    free_mpool(mpool);

    puts("mpool ok");
}

void test_proc(void)
{
    struct proc_handle *handle = NULL;

    proc_register(&handle,
                  0,
                  "servicename",
                  "clienthost",
                  "userid",
                  "mailbox",
                  "cmd");

    proc_cleanup(&handle);

    puts("proc ok");
}

void test_retry(void)
{
    const char str[] = "retry ok\n";

    fflush(stdout);
    retry_write(STDOUT_FILENO, str, sizeof(str));
}

void test_smallarrayu64(void)
{
    smallarrayu64_t sa = SMALLARRAYU64_INITIALIZER;
    uint64_t u;

    for (u = 0; u < 20; u++) {
        smallarrayu64_append(&sa, u);
    }

    smallarrayu64_fini(&sa);

    puts("smallarrayu64 ok");
}

void test_strarray(void)
{
    strarray_t sa = STRARRAY_INITIALIZER;
    unsigned u;

    for (u = 0; u < 20; u++) {
        char buf[128] = "";
        snprintf(buf, sizeof(buf), "%u", u);
        strarray_append(&sa, buf);
    }

    strarray_fini(&sa);

    puts("strarray ok");
}

void test_strhash(void)
{
    unsigned hash;

    hash = strhash_seeded_djb2(time(NULL), "some string");
    (void) hash;

    puts("strhash ok");
}

void test_tok(void)
{
    tok_t tok;
    char *s;

    tok_init(&tok, "tok|ok", "|", 0);

    while ((s = tok_next(&tok))) {
        printf("%s ", s);
    }
    printf("\n");

    tok_fini(&tok);
}

void test_xmalloc(void)
{
    char *s = xstrdup("xmalloc ok");

    puts(s);
    free(s);
}

void test_xsha1(void)
{
    SHA1_CTX ctx = {0};
    unsigned char digest[SHA1_DIGEST_LENGTH];
    const unsigned char data[] = "this is some data";

    SHA1Init(&ctx);
    SHA1Update(&ctx, data, sizeof(data));
    SHA1Final(digest, &ctx);

    memset(&ctx, 0, sizeof(ctx));
    xsha1(data, sizeof(data), digest);

    puts("xsha1 ok");
}

int main(int argc, char **argv)
{
    const char *alt_config = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "C:")) != -1) {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        default:
            usage();
            break;
        }
    }

    config_read(alt_config, 0);

    test_arrayu64();
    test_buf();
    test_dynarray();
    test_hash();
    test_hashset();
    test_hashu64();
    test_mpool();
    test_proc();
    test_retry();
    test_smallarrayu64();
    test_strarray();
    test_strhash();
    test_tok();
    test_xmalloc();
    test_xsha1();
}
