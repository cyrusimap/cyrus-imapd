/* example for linking against libcyrus.so
 *
 * compile and run something like:
 *
   export LD_LIBRARY_PATH=/path/to/cyrus/lib
   export PKG_CONFIG_PATH=/path/to/cyrus/lib/pkgconfig
   export CFLAGS=-Wall -Wextra -Werror -g -O0 $(pkg-config --cflags libcyrus libcyrus_min)
   export LDFLAGS=$(pkg-config --libs-only-L --libs-only-other libcyrus libcyrus_min)
   export LDLIBS=$(pkg-config --libs-only-l libcyrus libcyrus_min)
   make example_libcyrus
   ./example_libcyrus
 */

/* DEPS: libcyrus libcyrus_min */

#define _GNU_SOURCE 1

#include "acl.h"
#include "auth.h"
#include "bitvector.h"
#include "bloom.h"
#include "bsearch.h"
#include "charset.h"
/* #include "command.h" */  /* XXX bogus: needs prot.h for struct protstream */
#include "cyr_qsort_r.h"
#include "cyrusdb.h"
#include "glob.h"
#include "imapurl.h"
#include "imclient.h"
#include "imparse.h"
#include "iostat.h"
#include "iptostring.h"
#include "libconfig.h"
#include "libcyr_cfg.h"
#include "lsort.h"
#include "mappedfile.h"
#include "murmurhash2.h"
#include "nonblock.h"
#include "parseaddr.h"
#include "procinfo.h"
#include "rfc822tok.h"
#include "seqset.h"
#include "signals.h"
/* #include "sqldb.h" */ /* XXX bogus: needs ptrarray.h */
#include "stristr.h"
#include "times.h"
#include "wildmat.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
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

void test_acl(void)
{
    const char str[] = "lrswipckxtedan";
    char *errstr = NULL;
    int mask;

    cyrus_acl_checkstr(str, &errstr);
    free(errstr);

    mask = cyrus_acl_strtomask(str, &mask);
    (void) mask;

    puts("acl ok");
}

void test_auth(void)
{
    const char id[] = "cassandane";
    const char *canonid;

    canonid = auth_canonifyid(id, strlen(id));
    (void) canonid;

    puts("auth ok");
}

void test_bitvector(void)
{
    bitvector_t bv = BV_INITIALIZER;
    char *str = NULL;
    unsigned u;

    for (u = 0; u < 20; u++) {
        if (u % 5 == 0 || u % 3 == 0)
            bv_set(&bv, u);
    }

    str = bv_cstring(&bv);
    free(str);

    bv_fini(&bv);
    puts("bitvector ok");
}

void test_bloom(void)
{
    struct bloom bloom;
    unsigned u;

    bloom_init(&bloom, 4000000, 0.01);

    for (u = 0; u < 20; u++) {
        char buf[128];

        snprintf(buf, sizeof(buf), "%u", u);

        bloom_add(&bloom, buf, strlen(buf));
    }

    bloom_free(&bloom);
    puts("bloom ok");
}

void test_bsearch(void)
{
    const char *s1 = "hello", *s2 = "world";
    int cmp;

    cmp = cmpstringp_raw(&s1, &s2);
    cmp = cmpstringp_mbox(&s1, &s2);
    (void) cmp;

    puts("bsearch ok");
}

void test_charset(void)
{
    charset_t charset;

    charset = charset_lookupname("us-ascii");
    charset_free(&charset);

    puts("charset ok");
}

static int cmp QSORT_R_COMPAR_ARGS(const void *a, const void *b,
                                   void *thunk __attribute__((unused)))
{
    return *(const int *) a - *(const int *) b;
}

void test_cyr_qsort_r(void)
{
    int array[20];
    const size_t n_elem = sizeof array / sizeof array[0];
    unsigned u;

    srand(time(NULL));
    for (u = 0; u < n_elem; u++) {
        array[u] = rand();
    }

    cyr_qsort_r(array, n_elem, sizeof(array[0]), &cmp, NULL);

    puts("cyr_qsort_r ok");
}

void test_cyrusdb(void)
{
    const char *dbname = "twoskip";
    char fname[1024] = "";
    struct db *db = NULL;
    struct txn *tid = NULL;
    const char key[] = "cassandane";
    size_t keylen = sizeof(key) - 1;
    const char *data = NULL;
    size_t datalen = 0;
    int r;

    snprintf(fname, sizeof(fname), "%s/%s", config_dir, "foo.db");

    r = cyrusdb_open(dbname, fname, CYRUSDB_CREATE, &db);
    if (!r) r = cyrusdb_store(db, key, keylen, "foo", strlen("foo"), &tid);
    if (!r) r = cyrusdb_fetch(db, key, keylen, &data, &datalen, &tid);
    if (!r) r = cyrusdb_commit(db, tid);

    r = cyrusdb_close(db);
    (void) r;

    puts("cyrusdb ok");
}

void test_glob(void)
{
    glob *g;
    int r;

    g = glob_init("fo*", '.');

    r = glob_test(g, "foo");
    (void) r;

    glob_free(&g);
    puts("glob ok");
}

void test_imapurl(void)
{
    const char src[] = "imap://joe@example.com/INBOX/;uid=20/"
                       ";section=1.2;urlauth=submit+fred:internal"
                       ":91354a473744909de610943775f92038";
    struct imapurl url;
    int r;

    r = imapurl_fromURL(&url, src);
    (void) r;

    free(url.freeme);
    puts("imapurl ok");
}

#if 0
void test_imclient(void)
{
    /* XXX need somewhere to connect to...  cass already has an imapd running,
     * right? could get the host:port for that as commandline args i guess
     */
    /* XXX though there's already an "example" imclient in the imclient.3 man
     * page, though the API it demonstrates doesn't match the headers, so i
     * guess it's bitrotted
     */
    /* XXX might need a separate example_imclient.c, which is possible now that
     * the file name isn't the dependencies list!
     */
}
#endif

void test_mappedfile(void)
{
    struct mappedfile *mf = NULL;
    char fname[PATH_MAX];
    int r;

    snprintf(fname, sizeof(fname), "/tmp/%ld-example_libcyrus_mappedfile.junk",
                                   (long) getpid());

    r = mappedfile_open(&mf, fname, MAPPEDFILE_CREATE);

    if (!r) {
        r = mappedfile_close(&mf);
        (void) r;

        unlink(fname);
    }

    puts("mappedfile ok");
}

void test_rfc822tok(void)
{
    const char *str = "lorem ipsum dolor sit amet";
    rfc822tok_t tok = RFC822TOK_INITIALIZER;
    int t;
    char *p;

    rfc822tok_init(&tok, str, strlen(str), 0);

    do {
        t = rfc822tok_next(&tok, &p);
    } while (t >= 0);

    rfc822tok_fini(&tok);
    puts("rfc822tok ok");
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

    test_acl();
    test_auth();
    test_bitvector();
    test_bloom();
    test_bsearch();
    test_charset();
    test_cyr_qsort_r();
    test_cyrusdb();
    test_glob();
    test_imapurl();
    test_mappedfile();
    test_rfc822tok();
}
