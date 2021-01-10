#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../cyrusdb.h"
#include "../xmalloc.h"
#include "../assert.h"

#ifdef BACKEND
struct cyrusdb_backend *DB = &(BACKEND);
#else
struct cyrusdb_backend *DB = &cyrusdb_skiplist;
#endif

#define TRY(s) do { \
    r = s; \
    if (r && r != CYRUSDB_NOTFOUND) { \
        printf("%s failed (i=%d): %d\n", #s, i, r); \
        exit(1); \
    } \
} while (0)

char *victim;
int count;
int verbose = 0;

struct timeval t_add = { 0, 0 };
struct timeval t_mod = { 0, 0 };
struct timeval t_del = { 0, 0 };
struct timeval t_find = { 0, 0 };

int c_add = 0;
int c_mod = 0;
int c_del = 0;
int c_find = 0;


#define ADDDIFF(a, b, c) do { a.tv_sec += (c.tv_sec - b.tv_sec); \
                              a.tv_usec += (c.tv_usec - b.tv_usec); \
                              while (a.tv_usec < 0) \
                                { a.tv_sec--; a.tv_usec += 1000000; } \
                              while (a.tv_usec > 1000000) \
                                { a.tv_sec++; a.tv_usec -= 1000000; } } while (0)

int countem(void *rock,
        const char *key, int keylen,
        const char *data, int datalen)
{
    (void)rock; (void)key; (void)keylen; (void)data; (void)datalen;
    count++;
    return 0;
}

int findvictim(void *rock,
               const char *key, int keylen,
               const char *data, int datalen)
{
    (void)rock; (void)keylen; (void)data; (void)datalen;
    if (!victim) {
        if ((rand() % count) == 0) {
            victim = xstrdup(key);
        }
    }
    count--;
    return 0;
}

char *genrand(int len)
{
    char *ret = xmalloc(len + 1);
    char *p = ret;

    while (len--) {
        *p++ = 'a' + (rand() % 26);
    }
    *p = '\0';

    return ret;
}

void fatal(const char *msg, int code)
{
    printf("fatal: %s\n", msg);
    exit(code);
}

void do_report(void)
{
        printf("\n");
    printf("*** add %ld.%ld %d\n", t_add.tv_sec, t_add.tv_usec, c_add);
    printf("*** mod %ld.%ld %d\n", t_mod.tv_sec, t_mod.tv_usec, c_mod);
    printf("*** del %ld.%ld %d\n", t_del.tv_sec, t_del.tv_usec, c_del);
    printf("*** find %ld.%ld %d\n", t_find.tv_sec, t_find.tv_usec, c_find);

    printf("\n");
    printf("*** add %lf\n", ((double) t_add.tv_sec +
                             ((double) t_add.tv_usec) / 1000000) /
           (double) c_add);
    printf("*** mod %lf\n", ((double) t_mod.tv_sec +
                             ((double) t_mod.tv_usec) / 1000000) /
           (double) c_mod);
    printf("*** del %lf\n", ((double) t_del.tv_sec +
                             ((double) t_del.tv_usec) / 1000000) /
           (double) c_del);
    printf("*** find %lf\n", ((double) t_find.tv_sec +
                             ((double) t_find.tv_usec) / 1000000) /
           (double) c_find);


}

int main(int argc, char *argv[])
{
    int iter;
    int seed;
    int i;
    char *key;
    char *val;
    struct db *db;
    int r;
    struct txn *txn;
    const char *data;
    int datalen;
    struct timeval t1, t2;
    int initsize;

    if (argc > 1) {
        iter = atoi(argv[1]);
    } else {
      printf("%s [iterations] [rndseed] [initsize]\n", argv[0]);
      printf("if iterations is negative, run forever and report every -iter\n");
      exit(1);
    }
    TRY(DB->init(".", 0));

    if (argc > 2) {
        srand(atoi(argv[2]));
    }

    TRY(cyrusdb_open(DB, "scratch", &db));

    if (cyrusdb_consistent) {
        TRY(cyrusdb_consistent(db));
    }

    if (argc > 3) {
      initsize = atoi(argv[3]);

      txn = NULL;
      for (i = 0; i < initsize; i++) {
        /* generate a random key */
        key = genrand(10 + (rand() % 10));

        /* generate a random value */
        val = genrand(10 + (rand() % 100));

        TRY(cyrusdb_store(db, key, strlen(key), val, strlen(val), &txn));
      }

      TRY(cyrusdb_commit(db, txn));
      if (cyrusdb_consistent) {
        TRY(cyrusdb_consistent(db));
      }
    }

    printf("starting...\n");

    /* repeat for ever if iter < 0 */
    for (i = 0; iter > 0 ? (i < iter) : 1; i++) {
        int oper = rand() % 10;

        if (i > 0 && iter < 0 && ((i % -iter) == 0)) {
          do_report();
        }

        switch (oper) {
        case 0:
            /* do an ADD */

            if (verbose) printf("A");

            /* insert it */
            gettimeofday(&t1, NULL);

            /* generate a random key */
            key = genrand(10 + (rand() % 10));

            /* generate a random value */
            val = genrand(10 + (rand() % 100));

            txn = NULL;
            TRY(cyrusdb_store(db, key, strlen(key), val, strlen(val), &txn));
            TRY(cyrusdb_commit(db, txn));
            gettimeofday(&t2, NULL);

            ADDDIFF(t_add, t1, t2);
            c_add++;

            free(key);
            free(val);

            break;

        case 1: /* do a modify */
            if (verbose) printf("M");

            gettimeofday(&t1, NULL);

            /* pick a random victim */
            count = 0;
            victim = NULL;
            txn = NULL;
            TRY(cyrusdb_foreach(db, NULL, 0, NULL, &countem, NULL, &txn));

            if (count == 0) continue;

            TRY(cyrusdb_foreach(db, NULL, 0, NULL, &findvictim, NULL, &txn));

            assert(victim != NULL);

            /* generate a random value */
            val = genrand(10 + (rand() % 100));

            /* do an add */
            TRY(cyrusdb_store(db, victim, strlen(victim), val, strlen(val), &txn));
            free(val);

            TRY(cyrusdb_commit(db, txn));
            free(victim); victim = NULL;

            gettimeofday(&t2, NULL);

            ADDDIFF(t_mod, t1, t2);
            c_mod++;

            break;

        case 2: /* do a delete */
            if (verbose) printf("D");

            gettimeofday(&t1, NULL);

            /* pick a random victim */
            count = 0;
            victim = NULL;
            txn = NULL;
            TRY(cyrusdb_foreach(db, NULL, 0, NULL, &countem, NULL, &txn));

            if (count == 0) continue;

            TRY(cyrusdb_foreach(db, NULL, 0, NULL, &findvictim, NULL, &txn));
            assert(victim != NULL);

            /* delete it */
            TRY(cyrusdb_delete(db, victim, strlen(victim), &txn, 0));

            TRY(cyrusdb_commit(db, txn));
            free(victim); victim = NULL;

            gettimeofday(&t2, NULL);

            ADDDIFF(t_del, t1, t2);
            c_del++;

            break;

        default:
            /* do a "read" */
            if (verbose) printf("R");

            gettimeofday(&t1, NULL);

            /* generate a random key */
            key = genrand(10 + (rand() % 10));

            txn = NULL;
            TRY(cyrusdb_fetch(db, key, strlen(key), &data, &datalen, &txn));
            TRY(cyrusdb_commit(db, txn));

            gettimeofday(&t2, NULL);

            ADDDIFF(t_find, t1, t2);
            c_find++;

            free(key);
        }

        fflush(stdout);

#if 0
        /* run the consistency function, if any */
        if (cyrusdb_consistent) {
            TRY(cyrusdb_consistent(db));
        }
#endif
    }

    TRY(cyrusdb_close(db));
    TRY(DB->done());

    do_report();
    return 0;
}
