#include <stdio.h>
#include <string.h>

#include "../cyrusdb.h"
#include "../xmalloc.h"
#include "../exitcodes.h"
#include "../assert.h"

#ifdef BACKEND
struct cyrusdb_backend *DB = &(BACKEND);
#else
struct cyrusdb_backend *DB = &cyrusdb_skiplist;
#endif

#define TRY(s) { r = s; \
                 if (r) { printf("%s failed: %d\n", #s, r); exit(1); } }

char *victim;
int count;
int verbose = 0;

int countem(void *rock,
	const char *key, int keylen,
	const char *data, int datalen)
{
    count++;
    return 0;
}

int findvictim(void *rock,
	       const char *key, int keylen,
	       const char *data, int datalen)
{
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

    if (argc > 1) {
	iter = atoi(argv[1]);
    } else {
	iter = 1000;
    }
    TRY(DB->init(".", 0));

    if (argc > 2) {
	srand(atoi(argv[2]));
    }

    TRY(DB->open("scratch", &db));

    if (DB->consistent) {
	TRY(DB->consistent(db));
    }

    printf("starting...\n");

    for (i = 0; i < iter; i++) {
	int oper = rand() % 10;

	switch (oper) {
	case 0:
	    /* do an ADD */
	    
	    /* generate a random key */
	    key = genrand(10 + (rand() % 10));

	    /* generate a random value */
	    val = genrand(10 + (rand() % 100));

	    if (verbose) printf("adding %s %s\n", key, val);
	    else printf("A");

	    /* insert it */
	    TRY(DB->store(db, key, strlen(key), val, strlen(val), &txn));
	    TRY(DB->commit(db, txn));

	    free(key);
	    free(val);

	    break;

	case 1: /* do a modify */
	case 2: /* do a delete */

	    /* pick a random victim */
	    count = 0;
	    victim = NULL;
	    txn = NULL;
	    TRY(DB->foreach(db, NULL, 0, &countem, NULL, NULL, &txn));
	    
	    if (count == 0) continue;

	    TRY(DB->foreach(db, NULL, 0, &findvictim, NULL, NULL, &txn));

	    assert(victim != NULL);

	    if (oper == 1) {
		/* generate a random value */
		val = genrand(10 + (rand() % 100));

		if (verbose) printf("modding %s %s\n", victim, val);
		else printf("M");

		/* do an add */
		TRY(DB->store(db, victim, strlen(victim), val, strlen(val), &txn));
		free(val);
	    } else {
		/* delete it */
		TRY(DB->delete(db, victim, strlen(victim), &txn));

		if (verbose) printf("deleting %s\n", victim);
		else printf("D");
	    }

	    TRY(DB->commit(db, txn));
	    free(victim); victim = NULL;
	    break;
	    
	default:
	    /* do a "read" */

	    /* generate a random key */
	    key = genrand(10 + (rand() % 10));

	    if (verbose) printf("reading %s\n", key);
	    else printf("R");

	    txn = NULL;
	    TRY(DB->fetch(db, key, strlen(key), &data, &datalen, &txn));
	    TRY(DB->commit(db, txn));

	    free(key);
	}

	fflush(stdout);

	/* run the consistency function, if any */
	if (DB->consistent) {
	    TRY(DB->consistent(db));
	}

    }

    TRY(DB->close(db));
    TRY(DB->done());
}
