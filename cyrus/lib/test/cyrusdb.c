#include <stdio.h>
#include <string.h>

#include "../cyrusdb.h"
#include "../xmalloc.h"
#include "../exitcodes.h"

#ifdef BACKEND
struct cyrusdb_backend *DB = &(BACKEND);
#else
struct cyrusdb_backend *DB = &cyrusdb_flat;
#endif

#define TRY(s) { r = s; \
                 if (r) { printf("%s failed: %d\n", #s, r); exit(1); } }

void fatal(const char *msg, int code)
{
    printf("fatal: %s\n", msg);
    exit(code);
}

int yes(void *rock,
	const char *key, int keylen,
	const char *data, int datalen)
{
    return 1;
}

int appkey(void *rock,
	   const char *key, int keylen,
	   const char *data, int datalen)
{
    char *r = *(char **) rock;
    int newlen;

    if (r) {
	newlen = strlen(r) + keylen + 2;
	r = xrealloc(r, newlen);
	strcat(r, " ");
	strncpy(r + strlen(r), key, keylen);
	r[newlen-1] = '\0';
    } else {
	r = xmalloc(keylen + 1);
	strncpy(r, key, keylen);
	r[keylen] = '\0';
    }

    *(char **)rock = r;
    return 0;
}

int main(int argc, char *argv[])
{
    char buf[1024];
    struct db *db = NULL;
    struct txn *txn = NULL;
    int txnp = 0;
    int r;

    TRY(DB->init(".", 0));

    for (;;) {
	if (fgets(buf, sizeof buf, stdin) == NULL) break;
	buf[strlen(buf)-1] = '\0';
	if (!strncasecmp(buf, "file ", 5)) {
	    char *fname = buf + 5;

	    if (db) { /* close it */
		TRY(DB->close(db));
	    }
	    TRY(DB->open(fname, &db));

	    printf("ok\n");
	} else if (!db) {
	    TRY(db == NULL);
	} else if (!strncasecmp(buf, "close", 5)) {
	    TRY(DB->close(db));
	    db = NULL;
	    printf("ok\n");
	} else if (!strncasecmp(buf, "put ", 4)) {
	    char *key = buf + 4;
	    char *data = strchr(key, ' ');
	    if (!data) goto bad;
	    *data++ = '\0';
	    TRY(DB->store(db, key, strlen(key), data, strlen(data), (txnp ? &txn : NULL)));
	    printf("ok\n");
	} else if (!strncasecmp(buf, "del ", 4)) {
	    char *key = buf + 4;
	    TRY(DB->delete(db, key, strlen(key), (txnp ? &txn : NULL)));
	    printf("ok\n");
	} else if (!strncasecmp(buf, "get ", 4)) {
	    char *key = buf + 4;
	    const char *data;
	    int datalen;
	    TRY(DB->fetch(db, key, strlen(key), &data, &datalen, (txnp ? &txn : NULL)));
	    printf("ok {%d} ", datalen);
	    while (datalen--) printf("%c", *data++);
	    printf("\n");
	} else if (!strncasecmp(buf, "list", 4)) {
	    char *keys = NULL;

	    TRY(DB->foreach(db, NULL, 0, yes, appkey, &keys, (txnp ? &txn : NULL)));
	    if (keys) {
		printf("ok {%d} %s", strlen(keys), keys);
		free(keys);
	    } else {
		printf("ok {0} ");
	    }
	    printf("\n");
	} else if (!strncasecmp(buf, "dump", 4)) {
	    if (DB->dump) {
		TRY(DB->dump(db, 0));
		printf("ok\n");
	    } else {
		printf("no\n");
	    }
	} else if (!strncasecmp(buf, "check", 4)) {
	    if (DB->consistent) {
		TRY(DB->consistent(db));
		printf("ok\n");
	    } else {
		printf("no\n");
	    }
	} else if (!strncasecmp(buf, "txn", 3)) {
	    if (txnp) {
		printf("no\n");
	    } else {
		printf("ok\n");
		txnp = 1;
	    }
	} else if (!strncasecmp(buf, "commit", 6)) {
	    TRY(DB->commit(db, txn));
	    txnp = 0;
	    txn = NULL;
	    printf("ok\n");
	} else if (!strncasecmp(buf, "abort", 5)) {
	    TRY(DB->abort(db, txn));
	    txnp = 0;
	    txn = NULL;
	    printf("ok\n");
	} else {
	bad:
	    printf("?syntax error\n");
	}
    }
}
