#include <stdio.h>
#include <string.h>

#include "../cyrusdb.h"
#include "../exitcodes.h"

struct cyrusdb_backend *DB = &cyrusdb_flat;

#define TRY(s) { r = s; if (r) { printf("%s failed: %d\n", #s, r); exit(1); } }

void fatal(const char *msg, int code)
{
    printf("fatal: %s\n", msg);
    exit(code);
}

int main(int argc, char *argv[])
{
    char buf[1024];
    struct db *db = NULL;
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
	} else if (!strncasecmp(buf, "close", 5)) {
	    if (db) { /* close it */
		TRY(DB->close(db));
	    }
	    printf("ok\n");
	} else if (!strncasecmp(buf, "put ", 4)) {
	    char *key = buf + 4;
	    char *data = strchr(key, ' ');
	    if (!data) goto bad;
	    *data++ = '\0';
	    TRY(DB->store(db, key, strlen(key), data, strlen(data), NULL));
	    printf("ok\n");
	} else if (!strncasecmp(buf, "del ", 4)) {
	    char *key = buf + 4;
	    TRY(DB->delete(db, key, strlen(key), NULL));
	    printf("ok\n");
	} else if (!strncasecmp(buf, "get ", 4)) {
	    char *key = buf + 4;
	    const char *data;
	    int datalen;
	    TRY(DB->fetch(db, key, strlen(key), &data, &datalen, NULL));
	    printf("ok {%d} ", datalen);
	    while (datalen--) printf("%c", *data++);
	    printf("\n");
	} else {
	bad:
	    printf("?syntax error\n");
	}
    }
}
