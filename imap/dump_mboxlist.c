#include <config.h>

#include <db.h>
#include "mboxlist.h"

extern DB *mbdb;
extern DB_ENV *dbenv;

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void do_dump(void)
{
    int r;
    DBC *cursor = NULL;
    DBT key, data;
    int buf[16384];
    int bufkey[MAX_MAILBOX_NAME * 2];
    struct mbox_entry *mboxent;

    memset(&key, 0, sizeof(key));
    key.flags = DB_DBT_USERMEM;
    key.data = bufkey;
    key.ulen = sizeof(bufkey);

    memset(&data, 0, sizeof(data));
    data.flags = DB_DBT_USERMEM;
    data.data = buf;
    data.ulen = sizeof(buf);

    r = mbdb->cursor(mbdb, NULL, &cursor, 0);
    if (r != 0) { 
	fprintf(stderr, "DBERROR: Unable to create cursor: %s\n",
		db_strerror(r));
	goto error;
    }

    r = cursor->c_get(cursor, &key, &data, DB_FIRST);
    while (r != DB_NOTFOUND) {
	switch (r) {
	case 0:
	    break;
	default:
	    fprintf(stderr, "DBERROR: error advancing: %s\n", db_strerror(r));
	    goto error;
	}

	mboxent = (struct mbox_entry *) data.data;
	printf("%s\t%s\t%s\n", mboxent->name, 
	       mboxent->partition, mboxent->acls);
	
	r = cursor->c_get(cursor, &key, &data, DB_NEXT);
    }

 error:
    switch (r = cursor->c_close(cursor)) {
    case 0:
	break;
    default:
	fprintf(stderr, "DBERROR: error closing cursor: %s\n", db_strerror(r));
	return;
    }

    return;
}

int main(int argc, char *argv[])
{
    char *mboxdb_fname = NULL;

    if (argc > 1) {
	mboxdb_fname = argv[1];
    }
    
    config_init("dump_mboxlist");
    mboxlist_init();
    mboxlist_open(mboxdb_fname);

    do_dump();

    mboxlist_close();
    mboxlist_done();
    return 0;
}
