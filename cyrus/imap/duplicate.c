#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <db.h>

#include "imap_err.h"
#include "config.h"
#include "exitcodes.h"

#include "duplicate.h"

/* it would be nice to cache some DBs so that we're not constantly
   opening and closing them; something to be evaluated */

static duplicate_dbinit = 0;
DB_ENV *duplicate_dbenv;

int duplicate_init()
{
    char buf[1024];
    int r;

    if (!duplicate_dbinit) {
	sprintf(buf, "%s/deliverdb/db", config_dir);

	if ((r = db_env_create(&duplicate_dbenv, 0)) != 0) {
	    char err[1024];
	    
	    sprintf(err, "DBERROR: db_appinit failed: %s", strerror(r));
	    syslog(LOG_ERR, err);
	    return IMAP_IOERROR;
	}

	/* create the name of the db file */
	r = duplicate_dbenv->open(duplicate_dbenv, buf, NULL, 
				  DB_INIT_CDB, 0644);
	if (r) {
	    char err[1024];
	    
	    sprintf(err, "DBERROR: dbenv->open failed: %s", strerror(r));
	    syslog(LOG_ERR, err);
	    return IMAP_IOERROR;
	}
    }

    duplicate_dbinit++;
}

/* too many processes are contending for single locks on delivered.db 
 * so we use this function to generate a specific delivered.db for a mailbox
 * First pass will be to just have 26 db files based on the first letter of 
 * the mailbox name. As distribution goes, this really blows but, hey, what do 
 * you expect from something quick and dirty?
 */
static char *get_db_name (char *mbox)
{
    static char buf[1024];
    char *idx;
    char c;
  
    idx = strchr(mbox,'.');   /* skip past user. */
    if (idx == NULL) {         /* no '.' so just use mbox */
	idx = mbox;
    } else {
	idx++;                   /* skip past '.' */
    }
    c = (char) tolower((int) *idx);
    if (!islower(c)) {
	c = 'q';
    }

    sprintf(buf, "%s/deliverdb/deliver-%c.db", config_dir, c);

    return buf;
}


time_t duplicate_check(char *id, int idlen, char *to, int tolen)
{
    char buf[1024];
    char *fname;
    DB *d;
    DBT date, delivery;
    int r;
    time_t mark;

    (void)memset(&date, 0, sizeof(date));
    (void)memset(&delivery, 0, sizeof(delivery));

    if (idlen + tolen > sizeof(buf) - 30) return 0;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';
    delivery.data = buf;
    delivery.size = idlen + tolen + 2;
          /* +2 b/c 1 for the center null; +1 for the terminating null */

    fname = get_db_name(to);

    r = db_create(&d, duplicate_dbenv, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_check: opening %s: %m", fname);
	return 0;
    }
    r = d->open(d, fname, NULL, DB_HASH, DB_CREATE, 0664);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_check: opening %s: %m", fname);
	return 0;
    }

    r = d->get(d, NULL, &delivery, &date, 0);
    if (r == 0) {
	/* found the record */
	memcpy(&mark, date.data, sizeof(time_t));
    } else if (r == DB_NOTFOUND) {
	mark = 0;
    } else {
	syslog(LOG_ERR, "duplicate_check: error looking up %s/%d: %m", id, to);
	mark = 0;
    }

    r = d->close(d, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_check: closing %s: %m", fname);
	return 0;
    }

    return mark;
}

void duplicate_mark(char *id, int idlen, char *to, int tolen, time_t mark)
{
    char buf[1024];
    char *fname;
    DB *d;
    DBT date, delivery;
    int r;

    (void)memset(&date, 0, sizeof(date));
    (void)memset(&delivery, 0, sizeof(delivery));

    if (idlen + tolen > sizeof(buf) - 30) return;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';
    delivery.data = buf;
    delivery.size = idlen + tolen + 2;
          /* +2 b/c 1 for the center null; +1 for the terminating null */

    date.data = &mark;
    date.size = sizeof(mark);

    fname = get_db_name(to);

    r = db_create(&d, duplicate_dbenv, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: opening %s: %m", fname);
	return;
    }
    r = d->open(d, fname, NULL, DB_HASH, DB_CREATE, 0664);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: opening %s: %m", fname);
	return;
    }

    r = d->put(d, NULL, &delivery, &date, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: error setting %s/%d: %m", id, to);
	mark = 0;
    }

    r = d->close(d, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: closing %s: %m", fname);
	return;
    }

    return;
}

int duplicate_prune()
{
    fatal("pruning not yet implemented", EC_TEMPFAIL);
}

int duplicate_done()
{
    int r;

    duplicate_dbinit--;

    if (duplicate_dbinit == 0) {
	r = duplicate_dbenv->close(duplicate_dbenv, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error exiting application: %s",
		   strerror(r));
	}
    }
}
