#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/file.h>
#include <errno.h>
#include <db.h>
#include <syslog.h>
#include <ctype.h>
#include <afs/ptserver.h>
#include <afs/cellconfig.h>

#define DBFIL "pts.db"
#define DBLOCK "ptlock"
#define PTCLIENT  "ptloader"

typedef struct {
  time_t cached;
  char user[PR_MAXNAMELEN];
  int ngroups;
} ptluser;


#define CLOSE(db) (db)->close((db))
#define GET(db,key,data,flags) (db)->get((db),(key),(data),(flags))
#define PUT(db,key,data,flags) (db)->put((db),(key),(data),(flags))
#define SEQ(db,key,data,flags) (db)->seq((db),(key),(data),(flags))
#define DEL(db,key,flags) (db)->del((db),(key),(flags))
#define SYNC(db,flags) (db)->sync((db),(flags))
#define EXPIRE_TIME 7200 /* 2 hours */

extern int errno;

/* Do not make this unsigned. you'll lose! (db won't open the file) */
static int32_t hashfn(const void *data, size_t size) {
    int32_t ret,val;
    int i;
    ret=0;
    if (size %4) {
        syslog(LOG_WARNING,
             "Database key size %d not multiple of 4; continuing anyway",
               size);
    }
    for (i=0;i*4<size;i++) {
        memcpy(&val,data+4*i,4);
        ret=ret^val;
    }
    return ret;
}


