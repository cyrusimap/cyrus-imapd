/* auth_krb_pts.h -- Kerberos authorization with AFS PTServer groups
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

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

#define DBFIL "/var/ptclient/ptscache.db"
#define DBLOCK "/var/ptclient/ptcache.lock"
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


