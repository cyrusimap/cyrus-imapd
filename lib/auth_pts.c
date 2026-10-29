/* auth_pts.c - PTLOADER authorization */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <inttypes.h>

#include "auth_pts.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "retry.h"
#include "strhash.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

static char *canonuser_id = NULL;
static struct auth_state *canonuser_cache = NULL;

/* XXX should make this an imap option */
#define PT_TIMEOUT_SEC  30

#define TS_READ 1
#define TS_WRITE 2
#define TS_RW 3

static int timeout_select(int sock, int op, int sec)
{
  struct timeval tv;
  int r;
  fd_set rfds, wfds, *rp, *wp;

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  rp = NULL;
  wp = NULL;

  switch (op) {
  case TS_READ:
    FD_SET(sock, &rfds);
    rp = &rfds;
    break;
  case TS_WRITE:
    FD_SET(sock, &wfds);
    wp = &wfds;
    break;
  case TS_RW:
    FD_SET(sock, &rfds);
    FD_SET(sock, &wfds);
    rp = &rfds;
    wp = &wfds;
  default:  /* no action */
    break;
  }

  tv.tv_sec = sec;
  tv.tv_usec = 0;

  xsyslog_ev(LOG_DEBUG, "pts.client.select",
             lf_d("pts.fd", sock),
             lf_b("pts.read", rp != NULL),
             lf_b("pts.write", wp != NULL),
             lf_d("pts.timeout", sec));

  if ((r = select(sock+1, rp, wp, NULL, &tv)) == 0) {
    /* r == 0 then timed out. we change this into an error */
    errno = ETIMEDOUT;
    r = -1;
  }

  xsyslog_ev(LOG_DEBUG, "pts.client.selected",
             lf_d("pts.result", r));
  return r;
}


static int nb_connect(int s, struct sockaddr *sa, socklen_t slen, int sec)
{
  int flags, rc=0;

  if ((flags = fcntl(s, F_GETFL,0)) == -1) {
    xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
               lf_s("pts.step", "get_flags"));
    return -1;
  }

  if (fcntl(s, F_SETFL, flags|O_NONBLOCK) == -1) {
    xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
               lf_s("pts.step", "set_nonblock"));
    return -1;
  }

  if (connect(s, sa, slen) < 0) {
    if (errno != EINPROGRESS) {
      rc = -1;
      goto done;
    }
  } else {
    /* yay, it got through on the first shot. */
    xsyslog_ev(LOG_DEBUG, "pts.client.connected",
               lf_b("pts.waited", 0));
    rc = 0;
    goto done;
  }

  xsyslog_ev(LOG_DEBUG, "pts.client.connecting");

  if (timeout_select(s, TS_RW, sec) < 0) {
    xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
               lf_s("pts.step", "select"));
    rc = -1;
    goto done;
  }

  xsyslog_ev(LOG_DEBUG, "pts.client.connected",
             lf_b("pts.waited", 1));
  rc = 0;

 done:
  /* set back to blocking so the reads/writes don't screw up), but why bother on an error... */
  if (!rc && (fcntl(s, F_SETFL, flags) == -1)) {
    xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
               lf_s("pts.step", "set_block"));
    rc = -1;
  }

  return rc;
}

/* Returns 0 on successful connection to ptloader/valid cache entry,
 * complete with allocated & filled in struct auth_state.
 *
 * state must be a NULL pointer when passed in */
static int ptload(const char *identifier,struct auth_state **state);
static void myfreestate(struct auth_state *auth_state);


/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 *      0       User does not match identifier
 *      1       identifier matches everybody
 *      2       User is in the group that is identifier
 *      3       User is identifer
 */
static int mymemberof(const struct auth_state *auth_state,
                  const char *identifier)
{
    int i;
    unsigned idhash = strhash(identifier);
    static unsigned anyonehash = 0;

    anyonehash = !anyonehash ? strhash("anyone") : anyonehash;

    if (!auth_state) {
        /* special case anonymous */
        if (!strcmp(identifier, "anyone")) return 1;
        else if (!strcmp(identifier, "anonymous")) return 3;

        /* "anonymous" is not a member of any group */
        else return 0;
    }

    /* is 'identifier' "anyone"? */
    if (idhash == anyonehash &&
        !strcmp(identifier, "anyone")) return 1;

    /* is 'identifier' me? */
    if (idhash == auth_state->userid.hash &&
        !strcmp(identifier, auth_state->userid.id)) return 3;

    /* is it a group i'm a member of ? */
    for (i=0; i < auth_state->ngroups; i++)
        if (idhash == auth_state->groups[i].hash &&
            !strcmp(identifier, auth_state->groups[i].id))
            return 2;

    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
static const char *mycanonifyid(const char *identifier,
                      size_t len __attribute__((unused)))
{
    static char retbuf[PTS_DB_KEYSIZE];

    if(canonuser_id &&
       (!strcmp(identifier, canonuser_id) || !strcmp(identifier, retbuf))) {
        /* It's the currently cached user, return the previous result */
        return retbuf;
    } else if(canonuser_id) {
        /* We've got a new one, invalidate our cache */
        free(canonuser_id);
        myfreestate(canonuser_cache);

        canonuser_id = NULL;
        canonuser_cache = NULL;
    }

    if(!strcmp(identifier, "anyone") ||
       !strcmp(identifier, "anonymous")) {
        /* we can fill this in ourselves - no cacheing */
        strlcpy(retbuf, identifier, sizeof(retbuf));
        return retbuf;
    }

    if (!strcmp(identifier, "")) {
        xsyslog_ev(LOG_ERR, "pts.canonify.failed",
                   lf_s("pts.reason", "empty"));
        return NULL;
    }


    canonuser_cache = NULL;
    if(ptload(identifier, &canonuser_cache) < 0) {
      if (canonuser_cache == NULL) {
        xsyslog_ev(LOG_ERR, "pts.canonify.failed",
                   lf_s("pts.id", identifier));
        return NULL;
      } else {
        xsyslog_ev(LOG_ERR, "pts.load.failed",
                   lf_s("pts.id", identifier),
                   lf_s("pts.canonical", canonuser_cache->userid.id));
      }
    }

    canonuser_id = xstrdup(identifier);
    strlcpy(retbuf, canonuser_cache->userid.id, sizeof(retbuf));
    xsyslog_ev(LOG_DEBUG, "pts.canonified",
               lf_s("pts.id", identifier),
               lf_s("pts.canonical", retbuf));
    return retbuf;
}

/*
 * Produce an auth_state structure for the given identifier
 */
static struct auth_state *mynewstate(const char *identifier)
{
    struct auth_state *output = NULL;

    if(canonuser_id &&
       (!strcmp(identifier, canonuser_id) ||
        !strcmp(identifier, canonuser_cache->userid.id))) {
        /* It's the currently cached user, return the previous result */
        free(canonuser_id);
        canonuser_id = NULL;

        output = canonuser_cache;
        canonuser_cache = NULL;
        return output;
    }

    /*
     * If anyone or anonymous, just pass through. Otherwise, try to load the
     * groups the user is in
     */
    if(strcmp(identifier, "anyone") &&
       strcmp(identifier, "anonymous")) {

      if(ptload(identifier, &output) < 0) {
        xsyslog_ev(LOG_ERR, "pts.load.failed",
                   lf_s("pts.id", identifier));
        /* Allowing this to go through is a problem if negative group access is
         * used significantly.   Allowing this to go through is a feature when
         * the ptserver is having problems and the user wants to get to his
         * inbox.
         *
         * note that even on a failure, output should either be NULL or a
         * correct (enough) value.
         */
      }
    }

    if (output == NULL) {
      output =
        (struct auth_state *)xzmalloc(sizeof(struct auth_state));
      strlcpy(output->userid.id, identifier,
              sizeof(output->userid.id));
      output->userid.hash = strhash(identifier);
      xsyslog_ev(LOG_DEBUG, "pts.state.empty",
                 lf_s("pts.id", identifier));
    } else {
      xsyslog_ev(LOG_DEBUG, "pts.state.loaded",
                 lf_s("pts.canonical", output->userid.id));
    }

    return output;
}

static const char *the_ptscache_db = NULL;

/* Returns 0 on success */
static int ptload(const char *identifier, struct auth_state **state)
{
    struct auth_state *fetched = NULL;
    size_t id_len;
    const char *data = NULL;
    size_t dsize;
    const char *fname = NULL;
    char *tofree = NULL;
    struct db *ptdb;
    int s;
    struct sockaddr_un srvaddr;
    int r, rc=0;
    static char response[1024];
    struct iovec iov[10];
    int niov, n;
    unsigned int start;
    const char *config_dir =
        libcyrus_config_getstring(CYRUSOPT_CONFIG_DIR);

    /* XXX this sucks, but it seems to be the only way to satisfy the linker */
    if(the_ptscache_db == NULL) {
        the_ptscache_db = libcyrus_config_getstring(CYRUSOPT_PTSCACHE_DB);
    }

    if(!state || *state) {
        fatal("bad state pointer passed to ptload()", EX_TEMPFAIL);
    }

    fname = libcyrus_config_getstring(CYRUSOPT_PTSCACHE_DB_PATH);

    if (!fname) {
        tofree = strconcat(config_dir, PTS_DBFIL, (char *)NULL);
        fname = tofree;
    }
    r = cyrusdb_open(the_ptscache_db, fname, CYRUSDB_CREATE, &ptdb);
    if (r != 0) {
        xsyslog_ev(LOG_ERR, "pts.cache.open.failed",
                   lf_s("sys.path", fname),
                   lf_s("error", cyrusdb_strerror(r)));
        free(tofree);
        *state = NULL;
        return -1;
    }
    free(tofree);
    tofree = NULL;

    id_len = strlen(identifier);
    if(id_len > PTS_DB_KEYSIZE) {
        xsyslog_ev(LOG_ERR, "pts.load.failed",
                   lf_s("pts.reason", "too_long"));
        *state = NULL;
        return -1;
    }

    /* fetch the current record for the user */
    r = cyrusdb_fetch(ptdb, identifier, id_len,
                               &data, &dsize, NULL);
    if (r && r != CYRUSDB_NOTFOUND) {
        xsyslog_ev(LOG_ERR, "pts.cache.read.failed",
                   lf_s("pts.step", "newstate"),
                   lf_s("error", cyrusdb_strerror(r)));

        rc = -1;
        goto done;
    }

    /* if it's expired (or nonexistent),
     * ask the ptloader to reload it and reread it */
    if (dsize && data) {
        fetched = (struct auth_state *)xmalloc(dsize);
        memcpy(fetched, data, dsize);
    }

    if (fetched) {
        time_t now = time(NULL);
        int timeout = libcyrus_config_getint(CYRUSOPT_PTS_CACHE_TIMEOUT);

        xsyslog_ev(LOG_DEBUG, "pts.cache.fetched",
                   lf_s("pts.id", identifier),
                   lf_time("pts.mark", fetched->mark),
                   lf_time("pts.time", now),
                   lf_time("pts.limit", now - timeout));

        if (fetched->mark > (now - timeout)) {
            /* not expired; let's return it */
            goto done;
        }
    }

    xsyslog_ev(LOG_DEBUG, "pts.client.pinging");

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
                   lf_s("pts.step", "socket"));
        rc = -1;
        goto done;
    }

    fname = libcyrus_config_getstring(CYRUSOPT_PTLOADER_SOCK);
    if (!fname) {
        tofree = strconcat(config_dir, PTS_DBSOCKET, (char *)NULL);
        fname = tofree;
    }

    if (strlen(fname) >= sizeof(srvaddr.sun_path)) {
        xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
                   lf_s("pts.step", "socket_path"),
                   lf_s("sys.path", fname),
                   lf_zu("limit.value", sizeof(srvaddr.sun_path)));
        rc = -1;
        goto done;
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strlcpy(srvaddr.sun_path, fname, sizeof(srvaddr.sun_path));
    r = nb_connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr), PT_TIMEOUT_SEC);
    free(tofree);

    if (r == -1) {
        xsyslog_ev(LOG_ERR, "pts.client.connect.failed",
                   lf_s("pts.step", "connect"));
        close(s);
        rc = -1;
        goto done;
    }

    xsyslog_ev(LOG_DEBUG, "pts.client.request.started");
    niov = 0;
    WRITEV_ADD_TO_IOVEC(iov, niov, (char *) &id_len, sizeof(id_len));
    WRITEV_ADD_TO_IOVEC(iov, niov, (char *) identifier, id_len);

    if (timeout_select(s, TS_WRITE, PT_TIMEOUT_SEC) < 0) {
      xsyslog_ev(LOG_ERR, "pts.client.request.failed",
                 lf_s("pts.step", "write"));
      rc = -1;
      goto done;
    }
    retry_writev(s, iov, niov);
    xsyslog_ev(LOG_DEBUG, "pts.client.request.sent");

    start = 0;
    while (start < sizeof(response) - 1) {
      if (timeout_select(s, TS_READ, PT_TIMEOUT_SEC) < 0) {
        xsyslog_ev(LOG_ERR, "pts.client.request.failed",
                   lf_s("pts.step", "read"));
        rc = -1;
        goto done;
      }
      n = read(s, response+start, sizeof(response) - 1 - start);
      if (n < 1) break;
      start += n;
    }
    response[sizeof(response)-1] = '\0';

    close(s);
    xsyslog_ev(LOG_DEBUG, "pts.client.response.received");

    if (start <= 1 || strncmp(response, "OK", 2)) {
       if(start > 1) {
           xsyslog_ev(LOG_ERR, "pts.client.request.failed",
                      lf_s("pts.step", "response"),
                      lf_s("error", response));
       } else {
           xsyslog_ev(LOG_ERR, "pts.client.request.failed",
                      lf_s("pts.step", "response"),
                      lf_s("pts.reason", "empty"));
       }
       rc = -1;
       goto done;
    }

    /* fetch the current record for the user */
    r = cyrusdb_fetch(ptdb, identifier, id_len,
                               &data, &dsize, NULL);
    if (r != 0 || !data) {
        xsyslog_ev(LOG_ERR, "pts.cache.read.failed",
                   lf_s("pts.step", "after_load"),
                   lf_s("error", cyrusdb_strerror(r)));
        dsize = 0;
        data = NULL;
        rc = -1;
        goto done;
    }

 done:
    /* ok, we got real data, let's use it */
    if (dsize && data) {
      free(fetched);
      fetched = (struct auth_state *)xmalloc(dsize);
      memcpy(fetched, data, dsize);
    }

    if (fetched == NULL) {
      *state = NULL;
      xsyslog_ev(LOG_DEBUG, "pts.load.empty");
    } else  {
      /* copy it into our structure */
      *state = fetched;
      xsyslog_ev(LOG_DEBUG, "pts.load.returned");
    }

    /* close and unlock the database */
    (cyrusdb_close)(ptdb);

    return rc;
}

static void myfreestate(struct auth_state *auth_state)
{
    free(auth_state);
}

static strarray_t *mygroups(const struct auth_state *auth_state)
{
    strarray_t *sa;
    int i;

    if (!auth_state->ngroups)
        return NULL;

    sa = strarray_new();
    for (i = 0; i < auth_state->ngroups; i++) {
        strarray_append(sa, auth_state->groups[i].id);
    }

    return sa;
}

HIDDEN struct auth_mech auth_pts =
{
    "pts",              /* name */

    &mycanonifyid,
    &mymemberof,
    &mynewstate,
    &myfreestate,
    &mygroups,
    NULL, /* refresh */
};
