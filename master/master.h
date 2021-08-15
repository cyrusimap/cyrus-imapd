#ifndef HAVE_MASTER_H
#define HAVE_MASTER_H

#include <config.h>
#include <sys/resource.h> /* for rlim_t */

#include "libconfig.h" /* for config_dir and IMAPOPT_SYNC_MACHINEID */
#include "hash.h"
#include "ptrarray.h"
#include "strarray.h"

struct service {
    char *name;                 /* name of service */
    char *listen;               /* port/socket to listen to */
    char *proto;                /* protocol to accept */
    strarray_t *exec;           /* command (with args) to execute */
    int babysit;                /* babysit this service? */

    /* multiple address family support */
    int associate;              /* are we primary or additional instance? */
    int family;                 /* address family */
    const char *familyname;     /* address family name */

    /* communication info */
    int socket;                 /* client/child communication channel */
    int stat[2];                /* master/child communication channel */

    /* QUIC connection handling */
    ptrarray_t *quic_ready;     /* list of children ready for service */
    hash_table *quic_active;    /* table of children with active connections */

    /* limits */
    int desired_workers;        /* num child processes to have ready */
    int max_workers;            /* max num child processes to spawn */
    rlim_t maxfds;              /* max num file descriptors to use */
    unsigned int maxforkrate;   /* max rate to spawn children */

    /* stats */
    int ready_workers;          /* num child processes ready for service */
    int nforks;                 /* num child processes spawned */
    int nactive;                /* num children servicing clients */
    int nconnections;           /* num connections made to children */
    double forkrate;            /* rate at which we're spawning children */
    int nreadyfails;            /* number of failures in READY state */
    time_t lastreadyfail;       /* timestamp of last failure in READY state */

    /* fork rate computation */
    struct timeval last_interval_start;
    unsigned int interval_forks;
};

extern struct service *Services;
extern int nservices;

/*
 * Description of multiple address family support from
 * Hajimu UMEMOTO <ume@mahoroba.org>:
 *
 * In service_create(), master tries to listen each address family which
 * getaddrinfo() returns.  With existing implementation of getaddrinfo(),
 * when a protocol is not specified exactly by proto= in cyrus.conf and a
 * platform supports an IPv4 and an IPv6, getaddrinfo() returns two
 * struct addrinfo chain which contain INADDR_ANY (0.0.0.0; IPv4) and
 * IN6ADDR_ANY (::; IPv6), then master will listen an IPv4 and an IPv6.
 *
 * As a result, one SERVICE entry in cyrus.conf may correspond to two
 * Service memory blocks; one is for an IPv6 and the other is for an
 * IPv4.  The associate field was introduced to intend to distinguish
 * whether the entry is primary or not.  The associate field of primary
 * block is 0, 2nd is 1, 3rd is 2, ...
 * The blocks share same memory area of name, listen and proto.
 *
 *    +----------------+
 *    | Service[i]     |
 *    |   associate: 0 |
 *    |   name         | --------------> name
 *    |   listen       | ----- /- -----> listen
 *    |   proto        | ---- /- / ----> proto
 *    +----------------+     /  / /
 *    | Service[j]     |    /  / /
 *    |   associate: 1 |   /  / /
 *    |   name         |--/  / /
 *    |   listen       |----/ /
 *    |   proto        |-----/
 *    +----------------+
 *
 * This field is intended to avoid duplicate free by doing free only when
 * associate is zero.
 *
 */

#endif /* HAVE_MASTER_H */
