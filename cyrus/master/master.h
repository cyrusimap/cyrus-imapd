#ifndef HAVE_MASTER_H
#define HAVE_MASTER_H

/* $Id: master.h,v 1.6.4.1 2003/02/12 19:12:45 rjs3 Exp $ */

/* needed for possible SNMP monitoring */
struct service {
    char *name;
    char *listen;
    char *proto;
    char *const *exec;
    int babysit;
    unsigned int maxforkrate;
    
    int socket;
    struct sockaddr *saddr;

    int ready_workers;
    int desired_workers;
    int max_workers;
    int stat[2];

    /* fork rate computation */
    time_t last_interval_start;
    unsigned int interval_forks;

    /* stats */
    int nforks;
    int nactive;
    int nconnections;

    unsigned int forkrate;

    int associate;
};

extern struct service *Services;
extern int allocservices;
extern int nservices;

#endif /* HAVE_MASTER_H */
