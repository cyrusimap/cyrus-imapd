#ifndef HAVE_MASTER_H
#define HAVE_MASTER_H

/* needed for possible SNMP monitoring */
struct service {
    char *name;
    char *listen;
    char *proto;
    char *const *exec;

    int socket;
    struct sockaddr *saddr;

    int ready_workers;
    int desired_workers;
    unsigned int max_workers;
    int stat[2];

    /* stats */
    int nforks;
    int nactive;
};

extern struct service *Services;
extern int allocservices;
extern int nservices;

#endif /* HAVE_MASTER_H */
