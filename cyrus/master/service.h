#ifndef SERVICE_H
#define SERVICE_H

#define STATUS_FD (3)
#define LISTEN_FD (4)

#define SERVICE_AVAILABLE 0x01
#define SERVICE_UNAVAILABLE 0x02

extern int service_init(int argc, char **argv, char **envp);
extern int service_main(int argc, char **argv, char **envp);

#define MAX_USE 100

#endif
