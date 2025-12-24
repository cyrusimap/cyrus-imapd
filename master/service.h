/* service.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SERVICE_H
#define SERVICE_H

enum {
    STATUS_FD = 3,
    LISTEN_FD = 4
};

enum {
    MASTER_SERVICE_AVAILABLE = 0x01,
    MASTER_SERVICE_UNAVAILABLE = 0x02,
    MASTER_SERVICE_CONNECTION = 0x03,
    MASTER_SERVICE_CONNECTION_MULTI = 0x04
};

extern int service_init(int argc, char **argv, char **envp);
extern int service_main(int argc, char **argv, char **envp);
extern int service_main_fd(int fd, int argc, char **argv, char **envp);
extern void service_abort(int error) __attribute__((noreturn));

enum {
    MAX_USE = 250,
    REUSE_TIMEOUT = 60
};

struct notify_message {
    int message;
    pid_t service_pid;
};

#endif
