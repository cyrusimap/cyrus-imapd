/* command.h -- utility functions to run a command */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_COMMAND_H
#define INCLUDED_COMMAND_H

#include <sys/types.h>

#include "prot.h"
#include "strarray.h"

struct command {
    char *argv0;
    pid_t pid;
    struct protstream *stdin_prot;
    struct protstream *stdout_prot;
};

extern int run_command(const char *argv0, ...);
extern int run_command_strarray(const strarray_t *argv);
extern int command_popen(struct command **cmdp, const char *mode,
                         const char *cwd, const char *argv0, ...);
extern int command_pclose(struct command **cmdp);
extern int command_done_stdin(struct command *);

#endif /* INCLUDED_COMMAND_H */
