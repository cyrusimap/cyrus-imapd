/* command.c -- utility functions for running commands */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <sys/types.h>
#include <syslog.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "xmalloc.h"
#include "command.h"
#include "signals.h"
#include "strarray.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int wait_for_child(const char *argv0, pid_t pid);

EXPORTED int run_command_strarray(const strarray_t *argv)
{
    const char *argv0 = strarray_nth(argv, 0);
    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork: %m");
        return IMAP_SYS_ERROR;
    }

    if (!pid) {
        /* in child */
        execv(argv0, argv->data);
        syslog(LOG_ERR, "Failed to execute %s: %m", argv0);
        exit(1);
    }

    /* in parent */
    return wait_for_child(argv0, pid);
}

EXPORTED int run_command(const char *argv0, ...)
{
    va_list va;
    const char *p;
    strarray_t argv = STRARRAY_INITIALIZER;
    int r = 0;

    strarray_append(&argv, argv0);

    va_start(va, argv0);
    while ((p = va_arg(va, const char *)))
        strarray_append(&argv, p);
    va_end(va);

    r = run_command_strarray(&argv);

    strarray_fini(&argv);
    return r;
}

#define PIPE_READ       0
#define PIPE_WRITE      1

EXPORTED int command_popen(struct command **cmdp, const char *mode,
                           const char *cwd, const char *argv0, ...)
{
    va_list va;
    const char *p;
    strarray_t argv = STRARRAY_INITIALIZER;
    pid_t pid;
    int r = 0;
    struct command *cmd;
    int do_stdin = (strchr(mode, 'w') != NULL);
    int do_stdout = (strchr(mode, 'r') != NULL);
    int stdin_pipe[2] = { -1, -1 };
    int stdout_pipe[2] = { -1, -1 };

    strarray_append(&argv, argv0);

    va_start(va, argv0);
    while ((p = va_arg(va, const char *)))
        strarray_append(&argv, p);
    va_end(va);

    if (do_stdin) {
        r = pipe(stdin_pipe);
        if (r) {
            syslog(LOG_ERR, "Failed to pipe(): %m");
            r = IMAP_SYS_ERROR;
            goto out;
        }
    }

    if (do_stdout) {
        r = pipe(stdout_pipe);
        if (r) {
            syslog(LOG_ERR, "Failed to pipe(): %m");
            r = IMAP_SYS_ERROR;
            goto out;
        }
    }

    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork: %m");
        r = IMAP_SYS_ERROR;
        goto out;
    }

    if (!pid) {
        /* in child */
        if (do_stdin) {
            close(stdin_pipe[PIPE_WRITE]);
            dup2(stdin_pipe[PIPE_READ], STDIN_FILENO);
            close(stdin_pipe[PIPE_READ]);
        }
        if (do_stdout) {
            close(stdout_pipe[PIPE_READ]);
            dup2(stdout_pipe[PIPE_WRITE], STDOUT_FILENO);
            close(stdout_pipe[PIPE_WRITE]);
        }

        if (cwd) {
            r = chdir(cwd);
            if (r) syslog(LOG_ERR, "Failed to chdir(%s): %m", cwd);
        }

        r = execv(argv0, argv.data);
        syslog(LOG_ERR, "Failed to execute %s: %m", argv0);
        exit(1);
    }

    /* in parent */
    cmd = xzmalloc(sizeof(struct command));
    cmd->argv0 = xstrdup(argv0);
    cmd->pid = pid;
    if (do_stdin)
        cmd->stdin_prot = prot_new(stdin_pipe[PIPE_WRITE], /*write*/1);
    if (do_stdout)
        cmd->stdout_prot = prot_new(stdout_pipe[PIPE_READ], /*write*/0);
    *cmdp = cmd;

out:
    if (stdin_pipe[PIPE_READ] >= 0) close(stdin_pipe[PIPE_READ]);
    if (stdout_pipe[PIPE_WRITE] >= 0) close(stdout_pipe[PIPE_WRITE]);
    if (r) {
        if (stdin_pipe[PIPE_WRITE] >= 0) close(stdin_pipe[PIPE_WRITE]);
        if (stdout_pipe[PIPE_READ] >= 0) close(stdout_pipe[PIPE_READ]);
    }
    strarray_fini(&argv);
    return r;
}

EXPORTED int command_pclose(struct command **cmdp)
{
    struct command *cmd = (cmdp ? *cmdp : NULL);
    int r;

    if (!cmd) return 0;

    if (cmd->stdin_prot) {
        prot_flush(cmd->stdin_prot);
        close(cmd->stdin_prot->fd);
        prot_free(cmd->stdin_prot);
    }

    if (cmd->stdout_prot) {
        close(cmd->stdout_prot->fd);
        prot_free(cmd->stdout_prot);
    }

    r = wait_for_child(cmd->argv0, cmd->pid);

    free(cmd->argv0);
    free(cmd);
    *cmdp = NULL;

    return r;
}

EXPORTED int command_done_stdin(struct command *cmd)
{
    int r = 0;

    if (cmd->stdin_prot) {
        r = prot_flush(cmd->stdin_prot);
        close(cmd->stdin_prot->fd);
        prot_free(cmd->stdin_prot);
        cmd->stdin_prot = NULL;
    }
    return r;
}

static int wait_for_child(const char *argv0, pid_t pid)
{
    int r = 0;

    if (pid) {
        for (;;) {
            int status;
            pid_t pr = waitpid(pid, &status, 0);
            if (pr < 0) {
                if (errno == EINTR) {
                    signals_poll();
                    continue;
                }
                else if (errno == ECHILD || errno == ESRCH) {
                    r = 0;
                    break;  /* someone else reaped the child */
                }
                else {
                    syslog(LOG_ERR, "waitpid() failed: %m");
                    r = IMAP_SYS_ERROR;
                    break;
                }
            }
            if (WIFEXITED(status)) {
                r = 0;
                if (WEXITSTATUS(status)) {
                    syslog(LOG_ERR, "Program %s (pid %d) exited with status %d",
                           argv0, (int)pid, WEXITSTATUS(status));
                    r = IMAP_SYS_ERROR;
                }
                break;
            }
            if (WIFSIGNALED(status)) {
                syslog(LOG_ERR, "Program %s (pid %d) died with signal %d",
                       argv0, (int)pid, WTERMSIG(status));
                r = IMAP_SYS_ERROR;
                break;
            }
        }
    }

    return r;
}
