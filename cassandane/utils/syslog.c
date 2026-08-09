/* syslog.so
 *
 * LD_PRELOAD module for intercepting syslog calls and capturing them
 * to another file.  Captured lines are flushed as written, so there
 * is no buffering delay here (unlike real syslog).
 *
 * Set CASSANDANE_SYSLOG_FNAME in the environment to specify the file
 * to which logged lines should be appended.
 *
 * Each captured line is prefixed with the severity it was logged at, as
 * "<err> ", so that log consumers can recognise problems without having
 * to match on message text.  Real syslog discards the priority by the
 * time it reaches the log file, which is why we record it ourselves.
 * Cassandane::Instance::_check_syslog depends on this prefix.
 */

/* need _GNU_SOURCE for RTLD_NEXT */
#define _GNU_SOURCE

#include <sys/time.h>
#include <sys/types.h>

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define EXPORTED __attribute__((__visibility__("default")))

typedef void (*real_openlog_t)(const char *, int, int);
static void real_openlog(const char *ident, int option, int facility)
{
    real_openlog_t p = (real_openlog_t) dlsym(RTLD_NEXT, "openlog");
    p(ident, option, facility);
}

typedef void (*real_vsyslog_t)(int, const char *, va_list);
static void real_vsyslog(int priority, const char *format, va_list ap)
{
    real_vsyslog_t p = (real_vsyslog_t) dlsym(RTLD_NEXT, "vsyslog");
    p(priority, format, ap);
}

typedef void (*real_closelog_t)(void);
static void real_closelog(void)
{
    real_closelog_t p = (real_closelog_t) dlsym(RTLD_NEXT, "closelog");
    p();
}

static FILE *out = NULL;
static int is_opened = 0;
static char *myident = NULL;
static char hostname[HOST_NAME_MAX + 1] = {0};
static pid_t pid = 0;

EXPORTED void openlog(const char *ident, int option, int facility)
{
    const char *syslog_fname;

    if (is_opened) closelog();

    syslog_fname = getenv("CASSANDANE_SYSLOG_FNAME");
    if (syslog_fname) {
        out = fopen(syslog_fname, "ae");
        if (out) {
            gethostname(hostname, sizeof(hostname));
            myident = ident ? strdup(ident) : NULL;
            pid = getpid();
            is_opened = 1;
        }
    }

    real_openlog(ident, option, facility);
}

EXPORTED void closelog(void)
{
    real_closelog();

    if (out) fclose(out);
    out = NULL;
    free(myident);
    myident = NULL;
    memset(hostname, 0, sizeof(hostname));
    pid = 0;
    is_opened = 0;
}

/* The severity names used by syslog.conf(5), so that they'll look familiar. */
static const char *severity_name(int priority)
{
    switch (LOG_PRI(priority)) {
    case LOG_EMERG:   return "emerg";
    case LOG_ALERT:   return "alert";
    case LOG_CRIT:    return "crit";
    case LOG_ERR:     return "err";
    case LOG_WARNING: return "warning";
    case LOG_NOTICE:  return "notice";
    case LOG_INFO:    return "info";
    case LOG_DEBUG:   return "debug";
    default:          return "unknown";
    }
}

static void fake_vsyslog(int priority, const char *format, va_list ap)
{
    struct timeval now = {0};
    char timestamp[16] = {0};
    int saved_errno = errno;
    int logmask;

    if (!is_opened) return; /* no file to write to */

    logmask = setlogmask(0); /* get the real syslog's current mask */
    if (!(logmask & LOG_MASK(LOG_PRI(priority))))
        return; /* do not want messages of this priority logged */

    gettimeofday(&now, NULL);

    /* The severity goes first, so that it can be matched with an anchored
     * pattern that can never be confused by the message body. */
    strftime(timestamp, sizeof(timestamp), "%b %d %T", localtime(&now.tv_sec));
    fprintf(out, "<%s> %s.%06" PRIdMAX " %s %s[%" PRIdMAX "]: ",
                 severity_name(priority),
                 timestamp, (intmax_t) now.tv_usec,
                 hostname, myident, (intmax_t) pid);
    errno = saved_errno;

    /* glibc handles %m in vfprintf() so we don't need to do
     * anything special to simulate that feature of syslog() */
    vfprintf(out, format, ap);
    fputs("\n", out);
    fflush(out);
    errno = saved_errno;
}

EXPORTED void syslog(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fake_vsyslog(priority, format, ap);
    va_end(ap);

    va_start(ap, format);
    real_vsyslog(priority, format, ap);
    va_end(ap);
}

EXPORTED void vsyslog(int priority, const char *format, va_list ap)
{
    fake_vsyslog(priority, format, ap);
    real_vsyslog(priority, format, ap);
}
