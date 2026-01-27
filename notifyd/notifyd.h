/* notifyd.h - notification method definitions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "notify_null.h"
#include "notify_log.h"
#include "notify_mailto.h"
#include "notify_zephyr.h"
#include "notify_external.h"

/* Notify method dispatch table definition */
typedef struct {
    const char *name;                           /* name of the method */
    char *(*notify)(const char *class, const char *priority,
                    const char *user, const char *mailbox,
                    int nopt, char **options,
                    const char *message, const char *fname);    /* notification function */
} notifymethod_t;

/* array of supported notification methods */
static notifymethod_t methods[] = {
    { "null",   notify_null },          /* do nothing */
    { "log",    notify_log },           /* use syslog (for testing) */
    { "mailto", notify_mailto },        /* send an email */
#ifdef HAVE_ZEPHYR
    { "zephyr", notify_zephyr },        /* send a zephyrgram */
#endif
    { "external", notify_external },    /* send via external program */
    { NULL,     NULL }
};
