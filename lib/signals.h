/* signals.h - signal handling functions to allow clean shutdown */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_SIGNALS_H
#define INCLUDED_SIGNALS_H

#include <sys/select.h>
#include <unistd.h>

typedef void shutdownfn(int);

void signals_add_handlers(int alarm);
void signals_reset_sighup_handler(int restartable);
void signals_set_shutdown(shutdownfn *s);
int signals_poll(void);
int signals_select(int nfds, fd_set *rfds, fd_set *wfds,
                   fd_set *efds, struct timeval *tout);
void signals_clear(int sig);

#endif /* INCLUDED_SIGNALS_H */
