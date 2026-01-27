/* telemetry.h - interface for telemetry */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_TELEMETRY_H
#define INCLUDED_TELEMETRY_H

int telemetry_log(const char *userid, struct protstream *pin,
                  struct protstream *pout, int usetimestamp);
void telemetry_rusage(const char *userid);

#endif
