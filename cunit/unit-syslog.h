/* unit-syslog.h - declarations for CUnit syslog functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CUNIT_UNIT_SYSLOG_H
#define CUNIT_UNIT_SYSLOG_H

/* returns an active match number from 1 up */
extern unsigned int CU_syslogMatchBegin(const char *re, const char *filename,
                                        unsigned int lineno, int issubstr);
/* returns count of given match (or 0 for sum of all matches), and remove the match */
extern unsigned int CU_syslogMatchEnd(unsigned int match, const char **s);
/* reset all matches, call before each test */
#define CU_syslogMatchReset() \
    CU_syslogMatchEnd(0, NULL)

#endif /* CUNIT_UNIT_SYSLOG_H */
