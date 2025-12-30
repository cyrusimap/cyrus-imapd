/* loginlog - login logging API */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_LOGINLOG_H
#define INCLUDED_LOGINLOG_H

#include <stdbool.h>

extern void loginlog_good(const char *clienthost,
                          const char *username,
                          const char *mech,
                          bool tls);

extern void loginlog_good_http(const char *clienthost,
                               const char *username,
                               const char *scheme,
                               bool tls);

extern void loginlog_good_imap(const char *clienthost,
                               const char *username,
                               const char *mech,
                               bool tls,
                               const char *magicplus,
                               bool nopassword);

extern void loginlog_good_pop(const char *clienthost,
                              const char *username,
                              const char *mech,
                              bool tls,
                              const char *subfolder);

extern void loginlog_anon(const char *clienthost,
                          const char *mech,
                          bool tls,
                          const char *password);

extern void loginlog_bad(const char *clienthost,
                         const char *username,
                         const char *mech,
                         const char *scheme,
                         const char *error);

#endif
