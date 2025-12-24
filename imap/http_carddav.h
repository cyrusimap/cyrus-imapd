/* http_carddav.h -- Routines for dealing with CARDDAV in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_CARDDAV_H
#define HTTP_CARDDAV_H

#define DEFAULT_ADDRBOOK "Default"

/* Create the default addressbook for userid, if it doesn't exist. */
extern int carddav_create_defaultaddressbook(const char *userid);

#endif /* HTTP_CARDDAV_H */
