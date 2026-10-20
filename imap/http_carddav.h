/* http_carddav.h - Routines for dealing with CARDDAV in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_CARDDAV_H
#define HTTP_CARDDAV_H

#define DEFAULT_ADDRBOOK "Default"

/* Annotation on the addressbook home naming the default addressbook. */
#define DEFAULT_ADDRBOOK_ANNOT \
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">jmap-default-addressbook"

#define DAVX5_UA_STR          "DAVx5/"
#define DAVX5_UA_STR_LEN      6

/* Create the default addressbook for userid, if it doesn't exist. */
extern int carddav_create_defaultaddressbook(const char *userid);

/**
 * @brief Name the default addressbook of userid.
 *
 * Reads the DEFAULT_ADDRBOOK_ANNOT annotation on the addressbook home.
 * Without one, falls back to the DEFAULT_ADDRBOOK collection created
 * at provisioning.  Neither mailbox is checked for existence.
 *
 * @return the internal mailbox name, which the caller must free()
 */
extern char *carddav_defaultaddressbook_mboxname(const char *userid);

#endif /* HTTP_CARDDAV_H */
