/* httpd.h -- Common state for HTTP/WebDAV/CalDAV daemon
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef HTTPD_H
#define HTTPD_H

#include "mailbox.h"

#define HTTP_VERSION	"HTTP/1.1"
#define NS_URL_DAV	"DAV:"
#define NS_URL_CAL	"urn:ietf:params:xml:ns:caldav"
#define NS_URL_CS	"http://calendarserver.org/ns/"
#define NS_URL_APPLE	"http://apple.com/ns/ical/"

/* Path namespaces */
enum {
    URL_NS_DEFAULT = 0,
    URL_NS_PRINCIPAL,
    URL_NS_CALENDAR,
    URL_NS_ADDRESSBOOK
};

/* Request target context */
struct request_target_t {
    char path[MAX_MAILBOX_PATH+1]; /* working copy of URL path */
    unsigned namespace;		/* namespace of path */
    char *user;			/* ptr to owner of collection (NULL = shared) */
    size_t userlen;
    char *collection;		/* ptr to collection name */
    size_t collen;
    char *resource;		/* ptr to resource name */
    size_t reslen;
    unsigned long allow;	/* bitmask of allowed features/methods */
};

extern const char *http_statusline(long code);

#endif /* HTTPD_H */
