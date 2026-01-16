/* http_jmap.h - Routines for handling JMAP requests in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_JMAP_H
#define HTTP_JMAP_H

#include "httpd.h"
#include "jmap_api.h"

extern struct namespace jmap_namespace;

extern int jmap_open_upload_collection(const char *accountid,
                                       struct mailbox **mailbox);

extern int jmap_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

#endif /* HTTP_JMAP_H */
