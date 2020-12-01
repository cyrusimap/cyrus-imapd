/* http_dav_sharing.h -- Routines for dealing with DAV sharing in httpd
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

#ifndef HTTP_DAV_SHARING_H
#define HTTP_DAV_SHARING_H

#include "httpd.h"

#define DAVSHARING_CONTENT_TYPE "application/davsharing+xml"

/* Privileges assigned via WebDAV Sharing (draft-pot-webdav-resource-sharing) */
#define DACL_SHARE      (DACL_READ|DACL_WRITEPROPS)
#define DACL_SHARERW    (DACL_READ|DACL_WRITE)

#define SYSTEM_STATUS_NOTIFICATION  "systemstatus"
#define SHARE_INVITE_NOTIFICATION   "share-invite-notification"
#define SHARE_REPLY_NOTIFICATION    "share-reply-notification"

enum {
    SHARE_NONE = 0,
    SHARE_READONLY,
    SHARE_READWRITE
};

void xml_add_shareaccess(struct propfind_ctx *fctx,
                         xmlNodePtr resp, xmlNodePtr node, int legacy);
int propfind_shareaccess(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop, xmlNodePtr resp,
                         struct propstat propstat[], void *rock);
int propfind_invite(const xmlChar *name, xmlNsPtr ns,
                    struct propfind_ctx *fctx,
                    xmlNodePtr prop, xmlNodePtr resp,
                    struct propstat propstat[], void *rock);
int propfind_sharedurl(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop, xmlNodePtr resp,
                       struct propstat propstat[], void *rock);
int propfind_notifyurl(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);

int propfind_csnotify_collection(struct propfind_ctx *fctx, xmlNodePtr props);

int dav_post_share(struct transaction_t *txn, struct meth_params *pparams);
int dav_create_invite(xmlNodePtr *notify, xmlNsPtr *ns,
                      struct request_target_t *tgt,
                      const struct prop_entry *live_props,
                      const char *sharee, int access, xmlChar *content);
int dav_send_notification(xmlDocPtr doc, struct dlist *extradata,
                          const char *userid, const char *resource);

int dav_lookup_notify_collection(const char *userid, mbentry_t **mbentry);

int notify_post(struct transaction_t *txn);

#endif /* HTTP_DAV_SHARING_H */
