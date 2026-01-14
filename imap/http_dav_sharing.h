/* http_dav_sharing.h - Routines for dealing with DAV sharing in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_DAV_SHARING_H
#define HTTP_DAV_SHARING_H

#include "httpd.h"

#define DAVSHARING_CONTENT_TYPE "application/davsharing+xml"

/* Privileges assigned via WebDAV Sharing (draft-pot-webdav-resource-sharing)
 *
 * JMAP can always set calendar properties for read-only calendars,
 * but need to flag the account as isReadOnly=false, so include ACL_WRITE.
 */
#define DACL_SHARE      ( DACL_READ   | DACL_READFB       | ACL_WRITE )
#define DACL_SHARERW    ( DACL_SHARE  | DACL_WRITECONT    | DACL_WRITEPROPS |   \
                          DACL_RMRSRC | DACL_WRITEOWNRSRC | DACL_UPDATEPRIVATE )

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
int dav_schedule_notification(xmlDocPtr doc, struct dlist *extradata,
                          const char *userid, const char *resource);
void dav_run_notifications();

int dav_lookup_notify_collection(const char *userid, mbentry_t **mbentry);

int notify_post(struct transaction_t *txn);

#endif /* HTTP_DAV_SHARING_H */
