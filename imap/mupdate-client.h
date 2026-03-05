/* mupdate-client.h -- cyrus murder database clients */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_MUPDATE_CLIENT_H
#define INCLUDED_MUPDATE_CLIENT_H

#include <sasl/sasl.h>

enum {
    /* MUPDATE capabilities */
    CAPA_MAILBOXEXT          = (1 << 3),
};

#define FNAME_MUPDATE_TARGET_SOCK "/socket/mupdate.target"

typedef struct mupdate_handle_s mupdate_handle;

/* connect & authenticate to an mupdate server */
int mupdate_connect(const char *server, const char *port,
                    mupdate_handle **handle, sasl_callback_t *cbs);

/* disconnect from mupdate server */
void mupdate_disconnect(mupdate_handle **h);

/* activate a mailbox */
int mupdate_activate(mupdate_handle *handle,
                     const char *mailbox, const char *location,
                     const char *acl, const char *jmapid);

/* reserve a piece of namespace */
int mupdate_reserve(mupdate_handle *handle,
                    const char *mailbox, const char *location);

/* deactivate a mailbox (ACTIVE->RESERVE) */
int mupdate_deactivate(mupdate_handle *handle,
                       const char *mailbox, const char *location);

/* delete a mailbox */
int mupdate_delete(mupdate_handle *handle,
                   const char *mailbox);

enum mbtype {
    ACTIVE, RESERVE
};

/* mailbox data structure */
struct mupdate_mailboxdata {
    const char *mailbox;
    const char *location;
    const char *acl;
    const char *jmapid;
    enum mbtype t;
};

/* does a given mailbox exist?  1 if false, 0 if true, -1 if error,
 * "target" gets pointed at a struct mudate_mailboxdata that is only valid
 * until the next mupdate_* call on this mupdate_handle.
 */
int mupdate_find(mupdate_handle *handle, const char *mailbox,
                 struct mupdate_mailboxdata **target);

/* Callbacks for mupdate_scarf and mupdate_list */
/* cmd is one of DELETE, MAILBOX, RESERVE */
/* context is as provided to mupdate_scarf */
/* XXX: "cmd" can probably go away and instead
 * we just use the t in mdata */
typedef int (*mupdate_callback)(struct mupdate_mailboxdata *mdata,
                                const char *cmd, void *context);

/* perform an MUPDATE LIST operation (callback is called for
 * each remote mailbox) */
int mupdate_list(mupdate_handle *handle, mupdate_callback callback,
                 const char *prefix, void *context);

/* ping the mupdate server with a NOOP. */
int mupdate_noop(mupdate_handle *handle, mupdate_callback callback,
                 void *context);

/* ping a local slave */
void kick_mupdate(void);

/* parse extended mailbox args in ACTIVATE command and MAILBOX response */
int mupdate_parse_mailbox_extargs(struct protstream *pin,
                                  struct dlist **extargs);

#endif
