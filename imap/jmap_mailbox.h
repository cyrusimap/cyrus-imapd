/* jmap_mail.h -- Routines for handling JMAP mailboxes
 *
 * Copyright (c) 1994-2022 Carnegie Mellon University.  All rights reserved.
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

#ifndef JMAP_MAILBOX_H
#define JMAP_MAILBOX_H

#include <config.h>

#include "jmap_api.h"
#include "ptrarray.h"

enum mboxset_type { _MBOXSET_EMAIL, _MBOXSET_NODE };

struct mboxset_args {
    enum mboxset_type type;
    char *creation_id; // NULL for update
    char *id;
    char *name;
    char *parent_id;
    int is_toplevel;
    json_t *shareWith; // NULL if not set
    json_t *jargs;     // original JSON arguments

    /* Type-specific arguments */
    union {
        struct {
            char *specialuse;  // empty string means delete
            int is_subscribed; // -1 if not set
            int is_seenshared; // -1 if not set
            int sortorder;
            int overwrite_acl;
            char *color;
            int show_as_label;
        } email;
        struct {
            char *blobid; // NULL means folder
            char *type;   // NULL for folder
            char *title;
            char *comment;
        } node;
    } u;
};

enum mboxset_runmode { _MBOXSET_FAIL, _MBOXSET_SKIP, _MBOXSET_INTERIM };

struct mboxset_result {
    json_t *err;
    int skipped;
    char *old_imapname;
    char *new_imapname;
    char *tmp_imapname;
};

#define MBOXSET_RESULT_INITIALIZER { NULL, 0, NULL, NULL, NULL }

struct mboxset {
    struct jmap_set super;
    uint32_t mbtype;
    ptrarray_t create;
    ptrarray_t update;
    strarray_t *destroy;
    void (*create_cb)(jmap_req_t *, struct mboxset_args *, enum mboxset_runmode,
                      json_t **, struct mboxset_result *, strarray_t *);
    void (*update_cb)(jmap_req_t *, struct mboxset_args *, enum mboxset_runmode,
                      struct mboxset_result *, strarray_t *);
    int on_destroy_remove_msgs;
    const char *on_destroy_move_to_mailboxid;
};

extern void jmap_mailbox_init(jmap_settings_t *settings);
extern void jmap_mailbox_capabilities(json_t *jcapabilities);

extern int jmap_mailbox_find_role(jmap_req_t *req, const char *role,
                                  char **mboxnameptr, char **uniqueid);

extern void jmap_mboxset(jmap_req_t *req, struct mboxset *set);

#endif /* JMAP_MAIL_H */
