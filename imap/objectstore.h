/* objectstore.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */


#ifndef OBJECT_STORE
#define OBJECT_STORE

int objectstore_put (struct mailbox *mailbox,
        const struct index_record *record, const char *fname);

int objectstore_get (struct mailbox *mailbox,
        const struct index_record *record, const char *fname);

int objectstore_delete (struct mailbox *mailbox,
    const struct index_record *record);

int objectstore_is_filename_in_container (struct mailbox *mailbox,
        const struct index_record *record, int *isthere);

#endif /*OBJECT_STORE*/
