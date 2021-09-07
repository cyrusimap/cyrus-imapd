/* dlist.h - list protocol for dump and sync
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#ifndef INCLUDED_DLIST_H
#define INCLUDED_DLIST_H

#include "util.h"
#include "prot.h"
#include "mailbox.h"
#include "message_guid.h"

enum dlistsax_t {
    DLISTSAX_LISTSTART,
    DLISTSAX_LISTEND,
    DLISTSAX_KVLISTSTART,
    DLISTSAX_KVLISTEND,
    DLISTSAX_RESERVE,
    DLISTSAX_LITERAL,
    DLISTSAX_FLAG,
    DLISTSAX_STRING,
    /* error callbacks */
    DLISTSAX_ERROR
};

struct dlistsax_data {
    const struct buf kbuf;
    const struct buf buf;
    const char *data; // cstring buffer or NULL for NIL
    void *rock;
};

enum dlist_t {
    DL_NIL = 0,
    DL_ATOM,
    DL_FLAG,
    DL_NUM,
    DL_DATE,
    DL_HEX,
    DL_BUF,
    DL_GUID,
    DL_FILE,
    DL_KVLIST,
    DL_ATOMLIST
};

struct dlist {
    char *name;
    struct dlist *head;
    struct dlist *tail;
    struct dlist *next;
    int type;
    char *sval;
    bit64 nval;
    struct message_guid *gval; /* guid if any */
    char *part; /* so what if we're big! */
};

const char *dlist_reserve_path(const char *part, int isarchive, int isbackup,
                               const struct message_guid *guid);

/* set fields */
void dlist_makeatom(struct dlist *dl, const char *val);
void dlist_makeflag(struct dlist *dl, const char *val);
void dlist_makenum32(struct dlist *dl, uint32_t val);
void dlist_makenum64(struct dlist *dl, bit64 val);
void dlist_makedate(struct dlist *dl, time_t val);
void dlist_makehex64(struct dlist *dl, bit64 val);
void dlist_makemap(struct dlist *dl, const char *val, size_t len);
void dlist_makebuf(struct dlist *dl, const struct buf *buf);
void dlist_makeguid(struct dlist *dl, const struct message_guid *guid);
void dlist_makefile(struct dlist *dl,
                    const char *part, const struct message_guid *guid,
                    unsigned long size, const char *fname);

/* parse fields */
int dlist_toatom(struct dlist *dl, const char **valp);
int dlist_toflag(struct dlist *dl, const char **valp);
int dlist_tonum32(struct dlist *dl, uint32_t *valp);
int dlist_tonum(struct dlist *dl, bit64 *valp);
int dlist_todate(struct dlist *dl, time_t *valp);
int dlist_tohex32(struct dlist *dl, uint32_t *valp);
int dlist_tohex(struct dlist *dl, bit64 *valp);
int dlist_tomap(struct dlist *dl, const char **valp, size_t *lenp);
int dlist_tobuf(struct dlist *dl, struct buf *buf);

/* these two don't actually do anything except check type */
int dlist_tolist(struct dlist *dl, struct dlist **valp);
int dlist_tokvlist(struct dlist *dl, struct dlist **valp);
int dlist_toguid(struct dlist *dl, struct message_guid **valp);
int dlist_tofile(struct dlist *dl,
                 const char **partp, struct message_guid **guidp,
                 unsigned long *sizep, const char **fnamep);

int dlist_isatomlist(const struct dlist *dl);
int dlist_iskvlist(const struct dlist *dl);
int dlist_isfile(const struct dlist *dl);
/* XXX - these two aren't const, they can fiddle internals */
int dlist_isnum(struct dlist *dl);
int dlist_ishex64(struct dlist *dl);
int dlist_isguid(struct dlist *dl);

/* special number and string readers - return 0 and "" if nothing */
bit64 dlist_num(struct dlist *dl);
const char *dlist_cstring(struct dlist *dl);

/* wrappers for use in a kvlist */
struct dlist *dlist_newlist(struct dlist *parent, const char *name);
struct dlist *dlist_newpklist(struct dlist *parent, const char *name);
struct dlist *dlist_newkvlist(struct dlist *parent, const char *name);

struct dlist *dlist_setatom(struct dlist *parent, const char *name,
                            const char *val);
struct dlist *dlist_setflag(struct dlist *parent, const char *name,
                            const char *val);
struct dlist *dlist_setnum32(struct dlist *parent, const char *name,
                             uint32_t val);
struct dlist *dlist_setnum64(struct dlist *parent, const char *name,
                             bit64 val);
struct dlist *dlist_setdate(struct dlist *parent, const char *name,
                            time_t val);
struct dlist *dlist_sethex64(struct dlist *parent, const char *name,
                             bit64 val);
struct dlist *dlist_setmap(struct dlist *parent, const char *name,
                           const char *val, size_t len);
struct dlist *dlist_setbuf(struct dlist *parent, const char *name,
                           const struct buf *buf);
struct dlist *dlist_setguid(struct dlist *parent, const char *name,
                            const struct message_guid *guid);
struct dlist *dlist_setfile(struct dlist *parent, const char *name,
                            const char *part, const struct message_guid *guid,
                            size_t size, const char *fname);

struct dlist *dlist_updateatom(struct dlist *parent, const char *name,
                               const char *val);
struct dlist *dlist_updateflag(struct dlist *parent, const char *name,
                               const char *val);
struct dlist *dlist_updatenum32(struct dlist *parent, const char *name,
                                uint32_t val);
struct dlist *dlist_updatenum64(struct dlist *parent, const char *name,
                                bit64 val);
struct dlist *dlist_updatedate(struct dlist *parent, const char *name,
                               time_t val);
struct dlist *dlist_updatehex64(struct dlist *parent, const char *name,
                                bit64 val);
struct dlist *dlist_updatemap(struct dlist *parent, const char *name,
                              const char *val, size_t len);
struct dlist *dlist_updatebuf(struct dlist *parent, const char *name,
                              const struct buf *buf);
struct dlist *dlist_updateguid(struct dlist *parent, const char *name,
                               const struct message_guid *guid);
struct dlist *dlist_updatefile(struct dlist *parent, const char *name,
                               const char *part, const struct message_guid *guid,
                               size_t size, const char *fname);

int dlist_getatom(struct dlist *parent, const char *name,
                  const char **valp);
int dlist_getflag(struct dlist *parent, const char *name,
                  const char **valp);
int dlist_getnum32(struct dlist *parent, const char *name,
                   uint32_t *valp);
int dlist_getnum64(struct dlist *parent, const char *name,
                 bit64 *valp);
int dlist_getdate(struct dlist *parent, const char *name,
                  time_t *valp);
int dlist_gethex64(struct dlist *parent, const char *name,
                   bit64 *valp);
int dlist_getmap(struct dlist *parent, const char *name,
                 const char **valp, size_t *lenp);
int dlist_getbuf(struct dlist *parent, const char *name,
                 struct buf *buf);
int dlist_getlist(struct dlist *parent, const char *name,
                  struct dlist **valp);
int dlist_getkvlist(struct dlist *parent, const char *name,
                    struct dlist **valp);
int dlist_getguid(struct dlist *parent, const char *name,
                  struct message_guid **valp);
int dlist_getfile(struct dlist *parent, const char *name,
                  const char **partp, struct message_guid **guidp,
                  unsigned long *sizep, const char **fnamep);

void dlist_unlink_files(struct dlist *dl);
void dlist_free(struct dlist **dlp);

void dlist_print(const struct dlist *dl, int printkeys,
                 struct protstream *out);
void dlist_printbuf(const struct dlist *dl, int printkeys,
                    struct buf *outbuf);
int dlist_parse(struct dlist **dlp, int parsekeys, int isbackup,
                 struct protstream *in);
int dlist_parse_asatomlist(struct dlist **dlp, int parsekey,
                            struct protstream *in);
int dlist_parsemap(struct dlist **dlp, int parsekeys, int isbackup,
                   const char *base, unsigned len);

typedef int dlistsax_cb_t(int type, struct dlistsax_data *data);

int dlist_parsesax(const char *base, size_t len, int parsekey,
                   dlistsax_cb_t *proc, void *rock);

void dlist_push(struct dlist *parent, struct dlist *child);
struct dlist *dlist_pop(struct dlist *parent);
void dlist_stitch(struct dlist *parent, struct dlist *child);
void dlist_unstitch(struct dlist *parent, struct dlist *child);
struct dlist *dlist_splice(struct dlist *parent, int num);

/* splat: convert a list into its child elements */
void dlist_splat(struct dlist *parent, struct dlist *child);

struct dlist *dlist_getchild(struct dlist *dl, const char *name);
struct dlist *dlist_getchildn(struct dlist *dl, int num);
struct dlist *dlist_getkvchild_bykey(struct dlist *dl,
                                     const char *key, const char *val);

void dlist_rename(struct dlist *dl, const char *name);

const char *dlist_lastkey(void);

/* print a dlist iteratively rather than recursively */
struct dlist_print_iter;

struct dlist_print_iter *dlist_print_iter_new(const struct dlist *dl,
                                              int printkeys);
const char *dlist_print_iter_step(struct dlist_print_iter *iter,
                                  struct buf *outbuf);
void dlist_print_iter_free(struct dlist_print_iter **iterp);

#endif /* INCLUDED_DLIST_H */
