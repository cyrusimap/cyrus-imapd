/* imap_proxy.h - IMAP proxy support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _IMAP_PROXY_H
#define _IMAP_PROXY_H

#include "annotate.h"
#include "backend.h"
#include "imapurl.h"
#include "strarray.h"

enum {
    PROXY_NOCONNECTION = -1,
    PROXY_OK = 0,
    PROXY_NO = 1,
    PROXY_BAD = 2
};

enum {
    /* IMAP capabilities */
    CAPA_IDLE                = (1 << 3),
    CAPA_MUPDATE             = (1 << 4),
    CAPA_MULTIAPPEND         = (1 << 5),
    CAPA_ACLRIGHTS           = (1 << 6),
    CAPA_LISTEXTENDED        = (1 << 7),
    CAPA_SASL_IR             = (1 << 8),
    CAPA_REPLICATION         = (1 << 9),
    CAPA_METADATA            = (1 << 10),
    CAPA_SIEVE_MAILBOX       = (1 << 11),
    CAPA_REPLICATION_ARCHIVE = (1 << 12),
    CAPA_QUOTASET            = (1 << 13),
};

extern struct protocol_t imap_protocol;

void proxy_gentag(char *tag, size_t len);

struct backend *proxy_findinboxserver(const char *userid);

int pipe_until_tag(struct backend *s, const char *tag, int force_notfatal);
int pipe_including_tag(struct backend *s, const char *tag, int force_notfatal);
int pipe_command(struct backend *s, int optimistic_literal);
int pipe_lsub(struct backend *s, const char *userid, const char *tag,
              int force_notfatal, struct listargs *listargs, strarray_t *subs);

void print_listresponse(unsigned cmd, const char *extname, const char *oldname,
                        char hier_sep, uint32_t attributes, struct buf *extraflags);

int proxy_fetch(char *sequence, int usinguid, unsigned items,
                void (*item_cb)(uint32_t seqno, unsigned item,
                                void *datap, void *rock),
                void *rock);

void proxy_copy(const char *tag, char *sequence, char *name, int myrights,
                int usinguid, struct backend *s);

int proxy_catenate_url(struct backend *s, struct imapurl *url, FILE *f,
                       size_t maxsize, unsigned long *size, const char **parseerr);

int annotate_fetch_proxy(const char *server, const char *mbox_pat,
                         const strarray_t *entry_pat,
                         const strarray_t *attribute_pat);
int annotate_store_proxy(const char *server, const char *mbox_pat,
                         struct entryattlist *entryatts);
char *find_free_server(void);
#endif /* _IMAP_PROXY_H */
