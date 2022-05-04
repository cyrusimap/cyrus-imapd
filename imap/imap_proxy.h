/* imap_proxy.h - IMAP proxy support functions
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
 */

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
};

extern struct protocol_t imap_protocol;

void proxy_gentag(char *tag, size_t len);

struct backend *proxy_findinboxserver(const char *userid);

int pipe_until_tag(struct backend *s, const char *tag, int force_notfatal);
int pipe_including_tag(struct backend *s, const char *tag, int force_notfatal);
int pipe_command(struct backend *s, int optimistic_literal);
int pipe_lsub(struct backend *s, const char *userid, const char *tag,
              int force_notfatal, struct listargs *listargs, strarray_t *subs);

void print_listresponse(unsigned cmd, const char *extname, char hier_sep,
                        uint32_t attributes, struct buf *extraflags);

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
