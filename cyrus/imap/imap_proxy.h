/*
 * imap_proxy.h - IMAP proxy support functions
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    "This product includes software developed by Computing Services
 *    acknowledgment:
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
 * $Id: imap_proxy.h,v 1.1.2.5 2004/05/05 20:52:15 ken3 Exp $
 */

#ifndef _IMAP_PROXY_H
#define _IMAP_PROXY_H

#include "annotate.h"
#include "backend.h"

enum {
    PROXY_NOCONNECTION = -1,
    PROXY_OK = 0,
    PROXY_NO = 1,
    PROXY_BAD = 2
};

void proxy_gentag(char *tag, size_t len);

struct backend *proxy_findinboxserver(void);

int pipe_until_tag(struct backend *s, const char *tag, int force_notfatal);
int pipe_including_tag(struct backend *s, const char *tag, int force_notfatal);
int pipe_command(struct backend *s, int optimistic_literal);
int pipe_lsub(struct backend *s, const char *tag,
	      int force_notfatal, const char *resp);

void proxy_copy(const char *tag, char *sequence, char *name, int usinguid,
		struct backend *s);

int annotate_fetch_proxy(const char *server, const char *mbox_pat,
			 struct strlist *entry_pat,
			 struct strlist *attribute_pat);
int annotate_store_proxy(const char *server, const char *mbox_pat,
			 struct entryattlist *entryatts);
#endif /* _IMAP_PROXY_H */
