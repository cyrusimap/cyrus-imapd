/* namespace.h -- Namespace manipulation routines
 * $Id: namespace.h,v 1.1.2.3 2001/06/20 02:08:30 ken3 Exp $
 *
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_NAMESPACE_H
#define INCLUDED_NAMESPACE_H

#define MAX_NAMESPACE_PREFIX 40

enum { NAMESPACE_INBOX, NAMESPACE_USER, NAMESPACE_SHARED };

struct namespace {
    int isalt;
    char prefix[3][MAX_NAMESPACE_PREFIX+1];
    char hier_sep;
    int (*mboxname_tointernal)(const char *name, struct namespace *namespace,
			       const char *userid, char *result);
    int (*mboxname_toexternal)(const char *name, struct namespace *namespace,
			       const char *userid, char *result);
};

/* Initialize namespace (prefixes & hierarchy separator from imapd.conf) */
int namespace_init(struct namespace *namespace, int force_std);

#endif
