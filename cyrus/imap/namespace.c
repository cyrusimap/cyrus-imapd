/* namespace.c -- Namespace manipulation routines
 * $Id: namespace.c,v 1.1.2.1 2001/04/17 22:21:34 ken3 Exp $
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

#include <config.h>

#include "namespace.h"
#include "mboxname.h"

/*
 * Create namespace based on config options.
 */
int namespace_init(struct namespace *namespace)
{
    namespace->hier_sep = '.';
    namespace->isalt = config_getswitch("altnamespace", 0);

    if (namespace->isalt) {
	/* alternate namespace */
	strcpy(namespace->prefix[NAMESPACE_INBOX], "");
	sprintf(namespace->prefix[NAMESPACE_USER], "%.*s%c",
		MAX_NAMESPACE_PREFIX-1,
		config_getstring("userprefix", "Other Users"),
		namespace->hier_sep);
	sprintf(namespace->prefix[NAMESPACE_SHARED], "%.*s%c",
		MAX_NAMESPACE_PREFIX-1,
		config_getstring("sharedprefix", "Shared Folders"),
		namespace->hier_sep); 
    } else {
	/* standard namespace */
	sprintf(namespace->prefix[NAMESPACE_INBOX], "%s%c",
		"INBOX", namespace->hier_sep);
	sprintf(namespace->prefix[NAMESPACE_USER], "%s%c",
		"user", namespace->hier_sep);
	strcpy(namespace->prefix[NAMESPACE_SHARED], "");
    }

    return 0;
}
