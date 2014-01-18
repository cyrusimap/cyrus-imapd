/* dav_util.c -- utility functions for dealing with DAV database
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <string.h>

#include "dav_util.h"
#include "global.h"
#include "mailbox.h"
#include "mboxname.h"
#include "util.h"

/* Create filename corresponding to DAV DB for mailbox */
void dav_getpath(struct buf *fname, struct mailbox *mailbox)
{
    const char *userid;

    userid = mboxname_to_userid(mailbox->name);

    if (userid) dav_getpath_byuserid(fname, userid);
    else buf_setcstr(fname, mailbox_meta_fname(mailbox, META_DAV));
}


/* Create filename corresponding to DAV DB for userid */
void dav_getpath_byuserid(struct buf *fname, const char *userid)
{
    char c, *domain;

    buf_reset(fname);
    if (config_virtdomains && (domain = strchr(userid, '@'))) {
	char d = (char) dir_hash_c(domain+1, config_fulldirhash);
	*domain = '\0';  /* split user@domain */
	c = (char) dir_hash_c(userid, config_fulldirhash);
	buf_printf(fname, "%s%s%c/%s%s%c/%s%s", config_dir, FNAME_DOMAINDIR, d,
		   domain+1, FNAME_USERDIR, c, userid, FNAME_DAVSUFFIX);
	*domain = '@';  /* reassemble user@domain */
    }
    else {
	c = (char) dir_hash_c(userid, config_fulldirhash);
	buf_printf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
		   FNAME_DAVSUFFIX);
    }
}
