/*
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
 * $Id: imapurl.h,v 1.8 2008/03/24 17:43:09 murch Exp $
 */

#ifndef IMAPURL_H
#define IMAPURL_H

struct imapurl {
    char *freeme;		/* copy of original URL + decoded mailbox;
				   caller must free() */

    /* RFC 2192 */
    const char *user;
    const char *auth;
    const char *server;
    const char *mailbox;
    unsigned long uidvalidity;
    unsigned long uid;
    const char *section;
    /* RFC 2192bis */
    unsigned long start_octet;
    unsigned long octet_count;
    /* URLAUTH */
    struct {
	const char *access;
	const char *mech;
	const char *token;
	time_t expire;
	size_t rump_len;
    } urlauth;
};

/* Convert hex coded UTF-8 URL path to modified UTF-7 IMAP mailbox
 *  mailbox should be about twice the length of src to deal with non-hex
 *  coded URLs; server should be as large as src.
 */
int imapurl_fromURL(struct imapurl *url, const char *src);
int URLtoMailbox(char *dst, char *src);
#define UTF8_to_mUTF7(dst, src) URLtoMailbox(dst, src)

/* Convert an IMAP mailbox to a URL path
 *  dst needs to have roughly 4 times the storage space of mailbox
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 *
 *  it is valid for mechname to be NULL (implies anonymous mech)
 */
void imapurl_toURL(char *dst, struct imapurl *url);

#endif /* IMAPURL_H */
