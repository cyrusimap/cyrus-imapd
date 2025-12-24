/* imapurl.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef IMAPURL_H
#define IMAPURL_H

#include "buf.h"

struct imapurl {
    char *freeme;               /* copy of original URL + decoded mailbox;
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
extern int imapurl_fromURL(struct imapurl *url, const char *src);
extern int URLtoMailbox(char *dst, const char *src);
#define UTF8_to_mUTF7(dst, src) URLtoMailbox(dst, src)

/* Convert an IMAP mailbox to a URL path
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 *
 *  it is valid for mechname to be NULL (implies anonymous mech)
 */
extern void imapurl_toURL(struct buf *dst, const struct imapurl *url);

#endif /* IMAPURL_H */
