#ifndef IMAPURL_H
#define IMAPURL_H

/* Convert hex coded UTF-8 URL path to modified UTF-7 IMAP mailbox
 *  mailbox should be about twice the length of src to deal with non-hex
 *  coded URLs; server should be as large as src.
 */
void imapurl_fromURL(char *server, char *mailbox, const char *src);

/* Convert an IMAP mailbox to a URL path
 *  dst needs to have roughly 4 times the storage space of mailbox
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 */
void imapurl_toURL(char *dst, const char *server, const char *mailbox);

#endif
