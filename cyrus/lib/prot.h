/* prot.h -- stdio-like module that handles IMAP protection mechanisms
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <time.h>

#define PROT_BUFSIZE 4096

struct protstream {
    unsigned char buf[PROT_BUFSIZE+4];
    unsigned char *ptr;
    int cnt;
    unsigned char *leftptr;
    unsigned char leftcnt;
    int fd;
    int write;
    int logfd;
    time_t *log_timeptr;
    char *(*func)();
    void *state;
    int maxplain;
    char *error;
    int eof;
    int read_timeout;
};

#define prot_getc(s) ((s)->cnt-- > 0 ? (int)*(s)->ptr++ : prot_fill(s))
#define prot_ungetc(c, s) ((s)->cnt++, (*--(s)->ptr = (c)))
#define prot_putc(c, s) ((*(s)->ptr++ = (c)), --(s)->cnt == 0 ? prot_flush(s) : 0)

struct protstream *prot_new();
char *prot_error();
char *prot_fgets();
#ifdef __STDC__
int prot_printf(struct protstream *, const char *, ...);
#endif
