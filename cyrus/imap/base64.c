/* some random base64 code shared by imapd/proxyd, pop3d/pop3proxyd */

#include "xmalloc.h"
#include "prot.h"

#define BUFGROWSIZE 100

struct buf {
    char *s;
    int alloc;
};

/*
 * Print an authentication ready response
 */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void printauthready(struct protstream *out, int len, unsigned char *data)
{
    int c1, c2, c3;

    prot_putc('+', out);
    prot_putc(' ', out);
    while (len) {
	c1 = *data++;
	len--;
	prot_putc(basis_64[c1>>2], out);
	if (len == 0) c2 = 0;
	else c2 = *data++;
	prot_putc(basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)], out);
	if (len == 0) {
	    prot_putc('=', out);
	    prot_putc('=', out);
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = *data++;
        prot_putc(basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)], out);
	if (len == 0) {
	    prot_putc('=', out);
	    break;
	}
	
	--len;
        prot_putc(basis_64[c3 & 0x3F], out);
    }
    prot_putc('\r', out);
    prot_putc('\n', out);
    prot_flush(out);
}

#define XX 127
/*
 * Table for decoding base64
 */
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

extern void eatline(int c);
/*
 * Parse a base64_string
 */
int getbase64string(struct protstream *in, struct buf *buf)
{
    int c1, c2, c3, c4;
    int len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c1 = prot_getc(in);
	if (c1 == '\r') {
	    c1 = prot_getc(in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    return len;
	}
	else if (c1 == '\n') return len;

	if (CHAR64(c1) == XX) {
	    eatline(c1);
	    return -1;
	}
	
	c2 = prot_getc(in);
	if (CHAR64(c2) == XX) {
	    eatline(c2);
	    return -1;
	}

	c3 = prot_getc(in);
	if (c3 != '=' && CHAR64(c3) == XX) {
	    eatline(c3);
	    return -1;
	}

	c4 = prot_getc(in);
	if (c4 != '=' && CHAR64(c4) == XX) {
	    eatline(c4);
	    return -1;
	}

	if (len+3 >= buf->alloc) {
	    buf->alloc = len+BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}

	buf->s[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    c1 = prot_getc(in);
	    if (c1 == '\r') c1 = prot_getc(in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    if (c4 != '=') return -1;
	    return len;
	}
	buf->s[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = prot_getc(in);
	    if (c1 == '\r') c1 = prot_getc(in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    return len;
	}
	buf->s[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
    }
}

/*
 * Parse a base64_string
 */
int parsebase64string(char **ptr, const char *s)
{
    int c1, c2, c3, c4;
    int len = 0;
    static char *buf;
    static int alloc = 0;

    if (alloc == 0) {
	alloc = BUFGROWSIZE;
	buf = xmalloc(alloc+1);
    }
	
    for (;;) {
	c1 = *s++;
	if (c1 == '\0') {
	    *ptr = buf;
	    return len;
	}

	if (CHAR64(c1) == XX) {
	    return -1;
	}
	
	c2 = *s++;
	if (CHAR64(c2) == XX) {
	    return -1;
	}

	c3 = *s++;
	if (c3 != '=' && CHAR64(c3) == XX) {
	    return -1;
	}

	c4 = *s++;
	if (c4 != '=' && CHAR64(c4) == XX) {
	    return -1;
	}

	if (len+3 >= alloc) {
	    alloc = len+BUFGROWSIZE;
	    buf = xrealloc(buf, alloc+1);
	}

	buf[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    c1 = *s++;
	    if (c1 != '\0') {
		return -1;
	    }
	    if (c4 != '=') return -1;
	    *ptr = buf;
	    return len;
	}
	buf[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = *s++;
	    if (c1 != '\0') {
		return -1;
	    }
	    *ptr = buf;
	    return len;
	}
	buf[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
    }
}

