/* bsearch.c -- binary search newline-separated fields in memory
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <string.h>

/* Case-independent comparison converter.
 * Treats \r and \t as end-of-string and treats '.' lower than
 * everything else.
 */
#define TOLOWER(c) (convert_to_lowercase[(unsigned char)(c)])
static char convert_to_lowercase[256] = {
    0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x01, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x02, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/*
 * Search for a line starting with 'word'.  The search ignores case if
 * 'caseSensitive' is nonzero.  The search is performed in 'buffer',
 * which is of length 'size'.  'hint' gives a idea of where to start
 * looking.
 *
 * On success, the offset in 'buffer' of the found line is returned and
 * the length of the found line is put in the unsigned long pointed to
 * by 'lenp'.  On failure, the offset in 'buffer' of where a new line should
 * be inserted is returned and zero is put in the unsigned long pointed to
 * by 'lenp'.
 */
bsearch_mem(word, caseSensitive, buffer, size, hint, lenp)
char *word;
int caseSensitive;
unsigned char *buffer;
unsigned long hint;
unsigned long size;
unsigned long *lenp;
{
    int firstsearch = 1;
    unsigned long start = 0, end = size - 1, mid, offset;
    unsigned long len, n;
    int cmp;
    unsigned char *wordp, *p;

    while (start < end + 1) {
	if (firstsearch) {
	    /* Use hint supplied by caller */
	    firstsearch = 0;
	    mid = offset = hint;
	    if (mid <= start || mid > end) mid = offset = start;
	}
	else {
	    /* Calculate position of middle of this range */
	    offset = mid = (start + end)/2;
	}

	if (mid) {
	    p = memchr(buffer+mid, '\n', (end + 1) - mid);
	    if (!p) {
		end = mid - 1;
		continue;
	    }
	    offset = p - buffer + 1;
	}

	p = memchr(buffer+offset, '\n', size-offset);
	if (p) {
	    len = p - (buffer+offset) + 1;
	}
	else {
		end = mid - 1;
		continue;
	}

	n = len;
	wordp = word;
	p = buffer+offset;

	if (caseSensitive) {
	    while (n-- > 0 && (cmp = *wordp - *p) == 0) {
		wordp++;
		p++;
	    }
	    if (n >= 0 && !*wordp) {
		cmp = '\t' - *p;
	    }
	    else if (!cmp) {
		cmp = 1;
	    }
	}
	else {
	    while (n-- > 0 && (cmp = TOLOWER(*wordp) - TOLOWER(*p)) == 0) {
		wordp++;
		p++;
	    }
	    if (n >= 0 && !*wordp) {
		cmp = TOLOWER('\t') - TOLOWER(*p);
	    }
	    else if (!cmp) {
		cmp = 1;
	    }
	}

	if (!cmp) {
	    if (lenp) *lenp = len;
	    return offset;
	}

	if (cmp < 0) {
	    if (mid == 0) break;
	    end = mid - 1;
	}
	else {
	    start = offset + 1;
	}
    }

    /* Word was not found.  Return offset where word should be inserted */
    if (lenp) *lenp = 0;
    if (start > size) return size;
    if (!start) return 0;
    p = memchr(buffer+start, '\n', size-start);
    return p - buffer + 1;
}
