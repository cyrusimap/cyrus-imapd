#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "assert.h"
#include "xmalloc.h"
#include "charset.h"

#include "charset/us-ascii.h"
#include "charset/iso-8859-1.h"
#include "charset/iso-8859-2.h"
#include "charset/iso-8859-3.h"
#include "charset/iso-8859-4.h"
#include "charset/iso-8859-5.h"
#include "charset/iso-8859-6.h"
#include "charset/iso-8859-7.h"
#include "charset/iso-8859-8.h"
#include "charset/iso-8859-9.h"

struct charset {
    char *name;
    char **table;
};

static struct charset charset_table[] = {
    { "us-ascii", us_ascii },
    { "iso-8859-1", iso_8859_1 },
    { "iso-8859-2", iso_8859_2 },
    { "iso-8859-3", iso_8859_3 },
    { "iso-8859-4", iso_8859_4 },
    { "iso-8859-5", iso_8859_5 },
    { "iso-8859-6", iso_8859_6 },
    { "iso-8859-7", iso_8859_7 },
    { "iso-8859-8", iso_8859_8 },
    { "iso-8859-9", iso_8859_9 },
};

#define NUM_CHARSETS (sizeof(charset_table)/sizeof(*charset_table))

#define GROWSIZE 10 /* 100 */

static char index_hex[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};

#define HEXCHAR(c)  (((c) < 0 || (c) > 127) ? -1 : index_hex[(c)])

static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};

#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

int charset_lookupname(name)
char *name;
{
    int i;

    for (i=0; i<NUM_CHARSETS; i++) {
	if (!strcasecmp(name, charset_table[i].name)) return i;
    }
    return -1;
}

char *charset_convert(s, charset)
char *s;
int charset;
{
    static char *retval = 0;
    static int alloced = 0;
    int pos = 0;
    char **table;
    char *translation;
    int len;

    assert(charset >= 0);
    assert(charset < NUM_CHARSETS);

    table = charset_table[charset].table;
    
    if (!alloced) {
	alloced = GROWSIZE;
	retval = xmalloc(alloced);
    }
    *retval = '\0';

    while (*s) {
	translation = table[(unsigned char)*s];
	if (!translation) {
	    translation = EMPTY_CHARACTER_STRING;
	}
	len = strlen(translation);
	if (pos + len >= alloced) {
	    alloced += len + GROWSIZE;
	    retval = xrealloc(retval, alloced);
	}
	strcpy(retval+pos, translation);
	pos += len;
	s++;
    }

    return retval;
}

char *charset_decode1522(s)
char *s;
{
    int eatspace = 0;
    char *start, *encoding, *end;
    char *p;
    int i, c, c1, c2, c3, c4;
    char **table;
    static char *retval = 0;
    static int alloced = 0;
    char *translation;
    int pos = 0;
    int len;

    start = s;
    while (start = strchr(start, '=')) {
	start++;
	if (*start != '?') continue;
	encoding = strchr(start+1, '?');
	if (!encoding) continue;
	if (encoding[1] != 'b' && encoding[1] != 'B' &&
	    encoding[1] != 'q' && encoding[1] != 'Q') continue;
	if (encoding[2] != '?') continue;
	end = strchr(encoding+3, '?');
	if (!end || end[1] != '=') continue;

	/*
	 * Have recognized a valid 1522-word
	 * Copy over leading text, unless its whitespace between two 1522-words
	 */
	if (eatspace) {
	    for (p = s; p < (start-1) && isspace(*p); p++);
	    if (p < (start-1)) eatspace = 0;
	}
	if (!eatspace) {
	    len = start - s - 1;
	    if (pos + len >= alloced) {
		alloced += len + GROWSIZE;
		retval = xrealloc(retval, alloced);
	    }
	    strncpy(retval+pos, s, len);
	    pos += len;
	}

	/*
	 * Get character set
	 */
	start++;
	for (i=0; i<NUM_CHARSETS; i++) {
	    if (strlen(charset_table[i].name) == encoding-start &&
		!strncasecmp(start, charset_table[i].name, encoding-start)) {
		table = charset_table[i].table;
		break;
	    }
	}

	if (i == NUM_CHARSETS) {
	    /* Unrecognized charset, nothing will match here */
	    if (pos + 2 >= alloced) {
		alloced += 2 + GROWSIZE;
		retval = xrealloc(retval, alloced);
	    }
	    strcpy(retval+pos, EMPTY_CHARACTER_STRING);
	    pos += 1;
	}
	else if (encoding[1] == 'q' || encoding[1] == 'Q') {
	    p = encoding+3;
	    while (p < end) {
		c = *p++;
		if (c == '=') {
		    c = HEXCHAR(*p);
		    p++;
		    i = HEXCHAR(*p);
		    p++;
		    if (c == -1 || i == -1) {
			c = '\0';
		    }
		    else {
			c = (c << 4) + i;
		    }
		}
		else if (c == '_') c = ' ';

		translation = table[(unsigned char)c];
		if (!c || !translation) {
		    translation = EMPTY_CHARACTER_STRING;
		}
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;
	    }
	}
	else {
	    /* BASE64 encoding */
	    p = encoding+3;
	    while (p < end) {
		c1 = CHAR64(p[0]);
		if (c1 == -1) break;
		c2 = CHAR64(p[1]);
		if (c2 == -1) break;
		translation = table[(unsigned char)((c1<<2) | ((c2&0x30)>>4))];
		if (!translation) {
		    translation = EMPTY_CHARACTER_STRING;
		}
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;

		c3 = CHAR64(p[2]);
		if (c3 == -1) break;
		translation = table[(unsigned char)(((c2&0XF) << 4) | ((c3&0x3C) >> 2))];
		if (!translation) {
		    translation = EMPTY_CHARACTER_STRING;
		}
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;

		c4 = CHAR64(p[3]);
		if (c4 == -1) break;
		translation = table[(unsigned char)(((c3&0x03) <<6) | c4)];
		if (!translation) {
		    translation = EMPTY_CHARACTER_STRING;
		}
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;

		p += 4;
	    }
	}

	/* Prepare for next iteration */
	s = start = end+2;
	eatspace = 1;
    }

    /* If no 1522-words, just return our input */
    if (!pos) return s;

    /* Copy over the tail part of the input string */
    len = strlen(s);
    if (pos + len >= alloced) {
	alloced += len + 1;
	retval = xrealloc(retval, alloced);
    }
    strcpy(retval+pos, s);
    return retval;
}
