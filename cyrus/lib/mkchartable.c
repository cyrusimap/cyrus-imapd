/* mkchartable.c -- Generate character set mapping table
 *
 * $Id: mkchartable.c,v 1.19.16.5 2003/05/14 19:43:06 ken3 Exp $
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "xmalloc.h"

#define XX 127
/*
 * Table for decoding hexadecimal
 */
static const char index_hex[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,XX,XX, XX,XX,XX,XX,
    XX,10,11,12, 13,14,15,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,10,11,12, 13,14,15,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define HEXCHAR(c)  (index_hex[(unsigned char)(c)])

#define MAX_MAPCODE 20

struct cmap {
    int code;
    int num_mapcode;
    int mapcode[MAX_MAPCODE];
    char *translation;
    int trans_offset;
};

struct cmap *map=NULL;
int map_num=0;
int map_alloc=0;
#define MAPGROW 200

struct tablechar {
    int code;
    char *translation;
    int trans_offset;
    char *action;
    char *comment;
};
#define EMPTYTCHAR(tc) ((tc).code == -1 && !(tc).translation && !(tc).action)

struct table {
    char *name;
    char *endaction;
    struct tablechar ch[256];
};

struct table *table=NULL;
int table_num=0;
int table_alloc=0;
#define TABLEGROW 200

static void readmapfile(char *name);
static void mungemappings(void);
static void readcharfile(char *name);
static void printtable(char *name);
static void freetabledata(void);
static void freetable(void);
static void freemap(void);
static void usage(void);
static int newstate(char *args);
static int findstate(char *name);
static void mkunicodetable(void);
static void mkutf8table(void);
static void mkutf7table(void);

int
main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "m:")) != EOF) {
	switch (opt) {
	case 'm':
	    readmapfile(optarg);
	    break;

	default:
	    usage();
	}
    }

    if (map_num == 0 || argc == optind) usage();

    printf("#include \"charset.h\"\n");
    printf("#include \"chartable.h\"\n");

    mungemappings();

    fprintf(stderr, "mkchartable: mapping unicode...\n");
    mkunicodetable();
    printtable("unicode");

    fprintf(stderr, "mkchartable: mapping UTF-8...\n");
    mkutf8table();
    printtable("utf-8");

    fprintf(stderr, "mkchartable: mapping UTF-7...\n");
    mkutf7table();
    printtable("utf-7");

    while (argv[optind]) {
	fprintf(stderr, "mkchartable: mapping %s...\n", argv[optind]);
	readcharfile(argv[optind]);
	printtable(argv[optind]);
	freetabledata();
	optind++;
    }

    printf("/*\n");
    printf(" * Mapping of character sets to tables\n");
    printf(" */\n");
    printf("const struct charset chartables_charset_table[] = {\n");
    printf("    { \"us-ascii\", chartables_us_ascii },	/* US-ASCII must be charset number 0 */\n");
    printf("    { \"utf-8\", chartables_utf_8 },\n");
    printf("    { \"utf-7\", chartables_utf_7 },\n");
    printf("    { \"iso-8859-1\", chartables_iso_8859_1 },\n");
    printf("    { \"iso-8859-2\", chartables_iso_8859_2 },\n");
    printf("    { \"iso-8859-3\", chartables_iso_8859_3 },\n");
    printf("    { \"iso-8859-4\", chartables_iso_8859_4 },\n");
    printf("    { \"iso-8859-5\", chartables_iso_8859_5 },\n");
    printf("    { \"iso-8859-6\", chartables_iso_8859_6 },\n");
    printf("    { \"iso-8859-7\", chartables_iso_8859_7 },\n");
    printf("    { \"iso-8859-8\", chartables_iso_8859_8 },\n");
    printf("    { \"iso-8859-9\", chartables_iso_8859_9 },\n");
    printf("    { \"koi8-r\", chartables_koi8_r },\n");
    printf("    { \"iso-2022-jp\", chartables_iso_2022_jp },\n");
    printf("    { \"iso-2022-kr\", chartables_iso_2022_kr },\n");
    printf("    { \"gb2312\", chartables_gb2312 },\n");
    printf("    { \"big5\", chartables_big5 },\n");
    printf("    /* Compatibility names */\n");
    printf("    { \"unicode-1-1-utf-7\", chartables_utf_7 },\n");
    printf("    { \"unicode-2-0-utf-7\", chartables_utf_7 },\n");
    printf("    { \"x-unicode-2-0-utf-7\", chartables_utf_7 },\n");
    printf("    /* End Compatibility Names */\n");
    printf("    { \"iso-8859-15\", chartables_iso_8859_15 },\n");
    printf("    { \"windows-1252\", chartables_windows_1252 },\n");
    printf("    { \"windows-1256\", chartables_windows_1256 },\n");
    printf("    /* New character sets should only be added to end so that\n");
    printf("     * cache files stay with valid information */\n");
    printf("};\n");
    printf("const int chartables_num_charsets = (sizeof(chartables_charset_table)/sizeof(*chartables_charset_table));\n");

    freetable();
    freemap();

    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: mkchartable -m mapfile charsetfile...\r\n");
    exit(1);
}

/* Read a Unicode table, deriving useful mappings from it */
static void
readmapfile(char *name)
{
    FILE *mapfile;
    char buf[1024];
    char *p;
    int line = 0;
    int n, code, i, c;
    static struct cmap zeromap;

    mapfile = fopen(name, "r");
    if (!mapfile) {
	perror(name);
	exit(1);
    }

    while (fgets(buf, sizeof(buf), mapfile)) {
	line++;
	p = buf;
	while (*p && isspace(*(unsigned char*)p)) p++;
	if (!*p || *p == '#') continue;

	/* Unicode character */
	code = 0;
	for (i=0; i<4; i++) {
	    c = HEXCHAR(*p);
	    p++;
	    if (c == XX) goto syntaxerr;
	    code = code*16 + c;
	}
	if (*p++ != ';') goto syntaxerr;

	/* Character name */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;
	   
	if (map_num == map_alloc) {
	    map_alloc += MAPGROW;
	    map = (struct cmap *)
		xrealloc((char *)map, map_alloc * sizeof(struct cmap));
	}
	map[map_num] = zeromap;
	map[map_num].code = code;
	
	/* General Category */
	if (*p == 'Z') {
	    /* Is whitespace, map to empty string */
	    map[map_num].num_mapcode = 0;
	    map_num++;
	    continue;
	}
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Canonical Combining Class */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Bidirectional category */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Character decomposition */
	n = 0;
	while (*p && *p != ';') {
	    if (n + 1 == MAX_MAPCODE) goto syntaxerr;
	    if (*p == '<') {
		/* Compatability mapping, skip over the <type> */
		p = strchr(p, '>');
		if (!p || p[1] != ' ') goto syntaxerr;
		p += 2;

		/* Ignore compat mappings to SP followed by combining char */
		if (!strncmp(p, "0020 ", 5)) {
		    p = strchr(p, ';');
		    break;
		}
	    }

	    code = 0;
	    for (i=0; i<4; i++) {
		c = HEXCHAR(*p);
		p++;
		if (c == XX) goto syntaxerr;
		code = code*16 + c;
	    }
	    if (*p == ' ') p++;
	    map[map_num].mapcode[n++] = code;
	}
	if (*p++ != ';') goto syntaxerr;

	/* Decimal digit value */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;
			   
	/* Digit value */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Numeric value */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Mirrored character */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Unicode 1.0 name */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Comment */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Upper case equivalent mapping */
	while (*p && *p != ';') p++;
	if (*p++ != ';') goto syntaxerr;

	/* Lower case equivalent mapping */
	if (*p == ';') {
	    /* No case mapping, use any decomposition we found above */
	    if (n) {
		map[map_num].num_mapcode = n;
		map_num++;
	    }
	    continue;
	}
	code = 0;
	for (i=0; i<4; i++) {
	    c = HEXCHAR(*p);
	    p++;
	    if (c == XX) goto syntaxerr;
	    code = code*16 + c;
	}
	if (*p != ';') goto syntaxerr;
	map[map_num].mapcode[0] = code;
	map[map_num].num_mapcode = 1;
	map_num++;
    }
    fclose(mapfile);
    return;
 syntaxerr:
    fprintf(stderr, "%s: line %d: syntax error\n", name, line);
    exit(1);
}

/* Perform the transitive closure on the unicode mapping table
 * Calculate translations for mappings
 */
static void
mungemappings(void)
{
    int didchange;
    int n, newn, n_mapcode, i;
    int new_mapcode[MAX_MAPCODE];
    int num_new_mapcode;
    int last_translation = 1;
    int max_len = 3;
    
    /* Keep scanning the table until no changes are made */
    do {
	didchange = 0;

	fprintf(stderr, "mkchartable: expanding unicode mappings...\n");

	for (n = 0; n < map_num; n++) {
	    /* Build new map code sequence by iterating over existing
	     * mapcode sequence
	     */
	    num_new_mapcode = 0;
	    for (n_mapcode = 0; n_mapcode < map[n].num_mapcode; n_mapcode++) {

		/* Search for a translation of this particular code */
		for (newn = 0; newn < map_num; newn++) {
		    if (map[newn].code == map[n].mapcode[n_mapcode]) break;
		}
		if (newn != map_num) {
		    /* We have a translation */
		    didchange++;
		    for (i = 0; i < map[newn].num_mapcode; i++) {
			new_mapcode[num_new_mapcode++] = map[newn].mapcode[i];
		    }
		}
		else {
		    /* Keep the old mapping for this code */
		    new_mapcode[num_new_mapcode++] = map[n].mapcode[n_mapcode];
		}
	    }

	    /* Copy in the new translation */
	    map[n].num_mapcode = num_new_mapcode;
	    memcpy(map[n].mapcode, new_mapcode, sizeof(new_mapcode));
	}
    } while (didchange);

    printf("/* The following unicode mapping table is in effect\n");
    printf("From To\n");
    for (n = 0; n < map_num; n++) {
	printf("\n%04x", map[n].code);
	for (i = 0; i < map[n].num_mapcode; i++) {
	    printf(" %04x", map[n].mapcode[i]);
	}
    }
    printf("\n*/\n");

    fprintf(stderr, "mkchartable: building expansion table...\n");    

    printf("/* Table of traslations longer than three octets.\n");
    printf(" * The XLT code in other tables is followed by an 2-octet\n");
    printf(" * index into this table.\n");
    printf(" * The index of 0 is reserved to mean 'no translation'\n");
    printf(" */\n");
    printf("const unsigned char chartables_long_translations[] = { 0, \n");

    for (n = 0; n < map_num; n++) {
	int n_mapcode, code;
	unsigned char translation[256];
	int n_t;
	
	/* Build translation strings for mappings to 0 or multiple codes */
	if (map[n].num_mapcode == 0) {
	    map[n].translation = xstrdup("");
	}
	else if (map[n].num_mapcode > 1) {
	    n_t = 0;
	    for (n_mapcode = 0; n_mapcode < map[n].num_mapcode; n_mapcode++) {
		code = map[n].mapcode[n_mapcode];
		/* Convert code to UTF-8 */
		if (code && code <= 0x7f) {
		    translation[n_t++] = (unsigned char)code;
		}
		else if (code <= 0x7FF) {
		    translation[n_t++] = (unsigned char) (0xc0 + (code>>6));
		    translation[n_t++] = (unsigned char) (0x80+(code&0x3f));
		}
		else {
		    translation[n_t++] = (unsigned char) (0xe0 + (code>>12));
		    translation[n_t++] = (unsigned char) (0x80+((code>>6)&0x3f));
		    translation[n_t++] = (unsigned char) (0x80+(code&0x3f));
		}
	    }
	    if (n_t <= 3) {
		map[n].translation = xmalloc(4);
		memcpy(map[n].translation, translation, n_t);
		map[n].translation[n_t] = '\0';
	    }
	    else {
		if (n_t > max_len) max_len = n_t;
		for (i = 0; i < n_t; i++) {
		    code = translation[i];
		    if (isprint(code) && code != '\\' && code != '\"' && code != '\'') {
			printf(" '%c',", code);
		    } else {
			printf(" %3d,", code);
		    }
		}
		printf(" END, /* Translation for %04x (offset %04x) */\n",
		       map[n].code, last_translation);
		map[n].trans_offset = last_translation;

                /* last_translation points to the offset the next translation will start from */
		last_translation += n_t + 1;
	    }
	}
    }
    printf("};\n\n const int charset_max_translation = %d;\n\n", max_len);
}

static void
setcode(int state, int character, int code)
{
    int i = 0;

    for (i = 0; i < map_num; i++) {
	if (map[i].code == code) break;
    }

    if (i == map_num) {
	table[state].ch[character].code = code;
    } else if (map[i].translation) {
	table[state].ch[character].translation = map[i].translation;
    } else if (map[i].trans_offset) {
	table[state].ch[character].trans_offset = map[i].trans_offset;
    } else {
	table[state].ch[character].code = map[i].mapcode[0];
    }
	
}

static void
readcharfile(char *name)
{
    FILE *charfile;
    char buf[1024];
    char *p;
    int line = 0;
    int curstate = -1;
    int thischar, thisstate;
    int code, i, c;
    
    charfile = fopen(name, "r");
    if (!charfile) {
	perror(name);
	exit(1);
    }

    table_num = 0;

    while (fgets(buf, sizeof(buf), charfile)) {
	line++;
	p = buf + strlen(buf);
	if (p > buf && p[-1] == '\n') p[-1] = '\0';
	p = buf;
	while (*p && isspace(*(unsigned char*)p)) p++;
	if (!*p || *p == '#') continue;

	if (*p == ':') {
	    /* New state */
	    curstate = newstate(p+1);
	    continue;
	}
	
	if (curstate == -1) {
	    curstate = newstate("");
	}

	thisstate = curstate;
	thischar = i = 0;
	while (!isspace(*(unsigned char*)p)) {
	    c = HEXCHAR(*p);
	    i++;
	    p++;
	    if (c == XX) goto syntaxerr;
	    thischar = thischar*16 + c;
	}
	while (*p && isspace(*(unsigned char*)p)) p++;

	if (i > 4) goto syntaxerr;	
	if (i > 2) {
	    if (EMPTYTCHAR(table[thisstate].ch[thischar>>8])) {
                /* we create a new state (not in the input file) to
                   deal with multibyte characters that start with the
                   byte 'thischar >> 8'. */

		char action[1024];

		sprintf(action, ">%s_%02x <", table[thisstate].name,
			thischar>>8);
		table[thisstate].ch[thischar>>8].action = xstrdup(action);
		*(strchr(table[thisstate].ch[thischar>>8].action, ' ')) = '\0';
		table[thisstate].ch[thischar>>8].comment = xstrdup("multi-byte");
		thisstate = newstate(action+1);
	    }
	    else if (!table[thisstate].ch[thischar>>8].action ||
		     table[thisstate].ch[thischar>>8].action[0] != '>') {
                /* either we think this byte isn't the start of a
                   multibyte character, or the action associated with this
                   byte isn't a state change. */

		fprintf(stderr,
			"%s: line %d: multibyte/single-byte conflict\n",
			name, line);
		exit(1);
	    }
	    else {
                /* we find the already created state to deal with multibytes
                   starting with 'thischar >> 8' and move to it so we
                   insert the 2nd byte of this multibyte char in the right
                   state. */

		thisstate =
		  findstate(table[thisstate].ch[thischar>>8].action+1);
		if (thisstate == -1) {
		    fprintf(stderr,
			    "%s: line %d: can't find multibyte state\n",
			    name, line);
		    exit(1);
		}
	    }
	    thischar &= 0xff;
	}

	if (!EMPTYTCHAR(table[thisstate].ch[thischar])) {
	    fprintf(stderr, "%s: line %d: duplicate defs for %x\n",
		    name, line, thischar);
	    exit(1);
	}

	table[thisstate].ch[thischar].comment = xstrdup(buf);

	if (*p == '?') {
	    continue;
	}

	if (*p == ':' || *p == '>' || *p == '<') {
	    p = table[thisstate].ch[thischar].action = xstrdup(p);
	    while (*p && !isspace(*(unsigned char*)p)) p++;
	    *p = '\0';
	    continue;
	}

	code = 0;
	for (i=0; i<4; i++) {
	    c = HEXCHAR(*p);
	    p++;
	    if (c == XX) goto syntaxerr;
	    code = code*16 + c;
	}
	setcode(thisstate, thischar, code);
    }
    fclose(charfile);
    return;
 syntaxerr:
    fprintf(stderr, "%s: line %d: syntax error\n", name, line);
    exit(1);
}

/* Generate the table used for mapping raw unicode values */
static void mkunicodetable(void)
{
    int i;
    int thisstate;
    unsigned char need_block[256];
    int block;
    char buf[80];

    /* Record which blocks we need mappings for */
    for (i = 0; i < 256; i++) {
	need_block[i] = 0;
    }
    for (i = 0; i < map_num; i++) {
	need_block[map[i].code>>8] = 1;
    }

    table_num = 0;

    printf("/* The next two tables are used for doing translations on\n");
    printf(" * 16-bit unicode values.  First look up the Unicode block\n");
    printf(" * (high-order byte) in the chartables_unicode_block table\n");
    printf(" * to find the index into chartables_unicode for that block.\n");
    printf(" * If the index is 255, there are no translations for that\n");
    printf(" * block, so characters can be encoded in UTF-8 algorithmically\n");
    printf(" * Otherwise, look up the low-order byte in the chartables_unicode\n");
    printf(" * using the index to select the state.\n");
    printf(" */\n");
    printf("const unsigned char chartables_unicode_block[256] = {");

    for (block = 0; block < 256; block++) {
	if (!(block & 0x7)) printf("\n");
	if (!need_block[block]) {
	    printf(" 255,");
	    continue;
	}

 	sprintf(buf, "BLOCK-%02x-INDEX-%d", block, table_num);
	thisstate = newstate(buf);
	printf(" %3d,", thisstate);

	for (i = 0; i < 256; i++) {
	    setcode(thisstate, i, (block << 8) + i);
	}
    }

    printf("\n};\n\n");

    printf("/* NOTE: Unlike other charset translation tables, the \n");
    printf(" * chartables_unicode table is NOT used to directly parse\n");
    printf(" * a charset.  See the comment on chartables_unicode_block\n");
    printf(" * for a descripton of how this table is used.\n");
    printf(" */\n");
}

static void mkutf8table(void)
{
    int start_state, thisstate;
    int thischar, prefix;
    char buf[80];

    table_num = 0;

    start_state = newstate("START");

    /* Populate the ascii section */
    for (thischar = 0; thischar <= 0x7f; thischar++) {
	setcode(start_state, thischar, thischar);
    }

    /* 3-char sequence tables must be numbered 1 and 2 */
    thisstate = newstate("STATE-3-2 <");
    for (thischar = 0x80; thischar <= 0xbf; thischar++) {
	table[thisstate].ch[thischar].action = "U83_2";
    }
    thisstate = newstate("STATE-3-3 <");
    for (thischar = 0x80; thischar <= 0xbf; thischar++) {
	table[thisstate].ch[thischar].action = "U83_3";
    }

    /* Populate 2-char sequences---the first byte shifts to another
     * state; the 2nd byte chooses the character, just like any other
     * 2-byte encoding */
    for (prefix = 2; prefix <= 0x1f; prefix++) {
	sprintf(buf, ">STATE-2-%02x", prefix);
	table[start_state].ch[prefix+0xc0].action = xstrdup(buf);
	strcat(buf, " <");
	thisstate = newstate(xstrdup(buf+1));
	for (thischar = 0; thischar <= 0x3f; thischar++) {
	    setcode(thisstate, thischar+0x80, thischar+(prefix<<6));
	}
    }

    /* Populate 3-char sequences, which the decoder handles
     * magically, outside of the state system. */
    for (thischar = 0xe0; thischar <= 0xef; thischar++) {
	table[start_state].ch[thischar].action = "U83";
    }
    
}

static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void mkutf7table(void)
{
    int start_state, thisstate;
    int thischar;
    char *p;

    table_num = 0;

    start_state = newstate("START");

    /* Populate the ascii section */
    table[start_state].ch['+'].action = ">GOTSHIFT";
    for (thischar = 0; thischar <= 0x7f; thischar++) {
	if (!table[start_state].ch[thischar].action) {
	    setcode(start_state, thischar, thischar);
	}
    }

    /* Normal base64 decoding table must be numbered 1 */
    thisstate = newstate("B64NORMAL <");
    table[thisstate].ch['-'].action = "<";
    for (p = basis_64; *p; p++) {
	table[thisstate].ch[*(unsigned char*)p].action = "U7N";
    }
    for (thischar = 0; thischar <= 0x7f; thischar++) {
	if (!table[thisstate].ch[thischar].action) {
	    setcode(thisstate, thischar, thischar);
	}
    }
    
    /* Populate initial base64 decoding table */
    thisstate = newstate("GOTSHIFT <");
    setcode(thisstate, '-', '+');
    for (p = basis_64; *p; p++) {
	table[thisstate].ch[*(unsigned char*)p].action = "U7F";
    }
}

static int
newstate(char *args)
{
    char *p;
    int i;

    if (table_num == table_alloc) {
	table_alloc += TABLEGROW;
	table = (struct table *)xrealloc((char *)table,
					 table_alloc * sizeof(struct table));
    }

    table[table_num].name = xstrdup(args);
    table[table_num].endaction = "END";
    for (i = 0; i < 256; i++) {
	table[table_num].ch[i].code = -1;
	table[table_num].ch[i].translation = 0;
	table[table_num].ch[i].trans_offset = 0;
	table[table_num].ch[i].action = 0;
	table[table_num].ch[i].comment = 0;
    }

    p = table[table_num].name;
    while (*p && !isspace(*(unsigned char*)p)) p++;
    if (*p) *p++ = '\0';
    while (*p) {
	if (*p == '<') table[table_num].endaction = "RET";
	p++;
    }

    return table_num++;
}

static int
findstate(char *name)
{
    int i;

    for (i = 0; i < table_num; i++) {
	if (!strcmp(name, table[i].name)) return i;
    }
    return -1;
}

static void
printtable(char *name)
{
    char buf[1024];
    char *p;
    int curstate, thischar;
    int code;
    char *end;
    int i;
    
    p = strrchr(name, '/');
    if (!p) p = strrchr(name, '\\');
    if (p) p++;
    else p = name;
    strcpy(buf, p);
    if ((p = strchr(buf, '.')) != NULL) *p = '\0';
    while ((p = strchr(buf, '-')) != NULL) *p = '_';

    printf("const unsigned char chartables_%s[%d][256][4] = {\n", buf, table_num);

    for (curstate = 0; curstate < table_num; curstate++) {
	printf(" {");
	if (table[curstate].name[0]) {
	    printf(" /* %s */", table[curstate].name);
	}
	printf("\n");
	
	for (thischar = 0; thischar < 256; thischar++) {
	    printf("   {");
	    if ((code = table[curstate].ch[thischar].code) != -1) {
		if (code && code <= 0x7f) {
		    if (isprint(code) && code != '\\' && code != '\"' &&
			code != '\'') {
			printf(" '%c', %s,   0,   0,", code,
			       table[curstate].endaction);
		    }
		    else {
			printf(" %3d, %s,   0,   0,", code,
			       table[curstate].endaction);
		    }
		}
		else if (code <= 0x7FF) {
		    printf(" %3d, %3d, %s,   0,", 0xc0 + (code>>6),
			   0x80+(code&0x3f), table[curstate].endaction);
		}
		else {
		    printf(" %3d, %3d, %3d, %s,", 0xe0 + (code>>12),
			   0x80+((code>>6)&0x3f), 0x80+(code&0x3f),
			   table[curstate].endaction);
		}
	    } else if ((code = table[curstate].ch[thischar].trans_offset) != 0) {
		printf(" XLT, %3d, %3d, %s,", code >> 8, code & 0xff,
		       table[curstate].endaction); 
	    } else if ((p = table[curstate].ch[thischar].translation) != 0) {
		end = table[curstate].endaction;
		for (i = 0; i < 4; i++) {
		    if (isprint((unsigned char)*p) && *p != '\\' && *p != '\"' && *p != '\'') {
			printf(" '%c',", *p);
		    }
		    else if (!*p) {
			printf(" %s,", end);
			end = "  0";
		    }
		    else {
			printf(" %3d,", (unsigned char)*p);
		    }
		    if (*p) p++;
		}
	    }
	    else if ((p = table[curstate].ch[thischar].action) == 0) {
		printf(" EMPTY, %s, 0,   0,", table[curstate].endaction);
	    }
	    else if (*p == '<') {
		printf(" RET,   0,   0,   0,");
	    }
	    else if (*p == 'U') {
		printf(" %s,   0,   0,   0,", p);
	    }
	    else {
		code = findstate(p+1);
		if (code == -1) {
		    fprintf(stderr, "%s: unknown state %s\n", name, p+1);
		}
		printf(" %s, %3d, %3d,   0,",
		       *p == '>' ? "JSR" : "JMP",
		       (code>>8), (code&0xff));
	    }
	    printf(" },");
	    if (table[curstate].ch[thischar].comment) {
		printf(" /* %s */", table[curstate].ch[thischar].comment);
	    }
	    printf("\n");
	}
	printf(" },\n");
    }
    printf("};\n\n");
}

static void
freetabledata(void)
{
    int curstate, thischar;
/*    char *cp; */

    for (curstate = 0; curstate < table_num; curstate++) {
	for (thischar = 0; thischar < 256; thischar++) {
	    if (table[curstate].ch[thischar].comment != NULL) {
		free(table[curstate].ch[thischar].comment);
	    }

	    if (table[curstate].ch[thischar].action != NULL) {
		free(table[curstate].ch[thischar].action);
	    }
	}
	if (table[curstate].name != NULL) {
	    free(table[curstate].name);
	}
    }
}

static void
freetable(void)
{
    if (table_alloc) {
        free(table);
	table_alloc=0;
    }
}

static void
freemap(void)
{
    int n;
/*	int n_mapcode; */

    for (n = 0; n < map_num; n++) {
	if (map[n].translation != NULL) {
	    free(map[n].translation);
	}
    }

    if (map_alloc) {
        free(map);
	map_alloc=0;
    }
}

void fatal(const char* s, int c)
{
    fprintf(stderr, "Error while building charset table: %s\n", s);
    exit(c);
}
