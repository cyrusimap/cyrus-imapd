/* mkchartable.c -- Generate character set mapping table
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "xmalloc.h"

extern int optind;
extern char *optarg;

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

struct map {
    int code;
    int mapcode;
    char *translation;
};

struct map *map;
int map_num;
int map_alloc;
#define MAPGROW 10 /* XXX 200 */

struct tablechar {
    int code;
    char *translation;
    char *action;
    char *comment;
};
#define EMPTYTCHAR(tc) ((tc).code == -1 && !(tc).translation && !(tc).action)

struct table {
    char *name;
    char *endaction;
    struct tablechar ch[256];
};

struct table *table;
int table_num;
int table_alloc;
#define TABLEGROW 10 /* XXX 200 */


main(argc, argv)
int argc;
char **argv;
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

    if (map_num == 0) usage();

    while (argv[optind]) {
	readcharfile(argv[optind]);
	printtable(argv[optind]);
	optind++;
    }
    return 0;
}

usage()
{
    fprintf(stderr, "usage: mkchartable -m mapfile charsetfile...\r");
    exit(1);
}

readmapfile(name)
char *name;
{
    FILE *mapfile;
    char buf[1024];
    char *p;
    int line = 0;
    int code, i, c;
    static struct map zeromap;
    char *dest;

    mapfile = fopen(name, "r");
    if (!mapfile) {
	perror(name);
	exit(1);
    }

    while (fgets(buf, sizeof(buf), mapfile)) {
	line++;
	p = buf;
	while (*p && isspace(*p)) p++;
	if (!*p || *p == '#') continue;

	code = 0;
	for (i=0; i<4; i++) {
	    c = HEXCHAR(*p);
	    *p++;
	    if (c == XX) goto syntaxerr;
	    code = code*16 + c;
	}
	if (!*p || !isspace(*p)) goto syntaxerr;

	if (map_num == map_alloc) {
	    map_alloc += MAPGROW;
	    map = (struct map *) xrealloc((char *)map, map_alloc * sizeof(struct map));
	}
	map[map_num] = zeromap;
	map[map_num].code = code;
	
	while (*p && isspace(*p)) p++;
	
	if (*p == '\"') {
	    p++;
	    
	    map[map_num].translation = dest = xmalloc(strlen(p));
	    while (*p != '\"') {
		if (!*p) goto syntaxerr;
		if (*p == '\\') {
		    if (p[1] >= '0' && p[1] <= '3') {
			if (p[2] < '0' || p[2] > '7' || p[3] < '0' || p[3] > '7')
			  goto syntaxerr;
			*dest++ = (p[1] - '0') * 64 + (p[2] - '0') * 8 + p[3] - '0';
			p += 3;
		    }
		    else {
			*dest++ = *++p;
		    }
		}
		else {
		    *dest++ = *p;
		}
		p++;
	    }
	    *dest = '\0';
	    if (strlen(map[map_num].translation) > 3) {
		fprintf(stderr, "%s: line %d: translation too long\n", name, line);
		exit(1);
	    }
	}
	else {
	    code = 0;
	    for (i=0; i<4; i++) {
		c = HEXCHAR(*p);
		*p++;
		if (c == XX) goto syntaxerr;
		code = code*16 + c;
	    }
	    map[map_num].mapcode = code;
	}
	map_num++;
    }
    fclose(mapfile);
    return;
 syntaxerr:
    fprintf(stderr, "%s: line %d: syntax error\n", name, line);
    exit(1);
}
		     
readcharfile(name)
char *name;
{
    FILE *charfile;
    char buf[1024];
    char *p;
    int line = 0;
    int curstate = -1;
    int thischar, thisstate;
    int code, i, c;
    int hops;
    
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
	while (*p && isspace(*p)) p++;
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
	while (!isspace(*p)) {
	    c = HEXCHAR(*p);
	    i++;
	    *p++;
	    if (c == XX) goto syntaxerr;
	    thischar = thischar*16 + c;
	}
	while (*p && isspace(*p)) p++;

	if (i > 4) goto syntaxerr;	
	if (i > 2) {
	    if (EMPTYTCHAR(table[thisstate].ch[thischar>>8])) {
		char action[1024];
		sprintf(action, ">%s_%02x <", table[thisstate].name,
			thischar>>8);
		table[thisstate].ch[thischar>>8].action = strsave(action);
		*(strchr(table[thisstate].ch[thischar>>8].action, ' ')) = '\0';
		table[thisstate].ch[thischar>>8].comment = "multi-byte";
		thisstate = newstate(action+1);
	    }
	    else if (!table[thisstate].ch[thischar>>8].action ||
		     table[thisstate].ch[thischar>>8].action[0] != '>') {
		fprintf(stderr,
			"%s: line %d: multibyte/single-byte conflict\n",
			name, line);
		exit(1);
	    }
	    else {
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

	table[thisstate].ch[thischar].comment = strsave(buf);

	if (*p == '?') {
	    continue;
	}

	if (*p == ':' || *p == '>' || *p == '<') {
	    p = table[thisstate].ch[thischar].action = strsave(p);
	    while (*p && !isspace(*p)) p++;
	    *p = '\0';
	    continue;
	}

	code = 0;
	for (i=0; i<4; i++) {
	    c = HEXCHAR(*p);
	    *p++;
	    if (c == XX) goto syntaxerr;
	    code = code*16 + c;
	}
	
	for (hops = 0; hops < 10; hops++) {
	    for (i = 0; i < map_num; i++) {
		if (map[i].code == code) break;
	    }
	    if (i == map_num || map[i].translation) break;
	    code = map[i].mapcode;
	}

	if (hops == 10) {
	    fprintf(stderr, "too many translations for code %x\n", code);
	    exit(1);
	}
	if (i == map_num) {
	    table[thisstate].ch[thischar].code = code;
	}
	else {
	    table[thisstate].ch[thischar].translation = map[i].translation;
	}
    }
    fclose(charfile);
    return;
 syntaxerr:
    fprintf(stderr, "%s: line %d: syntax error\n", name, line);
    exit(1);
}

int
newstate(args)
char *args;
{
    char *p;
    int i;

    if (table_num == table_alloc) {
	table_alloc += TABLEGROW;
	table = (struct table *)xrealloc((char *)table,
					 table_alloc * sizeof(struct table));
    }

    table[table_num].name = strsave(args);
    table[table_num].endaction = "END";
    for (i = 0; i < 256; i++) {
	table[table_num].ch[i].code = -1;
	table[table_num].ch[i].translation = 0;
	table[table_num].ch[i].action = 0;
	table[table_num].ch[i].comment = 0;
    }

    p = table[table_num].name;
    while (*p && !isspace(*p)) p++;
    *p++ = '\0';
    while (*p) {
	if (*p == '<') table[table_num].endaction = "RET";
	p++;
    }

    return table_num++;
}

int
findstate(name)
char *name;
{
    int i;

    for (i = 0; i < table_num; i++) {
	if (!strcmp(name, table[i].name)) return i;
    }
    return -1;
}

printtable(name)
char *name;
{
    char buf[1024];
    char *p;
    int curstate, thischar;
    int code;
    char *end;
    int i;
    
    p = strrchr(name, '/');
    if (p) p++;
    else p = name;
    strcpy(buf, p);
    if (p = strchr(buf, '.')) *p = '\0';
    while (p = strchr(buf, '-')) *p = '_';

    printf("const unsigned char %s[%d][256][4] = {\n", buf, table_num);

    for (curstate = 0; curstate < table_num; curstate++) {
	printf(" {");
	if (table[curstate].name[0]) {
	    printf(" /* %s */", table[curstate].name);
	}
	printf("\n");
	
	for (thischar = 0; thischar < 256; thischar++) {
	    printf("   {");
	    if ((code = table[curstate].ch[thischar].code) != -1) {
		if (code <= 0x7FF) {
		    printf(" %3d, %3d, %s,   0,", 0xc0 + (code>>6),
			   0x80+(code&0x3f), table[curstate].endaction);
		}
		else {
		    printf(" %3d, %3d, %3d, %s,", 0xe0 + (code>>12),
			   0x80+((code>>6)&0x3f), 0x80+(code&0x3f),
			   table[curstate].endaction);
		}
	    }
	    else if ((p = table[curstate].ch[thischar].translation) != 0) {
		end = table[curstate].endaction;
		for (i = 0; i < 4; i++) {
		    if (isprint(*p) && *p != '\\' && *p != '\"' && *p != '\'') {
			printf(" '%c',", *p);
		    }
		    else if (!*p) {
			printf(" %s,", end);
			end = "  0";
		    }
		    else {
			printf(" %3d,", *p);
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



fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "mkchartable: %s\n", s);
    exit(code);
}
    
