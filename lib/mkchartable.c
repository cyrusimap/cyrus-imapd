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
static const signed char index_hex[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,XX,XX, XX,XX,XX,XX,
    XX,10,11,12, 13,14,15,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,10,11,12, 13,14,15,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
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
	readcharfile(argv[optind++]);
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
    int thischar, curchar = 0;
    int code, i, c;
    int hops;
    
    charfile = fopen(name, "r");
    if (!charfile) {
	perror(name);
	exit(1);
    }

    p = strrchr(name, '/');
    if (p) p++;
    else p = name;
    strcpy(buf, p);
    if (p = strchr(buf, '.')) *p = '\0';
    while (p = strchr(buf, '-')) *p = '_';

    printf("const unsigned char %s[1][256][4] = { {\n", buf);
    
    while (fgets(buf, sizeof(buf), charfile)) {
	line++;
	p = buf + strlen(buf);
	if (p > buf && p[-1] == '\n') p[-1] = '\0';
	p = buf;
	while (*p && isspace(*p)) p++;
	if (!*p || *p == '#') continue;

	thischar = 0;
	while (!isspace(*p)) {
	    c = HEXCHAR(*p);
	    *p++;
	    if (c == XX) goto syntaxerr;
	    thischar = thischar*16 + c;
	}
	if (thischar != curchar) {
	    fprintf(stderr, "%s: line %d: got %x, was expecting %x", name, line, thischar,
		    curchar);
	    exit(1);
	}
	curchar++;
	while (*p && isspace(*p)) p++;

	if (*p == '?') {
	    printf(" { EMPTY, 0,   0,   0, }, /* %s */\n", buf);
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
	    printf(" { '%c', %3d, %3d,   0, }, /* %s */\n",
		   'A' + (code>>14), 0x80+((code>>7)&0x7f), 0x80+(code&0x7f), buf);
	}
	else {
	    p = map[i].translation;
	    printf(" {");
	    for (i = 0; i < 4; i++) {
		if (isprint(*p) && *p != '\\' && *p != '\"' && *p != '\'') {
		    printf(" '%c',", *p);
		}
		else {
		    printf(" %3d,", *p);
		}
		if (*p) p++;
	    }
	    printf(" }, /* %s */\n", buf);
	}
    }
    if (curchar != 0x100) {
	fprintf(stderr, "%s: too short\n");
	exit(1);
    }
    printf("} };\n\n");
    return;
 syntaxerr:
    fprintf(stderr, "%s: line %d: syntax error\n", name, line);
    exit(1);
}

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "mkchartable: %s\n", s);
    exit(code);
}
    
