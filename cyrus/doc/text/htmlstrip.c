/* htmlstrip.c -- HTML to text converter
 *
 * Copyright 1998, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */
  
/* $Id: htmlstrip.c,v 1.5.4.2 2002/11/14 15:56:33 ken3 Exp $ */
  
#include <stdio.h>
#include <string.h>

#define MODE_PRE 1		/* Preformatted */
#define MODE_IGNORETXT 2	/* Discard text */

#define FLAG_NOPUSH 1		/* Has no end marker, don't push on stack */
#define FLAG_BREAK 2		/* Breaks a line */
#define FLAG_PARAGRAPH 4	/* Breaks a paragraph */

struct mode {
    char *name;
    int indent;
    int listnum;
    int flags;
    int mode;
    int startline;
};

struct mode modestack[100] = {"TOPLEVEL", 4};
int curmode = 0;
int didparagraph = 1;

struct tag {
    char *name;
    int flags;
    int mode;
    int indent;
};

struct tag cmds[] = {
    { "!--",	FLAG_NOPUSH,	0,		0, },
    { "!DOCTYPE", FLAG_NOPUSH,	0,		0, },
    { "link",   FLAG_NOPUSH,	0,		0, },
    { "html",	0,		0,		0, },
    { "head",	0,		MODE_IGNORETXT,	0, },
    { "title",	0,		MODE_IGNORETXT,	0, },
    { "body",	0,		0,		0, },
    { "p",	FLAG_PARAGRAPH|FLAG_NOPUSH, 0,	0, },
    { "pre",	FLAG_PARAGRAPH,	MODE_PRE,	0, },
    { "a",	0,		0,		0, },
    /* KLUDGE: we set MODE_PRE on <h1> to fake centering it ourselves */
    { "h1",	FLAG_PARAGRAPH,	MODE_PRE,	-4, },
    { "h2",	FLAG_PARAGRAPH,	0,		-4, },
    { "h3",	FLAG_PARAGRAPH,	0,		-4, },
    { "h4",	FLAG_PARAGRAPH,	0,		-4, },
    { "h5",	FLAG_PARAGRAPH,	0,		-4, },
    { "h6",	FLAG_PARAGRAPH,	0,		-4, },
    { "em",	0,		0,		0, },
    { "strong",	0,		0,		0, },
    { "code",	0,		0,		0, },
    { "samp",	0,		0,		0, },
    { "kbd",	0,		0,		0, },
    { "var",	0,		0,		0, },
    { "dfn",	0,		0,		0, },
    { "cite",	0,		0,		0, },
    { "blockquote", FLAG_PARAGRAPH, 0,          4, },
    { "b",	0,		0,		0, },
    { "i",	0,		0,		0, },
    { "u",	0,		0,		0, },
    { "tt",	0,		0,		0, },
    { "dl",	FLAG_PARAGRAPH,	0,		8, },
    { "dt",	FLAG_BREAK|FLAG_NOPUSH,	0,	-8, },
    { "dd",	FLAG_NOPUSH,	0,		0, },
    { "ul",	FLAG_PARAGRAPH,	0,		4, },
    { "ol",	FLAG_PARAGRAPH,	0,		4, },
    { "li",	FLAG_BREAK|FLAG_NOPUSH, 0,	-4, },
    { "br",	FLAG_BREAK|FLAG_NOPUSH,	0,	0, },
    { "hr",	FLAG_BREAK|FLAG_NOPUSH,	0,	0, },
    { "meta",   FLAG_NOPUSH,    0,              0, },
    { "table",  0,		0,		0, },
    { "tr",	FLAG_PARAGRAPH,	0,		0, },
    { "td",	0,		0,		0, },
};


main(argc, argv)
int argc;
char **argv;
{
    FILE *infile;

    if (argc != 2) {
	fprintf(stderr, "usage: %s file\n", argv[0]);
	exit(1);
    }

    infile = fopen(argv[1], "r");
    if (!infile) {
	perror(argv[1]);
	exit(1);
    }

    parse(infile);
    exit(0);
}

parse(infile)
FILE *infile;
{
    char outputbuf[1024];
    int outpos = 0;
    int c;
    int cmd;
    int endtag;
    int lineno = 1;
    int i;
    char *p;

    while ((c = lex(infile, &cmd, &endtag, &lineno)) != EOF) {
	if (!c) {
	    if (endtag) {
		if (cmds[cmd].flags & FLAG_NOPUSH) {
		    /* ignore */
		}
		else if (strcmp(cmds[cmd].name, modestack[curmode].name)!=0) {
		    fprintf(stderr,
			    "<%s> line %d mismatched with </%s> on line %d\n",
			    modestack[curmode].name,
			    modestack[curmode].startline,
			    cmds[cmd].name, lineno);
		    exit(1);
		}
		else {
		    if ((modestack[curmode].flags & FLAG_PARAGRAPH) &&
			!(modestack[curmode].mode & MODE_IGNORETXT)) {
			if (outpos) {
			    outputbuf[outpos++] = '\n';
			    outputbuf[outpos++] = '\0';
			    fputs(outputbuf, stdout);
			    outpos = 0;
			}
			if (!didparagraph) {
			    putc('\n', stdout);
			    didparagraph = 1;
			}
		    }
		    curmode--;
		}
	    }
	    else {
		if (!(modestack[curmode].mode & MODE_IGNORETXT)) {
		    if (cmds[cmd].flags & (FLAG_PARAGRAPH|FLAG_BREAK)) {
			if (outpos) {
			    outputbuf[outpos++] = '\n';
			    outputbuf[outpos++] = '\0';
			    fputs(outputbuf, stdout);
			    outpos = 0;
			}
		    }
		    if ((cmds[cmd].flags & FLAG_PARAGRAPH)
			&& !didparagraph) {
			putc('\n', stdout);
			didparagraph = 1;
		    }
		}
		if (cmds[cmd].flags & FLAG_NOPUSH) {
		    
		    if (!strcmp(cmds[cmd].name, "dt")) {
			while (outpos < modestack[curmode].indent - 8) {
			    outputbuf[outpos++] = ' ';
			}
		    }

		    if (!strcmp(cmds[cmd].name, "dd")) {
			if (outpos-1 >= modestack[curmode].indent) {
			    /* Break line */
			    outputbuf[outpos++] = '\n';
			    outputbuf[outpos++] = '\0';
			    fputs(outputbuf, stdout);
			    outpos = 0;
			}
			/* Indent line */
			while (outpos < modestack[curmode].indent) {
			    outputbuf[outpos++] = ' ';
			}
		    }

		    if (!strcmp(cmds[cmd].name, "li")) {
			if (modestack[curmode].listnum == 0) {
			    fprintf(stderr, "<li> inside a <%s> on line %d\n",
				    modestack[curmode].name, lineno);
			    exit(1);
			}
			while (outpos < modestack[curmode].indent - 4) {
			    outputbuf[outpos++] = ' ';
			}
			
			if (modestack[curmode].listnum < 0) {
			    outputbuf[outpos++] = ' ';
			    outputbuf[outpos++] = ' ';
			    outputbuf[outpos++] = '*';
			    outputbuf[outpos++] = ' ';
			}
			else {
			    if (modestack[curmode].listnum >=100) {
				fprintf(stderr,
					"too many <li> items on line %d\n",
					lineno);
				exit(1);
			    }
			    outputbuf[outpos++] =
			      modestack[curmode].listnum > 9 ?
				modestack[curmode].listnum/10 + '0' : ' ';
			    outputbuf[outpos++] = 
			      modestack[curmode].listnum%10 + '0';
			    outputbuf[outpos++] = '.';
			    outputbuf[outpos++] = ' ';
			    modestack[curmode].listnum++;
			}
		    }
		    if (!strcmp(cmds[cmd].name, "hr")) {
			/* XXX hack */
			modestack[curmode].mode |= MODE_IGNORETXT;
		    }
		}
		else {
		    curmode++;
		    if (curmode >= 100) {
			fprintf(stderr, "too many nested tags on line %d\n",
				lineno);
			exit(1);
		    }
		    modestack[curmode].name = cmd[cmds].name;
		    modestack[curmode].indent =
			modestack[curmode-1].indent + cmd[cmds].indent;
		    modestack[curmode].listnum = 0;
		    modestack[curmode].flags = cmd[cmds].flags;
		    modestack[curmode].mode =
			modestack[curmode-1].mode | cmd[cmds].mode;
		    modestack[curmode].startline = lineno;

		    if (!strcmp(cmds[cmd].name, "ul")) {
			modestack[curmode].listnum = -1;
		    }
		    if (!strcmp(cmds[cmd].name, "ol")) {
			modestack[curmode].listnum = 1;
		    }
			
		}
	    }
	}
	else if (modestack[curmode].mode & MODE_IGNORETXT) {
	    /* do nothing */
	}
	else if (isspace(c) && !(modestack[curmode].mode & MODE_PRE)) {
	    /* Only emit space if previous char not a space */
	    if (outpos && !isspace(outputbuf[outpos-1])) {
		outputbuf[outpos++] = ' ';
	    }
	}
	else if (c == '\n') {
	    /* Newline inside MODE_PRE.  Emit current line */
	    if (outpos || !didparagraph) {
		outputbuf[outpos++] = '\n';
		outputbuf[outpos++] = '\0';
		fputs(outputbuf, stdout);
		outpos = 0;
		didparagraph = 0;
	    }
	}
	else {
	    didparagraph = 0;
	    if (!outpos) {
		/* Indent line */
		for (i = 0; i < modestack[curmode].indent; i++) {
		    outputbuf[outpos++] = ' ';
		}
	    }
	    outputbuf[outpos++] = c;

	    /* Check for line wrapping */
	    if (outpos > 75 && !(modestack[curmode].mode & MODE_PRE)) {
		outputbuf[outpos] = '\0';
		p = strrchr(outputbuf, ' ');
		if (p && p-outputbuf > modestack[curmode].indent) {
		    *p++ = '\0';
		    fputs(outputbuf, stdout);
		    putc('\n', stdout);
		    outpos = 0;
		    if (*p) {
			for (i = 0; i < modestack[curmode].indent; i++) {
			    outputbuf[outpos++] = ' ';
			}
			while (*p) {
			    outputbuf[outpos++] = *p++;
			}
		    }
		}
	    }
	}
    }

    /* Write out last line of output */;
    if (outpos) {
	outputbuf[outpos++] = '\n';
	outputbuf[outpos++] = '\0';
	fputs(outputbuf, stdout);
    }
}

int lex(infile, cmdptr, endtagptr, linenoptr)
FILE *infile;
int *cmdptr;
int *endtagptr;
int *linenoptr;
{
    int c;
    static char buf[1024];
    int i = 0;
    int lineno = *linenoptr;
    char *p;

    c = getc(infile);
    if (c == '&') {
	while ((c = getc(infile)) != EOF && c != ';') {
	    buf[i++] = c;
	    if (c == '\n' || i > 1000) {
		fprintf(stderr, "unterminated entity on line %d\n", lineno);
		exit(1);
	    }
	}
	if (c == EOF) {
	    fprintf(stderr, "unexpected EOF on line %d\n", lineno);
	    exit(1);
	}
	buf[i] = '\0';
	if (!strcasecmp(buf, "amp")) return '&';
	if (!strcasecmp(buf, "lt")) return '<';
	if (!strcasecmp(buf, "gt")) return '>';
	if (!strcasecmp(buf, "quot")) return '"';
	if (!strcasecmp(buf, "nbsp")) return ' ';
	fprintf(stderr, "unrecognized entity '%s' on line %d\n", buf, lineno);
	exit(1);
    }

    if (!c) {
	fprintf(stderr, "NUL character on line %d\n", lineno);
	exit(1);
    }

    if (c == '\n') (*linenoptr)++;
    if (c != '<') return c;
    
    while (i<=1000 && (c = getc(infile)) != EOF && c != '>') {
	if (c == '\n') (*linenoptr)++;
	if (isspace(c)) c = ' ';
	buf[i++] = c;

	if (c == '\"') {
	    while (i<=1000 && (c = getc(infile)) != EOF && c != '\"') {
		if (c == '\n') (*linenoptr)++;
		buf[i++] = c;
	    }
	    if (c == EOF || i > 1000) {
		fprintf(stderr,
			"unterminated string in tag starting on line %d\n",
			lineno);
		exit(1);
	    }
	    buf[i++] = c;
	}
    }

    buf[i] = '\0';
    
    if (c == EOF || i > 1000) {
	fprintf(stderr, "unterminated tag starting on line %d\n",
		lineno);
	exit(1);
    }

    if (p = strchr(buf, ' ')) *p = '\0';

    p = buf;
    if (*p == '/') {
	*endtagptr = 1;
	p++;
    }
    else {
	*endtagptr = 0;
    }

    for (i = 0; i<(sizeof(cmds)/sizeof(*cmds)); i++) {
	if (!strcasecmp(p, cmds[i].name)) {
	    *cmdptr = i;
	    return 0;
	}
    }
    
    fprintf(stderr, "unknown tag <%s> starting on line %d\n", buf,
	    lineno);
    exit(1);
}

