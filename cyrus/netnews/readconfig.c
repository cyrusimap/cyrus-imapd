/*
 *
 *  The code for reading expire.ctl files (most of this file) was borrowed from innd
 *   Minor modifications to that code were made
 */

/*
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: readconfig.c,v 1.5 2002/08/26 19:20:05 leg Exp $ */

/*     Copyright 1991 Rich Salz.
 *   All rights reserved.
 *   $Revision: 1.5 $
 *
 *    Redistribution and use in any form are permitted provided that the
 *    following restrictions are are met:
 *        1.  Source distributions must retain this entire copyright notice
 *            and comment.
 *        2.  Binary distributions must include the acknowledgement ``This
 *          product includes software developed by Rich Salz'' in the
 *          documentation or other materials provided with the
 *          distribution.  This must not be represented as an endorsement
 *          or promotion without specific prior written permission.
 *      3.  The origin of this software must not be misrepresented, either
 *          by explicit claim or by omission.  Credits must appear in the
 *          source and documentation.
 *      4.  Altered versions must be plainly marked as such in the source
 *          and documentation and must not be misrepresented as being the
 *          original software.
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#include "macros.h"

#include "xmalloc.h"
#include "imclient.h"
#include "imparse.h"

#define NUM_STORAGE_CLASSES 100

#define BOOL  int
#define FALSE (0)
#define TRUE  (1)
#define STATIC static

extern int wildmat(const char *text, const char *p);


typedef struct _NEWSGROUP {
    char		*Name;
    char		*Rest;
    unsigned long	Last;
    unsigned long	Lastpurged;
	/* These fields are new. */
    time_t		Keep;
    time_t		Default;
    time_t		Purge;
    /* X flag => remove entire article when it expires in this group */
    BOOL                Poison;
} NEWSGROUP;

typedef struct _EXPIRECLASS {
    time_t              Keep;
    time_t              Default;
    time_t              Purge;
    BOOL                Missing;
    BOOL                ReportedMissing;
} EXPIRECLASS;

/*
**  Expire-specific stuff.
*/
#define MAGIC_TIME	49710.


STATIC NEWSGROUP	EXPdefault;
STATIC int		nGroups;
STATIC int		nGroups_alloc;
STATIC time_t		EXPremember;
STATIC time_t		Now;
STATIC EXPIRECLASS      EXPclasses[NUM_STORAGE_CLASSES];
STATIC NEWSGROUP	*Groups;

STATIC int		EXPverbose;
/*
**  Split a line at a specified field separator into a vector and return
**  the number of fields found, or -1 on error.
*/
STATIC int EXPsplit(char *p, char sep, char **argv, int count)
{
    int	                i;

    if (!p)
      return 0;

    while (*p == sep)
      ++p;

    if (!*p)
      return 0;

    if (!p)
      return 0;

    while (*p == sep)
      ++p;

    if (!*p)
      return 0;

    for (i = 1, *argv++ = p; *p; )
	if (*p++ == sep) {
	    p[-1] = '\0';
	    for (; *p == sep; p++);
	    if (!*p)
		return i;
	    if (++i == count)
		/* Overflow. */
		return -1;
	    *argv++ = p;
	}
    return i;
}


/*
**  Parse a number field converting it into a "when did this start?".
**  This makes the "keep it" tests fast, but inverts the logic of
**  just about everything you expect.  Print a message and return FALSE
**  on error.
*/
STATIC BOOL EXPgetnum(int line, char *word, time_t *v, char *name)
{
    char	        *p;
    BOOL	        SawDot;
    double		d;

    if (caseEQ(word, "never")) {
	*v = (time_t)0;
	return TRUE;
    }

    /* Check the number.  We don't have strtod yet. */
    for (p = word; ISWHITE(*p); p++)
	continue;
    if (*p == '+' || *p == '-')
	p++;
    for (SawDot = FALSE; *p; p++)
	if (*p == '.') {
	    if (SawDot)
		break;
	    SawDot = TRUE;
	}
	else if (!isdigit( (int)*p))
	    break;
    if (*p) {
	(void)fprintf(stderr, "Line %d, bad `%c' character in %s field\n",
		line, *p, name);
	return FALSE;
    }
    d = atof(word);
    if (d > MAGIC_TIME)
	*v = (time_t)0;
    else
	*v = Now - (time_t)(d * 86400.);
    return TRUE;
}


/*
**  Set the expiration fields for all groups that match this pattern.
*/
STATIC void EXPmatch(char *p, NEWSGROUP *v, char mod)
{
    NEWSGROUP	        *ngp;
    int	                i;
    BOOL	        negate;

    negate = *p == '!';
    if (negate)
	p++;
    for (ngp = Groups, i = nGroups; --i >= 0; ngp++)
    {
	if (negate ? !wildmat(ngp->Name, p) : wildmat(ngp->Name, p))
	    if (mod == 'a') {
		/*|| (mod == 'm' && ngp->Rest[0] == NF_FLAG_MODERATED)
		  || (mod == 'u' && ngp->Rest[0] != NF_FLAG_MODERATED)) { */
		ngp->Keep      = v->Keep;
		ngp->Default   = v->Default;
		ngp->Purge     = v->Purge;
		ngp->Poison    = v->Poison;
		if (EXPverbose > 4) {
		    (void)printf("%s", ngp->Name);
		    (void)printf(" %13.13s", ctime(&v->Keep) + 3);
		    (void)printf(" %13.13s", ctime(&v->Default) + 3);
		    (void)printf(" %13.13s", ctime(&v->Purge) + 3);
		    (void)printf(" (%s)\n", p);
		}
	    }
    }
}

/*
**  Parse the expiration control file.  Return TRUE if okay.
*/
BOOL EXPreadfile(FILE *F)
{
    char	        *p;
    int	                i;
    int	                j;
    int	                k;
    char	        mod;
    NEWSGROUP		v;
    BOOL		SawDefault;
    char		buff[BUFSIZ];
    char		*fields[7];
    char		**patterns;

    /* Scan all lines. */
    EXPremember = -1;
    SawDefault = FALSE;
    patterns = NEW(char*, nGroups);
    for (i = 0; i < NUM_STORAGE_CLASSES; i++)
	EXPclasses[i].ReportedMissing = EXPclasses[i].Missing = TRUE;
    
    for (i = 1; fgets(buff, sizeof buff, F) != NULL; i++) {
	if ((p = strchr(buff, '\n')) == NULL) {
	    (void)fprintf(stderr, "Line %d too long\n", i);
	    return FALSE;
	}
	*p = '\0';
        p = strchr(buff, '#');
	if (p)
	    *p = '\0';
	else
	    p = buff + strlen(buff);
	while (--p >= buff) {
	    if (isspace((int)*p))
                *p = '\0';
            else
                break;
        }
        if (buff[0] == '\0')
	    continue;
	if ((j = EXPsplit(buff, ':', fields, SIZEOF(fields))) == -1) {
	    (void)fprintf(stderr, "Line %d too many fields\n", i);
	    return FALSE;
	}

	/* Expired-article remember line? */
	if (EQ(fields[0], "/remember/")) {
	    if (j != 2) {
		(void)fprintf(stderr, "Line %d bad format\n", i);
		return FALSE;
	    }
	    if (EXPremember != -1) {
		(void)fprintf(stderr, "Line %d duplicate /remember/\n", i);
		return FALSE;
	    }
	    if (!EXPgetnum(i, fields[1], &EXPremember, "remember"))
		return FALSE;
	    continue;
	}

	/* Storage class line? */
	if (j == 4) {
	    j = atoi(fields[0]);
	    if ((j < 0) || (j > NUM_STORAGE_CLASSES)) {
		fprintf(stderr, "Line %d bad storage class %d\n", i, j);
	    }
	
	    if (!EXPgetnum(i, fields[1], &EXPclasses[j].Keep,    "keep")
		|| !EXPgetnum(i, fields[2], &EXPclasses[j].Default, "default")
		|| !EXPgetnum(i, fields[3], &EXPclasses[j].Purge,   "purge"))
		return FALSE;
	    /* These were turned into offsets, so the test is the opposite
	     * of what you think it should be.  If Purge isn't forever,
	     * make sure it's greater then the other two fields. */
	    if (EXPclasses[j].Purge) {
		/* Some value not forever; make sure other values are in range. */
		if (EXPclasses[j].Keep && EXPclasses[j].Keep < EXPclasses[j].Purge) {
		    (void)fprintf(stderr, "Line %d keep>purge\n", i);
		    return FALSE;
		}
		if (EXPclasses[j].Default && EXPclasses[j].Default < EXPclasses[j].Purge) {
		    (void)fprintf(stderr, "Line %d default>purge\n", i);
		    return FALSE;
		}
	    }
	    EXPclasses[j].Missing = FALSE;
	    continue;
	}

	/* Regular expiration line -- right number of fields? */
	if (j != 5) {
	    (void)fprintf(stderr, "Line %d bad format\n", i);
	    return FALSE;
	}

	/* Parse the fields. */
	if (strchr(fields[1], 'M') != NULL)
	    mod = 'm';
	else if (strchr(fields[1], 'U') != NULL)
	    mod = 'u';
	else if (strchr(fields[1], 'A') != NULL)
	    mod = 'a';
	else {
	    (void)fprintf(stderr, "Line %d bad modflag\n", i);
	    return FALSE;
	}
	v.Poison = (strchr(fields[1], 'X') != NULL);
	if (!EXPgetnum(i, fields[2], &v.Keep,    "keep")
	 || !EXPgetnum(i, fields[3], &v.Default, "default")
	 || !EXPgetnum(i, fields[4], &v.Purge,   "purge"))
	    return FALSE;
	/* These were turned into offsets, so the test is the opposite
	 * of what you think it should be.  If Purge isn't forever,
	 * make sure it's greater then the other two fields. */
	if (v.Purge) {
	    /* Some value not forever; make sure other values are in range. */
	    if (v.Keep && v.Keep < v.Purge) {
		(void)fprintf(stderr, "Line %d keep>purge\n", i);
		return FALSE;
	    }
	    if (v.Default && v.Default < v.Purge) {
		(void)fprintf(stderr, "Line %d default>purge\n", i);
		return FALSE;
	    }
	}

	/* Is this the default line? */
	if (fields[0][0] == '*' && fields[0][1] == '\0' && mod == 'a') {
	    if (SawDefault) {
		(void)fprintf(stderr, "Line %d duplicate default\n", i);
                return FALSE;
	    }
	    EXPdefault.Keep    = v.Keep;
	    EXPdefault.Default = v.Default;
	    EXPdefault.Purge   = v.Purge;
	    EXPdefault.Poison  = v.Poison;
	    SawDefault = TRUE;
	}

	/* Assign to all groups that match the pattern and flags. */
	if ((j = EXPsplit(fields[0], ',', patterns, nGroups)) == -1) {
	    (void)fprintf(stderr, "Line %d too many patterns\n", i);
	    return FALSE;
	}
	for (k = 0; k < j; k++)
	    EXPmatch(patterns[k], &v, mod);
    }
    DISPOSE(patterns);

    return TRUE;
}

int ExpireExists(int num)
{
    if ((num<0) || (num>=nGroups))
	return 1;

    return 0;
}

time_t GetExpireTime(int num)
{
    return Groups[num].Default;
}

char *GetExpireName(int num)
{
    return Groups[num].Name;
}

int readconfig_init(void)
{
    Now = time(NULL);

    nGroups = 0;
    nGroups_alloc = 1000;
    Groups=(NEWSGROUP *) malloc(sizeof(NEWSGROUP) * 1000);
    if (Groups==NULL) fatal("Unable to alloc",0);

    return 0;
}

void artificial_matchall(int days)
{
    NEWSGROUP ne;

    ne.Default = Now - (time_t)(days * 86400.);
    EXPmatch("*", &ne,'a');
}

#if 0 /* debugginf */
void show_groups(void)
{
    int lup;

    for (lup=0;lup<nGroups;lup++)
    {
	printf("name = %s\n",Groups[lup].Name);
	printf("expires = %uld\n",Groups[lup].Keep);
	printf("expires = %uld\n",Groups[lup].Default);
	printf("expires = %uld\n",Groups[lup].Purge);

    }

}
#endif /* 0 */

/*
 * Callback to deal with untagged LIST/LSUB data
 */
void
callback_list(struct imclient *imclient,
	      void *rock,
	      struct imclient_reply *reply)
{
    char *s, *end;
    char *mailbox, *attributes, *separator;
    int c;

    s = reply->text;
    
    if (*s++ != '(') return;
    end = strchr(s, ')');
    if (!end) return;
    attributes = s;
    s = end;
    *s++ = '\0';

    if (*s++ != ' ') return;
    if (*s == 'N') {
	if (s[1] != 'I' || s[2] != 'L') return;
	separator = "";
    	s += 3;
    }
    else if (*s == '\"') {
	s++;
	if (*s == '\\') s++;
	separator = s++;
	if (*s != '\"') return;
	*s++ = '\0';
    }

    if (*s++ != ' ') return;
    c = imparse_astring(&s, &mailbox);
    if (c != '\0') return;

    /* don't match one of our own INBOXs */
    if (strncasecmp(mailbox,"INBOX",5) != 0) {
	Groups[nGroups].Name = malloc( strlen(mailbox)+1);
	strcpy(Groups[nGroups].Name, mailbox);
	nGroups++;

	if (nGroups >= nGroups_alloc)
	{
	    nGroups_alloc +=1000;
	    Groups=(NEWSGROUP *) realloc(Groups, sizeof(NEWSGROUP) * nGroups_alloc);
	    if (Groups==NULL) fatal("Unable to alloc",0);
	}

    }

    for (s = attributes; (end = strchr(s, ' '))!=NULL; s = end+1) {
	*s = '\0';

    }

}
