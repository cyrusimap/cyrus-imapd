/* imap_proxy.c - IMAP proxy support functions
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: imap_proxy.c,v 1.19 2010/01/06 17:01:32 murch Exp $
 */

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/un.h>

#include "assert.h"
#include "acl.h"
#include "annotate.h"
#include "backend.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "imap_proxy.h"
#include "proxy.h"
#include "mboxname.h"
#include "mupdate-client.h"
#include "prot.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"

extern unsigned int proxy_cmdcnt;
extern struct protstream *imapd_in, *imapd_out;
extern struct backend *backend_inbox, *backend_current, **backend_cached;
extern char *imapd_userid, *proxy_userid;
extern struct namespace imapd_namespace;

extern int mlookup(const char *tag, const char *ext_name,
		   const char *name, int *flags,
		   char **partp, char **aclp, struct txn **tid) ;

static char *imap_parsemechlist(const char *str, struct stdprot_t *std)
{
    char *ret = xzmalloc(strlen(str)+1);
    char *tmp;
    int num = 0;
    
    if (strstr(str, " SASL-IR")) {
	/* server supports initial response in AUTHENTICATE command */
	std->sasl_cmd.maxlen = USHRT_MAX;
    }
    
    while ((tmp = strstr(str, " AUTH="))) {
	char *end = (tmp += 6);
	
	while((*end != ' ') && (*end != '\0')) end++;
	
	/* add entry to list */
	if (num++ > 0) strcat(ret, " ");
	strlcat(ret, tmp, strlen(ret) + (end - tmp) + 1);
	
	/* reset the string */
	str = end;
    }
    
    return ret;
}

struct protocol_t imap_protocol =
{ "imap", "imap", TYPE_STD,
  { { { 1, NULL },
      { "C01 CAPABILITY", NULL, "C01 ", &imap_parsemechlist,
	{ { " AUTH=", CAPA_AUTH },
	  { " STARTTLS", CAPA_STARTTLS },
	  { " COMPRESS=DEFLATE", CAPA_COMPRESS },
	  { " IDLE", CAPA_IDLE },
	  { " MUPDATE", CAPA_MUPDATE },
	  { " MULTIAPPEND", CAPA_MULTIAPPEND },
	  { " RIGHTS=kxte", CAPA_ACLRIGHTS },
	  { " LIST-EXTENDED", CAPA_LISTEXTENDED },
	  { " X-REPLICATION", CAPA_REPLICATION },
	  { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*",
	NULL, AUTO_CAPA_AUTH_OK },
      { "Z01 COMPRESS DEFLATE", "* ", "Z01 OK" },
      { "N01 NOOP", "* ", "N01 OK" },
      { "Q01 LOGOUT", "* ", "Q01 " } } }
};

void proxy_gentag(char *tag, size_t len)
{
    snprintf(tag, len, "PROXY%d", proxy_cmdcnt++);
}

struct backend *proxy_findinboxserver(const char *userid)
{
    char inbox[MAX_MAILBOX_BUFFER];
    int r, mbtype;
    char *server = NULL;
    struct backend *s = NULL;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, "INBOX",
					       userid, inbox);

    if(!r) {
	r = mlookup(NULL, NULL, inbox, &mbtype, &server, NULL, NULL);
	if (!r && (mbtype & MBTYPE_REMOTE)) {
	    s = proxy_findserver(server, &imap_protocol,
				 proxy_userid, &backend_cached,
				 &backend_current, &backend_inbox, imapd_in);
	}
    }

    return s;
}

/* pipe_response() reads from 's->in' until either the tagged response
   starting with 'tag' appears, or if 'tag' is NULL, to the end of the
   current line.  If 'include_last' is set, the last/tagged line is included
   in the output, otherwise the last/tagged line is stored in 's->last_result'. 
   In either case, the result of the tagged command is returned.

   's->last_result' assumes that tagged responses don't contain literals.
   Unfortunately, the IMAP grammar allows them

   force_notfatal says to not fatal() if we lose connection to backend_current
   even though it is in 95% of the cases, a good idea...
*/
static int pipe_response(struct backend *s, const char *tag, int include_last,
			 int force_notfatal)
{
    char buf[2048];
    char eol[128];
    unsigned sl;
    int cont = 0, last = !tag, r = PROXY_OK;
    size_t taglen = 0;

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    if (tag) {
	taglen = strlen(tag);
	if(taglen >= sizeof(buf) + 1) {
	    fatal("tag too large",EC_TEMPFAIL);
	}
    }

    s->last_result.len = 0;

    /* the only complication here are literals */
    do {
	/* if 'cont' is set, we're looking at the continuation to a very
	   long line.
	   if 'last' is set, we've seen the tag we're looking for, we're
	   just reading the end of the line. */
	if (!cont) eol[0] = '\0';

	if (!prot_fgets(buf, sizeof(buf), s->in)) {
	    /* uh oh */
	    if(s == backend_current && !force_notfatal)
		fatal("Lost connection to selected backend", EC_UNAVAILABLE);
	    proxy_downserver(s);
	    return PROXY_NOCONNECTION;
	}

	sl = strlen(buf);

	if (tag) {
	    /* Check for the tagged line */
	    if (!cont && buf[taglen] == ' ' && !strncmp(tag, buf, taglen)) {

		switch (buf[taglen + 1]) {
		case 'O': case 'o':
		    r = PROXY_OK;
		    break;
		case 'N': case 'n':
		    r = PROXY_NO;
		    break;
		case 'B': case 'b':
		    r = PROXY_BAD;
		    break;
		default: /* huh? no result? */
		    if(s == backend_current && !force_notfatal)
			fatal("Lost connection to selected backend",
			      EC_UNAVAILABLE);
		    proxy_downserver(s);
		    r = PROXY_NOCONNECTION;
		    break;
		}

		last = 1;
	    }
	
	    if (last && !include_last) {
		/* Store the tagged line */
		if (sl > s->last_result.alloc - s->last_result.len) {
		    s->last_result.alloc =
			(s->last_result.alloc == 0) ? (int) sizeof(buf) :
			s->last_result.alloc * 2;
		    s->last_result.s = xrealloc(s->last_result.s,
						s->last_result.alloc+1);
		}

		strcpy(s->last_result.s + s->last_result.len, buf + taglen + 1);
		s->last_result.len += sl - taglen - 1;
	    }
	}

	if (sl == (sizeof(buf) - 1) && buf[sl-1] != '\n') {
            /* only got part of a line */
	    /* we save the last 64 characters in case it has important
	       literal information */
	    strcpy(eol, buf + sl - 64);

	    /* write out this part, but we have to keep reading until we
	       hit the end of the line */
	    if (!last || include_last) prot_write(imapd_out, buf, sl);
	    cont = 1;
	    continue;
	} else {		/* we got the end of the line */
	    int i;
	    int litlen = 0, islit = 0;

	    if (!last || include_last) prot_write(imapd_out, buf, sl);

	    /* now we have to see if this line ends with a literal */
	    if (sl < 64) {
		strcat(eol, buf);
	    } else {
		strcat(eol, buf + sl - 63);
	    }

	    /* eol now contains the last characters from the line; we want
	       to see if we've hit a literal */
	    i = strlen(eol);
	    if (i >= 4 &&
		eol[i-1] == '\n' && eol[i-2] == '\r' && eol[i-3] == '}') {
		/* possible literal */
		i -= 4;
		while (i > 0 && eol[i] != '{' && Uisdigit(eol[i])) {
		    i--;
		}
		if (eol[i] == '{') {
		    islit = 1;
		    litlen = atoi(eol + i + 1);
		}
	    }

	    /* copy the literal over */
	    if (islit) {
		while (litlen > 0) {
		    int j = (litlen > (int) sizeof(buf) ?
			     (int) sizeof(buf) : litlen);
		    
		    j = prot_read(s->in, buf, j);
		    if(!j) {
			/* EOF or other error */
			return -1;
		    }
		    if (!last || include_last) prot_write(imapd_out, buf, j);
		    litlen -= j;
		}

		/* none of our saved information has any relevance now */
		eol[0] = '\0';
		
		/* have to keep going for the end of the line */
		cont = 1;
		continue;
	    }
	}

	/* ok, let's read another line */
	cont = 0;

    } while (!last || cont);

    return r;
}

int pipe_until_tag(struct backend *s, const char *tag, int force_notfatal)
{
    return pipe_response(s, tag, 0, force_notfatal);
}

int pipe_including_tag(struct backend *s, const char *tag, int force_notfatal)
{
    int r;

    r = pipe_response(s, tag, 1, force_notfatal);
    if (r == PROXY_NOCONNECTION) {
	/* don't have to worry about downing the server, since
	 * pipe_until_tag does that for us */
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_SERVER_UNAVAILABLE));
    }
    return r;
}

static int pipe_to_end_of_response(struct backend *s, int force_notfatal)
{
    return pipe_response(s, NULL, 1, force_notfatal);
}

/* copy our current input to 's' until we hit a true EOL.

   'optimistic_literal' is how happy we should be about assuming
   that a command will go through by converting synchronizing literals of
   size less than optimistic_literal to nonsync

   returns 0 on success, <0 on big failure, >0 on full command not sent */
int pipe_command(struct backend *s, int optimistic_literal)
{
    char buf[2048];
    char eol[128];
    int sl;

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;
    
    eol[0] = '\0';

    /* again, the complication here are literals */
    for (;;) {
	if (!prot_fgets(buf, sizeof(buf), imapd_in)) {
	    /* uh oh */
	    return -1;
	}

	sl = strlen(buf);

	if (sl == (sizeof(buf) - 1) && buf[sl-1] != '\n') {
            /* only got part of a line */
	    strcpy(eol, buf + sl - 64);

	    /* and write this out, except for what we've saved */
	    prot_write(s->out, buf, sl - 64);
	    continue;
	} else {
	    int i, nonsynch = 0, islit = 0, litlen = 0;

	    if (sl < 64) {
		strcat(eol, buf);
	    } else {
		/* write out what we have, and copy the last 64 characters
		   to eol */
		prot_printf(s->out, "%s", eol);
		prot_write(s->out, buf, sl - 64);
		strcpy(eol, buf + sl - 64);
	    }

	    /* now determine if eol has a literal in it */
	    i = strlen(eol);
	    if (i >= 4 &&
		eol[i-1] == '\n' && eol[i-2] == '\r' && eol[i-3] == '}') {
		/* possible literal */
		i -= 4;
		if (eol[i] == '+') {
		    nonsynch = 1;
		    i--;
		}
		while (i > 0 && eol[i] != '{' && Uisdigit(eol[i])) {
		    i--;
		}
		if (eol[i] == '{') {
		    islit = 1;
		    litlen = atoi(eol + i + 1);
		}
	    }

	    if (islit) {
		if (nonsynch) {
		    prot_write(s->out, eol, strlen(eol));
		} else if (!nonsynch && (litlen <= optimistic_literal)) {
		    prot_printf(imapd_out, "+ i am an optimist\r\n");
		    prot_write(s->out, eol, strlen(eol) - 3);
		    /* need to insert a + to turn it into a nonsynch */
		    prot_printf(s->out, "+}\r\n");
		} else {
		    /* we do a standard synchronizing literal */
		    prot_write(s->out, eol, strlen(eol));
		    /* but here the game gets tricky... */
		    prot_fgets(buf, sizeof(buf), s->in);
		    /* but for now we cheat */
		    prot_write(imapd_out, buf, strlen(buf));
		    if (buf[0] != '+' && buf[1] != ' ') {
			/* char *p = strchr(buf, ' '); */
			/* strncpy(s->last_result, p + 1, LAST_RESULT_LEN);*/

			/* stop sending command now */
			return 1;
		    }
		}

		/* gobble literal and sent it onward */
		while (litlen > 0) {
		    int j = (litlen > (int) sizeof(buf) ?
			     (int) sizeof(buf) : litlen);

		    j = prot_read(imapd_in, buf, j);
		    if(!j) {
			/* EOF or other error */
			return -1;
		    }
		    prot_write(s->out, buf, j);
		    litlen -= j;
		}

		eol[0] = '\0';
		
		/* have to keep going for the send of the command */
		continue;
	    } else {
		/* no literal, so we're done! */
		prot_write(s->out, eol, strlen(eol));

		return 0;
	    }
	}
    }
}

/* This handles piping of the LSUB command, because we have to figure out
 * what mailboxes actually exist before passing them to the end user.
 *
 * It is also needed if we are doing a FIND MAILBOXES, for that we do an
 * LSUB on the backend anyway, because the semantics of FIND do not allow
 * it to return nonexistant mailboxes (RFC1176), but we need to really dumb
 * down the response when this is the case.
 */
int pipe_lsub(struct backend *s, const char *userid, const char *tag,
	      int force_notfatal, const char *resp) 
{
    int taglen = strlen(tag);
    int c;
    int r = PROXY_OK;
    int exist_r;
    char mailboxname[MAX_MAILBOX_BUFFER];
    static struct buf tagb, cmd, sep, name;
    int cur_flags_size = 64;
    char *flags = xmalloc(cur_flags_size);

    const char *end_strip_flags[] = { " \\NonExistent)", "\\NonExistent)",
				      " \\Noselect)", "\\Noselect)",
				      NULL };
    const char *mid_strip_flags[] = { "\\NonExistent ",
				      "\\Noselect ",
				      NULL 
				    };

    assert(s);
    assert(s->timeout);
    
    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    while(1) {
	c = getword(s->in, &tagb);

	if(c == EOF) {
	    if(s == backend_current && !force_notfatal)
		fatal("Lost connection to selected backend", EC_UNAVAILABLE);
	    proxy_downserver(s);
	    free(flags);
	    return PROXY_NOCONNECTION;
	}

	if(!strncmp(tag, tagb.s, taglen)) {
	    char buf[2048];
	    if(!prot_fgets(buf, sizeof(buf), s->in)) {
		if(s == backend_current && !force_notfatal)
		    fatal("Lost connection to selected backend",
			  EC_UNAVAILABLE);
		proxy_downserver(s);
		free(flags);
		return PROXY_NOCONNECTION;
	    }	
	    /* Got the end of the response */
	    if (s->last_result.alloc == 0) {
		s->last_result.alloc = sizeof(buf);
		s->last_result.s = xmalloc(s->last_result.alloc+1);
	    }
	    strcpy(s->last_result.s, buf);
	    s->last_result.len = strlen(buf);

	    switch (buf[0]) {
	    case 'O': case 'o':
		r = PROXY_OK;
		break;
	    case 'N': case 'n':
		r = PROXY_NO;
		break;
	    case 'B': case 'b':
		r = PROXY_BAD;
		break;
	    default: /* huh? no result? */
		if(s == backend_current && !force_notfatal)
		    fatal("Lost connection to selected backend",
			  EC_UNAVAILABLE);
		proxy_downserver(s);
		r = PROXY_NOCONNECTION;
		break;
	    }
	    break; /* we're done */
	}

	c = getword(s->in, &cmd);

	if(c == EOF) {
	    if(s == backend_current && !force_notfatal)
		fatal("Lost connection to selected backend", EC_UNAVAILABLE);
	    proxy_downserver(s);
	    free(flags);
	    return PROXY_NOCONNECTION;
	}

	if(strncasecmp("LSUB", cmd.s, 4) && strncasecmp("LIST", cmd.s, 4)) {
	    prot_printf(imapd_out, "%s %s ", tagb.s, cmd.s);
	    r = pipe_to_end_of_response(s, force_notfatal);
	    if(r != PROXY_OK) {
		free(flags);
		return r;
	    }
	} else {
	    /* build up the response bit by bit */
	    int i = 0;
	    char *p;

	    c = prot_getc(s->in);
	    while(c != ')' && c != EOF) {
		flags[i++] = c;
		if(i == cur_flags_size) {
		    /* expand our buffer */
		    cur_flags_size *= 2;
		    flags = xrealloc(flags, cur_flags_size);
		}
		c = prot_getc(s->in);
	    }

	    if(c != EOF) {
		/* terminate string */
		flags[i++] = ')';
		if(i == cur_flags_size) {
		    /* expand our buffer */
		    cur_flags_size *= 2;
		    flags = xrealloc(flags, cur_flags_size);
		}
		flags[i] = '\0';
		/* get the next character */
 		c = prot_getc(s->in);
	    }
	    
	    if(c != ' ') {
		if(s == backend_current && !force_notfatal)
		    fatal("Bad LSUB response from selected backend",
			  EC_UNAVAILABLE);
		proxy_downserver(s);
		free(flags);
		return PROXY_NOCONNECTION;
	    }

	    /* Check for flags that we should remove
	     * (e.g. Noselect, NonExistent) */
	    for(i=0; end_strip_flags[i]; i++) {
		p = strstr(flags, end_strip_flags[i]);
		if(p) {
		    *p = ')';
		    *(p+1) = '\0';
		}
	    }

	    for(i=0; mid_strip_flags[i]; i++) {
		int mid_strip_len = strlen(mid_strip_flags[i]);
		p = strstr(flags, mid_strip_flags[i]);
		while(p) {
		    strcpy(p, p + mid_strip_len);
		    p = strstr(flags, mid_strip_flags[i]);
		}
	    }

	    /* Get separator */
	    c = getastring(s->in, s->out, &sep);

	    if(c != ' ') {
		if(s == backend_current && !force_notfatal)
		    fatal("Bad LSUB response from selected backend",
			  EC_UNAVAILABLE);
		proxy_downserver(s);
		free(flags);
		return PROXY_NOCONNECTION;
	    }

	    /* Get name */
	    c = getastring(s->in, s->out, &name);

	    if(c == '\r') c = prot_getc(s->in);
	    if(c != '\n') {
		if(s == backend_current && !force_notfatal)
		    fatal("Bad LSUB response from selected backend",
			  EC_UNAVAILABLE);
		proxy_downserver(s);
		free(flags);
		return PROXY_NOCONNECTION;
	    }

	    /* lookup name */
	    exist_r = 1;
	    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
							name.s,
							userid,
							mailboxname);
	    if (!r) {
		struct mboxlist_entry mbentry;
		exist_r = mboxlist_lookup(mailboxname, &mbentry, NULL);
		if(!exist_r && (mbentry.mbtype & MBTYPE_RESERVE))
		    exist_r = IMAP_MAILBOX_RESERVED;
	    } else {
		/* skip this one */
		syslog(LOG_ERR, "could not convert %s to internal form",
		       name.s);
		continue;
	    }

	    /* send our response */
	    /* we need to set \Noselect if it's not in our mailboxes.db */
	    if(resp[0] == 'L') {
		if(!exist_r) {
		    prot_printf(imapd_out, "* %s %s \"%s\" ",
				resp, flags, sep.s);
		} else {
		    prot_printf(imapd_out, "* %s (\\Noselect) \"%s\" ",
				resp, sep.s);
		}

		prot_printstring(imapd_out, name.s);
		prot_printf(imapd_out, "\r\n");

	    } else if(resp[0] == 'M' && !exist_r) {
		/* Note that it has to exist for a find response */
		prot_printf(imapd_out, "* %s ", resp);
		prot_printastring(imapd_out, name.s);
		prot_printf(imapd_out, "\r\n");
	    }
	}
    } /* while(1) */

    free(flags);
    return r;
}

/* xxx  start of separate proxy-only code
   (remove when we move to a unified environment) */
static int chomp(struct protstream *p, char *s)
{
    int c = prot_getc(p);

    while (*s) {
	if (tolower(c) != tolower(*s)) { break; }
	s++;
	c = prot_getc(p);
    }
    if (*s) {
	if (c != EOF) prot_ungetc(c, p);
	c = EOF;
    }
    return c;
}

#define BUFGROWSIZE 100

/* read characters from 'p' until 'end' is seen */
static char *grab(struct protstream *p, char end)
{
    int alloc = BUFGROWSIZE, cur = 0;
    int c = -1;
    char *ret = (char *) xmalloc(alloc);

    ret[0] = '\0';
    while ((c = prot_getc(p)) != end) {
	if (c == EOF) break;
	if (cur == alloc - 1) {
	    alloc += BUFGROWSIZE;
	    ret = xrealloc(ret, alloc);

	}
	ret[cur++] = c;
    }
    if (cur) ret[cur] = '\0';

    return ret;
}

/* remove \Recent from the flags */
static char *editflags(char *flags)
{
    char *p;

    p = flags;
    while ((p = strchr(p, '\\')) != NULL) {
	if (!strncasecmp(p + 1, "recent", 6)) {
	    if (p[7] == ' ') {
		/* shift everything over so that \recent vanishes */
		char *q;
		
		q = p + 8;
		while (*q) {
		    *p++ = *q++;
		}
		*p = '\0';
	    } else if (p[7] == '\0') {
		/* last flag in line */
		*p = '\0';
	    } else {
		/* not really \recent, i guess */
		p++;
	    }
	} else {
	    p++;
	}
    }

    return flags;
}

void proxy_copy(const char *tag, char *sequence, char *name, int myrights,
		int usinguid, struct backend *s)
{
    char mytag[128];
    struct d {
	char *idate;
	char *flags;
	unsigned int seqno, uid;
	struct d *next;
    } *head, *p, *q;
    int c;

    /* find out what the flags & internaldate for this message are */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(backend_current->out, 
		"%s %s %s (Flags Internaldate)\r\n", 
		tag, usinguid ? "Uid Fetch" : "Fetch", sequence);
    head = (struct d *) xmalloc(sizeof(struct d));
    head->flags = NULL; head->idate = NULL;
    head->seqno = head->uid = 0;
    head->next = NULL;
    p = head;
    /* read all the responses into the linked list */
    for (/* each FETCH response */;;) {
	unsigned int seqno = 0, uidno = 0;
	char *flags = NULL, *idate = NULL;

	/* read a line */
	c = prot_getc(backend_current->in);
	if (c != '*') break;
	c = prot_getc(backend_current->in);
	if (c != ' ') { /* protocol error */ c = EOF; break; }
	    
	/* check for OK/NO/BAD/BYE response */
	if (!isdigit(c = prot_getc(backend_current->in))) {
	    prot_printf(imapd_out, "* %c", c);
	    pipe_to_end_of_response(backend_current, 0);
	    continue;
	}

	/* read seqno */
	prot_ungetc(c, backend_current->in);
	c = getuint32(backend_current->in, &seqno);
	if (seqno == 0 || c != ' ') {
	    /* we suck and won't handle this case */
	    c = EOF; break;
	}
	c = chomp(backend_current->in, "fetch (");
	if (c == EOF) {
	    c = chomp(backend_current->in, "exists\r");
	    if (c == '\n') { /* got EXISTS response */
		prot_printf(imapd_out, "* %d EXISTS\r\n", seqno);
		continue;
	    }
	}
	if (c == EOF) {
	    /* XXX  the "exists" check above will eat "ex" */
	    c = chomp(backend_current->in, "punge\r");
	    if (c == '\n') { /* got EXPUNGE response */
		prot_printf(imapd_out, "* %d EXPUNGE\r\n", seqno);
		continue;
	    }
	}
	if (c == EOF) {
	    c = chomp(backend_current->in, "recent\r");
	    if (c == '\n') { /* got RECENT response */
		prot_printf(imapd_out, "* %d RECENT\r\n", seqno);
		continue;
	    }
	}
	/* huh, don't get this response */
	if (c == EOF) break;
	for (/* each fetch item */;;) {
	    /* looking at the first character in an item */
	    switch (c) {
	    case 'f': case 'F': /* flags? */
		c = chomp(backend_current->in, "lags");
		if (c != ' ') { c = EOF; }
		else c = prot_getc(backend_current->in);
		if (c != '(') { c = EOF; }
		else {
		    flags = grab(backend_current->in, ')');
		    c = prot_getc(backend_current->in);
		}
		break;
	    case 'i': case 'I': /* internaldate? */
		c = chomp(backend_current->in, "nternaldate");
		if (c != ' ') { c = EOF; }
		else c = prot_getc(backend_current->in);
		if (c != '"') { c = EOF; }
		else {
		    idate = grab(backend_current->in, '"');
		    c = prot_getc(backend_current->in);
		}
		break;
	    case 'u': case 'U': /* uid */
		c = chomp(backend_current->in, "id");
		if (c != ' ') { c = EOF; }
		else c = getuint32(backend_current->in, &uidno);
		break;
	    default: /* hmm, don't like the smell of it */
		c = EOF;
		break;
	    }
	    /* looking at either SP seperating items or a RPAREN */
	    if (c == ' ') { c = prot_getc(backend_current->in); }
	    else if (c == ')') break;
	    else { c = EOF; break; }
	}
	/* if c == EOF we have either a protocol error or a situation
	   we can't handle, and we should die. */
	if (c == ')') c = prot_getc(backend_current->in);
	if (c == '\r') c = prot_getc(backend_current->in);
	if (c != '\n') { 
	    c = EOF;
	    free(flags);
	    free(idate);
	    break;
	}

	/* if we're missing something, we should echo */
	if (!flags || !idate) {
	    char sep = '(';
	    prot_printf(imapd_out, "* %d FETCH ", seqno);
	    if (uidno) {
		prot_printf(imapd_out, "%cUID %d", sep, uidno);
		sep = ' ';
	    }
	    if (flags) {
		prot_printf(imapd_out, "%cFLAGS %s", sep, flags);
		sep = ' ';
	    }
	    if (idate) {
		prot_printf(imapd_out, "%cINTERNALDATE %s", sep, flags);
		sep = ' ';
	    }
	    prot_printf(imapd_out, ")\r\n");
	    if (flags) free(flags);
	    if (idate) free(idate);
	    continue;
	}

	/* add to p->next */
	p->next = xmalloc(sizeof(struct d));
	p = p->next;
	p->idate = idate;
	p->flags = editflags(flags);
	p->uid = uidno;
	p->seqno = seqno;
	p->next = NULL;
    }
    if (c != EOF) {
	prot_ungetc(c, backend_current->in);

	/* we should be looking at the tag now */
	pipe_until_tag(backend_current, tag, 0);
    }
    if (c == EOF) {
	/* uh oh, we're not happy */
	fatal("Lost connection to selected backend", EC_UNAVAILABLE);
    }

    /* start the append */
    prot_printf(s->out, "%s Append {" SIZE_T_FMT "+}\r\n%s",
		tag, strlen(name), name);
    prot_printf(backend_current->out, "%s %s %s (Rfc822.peek)\r\n",
		mytag, usinguid ? "Uid Fetch" : "Fetch", sequence);
    for (/* each FETCH response */;;) {
	unsigned int seqno = 0, uidno = 0;

	/* read a line */
	c = prot_getc(backend_current->in);
	if (c != '*') break;
	c = prot_getc(backend_current->in);
	if (c != ' ') { /* protocol error */ c = EOF; break; }

	/* check for OK/NO/BAD/BYE response */
	if (!isdigit(c = prot_getc(backend_current->in))) {
	    prot_printf(imapd_out, "* %c", c);
	    pipe_to_end_of_response(backend_current, 0);
	    continue;
	}

	/* read seqno */
	prot_ungetc(c, backend_current->in);
	c = getuint32(backend_current->in, &seqno);
	if (seqno == 0 || c != ' ') {
	    /* we suck and won't handle this case */
	    c = EOF; break;
	}
	c = chomp(backend_current->in, "fetch (");
	if (c == EOF) { /* not a fetch response */
	    c = chomp(backend_current->in, "exists\r");
	    if (c == '\n') { /* got EXISTS response */
		prot_printf(imapd_out, "* %d EXISTS\r\n", seqno);
		continue;
	    }
	}
	if (c == EOF) { /* not an exists response */
	    /* XXX  the "exists" check above will eat "ex" */
	    c = chomp(backend_current->in, "punge\r");
	    if (c == '\n') { /* got EXPUNGE response */
		prot_printf(imapd_out, "* %d EXPUNGE\r\n", seqno);
		continue;
	    }
	}
	if (c == EOF) { /* not an exists response */
	    c = chomp(backend_current->in, "recent\r");
	    if (c == '\n') { /* got RECENT response */
		prot_printf(imapd_out, "* %d RECENT\r\n", seqno);
		continue;
	    }
	}
	if (c == EOF) {
	    /* huh, don't get this response */
	    break;
	}
	/* find seqno in the list */
	p = head;
	while (p->next && seqno != p->next->seqno) p = p->next;
	if (!p->next) break;
	q = p->next;
	p->next = q->next;
	for (/* each fetch item */;;) {
	    int sz = 0;

	    switch (c) {
	    case 'u': case 'U':
		c = chomp(backend_current->in, "id");
		if (c != ' ') { c = EOF; }
		else c = getuint32(backend_current->in, &uidno);
		break;

	    case 'r': case 'R':
		c = chomp(backend_current->in, "fc822");
		if (c == ' ') c = prot_getc(backend_current->in);
		if (c != '{') {
		    /* NIL? */
		    eatline(backend_current->in, c);
		    c = EOF;
		}
		else c = getint32(backend_current->in, &sz);
		if (c == '}') c = prot_getc(backend_current->in);
		if (c == '\r') c = prot_getc(backend_current->in);
		if (c != '\n') c = EOF;

		if (c != EOF) {
		    /* append p to s->out */
		    prot_printf(s->out, " (%s) \"%s\" {%d+}\r\n", 
				q->flags, q->idate, sz);
		    while (sz) {
			char buf[2048];
			int j = (sz > (int) sizeof(buf) ?
				 (int) sizeof(buf) : sz);

			j = prot_read(backend_current->in, buf, j);
			if(!j) break;
			prot_write(s->out, buf, j);
			sz -= j;
		    }
		    c = prot_getc(backend_current->in);
		}

		break; /* end of case */
	    default:
		c = EOF;
		break;
	    }
	    /* looking at either SP seperating items or a RPAREN */
	    if (c == ' ') { c = prot_getc(backend_current->in); }
	    else if (c == ')') break;
	    else { c = EOF; break; }
	}

	/* if c == EOF we have either a protocol error or a situation
	   we can't handle, and we should die. */
	if (c == ')') c = prot_getc(backend_current->in);
	if (c == '\r') c = prot_getc(backend_current->in);
	if (c != '\n') { c = EOF; break; }

	/* free q */
	free(q->idate);
	free(q->flags);
	free(q);
    }
    if (c != EOF) {
	char *appenduid, *b;
	int res;

	/* pushback the first character of the tag we're looking at */
	prot_ungetc(c, backend_current->in);

	/* nothing should be left in the linked list */
	assert(head->next == NULL);

	/* ok, finish the append; we need the UIDVALIDITY and UIDs
	   to return as part of our COPYUID response code */
	prot_printf(s->out, "\r\n");

	/* should be looking at 'mytag' on 'backend_current', 
	   'tag' on 's' */
	pipe_until_tag(backend_current, mytag, 0);
	res = pipe_until_tag(s, tag, 0);

	if (res == PROXY_OK) {
	    if (myrights & ACL_READ) {
		appenduid = strchr(s->last_result.s, '[');
		/* skip over APPENDUID */
		if (appenduid) {
		    appenduid += strlen("[appenduid ");
		    b = strchr(appenduid, ']');
		    if (b) *b = '\0';
		    prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
				appenduid, error_message(IMAP_OK_COMPLETED));
		}
		else
		    prot_printf(imapd_out, "%s OK %s\r\n", tag, s->last_result.s);
	    }
	    else {
		prot_printf(imapd_out, "%s OK %s\r\n", tag,
			    error_message(IMAP_OK_COMPLETED));
	    }
	} else {
	    prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
	}
    } else {
	/* abort the append */
	prot_printf(s->out, " {0+}\r\n\r\n");
	pipe_until_tag(backend_current, mytag, 0);
	pipe_until_tag(s, tag, 0);
	    
	/* report failure */
	prot_printf(imapd_out, "%s NO inter-server COPY failed\r\n", tag);
    }

    /* free dynamic memory */
    while (head) {
	p = head;
	head = head->next;
	if (p->idate) free(p->idate);
	if (p->flags) free(p->flags);
	free(p);
    }
}
/* xxx  end of separate proxy-only code */

int proxy_catenate_url(struct backend *s, struct imapurl *url, FILE *f,
		       unsigned long *size, const char **parseerr)
{
    char mytag[128];
    int c, r = 0, found = 0;
    unsigned int uidvalidity = 0;

    *size = 0;
    *parseerr = NULL;

    /* select the mailbox (read-only) */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(s->out, "%s Examine {" SIZE_T_FMT "+}\r\n%s\r\n",
		mytag, strlen(url->mailbox), url->mailbox);
    for (/* each examine response */;;) {
	/* read a line */
	c = prot_getc(s->in);
	if (c != '*') break;
	c = prot_getc(s->in);
	if (c != ' ') { /* protocol error */ c = EOF; break; }

	c = chomp(s->in, "ok [uidvalidity");
	if (c == EOF) {
	    /* we don't care about this response */
	    eatline(s->in, c);
	    continue;
	}

	/* read uidvalidity */
	c = getuint32(s->in, &uidvalidity);
	if (c != ']') { c = EOF; break; }
	eatline(s->in, c); /* we don't care about the rest of the line */
    }
    if (c != EOF) {
	prot_ungetc(c, s->in);

	/* we should be looking at the tag now */
	eatline(s->in, c);
    }
    if (c == EOF) {
	/* uh oh, we're not happy */
	fatal("Lost connection to backend", EC_UNAVAILABLE);
    }

    if (url->uidvalidity && (uidvalidity != url->uidvalidity)) {
	*parseerr = "Uidvalidity of mailbox has changed";
	r = IMAP_BADURL;
	goto unselect;
    }

    /* fetch the bodypart */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(s->out, "%s Uid Fetch %lu Body.Peek[%s]\r\n",
		mytag, url->uid, url->section ? url->section : "");
    for (/* each fetch response */;;) {
	unsigned int seqno;

      next_resp:
	/* read a line */
	c = prot_getc(s->in);
	if (c != '*') break;
	c = prot_getc(s->in);
	if (c != ' ') { /* protocol error */ c = EOF; break; }
	    
	/* read seqno */
	c = getuint32(s->in, &seqno);
	if (seqno == 0 || c != ' ') {
	    /* we suck and won't handle this case */
	    c = EOF; break;
	}
	c = chomp(s->in, "fetch (");
	if (c == EOF) { /* not a fetch response */
	    eatline(s->in, c);
	    continue;
	}

	for (/* each fetch item */;;) {
	    unsigned uid, sz = 0;

	    switch (c) {
	    case 'u': case 'U':
		c = chomp(s->in, "id");
		if (c != ' ') { c = EOF; }
		else {
		    c = getuint32(s->in, &uid);
		    if (uid != url->uid) {
			/* not our response */
			eatline(s->in, c);
			goto next_resp;
		    }
		}
		break;

	    case 'b': case 'B':
		c = chomp(s->in, "ody[");
		while (c != ']') c = prot_getc(s->in);
		if (c == ']') c = prot_getc(s->in);
		if (c == ' ') c = prot_getc(s->in);
		if (c == '{') {
		    c = getuint32(s->in, &sz);
		    if (c == '}') c = prot_getc(s->in);
		    if (c == '\r') c = prot_getc(s->in);
		    if (c != '\n') c = EOF;
		}
		else if (c == 'n' || c == 'N') {
		    c = chomp(s->in, "il");
		    r = IMAP_BADURL;
		    *parseerr = "No such message part";
		}

		if (c != EOF) {
		    /* catenate to f */
		    found = 1;
		    *size = sz;
		    
		    while (sz) {
			char buf[2048];
			int j = (sz > sizeof(buf) ? sizeof(buf) : sz);

			j = prot_read(s->in, buf, j);
			if(!j) break;
			fwrite(buf, j, 1, f);
			sz -= j;
		    }
		    c = prot_getc(s->in);
		}

		break; /* end of case */
	    default:
		/* probably a FLAGS item */
		eatline(s->in, c);
		goto next_resp;
	    }
	    /* looking at either SP separating items or a RPAREN */
	    if (c == ' ') { c = prot_getc(s->in); }
	    else if (c == ')') break;
	    else { c = EOF; break; }
	}

	/* if c == EOF we have either a protocol error or a situation
	   we can't handle, and we should die. */
	if (c == ')') c = prot_getc(s->in);
	if (c == '\r') c = prot_getc(s->in);
	if (c != '\n') { c = EOF; break; }
    }
    if (c != EOF) {
	prot_ungetc(c, s->in);

	/* we should be looking at the tag now */
	eatline(s->in, c);
    }
    if (c == EOF) {
	/* uh oh, we're not happy */
	fatal("Lost connection to backend", EC_UNAVAILABLE);
    }

  unselect:
    /* unselect the mailbox */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(s->out, "%s Unselect\r\n", mytag);
    for (/* each unselect response */;;) {
	/* read a line */
	c = prot_getc(s->in);
	if (c != '*') break;
	c = prot_getc(s->in);
	if (c != ' ') { /* protocol error */ c = EOF; break; }

	/* we don't care about this response */
	eatline(s->in, c);
    }
    if (c != EOF) {
	prot_ungetc(c, s->in);

	/* we should be looking at the tag now */
	eatline(s->in, c);
    }
    if (c == EOF) {
	/* uh oh, we're not happy */
	fatal("Lost connection to backend", EC_UNAVAILABLE);
    }

    if (!r && !found) {
	r = IMAP_BADURL;
	*parseerr = "No such message in mailbox";
    }

    return r;
}

/* Proxy GETANNOTATION commands to backend */
int annotate_fetch_proxy(const char *server, const char *mbox_pat,
			 struct strlist *entry_pat,
			 struct strlist *attribute_pat) 
{
    struct backend *be;
    struct strlist *l;
    char mytag[128];
    
    assert(server && mbox_pat && entry_pat && attribute_pat);
    
    be = proxy_findserver(server, &imap_protocol,
			  proxy_userid, &backend_cached,
			  &backend_current, &backend_inbox, imapd_in);
    if (!be) return IMAP_SERVER_UNAVAILABLE;

    /* Send command to remote */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(be->out, "%s GETANNOTATION \"%s\" (", mytag, mbox_pat);
    for (l = entry_pat; l; l = l->next) {
	prot_printf(be->out, "\"%s\"%s", l->s, l->next ? " " : "");
    }
    prot_printf(be->out, ") (");
    for (l = attribute_pat; l; l = l->next) {
	prot_printf(be->out, "\"%s\"%s", l->s, l->next ? " " : "");
    }
    prot_printf(be->out, ")\r\n");
    prot_flush(be->out);

    /* Pipe the results.  Note that backend-current may also pipe us other
       messages. */
    pipe_until_tag(be, mytag, 0);

    return 0;
}

/* Proxy SETANNOTATION commands to backend */
int annotate_store_proxy(const char *server, const char *mbox_pat,
			 struct entryattlist *entryatts)
{
    struct backend *be;
    struct entryattlist *e;
    struct attvaluelist *av;
    char mytag[128];
    
    assert(server && mbox_pat && entryatts);
    
    be = proxy_findserver(server, &imap_protocol,
			  proxy_userid, &backend_cached,
			  &backend_current, &backend_inbox, imapd_in);
    if (!be) return IMAP_SERVER_UNAVAILABLE;

    /* Send command to remote */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(be->out, "%s SETANNOTATION \"%s\" (", mytag, mbox_pat);
    for (e = entryatts; e; e = e->next) {
	prot_printf(be->out, "\"%s\" (", e->entry);

	for (av = e->attvalues; av; av = av->next) {
	    prot_printf(be->out, "\"%s\" \"%s\"%s", av->attrib, av->value,
			av->next ? " " : "");
	}
	prot_printf(be->out, ")");
	if (e->next) prot_printf(be->out, " ");
    }
    prot_printf(be->out, ")\r\n");
    prot_flush(be->out);

    /* Pipe the results.  Note that backend-current may also pipe us other
       messages. */
    pipe_until_tag(be, mytag, 0);

    return 0;
}


char *find_free_server()
{
    const char *servers = config_getstring(IMAPOPT_SERVERLIST);
    unsigned long max_avail = 0;
    char *server = NULL;

    if (servers) {
	char *tmpbuf, *cur_server, *next_server;
	char mytag[128];
	struct backend *be;

	/* make a working copy of the list */
	cur_server = tmpbuf = xstrdup(servers);

	while (cur_server) {
	    /* eat any leading whitespace */
	    while (Uisspace(*cur_server)) cur_server++;

	    if (!*cur_server) break;

	    /* find end of server */
	    if ((next_server = strchr(cur_server, ' ')) ||
		(next_server = strchr(cur_server, '\t')))
		*next_server++ = '\0';

	    syslog(LOG_DEBUG, "checking free space on server '%s'", cur_server);

	    /* connect to server */
	    be = proxy_findserver(cur_server, &imap_protocol,
				  proxy_userid, &backend_cached,
				  &backend_current, &backend_inbox, imapd_in);
	    if (be) {
		unsigned avail = 0;
		int c;

		/* fetch annotation from remote */
		proxy_gentag(mytag, sizeof(mytag));
		prot_printf(be->out,
			    "%s GETANNOTATION \"\" "
			    "\"/vendor/cmu/cyrus-imapd/freespace\" "
			    "\"value.shared\"\r\n", mytag);
		prot_flush(be->out);

		for (/* each annotation response */;;) {
		    /* read a line */
		    c = prot_getc(be->in);
		    if (c != '*') break;
		    c = prot_getc(be->in);
		    if (c != ' ') { /* protocol error */ c = EOF; break; }

		    c = chomp(be->in,
			      "ANNOTATION \"\" "
			      "\"/vendor/cmu/cyrus-imapd/freespace\" "
			      "(\"value.shared\" \"");
		    if (c == EOF) {
			/* we don't care about this response */
			eatline(be->in, c);
			continue;
		    }

		    /* read uidvalidity */
		    c = getuint32(be->in, &avail);
		    if (c != '\"') { c = EOF; break; }
		    eatline(be->in, c); /* we don't care about the rest of the line */
		}
		if (c != EOF) {
		    prot_ungetc(c, be->in);

		    /* we should be looking at the tag now */
		    eatline(be->in, c);
		}
		if (c == EOF) {
		    /* uh oh, we're not happy */
		    fatal("Lost connection to backend", EC_UNAVAILABLE);
		}
		if (avail > max_avail) {
		    server = cur_server;
		    max_avail = avail;
		}
	    }

	    /* move to next server */
	    cur_server = next_server;
	}

	if (server) server = xstrdup(server);

	free(tmpbuf);
    }

    return server;
}
