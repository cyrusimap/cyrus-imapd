/* script.c -- sieve script functions
 * Larry Greenfield
 * $Id: script.c,v 1.13 2000/01/28 22:09:56 leg Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#include <stdlib.h>
#include <string.h>
#include <md5global.h>
#include <md5.h>

#include "xmalloc.h"

#include "sieve_interface.h"
#include "interp.h"
#include "script.h"
#include "tree.h"
#include "y.tab.h"
#include "message.h"

/* does this interpretor support this requirement? */
int script_require(sieve_script_t *s, char *req)
{
    if (!strcmp("fileinto", req)) {
	if (s->interp.fileinto) {
	    s->support.fileinto = 1;
	    return 1;
	} else {
	    return 0;
	}
    } else if (!strcmp("reject", req)) {
	if (s->interp.reject) {
	    s->support.reject = 1;
	    return 1;
	} else {
	    return 0;
	}
    } else if (!strcmp("envelope", req)) {
	if (s->interp.getenvelope) {
	    s->support.envelope = 1;
	    return 1;
	} else {
	    return 0;
	}
    } else if (!strcmp("vacation", req)) {
	if (s->interp.vacation) {
	    s->support.vacation = 1;
	    return 1;
	} else {
	    return 0;
	}
    } else if (!strcmp("imapflags", req)) {
	if (s->interp.setflag &&
	    s->interp.addflag &&
	    s->interp.removeflag &&
	    s->interp.mark &&
	    s->interp.unmark) {
	    s->support.imapflags = 1;
	    return 1;
	} else {
	    return 0;
	}
    } else if (!strcmp("notify",req)) {
	if (s->interp.notify &&
	    s->interp.denotify) {
	    s->support.notify = 1;
	    return 1;
	} else {
	    return 0;
	}
#ifdef ENABLE_REGEX
    } else if (!strcmp("regex", req)) {
	s->support.regex = 1;
	return 1;
#endif
    } else if (!strcmp("comparator-i;octet", req)) {
	return 1;
    } else if (!strcmp("comparator-i;ascii-casemap", req)) {
	return 1;
    }
    return 0;
}

/* given an interpretor and a script, produce an executable script */
int sieve_script_parse(sieve_interp_t *interp, FILE *script,
		       void *script_context, sieve_script_t **ret)
{
    sieve_script_t *s;
    int res = SIEVE_OK;

    res = interp_verify(interp);
    if (res != SIEVE_OK) {
	return res;
    }

    s = (sieve_script_t *) xmalloc(sizeof(sieve_script_t));
    s->interp = *interp;
    s->script_context = script_context;
    s->support.fileinto = s->support.reject = s->support.envelope = 
	s->support.vacation = s->support.imapflags = s->support.regex = 0;
    s->err = 0;

    s->cmds = sieve_parse(s, script);
    if (s->err > 0) {
	if (s->cmds) {
	    free_tree(s->cmds);
	}
	s->cmds = NULL;
	res = SIEVE_PARSE_ERROR;
    }

    *ret = s;
    return res;
}

char **stringlist_to_chararray(stringlist_t *list)
{
    int size = 0;
    stringlist_t *tmp = list;
    stringlist_t *tofree;
    char **ret;
    int lup;

    while (tmp!=NULL)
    {
	size++;
	tmp=tmp->next;
    }

    ret = malloc( sizeof(char *) * (size+1));
    if (ret == NULL) return NULL;

    tmp = list;

    for (lup = 0;lup<size;lup++)
    {
	ret[lup] = tmp->s;
	tmp=tmp->next;
    }

    ret[size]=NULL;

    /* free element holders */
    tmp = list;

    while (tmp!=NULL)
    {
	tofree = tmp;
	tmp=tmp->next;
	free(tofree);
    }
        
    return ret;
}

int sieve_script_free(sieve_script_t **s)
{
    if (*s) {
	if ((*s)->cmds) {
	    free_tree((*s)->cmds);
	}
	free(*s);
    }

    return SIEVE_OK;
}

static int sysaddr(char *addr)
{
    if (!strncasecmp(addr, "MAILER-DAEMON", 13))
	return 1;

    if (!strncasecmp(addr, "LISTSERV", 8))
	return 1;

    if (!strncasecmp(addr, "majordomo", 9))
	return 1;

    if (strstr(addr, "-request"))
	return 1;

    if (!strncmp(addr, "owner-", 6))
	return 1;

    return 0;
}

/* look for myaddr and myaddrs in the body of a header */
static int look_for_me(char *myaddr, stringlist_t *myaddrs, char **body)
{
    int found = 0;
    int l;
    stringlist_t *sl;

    /* loop through each TO header */
    for (l = 0; body[l] != NULL && !found; l++) {
	void *data = NULL, *marker = NULL;
	char *addr;
	
	parse_address(body[l], &data, &marker);
	/* loop through each address in the header */
	while (!found && ((addr = get_address(ADDRESS_ALL, 
					      &data, &marker)) != NULL)) {
	    if (!strcmp(addr, myaddr)) {
		found = 1;
		break;
	    }
	    
	    for (sl = myaddrs; sl != NULL; sl = sl->next) {
		/* is this address one of my addresses? */
		if (!strcmp(addr, sl->s)) {
		    found = 1;
		    break;
		}
	    }
	}
	free_address(&data, &marker);
    }

    return found;
}

/* evaluates the test t. returns 1 if true, 0 if false.
 */
static int evaltest(sieve_interp_t *i, test_t *t, void *m)
{
    testlist_t *tl;
    stringlist_t *sl;
    patternlist_t *pl;
    int res = 0;
    int addrpart = 0;

    switch (t->type) {
    case ADDRESS:
    case ENVELOPE:
	res = 0;
	switch (t->u.ae.addrpart) {
	case ALL: addrpart = ADDRESS_ALL; break;
	case LOCALPART: addrpart = ADDRESS_LOCALPART; break;
	case DOMAIN: addrpart = ADDRESS_DOMAIN; break;
	}
	for (sl = t->u.ae.sl; sl != NULL && !res; sl = sl->next) {
	    int l;
	    char **body;

	    /* use getheader for address, getenvelope for envelope */
	    if (((t->type == ADDRESS) ? 
		   i->getheader(m, sl->s, &body) :
		   i->getenvelope(m, sl->s, &body)) != SIEVE_OK) {
		continue; /* try next header */
	    }
	    for (pl = t->u.ae.pl; pl != NULL && !res; pl = pl->next) {
		for (l = 0; body[l] != NULL && !res; l++) {
		    /* loop through each header */
		    void *data = NULL, *marker = NULL;
		    char *val;

		    parse_address(body[l], &data, &marker);
                    val = get_address(addrpart, &data, &marker);
		    while (val != NULL && !res) { 
			/* loop through each address */
			res |= t->u.ae.comp(pl->p, val);
			val = get_address(addrpart, &data, &marker);
       		    }
		    free_address(&data, &marker);
		}
	    }
	}
	break;
    case ANYOF:
	res = 0;
	for (tl = t->u.tl; tl != NULL && !res; tl = tl->next) {
	    res |= evaltest(i, tl->t, m);
	}
	break;
    case ALLOF:
	res = 1;
	for (tl = t->u.tl; tl != NULL && res; tl = tl->next) {
	    res &= evaltest(i, tl->t, m);
	}
	break;
    case EXISTS:
	res = 1;
	for (sl = t->u.sl; sl != NULL && res; sl = sl->next) {
	    char **headbody = NULL;
	    res &= (i->getheader(m, sl->s, &headbody) == SIEVE_OK);
	}
	break;
    case FALSE:
	res = 0;
	break;
    case TRUE:
	res = 1;
	break;
    case HEADER:
	res = 0;
	for (sl = t->u.h.sl; sl != NULL && !res; sl = sl->next) {
	    char **val;
	    int l;
	    if (i->getheader(m, sl->s, &val) != SIEVE_OK)
		continue;
	    for (pl = t->u.h.pl; pl != NULL && !res; pl = pl->next) {
		for (l = 0; val[l] != NULL && !res; l++) {
		    res |= t->u.h.comp(pl->p, val[l]);
		}
	    }
	}
	break;
    case NOT:
	res = !evaltest(i, t->u.t, m);
	break;
    case SIZE:
    {
	int sz;

	if (i->getsize(m, &sz) != SIEVE_OK)
	    break;

	if (t->u.sz.t == OVER) {
	    res = (sz > t->u.sz.n);
	} else { /* UNDER */
	    res = (sz < t->u.sz.n);
	}
	break;
    }
    }

    return res;
}

/* evaluate the script c.  returns negative if error was encountered,
   0 if it exited off the end, or positive if a stop action was
   encountered.

   note that this is very stack hungry; we just evaluate the AST in
   the naivest way.  if we implement some sort of depth limit, we'll
   be ok here; otherwise we'd want to transform it a little smarter
 */
static int eval(sieve_interp_t *i, commandlist_t *c, 
		void *m, action_list_t *actions)
{
    int res = 0;
    stringlist_t *sl;

    while (c != NULL) {
	switch (c->type) {
	case IF:
	    if (evaltest(i, c->u.i.t, m))
		res = eval(i, c->u.i.do_then, m, actions);
	    else
		res = eval(i, c->u.i.do_else, m, actions);
	    break;
	case REJCT:
	    res = do_reject(actions, c->u.str);
	    break;
	case FILEINTO:
	    for (sl = c->u.sl; res == 0 && sl != NULL; sl = sl->next) {
		res = do_fileinto(actions, sl->s);
	    }
	    break;
	case FORWARD:
	    for (sl = c->u.sl; res == 0 && sl != NULL; sl = sl->next) {
		res = do_forward(actions, sl->s);
	    }
	    break;
	case KEEP:
	    res = do_keep(actions);
	    break;
	case VACATION:
	    {
		char **body, buf[128], myaddr[256], *fromaddr;
		char *reply_to = NULL;
		int l;

		strcpy(buf, "to");
		l = i->getenvelope(m, buf, &body);
		if (body[0]) {
		    strncpy(myaddr, body[0], sizeof(myaddr) - 1);
		}
		if (l == SIEVE_OK) {
		    strcpy(buf, "from");
		    l = i->getenvelope(m, buf, &body);
		}
		if (l == SIEVE_OK && body[0]) {
		    /* we have to parse this address & decide whether we
		       want to respond to it */
		    void *data = NULL, *marker = NULL;
		    char *tmp;
		
		    parse_address(body[0], &data, &marker);
		    tmp = get_address(ADDRESS_ALL, &data, &marker);
		    reply_to = (tmp != NULL) ? xstrdup(tmp) : NULL;
		    free_address(&data, &marker);

		    /* first, is there a reply-to address? */
		    if (reply_to == NULL) {
			l = SIEVE_DONE;
		    }

		    /* first, is it from me? really should use a
		       compare_address function */
		    if (l == SIEVE_OK && !strcmp(myaddr, reply_to)) {
			l = SIEVE_DONE;
		    }

		    /* ok, is it any of the other addresses i've
		       specified? */
		    if (l == SIEVE_OK)
			for (sl = c->u.v.addresses; sl != NULL; sl = sl->next)
			    if (!strcmp(sl->s, reply_to))
				l = SIEVE_DONE;
		
		    /* ok, is it a system address? */
		    if (l == SIEVE_OK && sysaddr(reply_to)) {
			l = SIEVE_DONE;
		    }
		}

		if (l == SIEVE_OK) {
		    int found = 0;

		    /* ok, we're willing to respond to the sender.
		       but is this message to me?  that is, is my address
		       in the TO or CC fields? */
		    if (strcpy(buf, "to"), i->getheader(m, buf, &body) == SIEVE_OK)
			found = look_for_me(myaddr, c->u.v.addresses, body);

		    if (!found && (strcpy(buf, "cc"),
				   (i->getheader(m, buf, &body) == SIEVE_OK)))
			found = look_for_me(myaddr, c->u.v.addresses, body);

		    if (!found)
			l = SIEVE_DONE;
		}

		if (l == SIEVE_OK) {
		    /* ok, ok, if we got here maybe we should reply */
		
		    if (c->u.v.subject == NULL) {
			/* we have to generate a subject */
			char **s;
		    
			strcpy(buf, "subject");
			if (i->getheader(m, buf, &s) != SIEVE_OK ||
			    s[0] == NULL) {
			    strcpy(buf, "Automated reply");
			} else {
			    /* s[0] contains the original subject */
			    while (!strncasecmp(s[0], "Re: ", 4)) {
				s[0] += 4;
			    }
			    snprintf(buf, sizeof(buf), "Re: %s", s[0]);
			}
		    } else {
			/* user specified subject */
			strncpy(buf, c->u.v.subject, sizeof(buf));
		    }

		    /* who do we want the message coming from? */
		    if (c->u.v.addresses) {
			fromaddr = c->u.v.addresses->s;
		    } else {
			fromaddr = myaddr;
		    }
		
		    res = do_vacation(actions, reply_to, strdup(fromaddr),
				      strdup(buf),
				      c->u.v.message, c->u.v.days, c->u.v.mime);
		
		} else {
		    if (l != SIEVE_DONE) res = -1; /* something went wrong */
		}
		break;
	    }
	case STOP:
	    res = 1;
	    break;
	case DISCARD:
	    res = do_discard(actions);
	    break;
	case SETFLAG:
	    sl = c->u.sl;
	    res = do_setflag(actions, sl->s);
	    for (sl = sl->next; res == 0 && sl != NULL; sl = sl->next) {
		res = do_addflag(actions, sl->s);
	    }
	    break;
	case ADDFLAG:
	    for (sl = c->u.sl; res == 0 && sl != NULL; sl = sl->next) {
		res = do_addflag(actions, sl->s);
	    }
	    break;
	case REMOVEFLAG:
	    for (sl = c->u.sl; res == 0 && sl != NULL; sl = sl->next) {
		res = do_removeflag(actions, sl->s);
	    }
	    break;
	case MARK:
	    res = do_mark(actions);
	    break;
	case UNMARK:
	    res = do_unmark(actions);
	    break;
	case NOTIFY:
	    res = do_notify(i,m,actions, c->u.n.priority, c->u.n.method, c->u.n.message, 
			    stringlist_to_chararray(c->u.n.headers_list));
	    break;
	case DENOTIFY:
	    res = do_denotify(&actions);
	    break;

	}

	if (res) /* we've either encountered an error or a stop */
	    break;

	/* execute next command */
	c = c->next;
    }

    return res;
}

#define HASHSIZE 16

static int makehash(unsigned char hash[HASHSIZE], char *s1, char *s2)
{
    MD5_CTX ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, s1, strlen(s1));
    MD5Update(&ctx, s2, strlen(s2));
    MD5Final(hash, &ctx);

    return SIEVE_OK;
}

/* execute a script on a message, producing side effects via callbacks.
   it is the responsibility of the caller to save a message if this
   returns anything but SIEVE_OK. */
int sieve_execute_script(sieve_script_t *s, void *message_context)
{
    int ret = 0;
    int implicit_keep;
    action_list_t *actions, *a;

    actions = new_action_list();
    if (actions == NULL)
	return SIEVE_NOMEM;

    if (eval(&s->interp, s->cmds, message_context, actions) < 0)
	return SIEVE_RUN_ERROR;

    /* now perform actions attached to m */
    a = actions;
    implicit_keep = 1;
    while (a != NULL) {
	switch (a->a) {
	case ACTION_REJECT:
	    implicit_keep = 0;
	    if (!s->interp.reject)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.reject(a->u.rej.msg, s->interp.interp_context,
				   s->script_context,
				   message_context);
	    break;
	case ACTION_FILEINTO:
	    implicit_keep = 0;
	    if (!s->interp.fileinto)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.fileinto(a->u.fil.mbox, s->interp.interp_context,
				     s->script_context,
				     message_context);
	    break;
	case ACTION_KEEP:
	    implicit_keep = 0;
	    if (!s->interp.keep)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.keep(NULL, s->interp.interp_context,
				 s->script_context,
				 message_context);
	    break;
	case ACTION_REDIRECT:
	    implicit_keep = 0;
	    if (!s->interp.redirect)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.redirect(a->u.red.addr, s->interp.interp_context,
				     s->script_context,
				     message_context);
	    break;
	case ACTION_DISCARD:
	    implicit_keep = 0;
	    if (s->interp.discard) /* discard is optional */
		ret = s->interp.discard(NULL, s->interp.interp_context,
					s->script_context,
					message_context);
	    break;

	case ACTION_VACATION:
	    {
		unsigned char hash[HASHSIZE];

		if (!s->interp.vacation)
		    return SIEVE_INTERNAL_ERROR;

		/* first, let's figure out if we should respond to this */
		ret = makehash(hash, a->u.vac.addr, a->u.vac.msg);
		if (ret == SIEVE_OK) {
		    ret = s->interp.vacation->autorespond(hash, HASHSIZE, 
							  a->u.vac.days, s->interp.interp_context,
							  s->script_context, message_context);
		}
		if (ret == SIEVE_OK) {
		    /* send the response */
		    ret = s->interp.vacation->send_response(a->u.vac.addr, 
							    a->u.vac.fromaddr,
							    a->u.vac.subj,
							    a->u.vac.msg, a->u.vac.mime,
							    s->interp.interp_context, s->script_context, 
							    message_context);
		} else if (ret == SIEVE_DONE) {
		    ret = SIEVE_OK;
		}
	    
		break;
	    }

 
	case ACTION_SETFLAG:
	    if (!s->interp.setflag)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.setflag(a->u.fla.flag, s->interp.interp_context,
                                    s->script_context,
                                    message_context);
	    break;
	case ACTION_ADDFLAG:
	    if (!s->interp.addflag)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.addflag(a->u.fla.flag, s->interp.interp_context,
                                    s->script_context,
                                    message_context);
	    break;
	case ACTION_REMOVEFLAG:
	    if (!s->interp.removeflag)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.removeflag(a->u.fla.flag, s->interp.interp_context,
				       s->script_context,
				       message_context);
	    break;
	case ACTION_MARK:
	    if (!s->interp.mark)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.mark(NULL, s->interp.interp_context,
				 s->script_context,
				 message_context);
	    break;
	case ACTION_UNMARK:
	    if (!s->interp.unmark)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.unmark(NULL, s->interp.interp_context,
				   s->script_context,
				   message_context);
	    break;

	case ACTION_NOTIFY:
	    if (!s->interp.notify)
		return SIEVE_INTERNAL_ERROR;

	    ret = s->interp.notify(a->u.not.priority,
				   a->u.not.method,
				   a->u.not.message,
				   a->u.not.headers,
				   s->interp.interp_context,
				   s->script_context,
				   message_context);
	    break;
	case ACTION_DENOTIFY:
	    if (!s->interp.denotify)
		return SIEVE_INTERNAL_ERROR;
	    ret = s->interp.denotify(NULL, s->interp.interp_context,
				     s->script_context,
				     message_context);
	    break;

	case ACTION_NONE:
	    break;

	default:
	    ret = SIEVE_INTERNAL_ERROR;
	    break;
	}

	a = a->next;

	if (ret != SIEVE_OK) {
	    /* uh oh! better bail! */
	    break;
	}
    }

    if (implicit_keep) {
	ret = s->interp.keep(NULL, s->interp.interp_context,
			     s->script_context, message_context);
    }

    free_action_list(actions);

    return ret;
}
