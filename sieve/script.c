/* script.c -- sieve script functions
 * Larry Greenfield
 * $Id: script.c,v 1.54.4.2 2003/02/27 18:13:53 rjs3 Exp $
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <md5global.h>
#include <md5.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "xmalloc.h"

#include "sieve_interface.h"
#include "interp.h"
#include "script.h"
#include "tree.h"
#include "map.h"
#include "sieve.h"
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
	if (s->interp.markflags->flag) {
	    s->support.imapflags = 1;
	    return 1;
	} else {
	    return 0;
	}
    } else if (!strcmp("notify",req)) {
	if (s->interp.notify) {
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
    } else if (!strcmp("subaddress", req)) {
	s->support.subaddress = 1;
	return 1;
    } else if (!strcmp("relational", req)) {
	s->support.relational = 1;
	return 1;
    } else if (!strcmp("comparator-i;octet", req)) {
	return 1;
    } else if (!strcmp("comparator-i;ascii-casemap", req)) {
	return 1;
    } else if (!strcmp("comparator-i;ascii-numeric", req)) {
	s->support.i_ascii_numeric = 1;
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
    extern int yylineno;

    res = interp_verify(interp);
    if (res != SIEVE_OK) {
	return res;
    }

    s = (sieve_script_t *) xmalloc(sizeof(sieve_script_t));
    s->interp = *interp;
    s->script_context = script_context;
    /* clear all support bits */
    memset(&s->support, 0, sizeof(struct sieve_support));

    s->imapflags.flag = NULL; s->imapflags.nflags = 0;
    s->err = 0;

    yylineno = 1;		/* reset line number */
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

void free_imapflags(sieve_imapflags_t *imapflags)
{
    while (imapflags->nflags)
	free(imapflags->flag[--imapflags->nflags]);
    free(imapflags->flag);
    
    imapflags->flag = NULL;
}
  
int sieve_script_free(sieve_script_t **s)
{
    if (*s) {
	if ((*s)->cmds) {
	    free_tree((*s)->cmds);
	}
	free_imapflags(&(*s)->imapflags);
	free(*s);
    }

    return SIEVE_OK;
}
 
#define GROW_AMOUNT 100

static void add_header(sieve_interp_t *i, int isenv, char *header, 
		       void *message_context, char **out, 
		       int *outlen, int *outalloc)
{
    const char **h;
    int addlen;
    /* get header value */
    if (isenv)
	i->getenvelope(message_context, header, &h);	
    else
	i->getheader(message_context, header, &h);	

    if (!h || !h[0])
	return;

    addlen = strlen(h[0]) + 1;

    /* realloc if necessary */
    if ( (*outlen) + addlen >= *outalloc)
    {
	*outalloc = (*outlen) + addlen + GROW_AMOUNT;
	*out = xrealloc(*out, *outalloc);
    }

    /* add header value */
    strcat(*out,h[0]);

    *outlen += addlen;
}

static int fillin_headers(sieve_interp_t *i, const char *msg, 
			  void *message_context, char **out, int *outlen)
{
    int allocsize = GROW_AMOUNT;
    const char *c;
    int n;

    *out = xmalloc(GROW_AMOUNT);
    *outlen = 0;
    (*out)[0]='\0';

    if (msg == NULL) return SIEVE_OK;

    /* construct the message */
    c = msg;
    while (*c) {
	/* expand variables */
	if (!strncasecmp(c, "$from$", 6)) {
	    add_header(i, 0 ,"From", message_context, out, outlen, &allocsize);
	    c += 6;
	}
	else if (!strncasecmp(c, "$env-from$", 10)) {
	    add_header(i, 1, "From", message_context, out, outlen, &allocsize);
	    c += 10;
	}
	else if (!strncasecmp(c, "$subject$", 9)) {
	    add_header(i, 0, "Subject", message_context, out, outlen, &allocsize);
	    c += 9;
	}
	/* XXX need to do $text$ variables */
	else {
	    /* find length of plaintext up to next potential variable */
	    n = strcspn(c+1, "$") + 1; /* skip opening '$' */
	    /* realloc if necessary */
	    if ( (*outlen) + n+1 >= allocsize) {
		allocsize = (*outlen) + n+1 + GROW_AMOUNT;
		*out = xrealloc(*out, allocsize);
	    }
	    /* copy the plaintext */
	    strncat(*out, c, n);
	    (*out)[*outlen+n]='\0';
	    (*outlen) += n;
	    c += n;
	}
    }

    return SIEVE_OK;
}

static int sieve_addflag(sieve_imapflags_t *imapflags, const char *flag)
{
    int n;
    /* search for flag already in list */
    for (n = 0; n < imapflags->nflags; n++) {
	if (!strcmp(imapflags->flag[n], flag))
	    break;
    }
 
    /* add flag to list, iff not in list */
    if (n == imapflags->nflags) {
	imapflags->nflags++;
	imapflags->flag =
	    (char **) xrealloc((char *)imapflags->flag,
			       imapflags->nflags*sizeof(char *));
	imapflags->flag[imapflags->nflags-1] = xstrdup(flag);
    }
 
    return SIEVE_OK;
}

static int sieve_removeflag(sieve_imapflags_t *imapflags, const char *flag)
{
    int n;
    /* search for flag already in list */
    for (n = 0; n < imapflags->nflags; n++) {
      if (!strcmp(imapflags->flag[n], flag))
	break;
    }
    
     /* remove flag from list, iff in list */
    if (n < imapflags->nflags) 
      {
	free(imapflags->flag[n]);
	/*imapflags->nflags--;*/
	
	for (; n < imapflags->nflags; n++)
	  imapflags->flag[n] = imapflags->flag[n+1];
	
	imapflags->nflags--;
	if (imapflags->nflags)
	  {imapflags->flag =
	     (char **) xrealloc((char *)imapflags->flag,
				imapflags->nflags*sizeof(char *));}
	else
	  {free(imapflags->flag);
	  imapflags->flag=NULL;}
      }
    
    return SIEVE_OK;
}

static int send_notify_callback(sieve_interp_t *interp, void *message_context, 
				void * script_context, notify_list_t *notify, 
				char *actions_string, const char **errmsg)
{
    sieve_notify_context_t nc;
    char *out_msg, *build_msg;
    int out_msglen;    
    int ret;

    assert(notify->isactive);

    if (!notify->method || !notify->options ||
	!notify->priority || !notify->message) {
	return SIEVE_RUN_ERROR;
    }

    nc.method = notify->method;
    nc.options = notify->options ? notify->options : NULL;
    nc.priority = notify->priority;

    fillin_headers(interp, notify->message, message_context, 
		   &out_msg, &out_msglen);

    build_msg = xmalloc(out_msglen + strlen(actions_string) + 30);

    strcpy(build_msg, out_msg);
    strcat(build_msg, "\n\n");
    strcat(build_msg, actions_string);

    nc.message = build_msg;

    free(out_msg);

    ret = interp->notify(&nc,
			 interp->interp_context,
			 script_context,
			 message_context,
			 errmsg);    

    if (nc.options) {
	/* This stuff lives in the sieve script itself, we only
	 * need to free the array. */
	free(nc.options);
    }

    free(build_msg);

    return ret;
}

static char *action_to_string(action_t action)
{
    switch(action)
	{
	case ACTION_REJECT: return "Reject";
	case ACTION_FILEINTO: return "Fileinto";
	case ACTION_KEEP: return "Keep";
	case ACTION_REDIRECT: return "Redirect";
	case ACTION_DISCARD: return "Discard";
	case ACTION_VACATION: return "Vacation";
	case ACTION_SETFLAG: return "Setflag";
	case ACTION_ADDFLAG: return "Addflag";
	case ACTION_REMOVEFLAG: return "Removeflag";
	case ACTION_MARK: return "Mark";
	case ACTION_UNMARK: return "Unmark";
	case ACTION_NOTIFY: return "Notify";
	case ACTION_DENOTIFY: return "Denotify";
	default: return "Unknown";
	}

    return "Error!";
}

static char *sieve_errstr(int code)
{
    switch (code)
	{
	case SIEVE_FAIL: return "Generic Error";
	case SIEVE_NOT_FINALIZED: return "Sieve not finalized";
	case SIEVE_PARSE_ERROR: return "Parse error";
	case SIEVE_RUN_ERROR: return "Run error";
	case SIEVE_INTERNAL_ERROR: return "Internal Error";
	case SIEVE_NOMEM: return "No memory";
	default: return "Unknown error";
	}

    return "Error!";
}

#define HASHSIZE 16

static int makehash(unsigned char hash[HASHSIZE],
		    const char *s1, const char *s2)
{
    MD5_CTX ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, s1, strlen(s1));
    MD5Update(&ctx, s2, strlen(s2));
    MD5Final(hash, &ctx);

    return SIEVE_OK;
}


/******************************bytecode functions*****************************
 *****************************************************************************/

/* Load a compiled script */
int sieve_script_load(sieve_interp_t *interp, int fd, const char *name,
		      void *script_context, sieve_bytecode_t **ret) 
{
    struct stat sbuf;
    sieve_bytecode_t *r;
   
    if(!ret || !interp) return SIEVE_FAIL;
    if(!name) name = "";
    
    if (fstat(fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstating sieve script: %m");
	return SIEVE_FAIL;
    }

    r = (sieve_bytecode_t *)xmalloc(sizeof(sieve_bytecode_t));
    if(!r) return SIEVE_NOMEM;
    
    memset(r, 0, sizeof(*r));

    r->fd = fd;
    r->interp = interp;
    r->script_context = script_context;
    
    map_refresh(fd, 1, &r->data, &r->len, sbuf.st_size,
		"sievescript", name);

    *ret = r;
    return SIEVE_OK;
}



int sieve_script_unload(sieve_bytecode_t **s) 
{
    if(s && *s) {
	map_free(&((*s)->data), &((*s)->len));
	close((*s)->fd);
	free(*s);
	*s = NULL;
    } 
    /*i added this else, i'm not sure why, but this function always returned SIEVE_FAIL*/
    else
      return SIEVE_FAIL;
    return SIEVE_OK;
}


#define ACTIONS_STRING_LEN 4096

static int do_sieve_error(int ret,
			  sieve_interp_t *interp,
			  void *script_context,
			  void *message_context,
			  sieve_imapflags_t * imapflags,
			  action_list_t *actions,
			  notify_list_t *notify_list,
			  /* notify_action_t *notify_action,*/
			  int lastaction,
			  int implicit_keep,
			  char *actions_string,
			  const char *errmsg
			  ) 
{
   if (ret != SIEVE_OK) {
	if (lastaction == -1) /* we never executed an action */
	    snprintf(actions_string+strlen(actions_string),
		     ACTIONS_STRING_LEN-strlen(actions_string),
		     "script execution failed: %s\n",
		     errmsg ? errmsg : sieve_errstr(ret));
	else
	    snprintf(actions_string+strlen(actions_string),
		     ACTIONS_STRING_LEN-strlen(actions_string),
		     "%s action failed: %s\n",
		     action_to_string(lastaction),
		     errmsg ? errmsg : sieve_errstr(ret));
    }
 
   
    /* Process notify actions */
    if (interp->notify && notify_list) 
      {
	notify_list_t *n = notify_list;
	int notify_ret = SIEVE_OK;
	
	while (n != NULL) 
	  {
	    if (n->isactive) 
	      {
	      lastaction = ACTION_NOTIFY;
	       notify_ret = send_notify_callback(interp, message_context, 
						script_context,n,
						actions_string, &errmsg);
	      ret |= notify_ret;
	      }
	    n = n->next;
	  }
	
	if (notify_list) free_notify_list(notify_list);
	notify_list = NULL;	/* don't try any notifications again */
	
	
	if (notify_ret != SIEVE_OK) 
	  return do_sieve_error(ret, interp, script_context, message_context,
				imapflags, actions, notify_list, lastaction,
				implicit_keep, actions_string, errmsg);
      
      }
    
    if ((ret != SIEVE_OK) && interp->err) {
	char buf[1024];
	if (lastaction == -1) /* we never executed an action */
	    sprintf(buf, "%s", errmsg ? errmsg : sieve_errstr(ret));
	else
	    sprintf(buf, "%s: %s", action_to_string(lastaction),
		    errmsg ? errmsg : sieve_errstr(ret));
 
	ret |= interp->execute_err(buf, interp->interp_context,
				   script_context, message_context);
    }

    if (implicit_keep) {
	sieve_keep_context_t keep_context;
	int keep_ret;
	keep_context.imapflags = imapflags;
 
	lastaction = ACTION_KEEP;
	keep_ret = interp->keep(&keep_context, interp->interp_context,
				script_context, message_context, &errmsg);
	ret |= keep_ret;
        if (keep_ret == SIEVE_OK)
            snprintf(actions_string+strlen(actions_string),
		     sizeof(actions_string)-strlen(actions_string),
		     "Kept\n");
	else {
	    implicit_keep = 0;	/* don't try an implicit keep again */
	    return do_sieve_error(ret, interp, script_context, message_context,
				  imapflags, actions, notify_list, lastaction,
				  implicit_keep, actions_string, errmsg);
	}
    }

    if (actions)
	free_action_list(actions);

    return ret;
}


static int do_action_list(sieve_interp_t *interp,
			  void *script_context,
			  void *message_context,
			  sieve_imapflags_t *imapflags,
			  action_list_t *actions,
			  notify_list_t *notify_list,
			  /* notify_action_t *notify_action,*/
			  char *actions_string,
			  const char *errmsg) 
{
    action_list_t *a;
    action_t lastaction = -1;
    int ret = 0;
    int implicit_keep = 0;
    
    strcpy(actions_string,"Action(s) taken:\n");
  
    /* now perform actions attached to m */
    a = actions;
    implicit_keep = 1;
    while (a != NULL) {
	lastaction = a->a;
	errmsg = NULL;
	switch (a->a) {
	case ACTION_REJECT:
	    implicit_keep = 0;
	    if (!interp->reject)
		return SIEVE_INTERNAL_ERROR;
	    ret = interp->reject(&a->u.rej,
				 interp->interp_context,
				 script_context,
				 message_context,
				 &errmsg);
	    
	    if (ret == SIEVE_OK)
		snprintf(actions_string+strlen(actions_string),
			 sizeof(actions_string)-strlen(actions_string), 
			 "Rejected with: %s\n", a->u.rej.msg);

	    break;
	case ACTION_FILEINTO:
	    implicit_keep = 0;
	    if (!interp->fileinto)
		return SIEVE_INTERNAL_ERROR;
	    ret = interp->fileinto(&a->u.fil,
				   interp->interp_context,
				   script_context,
				   message_context,
				   &errmsg);

	    if (ret == SIEVE_OK)
		snprintf(actions_string+strlen(actions_string),
			 sizeof(actions_string)-strlen(actions_string),
			 "Filed into: %s\n",a->u.fil.mailbox);
	    break;
	case ACTION_KEEP:
	    implicit_keep = 0;
	    if (!interp->keep)
		return SIEVE_INTERNAL_ERROR;
	    ret = interp->keep(&a->u.keep,
			       interp->interp_context,
			       script_context,
			       message_context,
			       &errmsg);
	    if (ret == SIEVE_OK)
		snprintf(actions_string+strlen(actions_string),
			 sizeof(actions_string)-strlen(actions_string),
			 "Kept\n");
	    break;
	case ACTION_REDIRECT:
	    implicit_keep = 0;
	    if (!interp->redirect)
		return SIEVE_INTERNAL_ERROR;
	    ret = interp->redirect(&a->u.red,
				   interp->interp_context,
				   script_context,
				   message_context,
				   &errmsg);
	    if (ret == SIEVE_OK)
		snprintf(actions_string+strlen(actions_string),
			 sizeof(actions_string)-strlen(actions_string),
			 "Redirected to %s\n", a->u.red.addr);
	    break;
	case ACTION_DISCARD:
	    implicit_keep = 0;
	    if (interp->discard) /* discard is optional */
		ret = interp->discard(NULL, interp->interp_context,
				      script_context,
				      message_context,
				      &errmsg);
	    if (ret == SIEVE_OK)
		snprintf(actions_string+strlen(actions_string),
			 sizeof(actions_string)-strlen(actions_string),
			 "Discarded\n");
	    break;

	case ACTION_VACATION:
	    {
		unsigned char hash[HASHSIZE];

		if (!interp->vacation)
		    return SIEVE_INTERNAL_ERROR;

		/* first, let's figure out if we should respond to this */
		ret = makehash(hash, a->u.vac.send.addr,
			       a->u.vac.send.msg);

		if (ret == SIEVE_OK) {
		    a->u.vac.autoresp.hash = hash;
		    a->u.vac.autoresp.len = HASHSIZE;
		    ret = interp->vacation->autorespond(&a->u.vac.autoresp,
							interp->interp_context,
							script_context,
							message_context,
							&errmsg);
		}
		if (ret == SIEVE_OK) {
		    /* send the response */
		    ret = interp->vacation->send_response(&a->u.vac.send,
							  interp->interp_context,
							  script_context, 
							  message_context,
							  &errmsg);

		    if (ret == SIEVE_OK)
			snprintf(actions_string+strlen(actions_string),
				 sizeof(actions_string)-strlen(actions_string),
				 "Sent vacation reply\n");

		} else if (ret == SIEVE_DONE) {
		    snprintf(actions_string+strlen(actions_string),
			     sizeof(actions_string)-strlen(actions_string),
			     "Vacation reply suppressed\n");

		    ret = SIEVE_OK;
		}
	    
		break;
	    }

 
	case ACTION_SETFLAG:
	    free_imapflags(imapflags);
	    ret = sieve_addflag(imapflags, a->u.fla.flag);
	    break;
	case ACTION_ADDFLAG:
	    ret = sieve_addflag(imapflags, a->u.fla.flag);
	    break;
	case ACTION_REMOVEFLAG:
	    ret = sieve_removeflag(imapflags, a->u.fla.flag);
	    break;
	case ACTION_MARK:
	    {
		int n = interp->markflags->nflags;

		ret = SIEVE_OK;
		while (n && ret == SIEVE_OK) {
		    ret = sieve_addflag(imapflags,
					interp->markflags->flag[--n]);
		}
		break;
	    }
	case ACTION_UNMARK:
	  {
	   
		int n = interp->markflags->nflags;
		ret = SIEVE_OK;
		while (n && ret == SIEVE_OK) {
		    ret = sieve_removeflag(imapflags,
					   interp->markflags->flag[--n]);
		}
		break;
	    }

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

    return do_sieve_error(ret, interp, script_context, message_context, 
			  imapflags, actions, notify_list, lastaction, 
			  implicit_keep, actions_string, errmsg);
}


/* execute some bytecode */
int sieve_eval_bc(sieve_interp_t *i, const void *bc_in, unsigned int bc_len,
		  void *m, sieve_imapflags_t * imapflags,
		  action_list_t *actions,
		  notify_list_t *notify_list,
		  const char **errmsg);

int sieve_execute_bytecode(sieve_bytecode_t *bc, void *message_context) 
{
    action_list_t *actions = NULL;
    notify_list_t *notify_list = NULL;
    /*   notify_action_t *notify_action;*/
    action_t lastaction = -1;
    int ret;
    char actions_string[ACTIONS_STRING_LEN] = "";
    const char *errmsg = NULL;
    sieve_imapflags_t imapflags;
    
    imapflags.flag = NULL; 
    imapflags.nflags = 0;
    
    if (bc->interp->notify)
    {
	notify_list = new_notify_list();
	if (notify_list == NULL)
	    return SIEVE_NOMEM;
    }

    actions = new_action_list();
    if (actions == NULL) 
    {
	ret = SIEVE_NOMEM;
	return do_sieve_error(ret, bc->interp, bc->script_context,
			      message_context, &imapflags,
			      actions, notify_list, lastaction, 0,
			      actions_string, errmsg);
    }
    
    if (sieve_eval_bc(bc->interp, bc->data, bc->len, message_context, 
		      &imapflags, actions, notify_list, &errmsg) < 0)
	return SIEVE_RUN_ERROR;  
    
    return do_action_list(bc->interp, bc->script_context, message_context, 
			  &imapflags, actions, notify_list, actions_string,
			  errmsg);
}
