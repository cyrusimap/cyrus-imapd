/* index_ext.c -- Routines for dealing with the index file in the imapd
 *                for IMAP extensions (SORT, THREAD, VIEW)
 *
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
 *
 */
/*
 * $Id: index_ext.c,v 1.1 2001/02/25 05:09:42 ken3 Exp $
 */
#include <config.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include "index.h"
#include "assert.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "imapd.h"
#include "xmalloc.h"
#include "lsort.h"
#include "message.h"
#include "parseaddr.h"
#include "hash.h"
#include "stristr.h"

extern int errno;

/* Special "sort criteria" to load message-id and references/in-reply-to
 * into msgdata array for threaders that need them.
 */
#define LOAD_IDS	256

typedef struct msgdata {
    unsigned msgno;		/* message number */
    char *msgid;		/* message ID */
    char **ref;			/* array of references */
    int nref;			/* number of references */
    time_t date;		/* sent date & time of message
				   from Date: header (adjusted by time zone) */
    char *cc;			/* local-part of first "cc" address */
    char *from;			/* local-part of first "from" address */
    char *to;			/* local-part of first "to" address */
    char *xsubj;		/* extracted subject text */
    unsigned xsubj_hash;	/* hash of extracted subject text */
    int is_refwd;		/* is message a reply or forward? */
    char **annot;		/* array of annotation attribute values
				   (stored in order of sortcrit) */
    int nannot;			/* number of annotation values */
    struct msgdata *next;
} MsgData;

typedef struct thread {
    MsgData *msgdata;		/* message data */
    struct thread *parent;	/* parent message */
    struct thread *child;	/* first child message */
    struct thread *next;	/* next sibling message */
} Thread;

struct rootset {
    Thread *root;
    unsigned nroot;
};

struct thread_algorithm {
    char *alg_name;
    void (*threader)(struct mailbox *mailbox, 
		     unsigned *msgno_list, int nmsg, int usinguid);
};

struct sortrock {
    struct mailbox *mailbox;
    struct sortcrit *sortcrit;
};

/* Forward declarations */
static char *find_msgid(char *str, int *len);
static char *get_localpart_addr(const char *header);
static char *index_extract_subject(const char *subj, int *is_refwd);
static char *_index_extract_subject(char *s, int *is_refwd);
static void index_get_ids(MsgData *msgdata,
			  char *envtokens[], const char *headers);
static MsgData *index_msgdata_load(struct mailbox *mailbox,
				   unsigned *msgno_list, int n,
				   struct sortcrit *sortcrit);

static void *index_sort_getnext(MsgData *node);
static void index_sort_setnext(MsgData *node, MsgData *next);
static int index_sort_compare(MsgData *md1, MsgData *md2,
			      struct sortrock *call_data);
static void index_msgdata_free(MsgData *md);

static void *index_thread_getnext(Thread *thread);
static void index_thread_setnext(Thread *thread, Thread *next);
static int index_thread_compare(Thread *t1, Thread *t2,
				struct sortrock *call_data);
static void index_thread_orderedsubj(struct mailbox *mailbox,
				     unsigned *msgno_list, int nmsg,
				     int usinguid);
static void index_thread_sort(struct mailbox *mailbox, 
			      Thread *root, struct sortcrit *sortcrit);
static void index_thread_print(struct mailbox *mailbox,
			       Thread *threads, int usinguid);
static void index_thread_ref(struct mailbox *mailbox, 
			     unsigned *msgno_list, int nmsg, int usinguid);

/* NOTE: Make sure these are listed in CAPABILITY_STRING */
static const struct thread_algorithm thread_algs[] = {
    { "ORDEREDSUBJECT", index_thread_orderedsubj },
    { "REFERENCES", index_thread_ref },
    { NULL, NULL }
};

/*
 * Performs a SORT command
 */
void
index_sort(struct mailbox *mailbox,
	   struct sortcrit *sortcrit,
	   struct searchargs *searchargs,
	   int usinguid)
{
    unsigned *msgno_list;
    MsgData *msgdata = NULL, *freeme = NULL;
    int nmsg;
    clock_t start = clock();

    /* Search for messages based on the given criteria */
    nmsg = _index_search(&msgno_list, mailbox, searchargs);

    prot_printf(imapd_out, "* SORT");

    if (nmsg) {
	struct sortrock sortrock;

	/* Create/load the msgdata array */
	freeme = msgdata = index_msgdata_load(mailbox, 
					      msgno_list, nmsg, sortcrit);
	free(msgno_list);

	sortrock.mailbox = mailbox;
	sortrock.sortcrit = sortcrit;
	/* Sort the messages based on the given criteria */
	msgdata = lsort(msgdata,
			(void * (*)(void*)) index_sort_getnext,
			(void (*)(void*,void*)) index_sort_setnext,
			(int (*)(void*,void*,void*)) index_sort_compare,
			&sortrock);

	/* Output the sorted messages */ 
	while (msgdata) {
	    prot_printf(imapd_out, " %u",
			usinguid ? UID(mailbox, msgdata->msgno) : msgdata->msgno);

	    /* free contents of the current node */
	    index_msgdata_free(msgdata);

	    msgdata = msgdata->next;
	}

	/* free the msgdata array */
	free(freeme);
    }

    prot_printf(imapd_out, "\r\n");

    /* debug */
    if (CONFIG_TIMING_VERBOSE) {
	char *key_names[] = { "SEQUENCE", "ARRIVAL", "CC", "DATE", "FROM",
			      "SIZE", "SUBJECT", "TO", "ANNOTATION" };
	char buf[1024] = "";

	while (sortcrit->key) {
	    if (sortcrit->flags & SORT_REVERSE) strcat(buf, "REVERSE ");
	    strcat(buf, key_names[sortcrit->key]);
	    switch (sortcrit->key) {
	    case SORT_ANNOTATION:
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1,
			 " \"%s\" \"%s\"",
			 sortcrit->args.annot.entry, sortcrit->args.annot.attrib);
		break;
	    }
	    if ((++sortcrit)->key) strcat(buf, " ");
	}

	syslog(LOG_DEBUG, "SORT (%s) processing time: %d msg in %f sec",
	       buf, nmsg, (clock() - start) / (double) CLOCKS_PER_SEC);
    }
}

/*
 * Performs a THREAD command
 */
void index_thread(struct mailbox *mailbox, int algorithm,
		  struct searchargs *searchargs, int usinguid)
{
    unsigned *msgno_list;
    int nmsg;
    clock_t start = clock();

    /* Search for messages based on the given criteria */
    nmsg = _index_search(&msgno_list, mailbox, searchargs);

    if (nmsg) {
	/* Thread messages using given algorithm */
	(*thread_algs[algorithm].threader)(mailbox, 
					   msgno_list, nmsg, usinguid);

	free(msgno_list);
    }

    /* print an empty untagged response */
    else
	index_thread_print(mailbox, NULL, usinguid);

    if (CONFIG_TIMING_VERBOSE) {
	/* debug */
	syslog(LOG_DEBUG, "THREAD %s processing time: %d msg in %f sec",
	       thread_algs[algorithm].alg_name, nmsg,
	       (clock() - start) / (double) CLOCKS_PER_SEC);
    }
}

/*
 * Creates a list of msgdata.
 *
 * We fill these structs with the processed info that will be needed
 * by the specified sort criteria.
 */
#define ANNOTGROWSIZE	10

static MsgData *index_msgdata_load(struct mailbox *mailbox, 
				   unsigned *msgno_list, int n,
				   struct sortcrit *sortcrit)
{
    MsgData *md, *cur;
    const char *cacheitem = NULL, *env = NULL, 
	*headers = NULL, *from = NULL, *to = NULL, *cc = NULL, *subj = NULL;
    int i, j;
    char *tmpenv;
    char *envtokens[NUMENVTOKENS];
    int did_cache, did_env;
    int label;
    int annotsize;

    if (!n)
	return NULL;

    /* create an array of MsgData to use as nodes of linked list */
    md = (MsgData *) xmalloc(n * sizeof(MsgData));
    memset(md, 0, n * sizeof(MsgData));

    for (i = 0, cur = md; i < n; i++, cur = cur->next) {
	/* set msgno */
	cur->msgno = msgno_list[i];

	/* set pointer to next node */
	cur->next = (i+1 < n ? cur+1 : NULL);

	did_cache = did_env = 0;
	tmpenv = NULL;
	annotsize = 0;

	for (j = 0; sortcrit[j].key; j++) {
	    label = sortcrit[j].key;

	    if ((label == SORT_CC || label == SORT_DATE ||
		 label == SORT_FROM || label == SORT_SUBJECT ||
		 label == SORT_TO || label == LOAD_IDS) &&
		!did_cache) {

		/* fetch cached info */
		env = mailbox->cache_base + CACHE_OFFSET(mailbox, cur->msgno);
		cacheitem = CACHE_ITEM_NEXT(env); /* bodystructure */
		cacheitem = CACHE_ITEM_NEXT(cacheitem); /* body */
		cacheitem = CACHE_ITEM_NEXT(cacheitem); /* section */
		headers = CACHE_ITEM_NEXT(cacheitem);
		from = CACHE_ITEM_NEXT(headers);
		to = CACHE_ITEM_NEXT(from);
		cc = CACHE_ITEM_NEXT(to);
		cacheitem = CACHE_ITEM_NEXT(cc); /* bcc */
		subj = CACHE_ITEM_NEXT(cacheitem);

		did_cache++;
	    }

	    if ((label == SORT_DATE || label == LOAD_IDS) &&
		!did_env) {

		/* make a working copy of envelope -- strip outer ()'s */
		tmpenv = xstrndup(env+5, strlen(env+4) - 2);

		/* parse envelope into tokens */
		parse_cached_envelope(tmpenv, envtokens);

		did_env++;
	    }

	    switch (label) {
	    case SORT_CC:
		cur->cc = get_localpart_addr(cc+4);
		break;
	    case SORT_DATE:
		cur->date = message_parse_date(envtokens[ENV_DATE],
					       PARSE_TIME | PARSE_ZONE);
		break;
	    case SORT_FROM:
		cur->from = get_localpart_addr(from+4);
		break;
	    case SORT_SUBJECT:
		cur->xsubj = index_extract_subject(subj+4, &cur->is_refwd);
		cur->xsubj_hash = hash(cur->xsubj);
		break;
	    case SORT_TO:
		cur->to = get_localpart_addr(to+4);
		break;
 	    case SORT_ANNOTATION:
 		/* reallocate space for the annotation values if necessary */
 		if (cur->nannot == annotsize) {
 		    annotsize += ANNOTGROWSIZE;
 		    cur->annot = (char **)
 			xrealloc(cur->annot, annotsize * sizeof(char *));
 		}

 		/* fetch attribute value - we fake it for now */
 		cur->annot[cur->nannot] = xstrdup(sortcrit[j].args.annot.attrib);
 		cur->nannot++;
 		break;
	    case LOAD_IDS:
		index_get_ids(cur, envtokens, headers+4);
		break;
	    }
	}

	if (tmpenv) free(tmpenv);
    }

    return md;
}

/*
 * Get the 'local-part' of an address from a header
 */
static char *get_localpart_addr(const char *header)
{
    struct address *addr = NULL;
    char *ret;

    parseaddr_list(header, &addr);
    ret = xstrdup(addr && addr->mailbox ? addr->mailbox : "");
    parseaddr_free(addr);
    return ret;
}

/*
 * Extract base subject from subject header
 *
 * This is a wrapper around _index_extract_subject() which preps the
 * subj NSTRING and checks for Netscape "[Fwd: ]".
 */
static char *index_extract_subject(const char *subj, int *is_refwd)
{
    char *buf, *s, *base;

    /* parse the subj NSTRING and make a working copy */
    if (!strcmp(subj, "NIL"))		       		/* NIL? */
	return xstrdup("");				/* yes, return empty */

    else
	buf = (*subj == '"') ?				/* quoted? */
	    xstrndup(subj + 1, strlen(subj) - 2) :	/* yes, strip quotes */
	xstrdup(strchr(subj, '}') + 3);			/* literal, skip { } */

    for (s = buf;;) {
	base = _index_extract_subject(s, is_refwd);

	/* If we have a Netscape "[Fwd: ...]", extract the contents */
	if (!strncasecmp(base, "[fwd:", 5) &&
	    base[strlen(base) - 1]  == ']') {

	    /* inc refwd counter */
	    *is_refwd += 1;

	    /* trim "]" */
	    base[strlen(base) - 1] = '\0';

	    /* trim "[fwd:" */
	    s = base + 5;
	}
	else	/* otherwise, we're done */
	    break;
    }

    base = xstrdup(base);

    free(buf);

    return base;
}

/*
 * Guts if subject extraction.
 *
 * Takes a subject string and returns a pointer to the base.
 */
static char *_index_extract_subject(char *s, int *is_refwd)
{
    char *base, *x;

    /* trim trailer
     *
     * start at the end of the string and work towards the front,
     * resetting the end of the string as we go.
     */
    for (x = s + strlen(s) - 1; x >= s;) {
	if (isspace((int) *x)) {                        /* whitespace? */
	    *x = '\0';					/* yes, trim it */
	    x--;					/* skip past it */
	}
	else if (x - s >= 4 &&
		 !strncasecmp(x-4, "(fwd)", 5)) {	/* "(fwd)"? */
	    *(x-4) = '\0';				/* yes, trim it */
	    x -= 5;					/* skip past it */
	    *is_refwd += 1;				/* inc refwd counter */
	}
	else
	    break;					/* we're done */
    }

    /* trim leader
     *
     * start at the head of the string and work towards the end,
     * skipping over stuff we don't care about.
     */
    for (base = s; base;) {
	if (isspace((int) *base)) base++;		/* whitespace? */

	/* possible refwd */
	else if ((!strncasecmp(base, "re", 2) &&	/* "re"? */
		  (x = base + 2)) ||			/* yes, skip past it */
		 (!strncasecmp(base, "fwd", 3) &&	/* "fwd"? */
		  (x = base + 3)) ||			/* yes, skip past it */
		 (!strncasecmp(base, "fw", 2) &&	/* "fw"? */
		  (x = base + 2))) {			/* yes, skip past it */
	    int count = 0;				/* init counter */
	    
	    while (isspace((int) *x)) x++;		/* skip whitespace */

	    if (*x == '[') {				/* start of blob? */
		for (x++; x;) {				/* yes, get count */
		    if (!*x) {				/* end of subj, quit */
			x = NULL;
			break;
		    }
		    else if (*x == ']')			/* end of blob, done */
			break;
		    			/* if we have a digit, and we're still
					   counting, keep building the count */
		    else if (isdigit((int) *x) && count != -1)
			count = count * 10 + *x - '0';
		    else				/* no digit, */
			count = -1;			/*  abort counting */
		    x++;
		}

		if (x)					/* end of blob? */
		    x++;				/* yes, skip past it */
		else
		    break;				/* no, we're done */
	    }

	    while (isspace((int) *x)) x++;              /* skip whitespace */

	    if (*x == ':') {				/* ending colon? */
		base = x + 1;				/* yes, skip past it */
		*is_refwd += (count > 0 ? count : 1);	/* inc refwd counter
							   by count or 1 */
	    }
	    else
		break;					/* no, we're done */
	}

#if 0 /* do nested blobs - wait for decision on this */
	else if (*base == '[') {			/* start of blob? */
	    int count = 1;				/* yes, */
	    x = base + 1;				/*  find end of blob */
	    while (count) {				/* find matching ']' */
		if (!*x) {				/* end of subj, quit */
		    x = NULL;
		    break;
		}
		else if (*x == '[')			/* new open */
		    count++;				/* inc counter */
		else if (*x == ']')			/* close */
		    count--;				/* dec counter */
		x++;
	    }

	    if (!x)					/* blob didn't close */
		break;					/*  so quit */

	    else if (*x)				/* end of subj? */
		base = x;				/* no, skip blob */
#else
	else if (*base == '[' &&			/* start of blob? */
		 (x = strpbrk(base+1, "[]")) &&		/* yes, end of blob */
		 *x == ']') {				/*  (w/o nesting)? */

	    if (*(x+1))					/* yes, end of subj? */
		base = x + 1;				/* no, skip blob */
#endif
	    else
		break;					/* yes, return blob */
	}
	else
	    break;					/* we're done */
    }

    return base;
}

/* Find a message-id looking thingy in a string.  Returns a pointer to the
 * id and the length is returned in the *len parameter.
 *
 * This is a poor-man's way of finding the message-id.  We simply look for
 * any string having the format "< ... @ ... >" and assume that the mail
 * client created a properly formatted message-id.
 */
static char *find_msgid(char *str, int *len)
{
    char *s, *p;

    *len = 0;
    p = str;
    while (p && (s = strchr(p, '<'))) {
	p = s + 1;
	while (*p && *p != '@' && *p != '<' && *p != '>') p++;
	if (*p != '@') continue;
	while (*p && *p != '<' && *p != '>') p++;
	if (*p == '>') {
	    *len = p - s + 1;
	    return s;
	}	    
    }

    return NULL;
}

/* Get message-id, and references/in-reply-to */
#define REFGROWSIZE 10

void index_get_ids(MsgData *msgdata, char *envtokens[], const char *headers)
{
    char *msgid, *refstr, *ref, *in_reply_to;
    int len, refsize = REFGROWSIZE;
    char buf[100];

    /* get msgid */
    msgid = find_msgid(envtokens[ENV_MSGID], &len);
    /* if we have one, make a copy of it */
    if (msgid)
	msgdata->msgid = xstrndup(msgid, len);
    /* otherwise, create one */
    else {
	sprintf(buf, "<Empty-ID: %u>", msgdata->msgno);
	msgdata->msgid = xstrdup(buf);
    }

    /* grab the References header */
    if ((refstr = stristr(headers, "references:"))) {
	/* allocate some space for refs */
	msgdata->ref = (char **) xmalloc(refsize * sizeof(char *));
	/* find references */
	while ((ref = find_msgid(refstr, &len)) != NULL) {
	    /* reallocate space for this msgid if necessary */
	    if (msgdata->nref == refsize) {
		refsize += REFGROWSIZE;
		msgdata->ref = (char **)
		    xrealloc(msgdata->ref, refsize * sizeof(char *));
	    }
	    /* store this msgid in the array */
	    msgdata->ref[msgdata->nref++] = xstrndup(ref, len);
	    /* skip past this msgid */
	    refstr = ref + len;
	}
    }

    /* if we have no references, try in-reply-to */
    if (!msgdata->nref) {
	/* get in-reply-to id */
	in_reply_to = find_msgid(envtokens[ENV_INREPLYTO], &len);
	/* if we have an in-reply-to id, make it the ref */
	if (in_reply_to) {
	    msgdata->ref = (char **) xmalloc(sizeof(char *));
	    msgdata->ref[msgdata->nref++] = xstrndup(in_reply_to, len);
	}
    }
}

/*
 * Getnext function for sorting message lists.
 */
static void *index_sort_getnext(MsgData *node)
{
    return node->next;
}

/*
 * Setnext function for sorting message lists.
 */
static void index_sort_setnext(MsgData *node, MsgData *next)
{
    node->next = next;
}

/*
 * Function for comparing two integers.
 */
static int numcmp(int i1, int i2)
{
    return ((i1 < i2) ? -1 : (i1 > i2) ? 1 : 0);
}

/*
 * Comparison function for sorting message lists.
 */
static int index_sort_compare(MsgData *md1, MsgData *md2,
			      struct sortrock *sortrock)
{
    int reverse, ret = 0, i = 0, ann = 0;
    struct sortcrit *sortcrit = sortrock->sortcrit;
    struct mailbox *mailbox = sortrock->mailbox;

    do {
	/* determine sort order from reverse flag bit */
	reverse = sortcrit[i].flags & SORT_REVERSE;

	switch (sortcrit[i].key) {
	case SORT_SEQUENCE:
	    ret = numcmp(md1->msgno, md2->msgno);
	    break;
	case SORT_ARRIVAL:
	    ret = numcmp(INTERNALDATE(mailbox, md1->msgno), 
			 INTERNALDATE(mailbox, md2->msgno));
	    break;
	case SORT_CC:
	    ret = strcmp(md1->cc, md2->cc);
	    break;
	case SORT_DATE:
	    ret = (md1->date && md2->date) ?
		numcmp(md1->date, md2->date) : numcmp(md1->msgno, md2->msgno);
	    break;
	case SORT_FROM:
	    ret = strcmp(md1->from, md2->from);
	    break;
	case SORT_SIZE:
	    ret = numcmp(SIZE(mailbox, md1->msgno), SIZE(mailbox, md2->msgno));
	    break;
	case SORT_SUBJECT:
	    ret = strcmp(md1->xsubj, md2->xsubj);
	    break;
	case SORT_TO:
	    ret = strcmp(md1->to, md2->to);
	    break;
	case SORT_ANNOTATION:
	    ret = strcmp(md1->annot[ann], md2->annot[ann]);
	    ann++;
	    break;
	}
    } while (!ret && sortcrit[i++].key != SORT_SEQUENCE);

    return (reverse ? -ret : ret);
}

/*
 * Free a msgdata node.
 */
static void index_msgdata_free(MsgData *md)
{
#define FREE(x)	if (x) free(x)
    int i;

    if (!md)
	return;
    FREE(md->cc);
    FREE(md->from);
    FREE(md->to);
    FREE(md->xsubj);
    FREE(md->msgid);
    for (i = 0; i < md->nref; i++)
	free(md->ref[i]);
    FREE(md->ref);
    for (i = 0; i < md->nannot; i++)
	free(md->annot[i]);
    FREE(md->annot);
}

/*
 * Getnext function for sorting thread lists.
 */
static void *index_thread_getnext(Thread *thread)
{
    return thread->next;
}

/*
 * Setnext function for sorting thread lists.
 */
static void index_thread_setnext(Thread *thread, Thread *next)
{
    thread->next = next;
}

/*
 * Comparison function for sorting threads.
 */
static int index_thread_compare(Thread *t1, Thread *t2,
				struct sortrock *call_data)
{
    MsgData *md1, *md2;

    /* if the container is empty, use the first child's container */
    md1 = t1->msgdata ? t1->msgdata : t1->child->msgdata;
    md2 = t2->msgdata ? t2->msgdata : t2->child->msgdata;
    return index_sort_compare(md1, md2, call_data);
}

/*
 * Sort a list of threads.
 */
static void index_thread_sort(struct mailbox *mailbox,
			      Thread *root, struct sortcrit *sortcrit)
{
    Thread *child;
    struct sortrock sortrock;

    /* sort the grandchildren */
    child = root->child;
    while (child) {
	/* if the child has children, sort them */
	if (child->child)
	    index_thread_sort(mailbox, child, sortcrit);
	child = child->next;
    }

    sortrock.mailbox = mailbox;
    sortrock.sortcrit = sortcrit;
    /* sort the children */
    root->child = lsort(root->child,
			(void * (*)(void*)) index_thread_getnext,
			(void (*)(void*,void*)) index_thread_setnext,
			(int (*)(void*,void*,void*)) index_thread_compare,
			(void *) &sortrock);
}

/*
 * Thread a list of messages using the ORDEREDSUBJECT algorithm.
 */
static void index_thread_orderedsubj(struct mailbox *mailbox, 
				     unsigned *msgno_list, int nmsg,
				     int usinguid)
{
    MsgData *msgdata, *freeme;
    struct sortcrit sortcrit[] = {{ SORT_SUBJECT,  0 },
				  { SORT_DATE,     0 },
				  { SORT_SEQUENCE, 0 }};
    struct sortrock sortrock;
    unsigned psubj_hash = 0;
    char *psubj;
    Thread *head, *newnode, *cur, *parent;

    /* Create/load the msgdata array */
    freeme = msgdata = index_msgdata_load(mailbox, msgno_list, nmsg, sortcrit);

    sortrock.mailbox = mailbox;
    sortrock.sortcrit = sortcrit;
    /* Sort messages by subject and date */
    msgdata = lsort(msgdata,
		    (void * (*)(void*)) index_sort_getnext,
		    (void (*)(void*,void*)) index_sort_setnext,
		    (int (*)(void*,void*,void*)) index_sort_compare,
		    (void *) &sortrock);

    /* create an array of Thread to use as nodes of thread tree
     *
     * we will be building threads under a dummy head,
     * so we need (nmsg + 1) nodes
     */
    head = (Thread *) xmalloc((nmsg + 1) * sizeof(Thread));
    memset(head, 0, (nmsg + 1) * sizeof(Thread));

    newnode = head + 1;	/* set next newnode to the second
			   one in the array (skip the head) */
    parent = head;	/* parent is the head node */
    psubj = NULL;	/* no previous subject */
    cur = NULL;		/* no current thread */

    while (msgdata) {
	/* if no previous subj, or
	   current subj = prev subj (subjs have same hash, and
	   the strings are equal), then add message to current thread */
	if (!psubj ||
	    (msgdata->xsubj_hash == psubj_hash &&
	     !strcmp(msgdata->xsubj, psubj))) {
	    parent->child = newnode;	/* create a new child */
	    parent->child->msgdata = msgdata;
	    if (!cur)
		cur = parent->child;	/* first thread */
	    parent = parent->child;	/* this'll be the parent 
					   next time around */
	}
	/* otherwise, create a new thread */
	else {
	    cur->next = newnode;	/* create and start a new thread */
	    cur->next->msgdata = msgdata;
	    parent = cur = cur->next;	/* now work with the new thread */
	}

	psubj_hash = msgdata->xsubj_hash;
	psubj = msgdata->xsubj;
	msgdata = msgdata->next;
	newnode++;
    }

    /* Sort threads by date */
    index_thread_sort(mailbox, head, sortcrit+1);

    /* Output the threaded messages */ 
    index_thread_print(mailbox, head, usinguid);

    /* free the thread array */
    free(head);

    /* free the msgdata array */
    free(freeme);
}

/*
 * Guts of thread printing.  Recurses over children when necessary.
 *
 * Frees contents of msgdata as a side effect.
 */
static void _index_thread_print(struct mailbox *mailbox, 
				Thread *thread, int usinguid)
{
    Thread *child;

    /* for each thread... */
    while (thread) {
	/* start the thread */
	prot_printf(imapd_out, "(");

	/* if we have a message, print its identifier
	 * (do nothing for empty containers)
	 */
	if (thread->msgdata) {
	    prot_printf(imapd_out, "%u",
			usinguid ? UID(mailbox, thread->msgdata->msgno) :
			thread->msgdata->msgno);

	    /* if we have a child, print the parent-child separator */
	    if (thread->child) prot_printf(imapd_out, " ");

	    /* free contents of the current node */
	    index_msgdata_free(thread->msgdata);
	}

	/* for each child, grandchild, etc... */
	child = thread->child;
	while (child) {
	    /* if the child has siblings, print new branch and break */
	    if (child->next) {
		_index_thread_print(mailbox, child, usinguid);
		break;
	    }
	    /* otherwise print the only child */
	    else {
		prot_printf(imapd_out, "%u",
			    usinguid ? UID(mailbox, child->msgdata->msgno) :
			    child->msgdata->msgno);

		/* if we have a child, print the parent-child separator */
		if (child->child) prot_printf(imapd_out, " ");

		/* free contents of the child node */
		index_msgdata_free(child->msgdata);

		child = child->child;
	    }
	}

	/* end the thread */
	prot_printf(imapd_out, ")");

	thread = thread->next;
    }
}

/*
 * Print a list of threads.
 *
 * This is a wrapper around _index_thread_print() which simply prints the
 * start and end of the untagged thread response.
 */
static void index_thread_print(struct mailbox *mailbox,
			       Thread *thread, int usinguid)
{
    prot_printf(imapd_out, "* THREAD");

    if (thread) {
	prot_printf(imapd_out, " ");
	_index_thread_print(mailbox, thread->child, usinguid);
    }

    prot_printf(imapd_out, "\r\n");
}

/*
 * Find threading algorithm for given arg.
 * Returns index into thread_algs[], or -1 if not found.
 */
int find_thread_algorithm(char *arg)
{
    int alg;

    ucase(arg);
    for (alg = 0; thread_algs[alg].alg_name; alg++) {
	if (!strcmp(arg, thread_algs[alg].alg_name))
	    return alg;
    }
    return -1;
}

/*
 * The following code is an interpretation of JWZ's description
 * and pseudo-code in http://www.jwz.org/doc/threading.html.
 *
 * It has been modified to match the THREAD=REFERENCES algorithm.
 */

/*
 * Determines if child is a descendent of parent.
 *
 * Returns 1 if yes, 0 otherwise.
 */
static int thread_is_descendent(Thread *parent, Thread *child)
{
    Thread *kid;

    /* self */
    if (parent == child)
	return 1;

    /* search each child's decendents */
    for (kid = parent->child; kid; kid = kid->next) {
	if (thread_is_descendent(kid, child))
	    return 1;
    }
    return 0;
}

/*
 * Links child into parent's children.
 */
static void thread_adopt_child(Thread *parent, Thread *child)
{
    child->parent = parent;
    child->next = parent->child;
    parent->child = child;
}

/*
 * Unlinks child from it's parent's children.
 */
static void thread_orphan_child(Thread *child)
{
    Thread *prev, *cur;

    /* sanity check -- make sure child is actually a child of parent */
    for (prev = NULL, cur = child->parent->child;
	 cur != child && cur != NULL; prev = cur, cur = cur->next);

    if (!cur) {
	/* uh oh!  couldn't find the child in it's parent's children
	 * we should probably return NO to thread command
	 */
	return;
    }

    /* unlink child */
    if (!prev)	/* first child */
	child->parent->child = child->next;
    else
	prev->next = child->next;
    child->parent = child->next = NULL;
}

/*
 * Link messages together using message-id and references.
 */
static void ref_link_messages(MsgData *msgdata, Thread **newnode,
		       struct hash_table *id_table)
{
    Thread *cur, *parent, *ref;
    int dup_count = 0;
    char buf[100];
    int i;

    /* for each message... */
    while (msgdata) {
	/* fill the containers with msgdata
	 *
	 * if we already have a container, use it
	 */
	if ((cur = (Thread *) hash_lookup(msgdata->msgid, id_table))) {
	    /* If this container is not empty, then we have a duplicate
	     * Message-ID.  Make this one unique so that we don't stomp
	     * on the old one.
	     */
	    if (cur->msgdata) {
		sprintf(buf, "-dup%d", dup_count++);
		msgdata->msgid =
		    (char *) xrealloc(msgdata->msgid,
				      strlen(msgdata->msgid) + strlen(buf) + 1);
		strcat(msgdata->msgid, buf);
		/* clear cur so that we create a new container */
		cur = NULL;
	    }
	    else
		cur->msgdata = msgdata;
	}

	/* otherwise, make and index a new container */
	if (!cur) {
	    cur = *newnode;
	    cur->msgdata = msgdata;
	    hash_insert(msgdata->msgid, cur, id_table);
	    (*newnode)++;
	}

	/* Step 1.A */
	for (i = 0, parent = NULL; i < msgdata->nref; i++) {
	    /* if we don't already have a container for the reference,
	     * make and index a new (empty) container
	     */
	    if (!(ref = (Thread *) hash_lookup(msgdata->ref[i], id_table))) {
		ref = *newnode;
		hash_insert(msgdata->ref[i], ref, id_table);
		(*newnode)++;
	    }

	    /* link the references together as parent-child iff:
	     * - we won't change existing links, AND
	     * - we won't create a loop
	     */
	    if (!ref->parent &&
		parent && !thread_is_descendent(ref, parent)) {
		thread_adopt_child(parent, ref);
	    }

	    parent = ref;
	}

	/* Step 1.B
	 *
	 * if we have a parent already, it is probably bogus (the result
	 * of a truncated references field), so unlink from it because
	 * we now have the actual parent
	 */
	if (cur->parent) thread_orphan_child(cur);

	/* make the last reference the parent of our message iff:
	 * - we won't create a loop
	 */
	if (parent && !thread_is_descendent(cur, parent))
	    thread_adopt_child(parent, cur);

	msgdata = msgdata->next;
    }
}

/*
 * Gather orphan messages under the root node.
 */
static void ref_gather_orphans(char *key, Thread *node, struct rootset *rootset)
{
    /* we only care about nodes without parents */
    if (!node->parent) {
	if (node->next) {
	    /* uh oh!  a node without a parent should not have a sibling
	     * we should probably return NO to thread command
	     */
	    return;
	}

	/* add this node to root's children */
	node->next = rootset->root->child;
	rootset->root->child = node;
	rootset->nroot++;
    }
}

/*
 * Prune tree of empty containers.
 */
static void ref_prune_tree(Thread *parent)
{
    Thread *cur, *prev, *next, *child;

    for (prev = NULL, cur = parent->child, next = cur->next;
	 cur;
	 prev = cur, cur = next, next = (cur ? cur->next : NULL)) {

	/* if we have an empty container with no children, delete it */
	if (!cur->msgdata && !cur->child) {
	    if (!prev)	/* first child */
		parent->child = cur->next;
	    else
		prev->next = cur->next;

	    /* we just removed cur from our list,
	     * so we need to keep the same prev for the next pass
	     */
	    cur = prev;
	}

	/* if we have empty container with children, AND
	 * we're not at the root OR we only have one child,
	 * then remove the container but promote its children to this level
	 * (splice them into the current child list)
	 */
	else if (!cur->msgdata && cur->child &&
		 (cur->parent || !cur->child->next)) {
	    /* move cur's children into cur's place (start the splice) */
	    if (!prev)	/* first child */
		parent->child = cur->child;
	    else
		prev->next = cur->child;

	    /* make cur's parent the new parent of cur's children
	     * (they're moving in with grandma!)
	     */
	    child = cur->child;
	    do {
		child->parent = cur->parent;
	    } while (child->next && (child = child->next));

	    /* make the cur's last child point to cur's next sibling
	     * (finish the splice)
	     */
	    child->next = cur->next;

	    /* we just replaced cur with it's children
	     * so make it's first child the next node to process
	     */
	    next = cur->child;

	    /* make cur childless and siblingless */
	    cur->child = cur->next = NULL;

	    /* we just removed cur from our list,
	     * so we need to keep the same prev for the next pass
	     */
	    cur = prev;
	}

	/* if we have a message with children, prune it's children */
	else if (cur->child)
	    ref_prune_tree(cur);
    }
}

/*
 * Sort the messages in the root set by date.
 */
static void ref_sort_root(struct mailbox *mailbox, Thread *root)
{
    Thread *cur;
    struct sortcrit sortcrit[] = {{ SORT_DATE,     0 },
				  { SORT_SEQUENCE, 0 }};
    struct sortrock sortrock;
    
    sortrock.mailbox = mailbox;
    sortrock.sortcrit = sortcrit;
    
    cur = root->child;
    while (cur) {
	/* if the message is a dummy, sort its children */
	if (!cur->msgdata) {
	    cur->child = lsort(cur->child,
			       (void * (*)(void*)) index_thread_getnext,
			       (void (*)(void*,void*)) index_thread_setnext,
			       (int (*)(void*,void*,void*)) index_thread_compare,
			       &sortrock);
	}
	cur = cur->next;
    }

    /* sort the root set */
    root->child = lsort(root->child,
			(void * (*)(void*)) index_thread_getnext,
			(void (*)(void*,void*)) index_thread_setnext,
			(int (*)(void*,void*,void*)) index_thread_compare,
			&sortrock);
}

/*
 * Group threads with same subject.
 */
static void ref_group_subjects(Thread *root, unsigned nroot, Thread **newnode)
{
    Thread *cur, *old, *prev, *next, *child;
    struct hash_table subj_table;
    char *subj;

    /* Step 5.A: create a subj_table with one bucket for every possible
     * subject in the root set
     */
    construct_hash_table(&subj_table, nroot);

    /* Step 5.B: populate the table with a container for each subject
     * at the root
     */
    for (cur = root->child; cur; cur = cur->next) {
	/* Step 5.B.i: find subject of the thread
	 *
	 * if the container is not empty, use it's subject
	 */
	if (cur->msgdata)
	    subj = cur->msgdata->xsubj;
	/* otherwise, use the subject of it's first child */
	else
	    subj = cur->child->msgdata->xsubj;

	/* Step 5.B.ii: if subject is empty, skip it */
	if (!strlen(subj)) continue;

	/* Step 5.B.iii: lookup this subject in the table */
	old = (Thread *) hash_lookup(subj, &subj_table);

	/* Step 5.B.iv: insert the current container into the table iff:
	 * - this subject is not in the table, OR
	 * - this container is empty AND the one in the table is not
	 *   (the empty one is more interesting as a root), OR
	 * - the container in the table is a re/fwd AND this one is not
	 *   (the non-re/fwd is the more interesting of the two)
	 */
	if (!old ||
	    (!cur->msgdata && old->msgdata) ||
	    (old->msgdata && old->msgdata->is_refwd &&
	     cur->msgdata && !cur->msgdata->is_refwd)) {
	  hash_insert(subj, cur, &subj_table);
	}
    }

    /* 5.C - group containers with the same subject together */
    for (prev = NULL, cur = root->child, next = cur->next;
	 cur;
	 prev = cur, cur = next, next = (next ? next->next : NULL)) {	
	/* Step 5.C.i: find subject of the thread
	 *
	 * if container is not empty, use it's subject
	 */
	if (cur->msgdata)
	    subj = cur->msgdata->xsubj;
	/* otherwise, use the subject of it's first child */
	else
	    subj = cur->child->msgdata->xsubj;

	/* Step 5.C.ii: if subject is empty, skip it */
	if (!strlen(subj)) continue;

	/* Step 5.C.iii: lookup this subject in the table */
	old = (Thread *) hash_lookup(subj, &subj_table);

	/* Step 5.C.iv: if we found ourselves, skip it */
	if (old == cur) continue;

	/* ok, we already have a container which contains our current subject,
	 * so pull this container out of the root set, because we are going to
	 * merge this node with another one
	 */
	if (!prev)	/* we're at the root */
	    root->child = cur->next;
	else
	    prev->next = cur->next;
	cur->next = NULL;

	/* if both containers are dummies, append cur's children to old's */
	if (!old->msgdata && !cur->msgdata) {
	    /* find old's last child */
	    for (child = old->child; child->next; child = child->next);

	    /* append cur's children to old's children list */
	    child->next = cur->child;

	    /* make old the parent of cur's children */
	    for (child = cur->child; child; child = child->next)
		child->parent = old;

	    /* make cur childless */
	    cur->child = NULL;
	}

	/* if:
	 * - old container is empty, OR
	 * - the current message is a re/fwd AND the old one is not,
	 * make the current container a child of the old one
	 *
	 * Note: we don't have to worry about the reverse cases
	 * because step 5.B guarantees that they won't happen
	 */
	else if (!old->msgdata ||
		 (cur->msgdata && cur->msgdata->is_refwd &&
		  !old->msgdata->is_refwd)) {
	    thread_adopt_child(old, cur);
	}

	/* if both messages are re/fwds OR neither are re/fwds,
	 * then make them both children of a new dummy container
	 * (we don't want to assume any parent-child relationship between them)
	 *
	 * perhaps we can create a parent-child relationship
	 * between re/fwds by counting the number of re/fwds
	 *
	 * Note: we need the hash table to still point to old,
	 * so we must make old the dummy and make the contents of the
	 * new container a copy of old's original contents
	 */
	else {
	    Thread *new = (*newnode)++;

	    /* make new a copy of old (except parent and next) */
 	    new->msgdata = old->msgdata;
	    new->child = old->child;
	    new->next = NULL;

	    /* make new the parent of it's newly adopted children */
	    for (child = new->child; child; child = child->next)
		child->parent = new;

	    /* make old the parent of cur and new */
	    cur->parent = old;
	    new->parent = old;

	    /* empty old and make it have two children (cur and new) */
	    old->msgdata = NULL;
	    old->child = cur;
	    cur->next = new;
	}

	/* we just removed cur from our list,
	 * so we need to keep the same prev for the next pass
	 */
	cur = prev;
    }

    free_hash_table(&subj_table, NULL);
}

/*
 * Free an entire thread.
 */
static void index_thread_free(Thread *thread)
{
    Thread *child;

    /* free the head node */
    if (thread->msgdata) index_msgdata_free(thread->msgdata);

    /* free the children recursively */
    child = thread->child;
    while (child) {
	index_thread_free(child);
	child = child->next;
    }
}

/*
 * Guts of thread searching.  Recurses over children when necessary.
 */
static int _index_thread_search(Thread *thread, int (*searchproc) (MsgData *))
{
    Thread *child;

    /* test the head node */
    if (thread->msgdata && searchproc(thread->msgdata)) return 1;

    /* test the children recursively */
    child = thread->child;
    while (child) {
	if (_index_thread_search(child, searchproc)) return 1;
	child = child->next;
    }

    /* if we get here, we struck out */
    return 0;
}

/*
 * Search a thread to see if it contains a message which matches searchproc().
 *
 * This is a wrapper around _index_thread_search() which iterates through
 * each thread and removes any which fail the searchproc().
 */
static void index_thread_search(Thread *root, int (*searchproc) (MsgData *))
{
    Thread *cur, *prev, *next;

    for (prev = NULL, cur = root->child, next = cur->next;
	 cur;
	 prev = cur, cur= next, next = (cur ? cur->next : NULL)) {
	if (!_index_thread_search(cur, searchproc)) {
	    /* unlink the thread from the list */
	    if (!prev)	/* first thread */
		root->child = cur->next;
	    else
		prev->next = cur->next;

	    /* free all nodes in the thread */
	    index_thread_free(cur);

	    /* we just removed cur from our list,
	     * so we need to keep the same prev for the next pass
	     */
	    cur = prev;
	}
    }
}

/*
 * Guts of the REFERENCES algorithms.  Behavior is tweaked with loadcrit[],
 * searchproc() and sortcrit[].
 */
static void _index_thread_ref(struct mailbox *mailbox, 
			      unsigned *msgno_list, int nmsg,
			      struct sortcrit loadcrit[],
			      int (*searchproc) (MsgData *),
			      struct sortcrit sortcrit[], int usinguid)
{
    MsgData *msgdata, *freeme, *md;
    int tref, nnode;
    Thread *newnode;
    struct hash_table id_table;
    struct rootset rootset;

    /* Create/load the msgdata array */
    freeme = msgdata = index_msgdata_load(mailbox, msgno_list, nmsg, loadcrit);

    /* calculate the sum of the number of references for all messages */
    for (md = msgdata, tref = 0; md; md = md->next)
	tref += md->nref;

    /* create an array of Thread to use as nodes of thread tree (including
     * empty containers)
     *
     * - We will be building threads under a dummy root, so we need at least
     *   (nmsg + 1) nodes.
     * - We also will need containers for references to non-existent messages.
     *   To make sure we have enough, we will take the worst case and
     *   use the sum of the number of references for all messages.
     * - Finally, we will might need containers to group threads with the same
     *   subject together.  To make sure we have enough, we will take the
     *   worst case which will be half of the number of messages.
     *
     * This is overkill, but it is the only way to make sure we have enough
     * ahead of time.  If we tried to use xrealloc(), the array might be moved,
     * and our parent/child/next pointers will no longer be correct
     * (been there, done that).
     */
    nnode = (int) (1.5 * nmsg + 1 + tref);
    rootset.root = (Thread *) xmalloc(nnode * sizeof(Thread));
    memset(rootset.root, 0, nnode * sizeof(Thread));

    newnode = rootset.root + 1;	/* set next newnode to the second
				   one in the array (skip the root) */

    /* Step 0: create an id_table with one bucket for every possible
     * message-id and reference (nmsg + tref)
     */
    construct_hash_table(&id_table, nmsg + tref);

    /* Step 1: link messages together */
    ref_link_messages(msgdata, &newnode, &id_table);

    /* Step 2: find the root set (gather all of the orphan messages) */
    rootset.nroot = 0;
    hash_enumerate(&id_table, (void (*)(char*,void*,void*)) ref_gather_orphans,
		   &rootset);

    /* discard id_table */
    free_hash_table(&id_table, NULL);

    /* Step 3: prune tree of empty containers - get our deposit back :^) */
    ref_prune_tree(rootset.root);

    /* Step 4: sort the root set */
    ref_sort_root(mailbox, rootset.root);

    /* Step 5: group root set by subject */
    ref_group_subjects(rootset.root, rootset.nroot, &newnode);

    /* Optionally search threads (to be used by REFERENCES derivatives) */
    if (searchproc) index_thread_search(rootset.root, searchproc);

    /* Step 6: sort threads */
    if (sortcrit) index_thread_sort(mailbox, rootset.root, sortcrit);

    /* Output the threaded messages */ 
    index_thread_print(mailbox, rootset.root, usinguid);

    /* free the thread array */
    free(rootset.root);

    /* free the msgdata array */
    free(freeme);
}

/*
 * Thread a list of messages using the REFERENCES algorithm.
 */
static void index_thread_ref(struct mailbox *mailbox,
			     unsigned *msgno_list, int nmsg, int usinguid)
{
    struct sortcrit loadcrit[] = {{ LOAD_IDS,      0 },
				  { SORT_SUBJECT,  0 },
				  { SORT_DATE,     0 },
				  { SORT_SEQUENCE, 0 }};
    struct sortcrit sortcrit[] = {{ SORT_DATE,     0 },
				  { SORT_SEQUENCE, 0 }};

    _index_thread_ref(mailbox,
		      msgno_list, nmsg, loadcrit, NULL, sortcrit, usinguid);
}
