/* search_squat.c -- glue code for searching via SQUAT
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "index.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "bitvector.h"

#include "search_engines.h"
#include "squat.h"

typedef struct {
    bitvector_t		*vector;
    struct index_state	*state;
    const char		*part_types;
    int			found_validity;
} SquatSearchResult;

/* The document name is of the form

   pnnn.vvv

   Where p is a part_type character (denoting which segment of the message
   is represented by the document), nnn is the UID of the message, and vvv
   is the UID validity value.

   This function parses the document name and returns the message
   UID only if the name has the right part type and it corresponds
   to a real message UID.
*/
static int parse_doc_name(SquatSearchResult *r, const char *doc_name)
{
    int ch = doc_name[0];
    const char *t = r->part_types;
    int doc_UID, index;

    if (ch == 'v' && strncmp(doc_name, "validity.", 9) == 0) {
	if ((unsigned) atoi(doc_name + 9) == r->state->mailbox->i.uidvalidity) {
	    r->found_validity = 1;
	}
	return -1;
    }

    /* make sure that the document part type is one of the ones we're
     accepting */
    while (*t != 0 && *t != ch) {
	t++;
    }
    if (*t == 0) {
	return -1;
    }

    doc_UID = atoi(++doc_name);
    while ((*doc_name >= '0' && *doc_name <= '9') || *doc_name == '-') {
	++doc_name;
    }
    if (*doc_name != 0) {
	return -1;
    }

    index = index_finduid(r->state, doc_UID);

    return index;
}

static int drop_indexed_docs(void* closure, const SquatListDoc *doc)
{
    SquatSearchResult* r = (SquatSearchResult*)closure;
    int doc_uid = parse_doc_name(r, doc->doc_name);

    if (doc_uid >= 0)
	bv_clear(r->vector, doc_uid);
    return SQUAT_CALLBACK_CONTINUE;
}

static int fill_with_hits(void* closure, char const* doc)
{
    SquatSearchResult* r = (SquatSearchResult*)closure;
    int doc_uid = parse_doc_name(r, doc);

    if (doc_uid >= 0)
	bv_set(r->vector, doc_uid);
    return SQUAT_CALLBACK_CONTINUE;
}

static int search_strlist(SquatSearchIndex* index, struct index_state *state,
			  bitvector_t *output, bitvector_t *tmp,
			  struct strlist* strs, char const* part_types)
{
    SquatSearchResult r;

    r.part_types = part_types;
    r.vector = tmp;
    r.state = state;
    while (strs != NULL) {
	char const* s = strs->s;

	bv_clearall(tmp);
	if (squat_search_execute(index, s, strlen(s), fill_with_hits, &r)
	    != SQUAT_OK) {
	    if (squat_get_last_error() == SQUAT_ERR_SEARCH_STRING_TOO_SHORT)
		return 1; /* The rest of the search is still viable */
	    syslog(LOG_DEBUG, "SQUAT string list search failed on string %s "
			      "with part types %s", s, part_types);
	    return 0;
	}
	bv_andeq(output, tmp);

	strs = strs->next;
    }
    return 1;
}

static int search_squat_do_query(SquatSearchIndex* index,
				 struct index_state *state,
				 const struct searchargs* args,
				 bitvector_t *vect)
{
    bitvector_t t_vect = BV_INITIALIZER;
    bitvector_t sub1_vect = BV_INITIALIZER;
    bitvector_t sub2_vect = BV_INITIALIZER;
    struct searchsub* sub;
    int found_something = 1;

    bv_setsize(vect, state->exists);
    bv_setall(vect);
    bv_setsize(&t_vect, state->exists);

    if (!(search_strlist(index, state, vect, &t_vect, args->to, "t")
	&& search_strlist(index, state, vect, &t_vect, args->from, "f")
	&& search_strlist(index, state, vect, &t_vect, args->cc, "c")
	&& search_strlist(index, state, vect, &t_vect, args->bcc, "b")
	&& search_strlist(index, state, vect, &t_vect, args->subject, "s")
	&& search_strlist(index, state, vect, &t_vect, args->header_name, "h")
	&& search_strlist(index, state, vect, &t_vect, args->header, "h")
	&& search_strlist(index, state, vect, &t_vect, args->body, "m")
	&& search_strlist(index, state, vect, &t_vect, args->text, "mh"))) {
	found_something = 0;
	goto cleanup;
    }

    sub = args->sublist;
    while (sub != NULL) {
	if (args->sublist->sub2 == NULL) {
	    /* do nothing; because our search is conservative (may include false
	       positives) we can't compute the NOT (since the result might include
	       false negatives, which we do not allow) */
	    /* Note that it's OK to do nothing. We'll just be returning more
	       false positives. */
	} else {
	    if (!search_squat_do_query(index, state,
				       args->sublist->sub1, &sub1_vect)) {
		found_something = 0;
		goto cleanup;
	    }

	    if (!search_squat_do_query(index, state,
				       args->sublist->sub2, &sub2_vect)) {
		found_something = 0;
		goto cleanup;
	    }

	    bv_oreq(&sub1_vect, &sub2_vect);
	    bv_oreq(vect, &sub1_vect);
	}

	sub = sub->next;
    }

cleanup:
    bv_free(&t_vect);
    bv_free(&sub1_vect);
    bv_free(&sub2_vect);
    return found_something;
}

static int search_squat(unsigned* msg_list, struct index_state *state,
			const struct searchargs *searchargs)
{
    char *fname;
    int fd;
    SquatSearchIndex* index;
    bitvector_t msg_vector = BV_INITIALIZER;
    int result;

    fname = mailbox_meta_fname(state->mailbox, META_SQUAT);
    if ((fd = open(fname, O_RDONLY)) < 0) {
	syslog(LOG_DEBUG, "SQUAT failed to open index file");
	return -1;   /* probably not found. Just bail */
    }
    if ((index = squat_search_open(fd)) == NULL) {
	syslog(LOG_DEBUG, "SQUAT failed to open index");
	close(fd);
	return -1;
    }
    if (!search_squat_do_query(index, state, searchargs, &msg_vector)) {
	result = -1;
    } else {
	unsigned i;
	bitvector_t unindexed_vector = BV_INITIALIZER;
	SquatSearchResult r;

	bv_setsize(&unindexed_vector, state->exists);
	bv_setall(&unindexed_vector);
	r.vector = &unindexed_vector;
	r.state = state;
	r.part_types = "tfcbsmh";
	r.found_validity = 0;
	if (squat_search_list_docs(index, drop_indexed_docs, &r) != SQUAT_OK) {
	    syslog(LOG_DEBUG, "SQUAT failed to get list of indexed documents");
	    result = -1;
	} else if (!r.found_validity) {
	    syslog(LOG_DEBUG, "SQUAT didn't find validity record");
	    result = -1;
	} else {
	    /* Add in any unindexed messages. They must be searched manually. */
	    bv_oreq(&msg_vector, &unindexed_vector);

	    result = 0;
	    for (i = 1; i <= state->exists; i++) {
		if (bv_isset(&msg_vector, i)) {
		    msg_list[result] = i;
		    result++;
		}
	    }
	}
	bv_free(&unindexed_vector);
    }
    bv_free(&msg_vector);
    squat_search_close(index);
    close(fd);
    return result;
}

const struct search_engine squat_search_engine = {
    "SQUAT",
    0,
    search_squat
};

