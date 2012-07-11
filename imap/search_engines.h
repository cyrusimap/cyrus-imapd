/* search_engines.h --  Prefiltering routines for SEARCH
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
 */

#ifndef INCLUDED_SEARCH_ENGINES_H
#define INCLUDED_SEARCH_ENGINES_H

#include "index.h"
#include "charset.h"

typedef struct search_builder search_builder_t;
struct search_builder {
#define SEARCH_OP_AND	    1
#define SEARCH_OP_OR	    2
#define SEARCH_OP_NOT	    3
    void (*begin_boolean)(search_builder_t *, int op);
    void (*end_boolean)(search_builder_t *, int op);
    void (*match)(search_builder_t *, int part, const char *str);
};

struct search_engine {
    const char *name;
    unsigned int flags;
    search_builder_t *(*begin_search1)(struct index_state *,
				      unsigned *msg_list,
				      int verbose);
    int (*end_search1)(search_builder_t *);
    search_text_receiver_t *(*begin_update)(int verbose);
    int (*end_update)(search_text_receiver_t *);
    int (*start_daemon)(int verbose, const char *mboxname);
    int (*stop_daemon)(int verbose, const char *mboxname);
};

/* Fill the msg_list with a list of message IDs which could match the
 * query built with the search_builder_t.
 * Return the number of message IDs inserted.
 */
extern search_builder_t *search_begin_search1(struct index_state *,
					      unsigned *msg_list,
					      int verbose);
extern int search_end_search1(search_builder_t *);

search_text_receiver_t *search_begin_update(int verbose);
int search_end_update(search_text_receiver_t *rx);
int search_start_daemon(int verbose, const char *mboxname);
int search_stop_daemon(int verbose, const char *mboxname);

/* for debugging */
extern const char *search_op_as_string(int op);

#endif
