/* search_engines.c -- Prefiltering routines for SEARCH
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 * $Id: search_engines.c,v 1.3.6.2 2003/04/23 20:26:16 ken3 Exp $
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

#include "imapd.h"
#include "xmalloc.h"

#include "squat.h"

typedef struct {
  unsigned char* vector;
  struct mailbox* mailbox;
  char const* part_types;
  int found_validity;
} SquatSearchResult;

static int vector_len() {
  return (imapd_exists >> 3) + 1;
}

/* The document name is of the form

   pnnn.vvv

   Where p is a part_type character (denoting which segment of the message
   is represented by the document), nnn is the UID of the message, and vvv
   is the UID validity value.

   This function parses the document name and returns the message
   UID only if the name has the right part type and it corresponds
   to a real message UID.
*/
static int parse_doc_name(SquatSearchResult* r, char const* doc_name) {
  int ch = doc_name[0];
  char const* t = r->part_types;
  int doc_UID, index;

  if (ch == 'v' && strncmp(doc_name, "validity.", 9) == 0) {
    if (atoi(doc_name + 9) == r->mailbox->uidvalidity) {
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
  
  /* now we need to convert the UID to the message sequence number */
  index = index_finduid(doc_UID);
  if (index < 1 || index > imapd_exists || doc_UID != index_getuid(index)) {
    return -1;
  }

  return index;
}

static int drop_indexed_docs(void* closure, SquatListDoc const* doc) {
  SquatSearchResult* r = (SquatSearchResult*)closure;
  int doc_ID = parse_doc_name(r, doc->doc_name);

  if (doc_ID >= 0) {
    unsigned char* vect = r->vector;
    vect[doc_ID >> 3] &= ~(1 << (doc_ID & 0x7));
  }
  return SQUAT_CALLBACK_CONTINUE;
}

static int fill_with_hits(void* closure, char const* doc) {
  SquatSearchResult* r = (SquatSearchResult*)closure;
  int doc_ID = parse_doc_name(r, doc);

  if (doc_ID >= 0) {
    unsigned char* vect = r->vector;
    vect[doc_ID >> 3] |= 1 << (doc_ID & 0x7);
  }
  return SQUAT_CALLBACK_CONTINUE;
}

static int search_strlist(SquatSearchIndex* index, struct mailbox* mailbox,
  unsigned char* output, unsigned char* tmp, struct strlist* strs,
  char const* part_types) {
  SquatSearchResult r;
  int i;
  int len = vector_len();

  r.part_types = part_types;
  r.vector = tmp;
  r.mailbox = mailbox;
  while (strs != NULL) {
    char const* s = strs->s;

    memset(tmp, 0, len);
    if (squat_search_execute(index, s, strlen(s), fill_with_hits, &r)
        != SQUAT_OK) {
      syslog(LOG_DEBUG, "SQUAT string list search failed on string %s "
             "with part types %s", s, part_types);
      return 0;
    }
    for (i = 0; i < len; i++) {
      output[i] &= tmp[i];
    }

    strs = strs->next;
  }
  return 1;
}

static unsigned char* search_squat_do_query(SquatSearchIndex* index,
  struct mailbox* mailbox, struct searchargs* args) {
  int vlen = vector_len();
  unsigned char* vect = xmalloc(vlen);
  unsigned char* t_vect = xmalloc(vlen);
  unsigned char* result = vect;
  struct searchsub* sub;
    
  memset(vect, 255, vlen);
  
  if (!(search_strlist(index, mailbox, vect, t_vect, args->to, "t")
      && search_strlist(index, mailbox, vect, t_vect, args->from, "f")
      && search_strlist(index, mailbox, vect, t_vect, args->cc, "c")
      && search_strlist(index, mailbox, vect, t_vect, args->bcc, "b")
      && search_strlist(index, mailbox, vect, t_vect, args->subject, "s")
      && search_strlist(index, mailbox, vect, t_vect, args->header_name, "h")
      && search_strlist(index, mailbox, vect, t_vect, args->header, "h")
      && search_strlist(index, mailbox, vect, t_vect, args->body, "m")
      && search_strlist(index, mailbox, vect, t_vect, args->text, "mh"))) {
    result = NULL;
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
      unsigned char* sub1_vect =
        search_squat_do_query(index, mailbox, args->sublist->sub1);
      unsigned char* sub2_vect;
      int i;

      if (sub1_vect == NULL) {
        result = NULL;
        goto cleanup;
      }

      sub2_vect = search_squat_do_query(index, mailbox, args->sublist->sub2);

      if (sub2_vect == NULL) {
        result = NULL;
        free(sub1_vect);
        goto cleanup;
      }

      for (i = 0; i < vlen; i++) {
        vect[i] &= sub1_vect[i] | sub2_vect[i];
      }

      free(sub1_vect);
      free(sub2_vect);
    }

    sub = sub->next;
  }

cleanup:
  free(t_vect);
  if (result != vect) {
    free(vect);
  }
  
  return result;
}

static int search_squat(unsigned* msg_list, struct mailbox *mailbox,
                        struct searchargs *searchargs) {
  char index_file_name[MAX_MAILBOX_PATH+1];
  int fd;
  SquatSearchIndex* index;
  unsigned char* msg_vector;
  int result;

  snprintf(index_file_name, sizeof(index_file_name),
	   "%s%s", mailbox->path, FNAME_SQUAT_INDEX);
  if ((fd = open(index_file_name, O_RDONLY)) < 0) {
    syslog(LOG_DEBUG, "SQUAT failed to open index file");
    return -1;   /* probably not found. Just bail */
  }
  if ((index = squat_search_open(fd)) == NULL) {
    syslog(LOG_DEBUG, "SQUAT failed to open index");
    close(fd);
    return -1;
  }
  if ((msg_vector = search_squat_do_query(index, mailbox, searchargs))
      == NULL) {
    result = -1;
  } else {
    int i;
    int vlen = vector_len();
    unsigned char* unindexed_vector = xmalloc(vlen);
    SquatSearchResult r;
    
    memset(unindexed_vector, 255, vlen);
    r.vector = unindexed_vector;
    r.mailbox = mailbox;
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
      for (i = 0; i < vlen; i++) {
        msg_vector[i] |= unindexed_vector[i];
      }

      result = 0;
      for (i = 1; i <= imapd_exists; i++) {
        if ((msg_vector[i >> 3] & (1 << (i & 7))) != 0) {
          msg_list[result] = i;
          result++;
        }
      }
    }
    free(msg_vector);
    free(unindexed_vector);
  }
  squat_search_close(index);
  close(fd);
  return result;
}

int search_prefilter_messages(unsigned* msg_list, struct mailbox *mailbox,
                              struct searchargs *searchargs) {
  int i, count;

  if (SQUAT_ENGINE) {
    count = search_squat(msg_list, mailbox, searchargs);
    if (count >= 0) {
      syslog(LOG_DEBUG, "SQUAT returned %d messages", count);
      return count;
    } else {
	/* otherwise, we failed for some reason, so do the default */
	syslog(LOG_DEBUG, "SQUAT failed");
    }
  }
  
  /* Just put in all possible messages. This falls back to Cyrus' default
     search. */
  for (i = 0; i < imapd_exists; i++) {
    msg_list[i] = i + 1;
  }
  return imapd_exists;
}
