/*
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
 * $Id: squat.h,v 1.1.8.1 2003/02/13 20:33:01 rjs3 Exp $
 */

/*
  SQUAT library public interface.
  Robert O'Callahan

  SQUAT (Search QUery Answer Tool) is a library for full-text indexing
  and searching. 

  The primary design goals are simplicity and robustness. There are
  two parts to the API: 
  -- Indexing: Build an index by feeding in a set of documents
     composed of arbitrary binary text.
  -- Searching: Specify an arbitrary substring (of length >=
     SQUAT_WORD_SIZE, default 4) and return a superset of the
     documents which contain the substring. (SQUAT can (and
     occasionally does) return documents which do not match the
     string, thus the documents must be searched 'by hand' after
     obtaining a document list from SQUAT.)

  SQUAT provides the following features that other similar engines do not:
  -- Simple generic API (see above). No "word" heuristics to tweak. No
     confusion about what can or cannot be matched. This makes SQUAT
     suitable for indexing non-English, non-ASCII documents.
  -- Simple, robust design. SQUAT has a very small amount of code. It
     has been engineered for robustness; arbitrary input documents are
     allowed, and corrupt index files are always be detected and
     handled by SQUAT (i.e., it should never crash or behave
     unpredictably). Anything less is a bug.
  -- Robust performance. SQUAT searches are always fast. SQUAT index
     creation uses a two-pass algorithm that consumes little memory
     even for very large document collections and runs in time linear
     in the combined size of the documents.
  -- Easy embedding. The simple C library API makes it easy to add
     SQUAT index creation and searching functionality to existing
     applications without the need for helper processes or
     tools. SQUAT's robustness makes it safe to do so.

  NOTES:

  SQUAT is not thread safe. Make sure that only one thread is in SQUAT
  code at a time.

  Arbitrary binary substring searching is often not what you want for
  your application. Most users will want to canonicalize the indexed
  text and/or queries before feeding them into SQUAT, for example by
  converting to a uniform case, or by converting runs of whitespace to
  a single space. Such conversions are the responsibility of the
  client.

  Minimal index size is *not* a goal of SQUAT. SQUAT tries to build
  small indices but does not use techniques such as aggregation of
  small documents (blocking) or aggressive file compression. The main
  reason for this is to keep the code simple and robust. Another
  reason is that disk is cheap. (Of course, one could perform blocking
  at the client level to feed approximately equal size documents into
  SQUAT, which would reduce index size and possibly make searches
  faster if the application needs to find the location of the search
  text and/or verify the search match within each document.) In
  practice I find that, indexing my email, the indexes are about the
  size as the processed source text, which is about 1/3 of the total
  size of my email (since Cyrus' processing strips whitespace, binary
  attachments, etc).

  The index file format is platform and architecture independent. The
  file format supports 64-bit file offsets so in theory >2GB index
  files would work, but the code has not been tested on any 64-bit
  architectures (64 bit addressing would be needed to mmap such
  files), so >2GB index files probably don't work in practice.
*/

#ifndef __SQUAT_H
#define __SQUAT_H

/* Don't change this unless you're SURE you know what you're doing.
   Its only effect on the API is that searches for strings that are
   shorter than SQUAT_WORD_SIZE are not allowed.
   In SQUAT, a 'word' simply refers to a string of SQUAT_WORD_SIZE
   arbitrary bytes.
*/
#define SQUAT_WORD_SIZE 4

/* Type used for an index under construction. */
typedef struct _SquatIndex SquatIndex; 
/* Type used for an index being searched. */
typedef struct _SquatSearchIndex SquatSearchIndex;

typedef long long SquatInt64;
typedef int       SquatInt32;

/* All SQUAT index files start with this magic 8 bytes */
extern char const squat_index_file_header[8]; /* "SQUAT 1\n" */

/* SQUAT return values */
#define SQUAT_OK           1
#define SQUAT_ERR          2
#define SQUAT_LAST_BUILTIN SQUAT_ERR

/* SQUAT error codes */
#define SQUAT_ERR_OK                         1
#define SQUAT_ERR_OUT_OF_MEMORY              2
#define SQUAT_ERR_SYSERR                     3   /* check errno */
#define SQUAT_ERR_INVALID_INDEX_FILE         4
#define SQUAT_ERR_SEARCH_STRING_TOO_SHORT    5
#define SQUAT_ERR_SEARCH_STRING_INVALID_CHAR 6
int squat_get_last_error(void);


/***************************************
   INDEX CONSTRUCTION API
***************************************/

/* You can get reports about the progress of index creation using a
   "stats callback" function. Your callback function is called every
   time an event occurs. */
#define SQUAT_STATS_COMPLETED_DOC          1 /* Finished processing a document */
#define SQUAT_STATS_COMPLETED_INITIAL_CHAR 2 /* Indexed all words
						beginning with a given
						byte */
typedef union { /* An event report */
  struct {
    int type;   /* the type of the event, a SQUAT_STATS_ constant */
  } generic;
  struct {      /* data for a COMPLETED_DOC event, issued during
		   squat_index_close_document */ 
    int type;
    int const* num_unique_words; /* num_unique_words[i] gives the
				    number of unique words in this
				    source document beginning with the
				    byte i */
  } completed_doc;
  struct {      /* data for a COMPLETED_INITIAL_CHAR event, issued
		   during squat_index_finish */
    int type;
    int completed_char;     /* We've just finished processing all
			       words beginning with this byte */
    int num_words;          /* How many unique words over all
			       documents start with this byte */
    int temp_file_size;     /* The size of the temporary file that was
			       used for this byte */
  } completed_initial_char;
} SquatStatsEvent;
typedef void (* SquatStatsCallback)(void* closure, SquatStatsEvent* params);

/* Create a SQUAT index. The index is dumped into 'fd', which should
   be an empty file opened for writing.

   SQUAT indexing takes space that may be up to 5 times the size of
   the input documents in the worst case (average case is much
   lower!). SQUAT will create hundreds of temporary files in /tmp or
   the directory you specify.

   Once a SquatIndex is successfully initialized, the caller is
   obligated to call "squat_index_destroy" or "squat_index_finish" on
   the index.
*/
#define SQUAT_OPTION_TMP_PATH    0x01  /* The tmp_path options field is valid. */
#define SQUAT_OPTION_VALID_CHARS 0x02  /* The valid_chars options field is valid. */
#define SQUAT_OPTION_STATISTICS  0x04  /* The stats_callback* options
					  fields are valid. */
typedef struct {
  int option_mask;                   /* Which options fields have been
					initialized? */
  char const* tmp_path;              /* A directory where all
					temporary files will be
					created. Must not have any
					trailing slash. */
  char const* valid_chars;           /* A null-terminated string
					containing the characters
					which can appear in search
					strings. (Sorry, if you use
					this option, the null
					character is never allowed in
					search strings.) If you try to
					use any other bytes in a
					search string, you will get an
					error. If you know in advance
					that certain bytes cannot
					appear in search strings, you
					can improve performance using
					this option (especially if
					those bytes do occur in source
					documents). */
  SquatStatsCallback stats_callback; /* See above */
  void* stats_callback_closure;      /* Private data passed down into
					the callback function */
} SquatOptions;
SquatIndex* squat_index_init(int fd, SquatOptions const* options);


/* Start adding a new document to the index. The name is a
   null-terminated UTF8 string which is associated with the document.
   Call this after successfully calling squat_index_init or
   squat_index_close_document.
*/
int         squat_index_open_document(SquatIndex* index, char const* name);


/* Notify SQUAT about some more data in the current document. This
   function can be called as many times as desired until all the data
   in the document has been fed into SQUAT. Call this after
   successfully calling squat_index_open_document or
   squat_index_append_document. */
int         squat_index_append_document(SquatIndex* index, char const* data,
               int data_len);


/* Notify SQUAT that the current document has ended.
   Call this after successfully calling squat_index_open_document or
   squat_index_append_document. */
int         squat_index_close_document(SquatIndex* index);


/* Notify SQUAT that there are no more documents. SQUAT will finish
   generating the index. It is the client's responsibility to close
   the original index file. All SQUAT resources associated with the
   index are released whether this call succeeds or fails.
   Call this after successfully calling squat_index_init or
   squat_index_close_document. */
int         squat_index_finish(SquatIndex* index);


/* Notify SQUAT that something has gone wrong and index construction
   must be aborted. It is the client's responsibility to close and/or
   remove the original index file. All SQUAT resources associated with
   the index are released whether this call succeeds or fails.
   Call this anytime. */
int         squat_index_destroy(SquatIndex* index);


/***************************************
   INDEX SEARCH API
***************************************/

/* Open an index for searching. 'fd' should be an index file opened
   for reading, positioned at the beginning of the file.
   
   This function mmaps the entire index file. If there is not enough
   virtual address space available it will fail with SQUAT_ERR_SYSERR.
*/
SquatSearchIndex* squat_search_open(int fd);

/* Get a list of the documents included in the index.
   The callback function is called once for each document. The
   callback function returns one of the following results to control
   the progress of the operation. Call this after successfully calling
   squat_search_open, squat_search_list_docs, or squat_search_execute. */
#define SQUAT_CALLBACK_CONTINUE   1  /* return this from the callback
					function to continue with the
					operation. */
#define SQUAT_CALLBACK_ABORT      2  /* return this from the callback
					function to abort the current
					operation and return to the
					client. */
typedef struct {
  char const* doc_name;  /* The UTF8 name of the document. */
  SquatInt64  size;      /* The total size of the document in bytes. */
} SquatListDoc;
typedef int (* SquatListDocCallback)(void* closure, SquatListDoc const* doc);
int               squat_search_list_docs(SquatSearchIndex* index, 
		    SquatListDocCallback handler, void* closure);


/* Get a list of the documents that may include the given search string.
   The callback function is called once for each possibly-matching
   document. The callback function returns one of the above results to
   control the progress of the operation. Call this after successfully
   calling squat_search_open, squat_search_list_docs, or
   squat_search_execute. */
typedef int (* SquatSearchResultCallback)(void* closure, char const* doc_name);
int               squat_search_execute(SquatSearchIndex* index, char const* data,
                    int data_len, SquatSearchResultCallback handler, void* closure);


/* Release the SQUAT resources associated with an index. The resources
   are released whether this call succeeds or fails.
   Call this anytime. */
int               squat_search_close(SquatSearchIndex* index);

#endif
