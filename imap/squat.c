/* SQUAT code for searching indexes.
 *  Robert O'Callahan
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

#include <config.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "squat_internal.h"

#include "assert.h"
#include "xmalloc.h"

struct _SquatSearchIndex
{
    int index_fd;                      /* the index file */
    char const *data;                  /* where it's mmaped to */
    char const *doc_list;              /* where does the doc-list
                                          sequence start in memory */
    char const *word_list;             /* where does the word trie
                                          offset table start in memory */
    char const *doc_ID_list;           /* where does the doc-ID-list
                                          array start in memory */
    char const *data_end;              /* the end of the mmaped file */
    unsigned char valid_char_bits[32]; /* which characters are valid in
                                          queries according to whoever
                                          created the index */
};

/* For each 0 <= i < 256, bit_counts[i] is the number of bits set in i */
static char bit_counts[256];

/* Returns true IFF the 'len' bytes starting at 's' are each equal to 'v' */
static int memconst(char const *s, int len, char v)
{
    while (len > 0 && *s == v) {
        s++;
        len--;
    }
    return len == 0;
}

EXPORTED SquatSearchIndex *squat_search_open(int fd)
{
    struct stat buf;
    SquatSearchIndex *index;
    SquatDiskHeader const *header;
    SquatInt64 doc_list_offset, doc_ID_list_offset, word_list_offset;
    SquatInt64 data_len;

    squat_set_last_error(SQUAT_ERR_OK);

    /* initialize bit_counts constant array.
       This is so clever, I could die */
    if (bit_counts[1] == 0) {
        int c;
        for (c = 1; c < 256; c++) {
            bit_counts[c] = bit_counts[c >> 1] + (c & 1);
        }
    }

    index = (SquatSearchIndex *) xmalloc(sizeof(SquatSearchIndex));
    index->index_fd = fd;

    if (fstat(fd, &buf) != 0) { /* fstat64? */
        squat_set_last_error(SQUAT_ERR_SYSERR);
        goto cleanup_index;
    }
    data_len = buf.st_size - SQUAT_SAFETY_ZONE;
    if ((size_t) data_len < sizeof(SquatDiskHeader)) {
        squat_set_last_error(SQUAT_ERR_INVALID_INDEX_FILE);
        goto cleanup_index;
    }

    index->data =
        mmap(NULL, data_len + SQUAT_SAFETY_ZONE, PROT_READ, MAP_SHARED, fd, 0);
    if (index->data == MAP_FAILED) {
        squat_set_last_error(SQUAT_ERR_SYSERR);
        goto cleanup_index;
    }

    header = (SquatDiskHeader const *) index->data;
    doc_list_offset = squat_decode_64(header->doc_list_offset);
    word_list_offset = squat_decode_64(header->word_list_offset);
    doc_ID_list_offset = squat_decode_64(header->doc_ID_list_offset);

    /* Do some sanity checking in case the header was corrupted. We wouldn't
       want to dereference any bad pointers... */
    if (memcmp(header->header_text, squat_index_file_header, 8) != 0
        || doc_list_offset < 0 || doc_list_offset >= data_len
        || word_list_offset < 0 || word_list_offset >= data_len
        || doc_ID_list_offset < 0 || doc_ID_list_offset >= data_len
        || !memconst(index->data + data_len, SQUAT_SAFETY_ZONE, 0))
    {
        squat_set_last_error(SQUAT_ERR_INVALID_INDEX_FILE);
        goto cleanup_unmap;
    }

    index->doc_list = index->data + doc_list_offset;
    index->word_list = index->data + word_list_offset;
    index->doc_ID_list = index->data + doc_ID_list_offset;
    index->data_end = index->data + data_len;
    memcpy(index->valid_char_bits,
           header->valid_char_bits,
           sizeof(index->valid_char_bits));

    return index;

cleanup_unmap:
    munmap((void *) index->data, data_len + SQUAT_SAFETY_ZONE);

cleanup_index:
    free(index);
    return NULL;
}

EXPORTED int squat_search_list_docs(SquatSearchIndex *index,
                                    SquatListDocCallback handler,
                                    void *closure)
{
    char const *s = index->doc_list;

    squat_set_last_error(SQUAT_ERR_OK);

    while (*s != 0) {
        SquatListDoc list_doc;
        int r;

        list_doc.doc_name = s;
        s += strlen(s) + 1;
        list_doc.size = squat_decode_I(&s);
        r = handler(closure, &list_doc);

        if (r == SQUAT_CALLBACK_ABORT) {
            break;
        }
        assert(r == SQUAT_CALLBACK_CONTINUE);
    }

    return SQUAT_OK;
}

/* Get a pointer to the index file's list of documents containing the
   word 'data' */
static char const *lookup_word_docs(SquatSearchIndex *index,
                                    char const *data,
                                    int *invalid_file)
{
    int i;
    char const *s = index->word_list;

    for (i = 0; i < SQUAT_WORD_SIZE; i++) {
        char p;
        char ch = data[i];
        char const *branch_start = s;
        int skip;

        /* decode 'present' bits to see if ch is present at this level of
           the tries */
        p = *s++;
        if ((p & 0xE0) != 0) { /* singleton */
            if (ch != p) {
                return NULL;
            }
            skip = 0;
            /* we're done. s is now pointing at the data for the singleton */
        }
        else { /* list of bits */
            char count;
            char const *base;
            int offset, j;

            if ((unsigned char) ch < 8 * p) { /* before start of list */
                return NULL;
            }

            count = (*s++) + 1;

            if ((unsigned char) ch
                >= 8 * (p + count)) { /* beyond end of list */
                return NULL;
            }

            offset = (unsigned char) ch / 8 - p;
            if ((s[offset] & (1 << (ch & 7))) == 0) { /* not in list */
                return NULL;
            }

            base = s;
            s += count;

            /* figure out how many entries there are before our entry */
            skip = 0;
            for (j = 0; j < offset; j++) {
                skip += bit_counts[(unsigned char) base[j]];
            }
            for (j = 0; j < (ch & 7); j++) {
                if ((base[offset] & (1 << j)) != 0) {
                    skip++;
                }
            }
        }

        if (i < SQUAT_WORD_SIZE - 1) {
            int next_offset;

            s = squat_decode_skip_I(s, skip);

            /* find offset to next branch data */
            next_offset = squat_decode_I(&s);
            s = branch_start - next_offset;
            if (next_offset < 0 || s >= index->data_end) {
                *invalid_file = 1;
                return NULL; /* corrupt index */
            }
        }
        else {
            /* leaf case. We need to scan through the document lists for each
               leaf to skip. */
            while (skip-- > 0) {
                char const *t = s;
                int v = (int) squat_decode_I(&t);

                if ((v & 1) != 0) {
                    s = t; /* singleton; no more data to eat for this word */
                }
                else {
                    s = t + (v >> 1); /* run-list; size is in v>>1 */
                }
            }
        }
        /* s now points at the trie branch for the data */
    }

    return s;
}

/* Get the pointer to the list of documents containing 'data' into
   '*run_start', and return the number of documents in the list. */
static int count_docs_containing_word(SquatSearchIndex *index,
                                      char const *data,
                                      char const **run_start)
{
    int invalid_file = 0;
    char const *raw_doc_list = lookup_word_docs(index, data, &invalid_file);
    int i;

    if (raw_doc_list == NULL) {
        return invalid_file ? -1 : 0;
    }

    *run_start = raw_doc_list;

    i = (int) squat_decode_I(&raw_doc_list);
    if ((i & 1) != 0) {
        return 1; /* singleton */
    }
    else {
        int size = i >> 1;
        char const *s = raw_doc_list;
        int count = 0;

        if (raw_doc_list + size >= index->data_end) {
            return -1;
        }

        while (s - raw_doc_list < size) {
            i = (int) squat_decode_I(&s);
            if ((i & 1) == 1) {
                count++;
            }
            else {
                count += i >> 1;
                s = squat_decode_skip_I(s, 1);
            }
        }

        if (raw_doc_list + size != s) {
            return -1;
        }

        return count;
    }
}

/* We store a set of documents in this little structure. The set
   also maintains a 'current' document pointer. */
typedef struct
{
    int array_len;   /* The length of the array below */
    int *array_data; /* An array of document IDs, sorted by increasing
                        document ID. It can also contain elements equal
                        to -1, which means "no document".
                     */
    int index;       /* The index of the 'current' document within the array. */
} SquatDocSet;

/* Extract the list of documents containing the word 'data' into a
   SquatDocSet. The list is extracted from the index file data
   'doc_list' which refers to 'doc_count' documents.
*/
static int set_to_docs_containing_word(SquatSearchIndex *index
                                       __attribute__((unused)),
                                       SquatDocSet *set,
                                       char const *data __attribute__((unused)),
                                       int doc_count,
                                       char const *doc_list)
{
    int i;

    set->array_len = doc_count;
    set->array_data = (int *) xmalloc(sizeof(int) * set->array_len);

    i = (int) squat_decode_I(&doc_list);
    if ((i & 1) != 0) {
        set->array_data[0] = i >> 1;
    }
    else {
        int size = i >> 1;
        char const *s = doc_list;
        int last_doc = 0;
        int j = 0;

        while (s - doc_list < size) {
            i = (int) squat_decode_I(&s);
            if ((i & 1) == 1) {
                last_doc = set->array_data[j++] = last_doc + (i >> 1);
            }
            else {
                int count = i >> 1;
                int delta = squat_decode_I(&s);

                last_doc += delta;
                set->array_data[j++] = last_doc;
                while (--count > 0) {
                    last_doc++;
                    set->array_data[j++] = last_doc;
                }
            }
        }
    }

    return SQUAT_OK;
}

/* Advance the "current document" in the set to the first document
   with ID > 'doc'. Remove any documents found along the way that were
   not 'doc'.
*/
static void filter_doc(SquatDocSet *set, int doc)
{
    int i = set->index;

    while (i < set->array_len && set->array_data[i] < doc) {
        /* this document is not in the currently filtered set */
        set->array_data[i] = -1;
        i++;
    }

    /* skip over the matched document, if we matched */
    if (i < set->array_len && set->array_data[i] == doc) {
        i++;
    }

    set->index = i;
}

/* Remove from a SquatDocSet any documents not in the list of
   documents containing the word 'data'. The list is extracted from
   the index file data 'doc_list'.
*/
static void filter_to_docs_containing_word(SquatSearchIndex *index
                                           __attribute__((unused)),
                                           SquatDocSet *set,
                                           char const *data
                                           __attribute__((unused)),
                                           char const *doc_list)
{
    int i = (int) squat_decode_I(&doc_list);

    set->index = 0;

    if ((i & 1) != 0) {
        filter_doc(set, i >> 1);
    }
    else {
        int size = i >> 1;
        char const *s = doc_list;
        int last_doc = 0;

        while (s - doc_list < size) {
            i = (int) squat_decode_I(&s);
            if ((i & 1) == 1) {
                filter_doc(set, last_doc += i >> 1);
            }
            else {
                int count = i >> 1;
                int delta = squat_decode_I(&s);

                last_doc += delta;
                filter_doc(set, last_doc);
                while (--count > 0) {
                    last_doc++;
                    filter_doc(set, last_doc);
                }
            }
        }
    }
}

/* Advance the "current document" pointer to the first document in the set. */
static void select_first_doc(SquatDocSet *set)
{
    set->index = 0;
    while (set->index < set->array_len && set->array_data[set->index] < 0) {
        set->index++;
    }
}

/* Is the "current document" pointer pointing to any real document? */
static int has_more_docs(SquatDocSet *set)
{
    return set->index < set->array_len;
}

/* Advance the "current document" pointer to the next document in the set,
   and return its old value */
static int get_next_doc(SquatDocSet *set)
{
    int doc = set->array_data[set->index];

    set->index++;
    while (set->index < set->array_len && set->array_data[set->index] < 0) {
        set->index++;
    }

    return doc;
}

static void destroy_docset(SquatDocSet *set)
{
    free(set->array_data);
}

/* The basic strategy here is pretty simple. We just want to find the
   documents that contain every subword of the search string. The
   index tells us which documents contain each subword so it's just a
   matter of doing O(N) lookups into the index. We construct an
   explicit document list for one of the subwords and then iterate
   through that list for each other subword, throwing out any
   documents that don't contain that subword.

   The only trick is that some subwords may occur in lots of documents
   while others only occur in a few (or no) documents. In that case we
   would rather construct the list with the smallest possible number
   of documents, to save memory and the cost of traversing that list
   several times.
*/
HIDDEN int squat_search_execute(SquatSearchIndex *index,
                                char const *data,
                                int data_len,
                                SquatSearchResultCallback handler,
                                void *closure)
{
    int i;
    int min_doc_count_word; /* The subword of 'data' that appears in
                               fewest documents */
    int min_doc_count;      /* The number of documents that include that
                               subword */
    SquatDocSet set;
    char const **run_starts;

    /* First, do sanity checking on the string. We wouldn't want invalid
       client searches to mysteriously return 'no documents'. */
    if (data_len < SQUAT_WORD_SIZE) {
        squat_set_last_error(SQUAT_ERR_SEARCH_STRING_TOO_SHORT);
        return SQUAT_ERR;
    }

    for (i = 0; i < data_len; i++) {
        int ch = (unsigned char) data[i];

        if ((index->valid_char_bits[ch >> 3] & (1 << (ch & 7))) == 0) {
            squat_set_last_error(SQUAT_ERR_SEARCH_STRING_INVALID_CHAR);
            return SQUAT_ERR;
        }
    }

    /* We search for every subword of the search string. We save a
       pointer to the document list for each subword in this array
       ... so we don't have to traverse the trie data structures more
       than once per subword.
    */
    run_starts = (char const **) xmalloc(sizeof(char const *)
                                         * (data_len - SQUAT_WORD_SIZE + 1));
    squat_set_last_error(SQUAT_ERR_OK);

    /* Now, for each subword, find its list of documents and how many
       documents are in the list. Remember the word which had minimum
       number of documents.
    */
    min_doc_count = count_docs_containing_word(index, data, run_starts);
    if (min_doc_count < 0) {
        squat_set_last_error(SQUAT_ERR_INVALID_INDEX_FILE);
        goto cleanup_run_starts;
    }
    else if (min_doc_count == 0) {
        /* The first word of the substring isn't in any documents, so we
           can just stop now. */
        goto cleanup_run_starts_ok;
    }
    min_doc_count_word = 0;
    for (i = 1; i <= data_len - SQUAT_WORD_SIZE; i++) {
        int doc_count =
            count_docs_containing_word(index, data + i, run_starts + i);
        if (doc_count < 0) {
            squat_set_last_error(SQUAT_ERR_INVALID_INDEX_FILE);
            goto cleanup_run_starts;
        }
        else if (doc_count == 0) {
            /* This word isn't in any documents, we can stop now. */
            goto cleanup_run_starts_ok;
        }
        else if (doc_count < min_doc_count) {
            min_doc_count = doc_count;
            min_doc_count_word = i;
        }
    }

    /* Now, extract the shortest document list into an array. By
       starting with the shortest document list we avoid pathological
       situations where one or more of the subwords occurs in zillions
       of documents, and we'd allocate a huge array and have to iterate
       through it all lots of times.
    */
    if (set_to_docs_containing_word(index,
                                    &set,
                                    data + min_doc_count_word,
                                    min_doc_count,
                                    run_starts[min_doc_count_word])
        == SQUAT_ERR)
    {
        goto cleanup_run_starts;
    }
    /* Scan through the other document lists and throw out any documents
       that aren't in all those lists. */
    for (i = 0; i <= data_len - SQUAT_WORD_SIZE; i++) {
        if (i != min_doc_count_word) {
            filter_to_docs_containing_word(index,
                                           &set,
                                           data + i,
                                           run_starts[i]);
        }
    }

    /* Now we have the results. Scan through the set and report each
       element to the callback function. */
    select_first_doc(&set);
    while (has_more_docs(&set)) {
        int next_doc;
        char const *next_doc_info;
        char const *next_doc_data;
        int r;

        /* Lookup the document info so we can get the document name to report. */
        next_doc = get_next_doc(&set);
        next_doc_info = index->doc_ID_list + next_doc * 4;
        if (next_doc < 0 && next_doc_info >= index->data_end) {
            squat_set_last_error(SQUAT_ERR_INVALID_INDEX_FILE);
            goto cleanup_docset;
        }

        next_doc_data = index->doc_list + squat_decode_32(next_doc_info);
        if (next_doc_data < index->doc_list || next_doc_data >= index->data_end)
        {
            squat_set_last_error(SQUAT_ERR_INVALID_INDEX_FILE);
            goto cleanup_docset;
        }

        r = handler(closure, next_doc_data);
        if (r == SQUAT_CALLBACK_ABORT) {
            break;
        }
        assert(r == SQUAT_CALLBACK_CONTINUE);
    }

    destroy_docset(&set);

cleanup_run_starts_ok:
    free(run_starts);
    return SQUAT_OK;

cleanup_docset:
    destroy_docset(&set);

cleanup_run_starts:
    free(run_starts);
    return SQUAT_ERR;
}

EXPORTED int squat_search_close(SquatSearchIndex *index)
{
    int r = SQUAT_OK;

    squat_set_last_error(SQUAT_ERR_OK);

    if (munmap((void *) index->data,
               index->data_end + SQUAT_SAFETY_ZONE - index->data)
        != 0)
    {
        squat_set_last_error(SQUAT_ERR_SYSERR);
        r = SQUAT_ERR;
    }

    free(index);
    return r;
}

/* ====================================================================== */

/* squat_scan(SquatSearchIndex* index, char first_char
 *            SquatScanCallback handler, void* closure)
 *
 * sweeps the entire subtrie for a given starting character. It generates
 * callbacks to the hander routine (which has it own opaque data structure
 * in closure) for each document ID that it finds in the leaves. The
 * callback function looks something like:
 *
 *   int add_word_callback(void* closure, char *name, int doc_ID);
 *
 * "name" is the full four character squat "word", including first_char and
 * a trailing '\0', just in case you want to print it. doc_ID is the
 * normal squat doc_ID offset.
 *
 * squat_scan_recurse() and squat_scan_leaf() are helper functions to
 * scan the entire trie. squat_find_branch() is used to find the initial
 * subtrie for a given first_char.
 *
 */

static int squat_scan_leaf(char const *doc_list,
                           char *name,
                           SquatScanCallback handler,
                           void *closure)
{
    int i;

    i = (int) squat_decode_I(&doc_list);
    if ((i & 1) != 0) {
        handler(closure, name, i >> 1);
    }
    else {
        int size = i >> 1;
        char const *s = doc_list;
        int last_doc = 0;

        while (s - doc_list < size) {
            i = (int) squat_decode_I(&s);
            if ((i & 1) == 1) {
                last_doc = last_doc + (i >> 1);
                handler(closure, name, last_doc);
            }
            else {
                int count = i >> 1;
                int delta = squat_decode_I(&s);

                last_doc += delta;
                handler(closure, name, last_doc);
                while (--count > 0) {
                    last_doc++;
                    handler(closure, name, last_doc);
                }
            }
        }
    }
    return (SQUAT_OK);
}

static int squat_scan_recurse(char const *s,
                              char const *data_end,
                              char *name,
                              int level,
                              SquatScanCallback handler,
                              void *closure)
{
    int r = SQUAT_OK;
    char p;
    char const *branch_start = s;
    char const *start_of_list;
    int skip;
    char count;
    char const *base;
    int offset, j;
    int next_offset;
    int ch;

    /* Ignore empty subtrees generated by old versions of squatter */
    if ((s[0] == 0) && (s[1] == 0)) {
        return (SQUAT_OK);
    }

    p = *s++;
    if ((p & 0xE0) != 0) {
        /* Byte >= 0x20 (ASCII SPACE) indicates singleton list */

        name[level] = p;
        if (level < (SQUAT_WORD_SIZE - 1)) {
            next_offset = squat_decode_I(&s);
            s = branch_start - next_offset;
            if (next_offset < 0 || s >= data_end) {
                return (SQUAT_ERR);
            }
            r = squat_scan_recurse(s,
                                   data_end,
                                   name,
                                   level + 1,
                                   handler,
                                   closure);
        }
        else {
            r = squat_scan_leaf(s, name, handler, closure);
        }
        return (r);
    }

    count = (*s++) + 1; /* +1 to allow range 1..32 using (*s) < 32 */
    base = s;
    s += count;
    start_of_list = s; /* So that we can repeat */

    /* Up to 256 subtree branches, determined by variable length bitmask
     * which is up to 32 bytes (plus two lead in bytes).
     *      p*8  : First p*8 branches all empty, can be ignored
     *  count*8  : Size of base array, in bits
     *
     *
     * Should be able to optimise following into linear scan,
     * without returning to start_of_list each time around the loop
     */

    for (ch = 8 * p; ch < 8 * (p + count) && r == SQUAT_OK; ch++) {
        offset = (unsigned char) ch / 8 - p;
        if ((base[offset] & (1 << (ch & 7))) == 0) /* not in list */
        {
            continue;
        }

        /* figure out how many entries there are before our entry */
        skip = 0;
        for (j = 0; j < offset; j++) {
            skip += bit_counts[(unsigned char) base[j]];
        }
        for (j = 0; j < (ch & 7); j++) {
            if ((base[offset] & (1 << j)) != 0) {
                skip++;
            }
        }
        s = start_of_list;

        name[level] = ch;
        if (level < (SQUAT_WORD_SIZE - 1)) {
            s = squat_decode_skip_I(s, skip);
            next_offset = squat_decode_I(&s);

            s = branch_start - next_offset;
            if (next_offset < 0 || s >= data_end) {
                return (SQUAT_ERR);
            }
            r = squat_scan_recurse(s,
                                   data_end,
                                   name,
                                   level + 1,
                                   handler,
                                   closure);
        }
        else {
            /* leaf case. We need to scan through the document lists for each
               leaf to skip. */
            while (skip-- > 0) {
                char const *t = s;
                int v = (int) squat_decode_I(&t);

                if ((v & 1) != 0) {
                    s = t; /* singleton; no more data to eat for this word */
                }
                else {
                    s = t + (v >> 1); /* run-list; size is in v>>1 */
                }
            }
            r = squat_scan_leaf(s, name, handler, closure);
        }
    }
    return (r);
}

/* char const** prev is used by squat_count_docs to find start of
 * mmap()ed byte range that we need to traverse, so that we can
 * read in the data before we start trie walk. No other purpose.
 */

static int squat_find_branch(char const **result,
                             char const **prev,
                             char const *s,
                             char const *data_end,
                             char ch)
{
    char p;
    char const *branch_start = s, *t;
    int skip;
    char count;
    char const *base;
    int offset, j;
    int next_offset, prev_offset;

    *result = NULL;
    if (prev) {
        *prev = NULL;
    }

    /* Ignore empty subtrees generated by old versions of squatter */
    if ((s[0] == 0) && (s[1] == 0)) {
        *result = NULL;
        return (SQUAT_OK);
    }

    p = *s++;

    if ((p & 0xE0) != 0) { /* singleton */
        if (p != ch) {
            *result = NULL;
            return (SQUAT_OK);
        }

        next_offset = squat_decode_I(&s);
        s = branch_start - next_offset;
        if (next_offset < 0 || s >= data_end) {
            return (SQUAT_ERR);
        }
        *result = s;
        return (SQUAT_OK);
    }

    count = (*s++) + 1;
    offset = (unsigned char) ch / 8 - p;
    base = s;
    s += count;

    /* Does this character fall in range */
    if (((unsigned char) ch < 8 * p) || ((unsigned char) ch >= 8 * (p + count))
        || ((base[offset] & (1 << (ch & 7))) == 0))
    {
        *result = NULL;
        return (SQUAT_OK);
    }

    /* figure out how many entries there are before our entry */
    skip = 0;
    for (j = 0; j < offset; j++) {
        skip += bit_counts[(unsigned char) base[j]];
    }
    for (j = 0; j < (ch & 7); j++) {
        if ((base[offset] & (1 << j)) != 0) {
            skip++;
        }
    }

    if (skip > 0) {
        s = squat_decode_skip_I(s, skip - 1);
        prev_offset = squat_decode_I(&s);

        t = branch_start - prev_offset;
        if (prev && (prev_offset >= 0 && t < data_end)) {
            *prev = t;
        }
    }

    /* find offset to next branch data */
    next_offset = squat_decode_I(&s);

    s = branch_start - next_offset;
    if (next_offset < 0 || s >= data_end) {
        return (SQUAT_ERR);
    }
    *result = s;
    return (SQUAT_OK);
}

EXPORTED int squat_scan(SquatSearchIndex *index,
                        char first_char,
                        SquatScanCallback handler,
                        void *closure)
{
    char buf[SQUAT_WORD_SIZE + 1];
    const char *s;
    int r = squat_find_branch(&s,
                              NULL,
                              index->word_list,
                              index->data_end,
                              first_char);

    if (r != SQUAT_OK) {
        return (r);
    }
    if (!s) {
        return SQUAT_OK;
    }

    memset(buf, 0, sizeof(buf));
    buf[0] = first_char;

    return (squat_scan_recurse(s, index->data_end, buf, 1, handler, closure));
}

/* ====================================================================== */

/* squat_count_docs(SquatSearchIndex* index, char first_char, int *counter)
 *
 * count the total number of document ID which appear in the entire
 * subtree for a given starting character. Typically followed immediately
 * by a call to squat_scan after caller has allocated a target array
 * which is large enough for counter callback elements.
 *
 * squat_count_docs() will page in lots of data from disk via the mmapped
 * index file. Unfortunately squat indexes are built back to front, so
 * the scan would read blocks out of order as the data structure is
 * traversed. squat_preload_data() is a rather evil hack to try and
 * force sequential disk I/O: it serves no other function.
 */

static int squat_count_docs_callback(void *closure,
                                     char *name __attribute__((unused)),
                                     int doc_ID __attribute__((unused)))
{
    int *counter = (int *) closure;

    (*counter)++;

    return SQUAT_CALLBACK_CONTINUE;
}

/* Attempt to load blocks of data from mmap()ed array before we start
   random access */

#define PRELOAD_BLOCK_SIZE (4096)           /*  4 KBytes */
#define PRELOAD_MAX_SIZE (20 * 1024 * 1024) /* 20 MBytes */

static void squat_preload_data(char const *t, char const *s)
{
    char buf[PRELOAD_BLOCK_SIZE];
    char const *start = (t > s) ? s : t;
    unsigned long len = (t > s) ? (t - s) : (s - t);

    if (len >= PRELOAD_MAX_SIZE) {
        return;
    }

    while (len > 0) {
        unsigned long size =
            (len > PRELOAD_BLOCK_SIZE) ? PRELOAD_BLOCK_SIZE : len;

        memcpy(buf, start, size);
        start += size;
        len -= size;
    }
}

EXPORTED int squat_count_docs(SquatSearchIndex *index,
                              char first_char,
                              int *counter)
{
    char buf[SQUAT_WORD_SIZE + 1];
    const char *s, *t;
    int r = squat_find_branch(&s,
                              &t,
                              index->word_list,
                              index->data_end,
                              first_char);
    *counter = 0;

    if (r != SQUAT_OK) {
        return (r);
    }
    if (!s) {
        return SQUAT_OK;
    }

    /* First trie is at index->doc_ID_list + (no_docIDs *4). However
     * no_docIDs doesn't appear to be stored anywhere (zero terminated list).
     * Following is good enough for our purposes */
    squat_preload_data((t) ? t : index->doc_ID_list, s);

    memset(buf, 0, sizeof(buf));
    buf[0] = first_char;

    return (squat_scan_recurse(s,
                               index->data_end,
                               buf,
                               1,
                               squat_count_docs_callback,
                               counter));
}
