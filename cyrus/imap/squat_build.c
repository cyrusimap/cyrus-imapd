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
 * $Id: squat_build.c,v 1.1 2001/09/25 16:49:51 ken3 Exp $
 */

/*
  SQUAT code for building indexes.
  Robert O'Callahan

  IMPLEMENTATION NOTES:

  The basic strategy here is pretty simple. During the index build
  process we keep 256 temporary files. Each time we read a source
  document, we add all its words that start with byte i, along with
  the document ID, to file #i. Once we've seen all the source
  documents we proceed through each temporary file #i, one by one,
  constructing a trie of all the words starting with byte i, and which
  stores the IDs of the documents that contain each word. When we get
  to the end of each temporary file, we can write out the trie to the
  index file and start all over again on the next temporary file.

  This is marvellously scalable! During the document reading phase,
  we're just dumping data out into temporary files, and the amount of
  data we dump out is proportional to the total size of the source
  documents. (In the worst case, with large input files of random
  data, we write out 3 bytes per input byte into temporary files.)
  During the trie-building phase, we reread the temporary files and
  output the final index. In this phase we consume a fair bit of
  memory, but in the worst case only 8 bytes per document ID per word
  which starts with the right byte. Even in the very worst case, if
  there were gigabytes of random data, there are only 2^24 possible
  such words, and in practice of course there are far fewer.

  In practice performance is dominated by sequential I/O. On my email,
  I can index half a megabyte of source text per second on a
  single-disk desktop PC.

  The same trie data structures are used to build tries to record the
  words used in a particular document (while the source document is
  being fed in) and to build tries to record the words used in all
  documents that start with a given byte (while we process each
  temporary file).

  Each "per document" trie stores all words occurring in the
  document. We make it a depth 3 trie, and at the leaves we store a
  bit vector recording which words are present in the document, with a
  bit set to 1 if a word occurs with its 4th character set to the
  corresponding byte.

  Each "all document" trie assumes a fixed first word byte, and
  therefore is only of depth 3. The leaves store the list of document
  IDs containing the word.
*/

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>

#include "squat_internal.h"

/* A simple write-buffering module which avoids copying of the output data. */

typedef struct {
  char* buf;               /* The malloc'ed buffer, or NULL if there
			      isn't one. */
  int buf_size;            /* The size of that buffer. */
  int data_len;            /* How much data in that buffer is valid. */
  int fd;                  /* The fd to write to. */
  int total_output_bytes;  /* How much data have we written out
			      through this buffer in total? */
} SquatWriteBuffer;

static int init_write_buffer(SquatWriteBuffer* b, int buf_size, int fd) {
  b->buf_size = buf_size;
  b->buf = malloc(b->buf_size);
  if (b->buf == NULL) {
    squat_set_last_error(SQUAT_ERR_SYSERR);
    return SQUAT_ERR;
  }
  b->fd = fd;
  b->data_len = 0;
  b->total_output_bytes = 0;

  return SQUAT_OK;
}

/* Make sure that there is enough space in the buffer to write 'len' bytes.
   Return a pointer to where the written data should be placed. */
static char* prepare_buffered_write(SquatWriteBuffer* b, int len) {
  if (b->data_len + len >= b->buf_size) {
    if (write(b->fd, b->buf, b->data_len) != b->data_len) {
      squat_set_last_error(SQUAT_ERR_SYSERR);
      return NULL;
    }
    if (b->buf_size < len) {
      b->buf = (char*)realloc(b->buf, len);
      if (b->buf == NULL) {
        squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
        return NULL;
      }
    }
    b->data_len = 0;
  }
  
  return b->buf + b->data_len;
}

/* Signal that data has been written up to the mark 'ptr'.
   Call this after prepare_buffered_write. */
static void complete_buffered_write(SquatWriteBuffer* b, char* ptr) {
  int old_data_len = b->data_len;

  b->data_len = ptr - b->buf;
  b->total_output_bytes += b->data_len - old_data_len;
}

/* Flush the output buffer to the file. Reset the file pointer to the start
   of the file. */
static int flush_and_reset_buffered_writes(SquatWriteBuffer* b) {
  if (b->data_len > 0) {
    if (write(b->fd, b->buf, b->data_len) != b->data_len) {
      squat_set_last_error(SQUAT_ERR_SYSERR);
      return SQUAT_ERR;
    }
    b->data_len = 0;
  }

  if (lseek(b->fd, 0, SEEK_SET) != 0) {
    squat_set_last_error(SQUAT_ERR_SYSERR);
    return SQUAT_ERR;
  }

  return SQUAT_OK;
}

/* A circular linked list of document IDs, stored in increasing order
   of document ID. */
typedef struct _WordDocEntry {
  struct _WordDocEntry* next;
  int doc_ID;
} WordDocEntry;

/* These form the leaves of the "all documents" tries. For each of the
   256 words with trailing byte 'i', docs[i] is NULL if the word does
   not occur in any document, otherwise it is the head of a linked
   list of document IDs for the documents which contain the word. */
typedef struct {
  short first_valid_entry;  /* We record the first and last valid
			       entries in the array below. These could
			       be computed by just scanning the array,
			       but it turns out that in practice such
			       array scanning dominates the CPU
			       consumption of the indexer. We get
			       major speedup by maintaining these
			       entries on the fly. */ 
  short last_valid_entry;
  WordDocEntry* docs[256];  /* Pointers to the document ID lists for
			       each of the 256 words rooted at this
			       part of the trie. Each non-NULL pointer
			       points to the LAST element of the
			       linked list (i.e. the entry with the
			       highest document ID). This means we can
			       efficiently add to the end of the
			       linked list, and also efficiently get
			       to the start of the linked list (the
			       element with lowest document ID)
			       (because it's circular). */
} SquatWordTableLeafDocs;

/* These form the leaves of the "per document" tries. For each of the
   256 words with trailing byte 'i', presence[i >> 3] & (1 << (i & 7))
   is 1 if the word occurs in the document, otherwise 0. */
typedef struct {
  short first_valid_entry;  /* We record the first and last valid
			       entries in the bit vector below. These
			       could be computed by just scanning the
			       array, but we get significant speedup
			       by maintaining them here. */
  short last_valid_entry;
  char presence[32];
} SquatWordTableLeafPresence;

/* This is an entry in a trie. */
typedef union _SquatWordTableEntry {
  struct _SquatWordTable* table;   /* This is a branch node */

  /* These variants are used for leaves of "per document" tries.
     They are distinguished by the value of the low bit. */
  SquatWordTableLeafPresence* leaf_presence;    /* low bit is 0 */
  int leaf_presence_singleton;                  /* low bit is 1 */

  /* This variant is used for leaves of "all document" tries. */
  SquatWordTableLeafDocs* leaf_docs;
} SquatWordTableEntry;

/* This is a trie branch node. */
typedef struct _SquatWordTable {
  short first_valid_entry;   /* We record the first and last valid
				entries in the array below, as in the
				above data structures. */
  short last_valid_entry;
  SquatWordTableEntry entries[256];
} SquatWordTable;

struct _SquatIndex {
  char* tmp_path;                     /* Saved tmp_path option, with
					 the temporary filename
					 pattern appended */
  SquatWriteBuffer out;               /* The buffer for the index file itself */
  char* doc_ID_list;                  /* A buffer where we hold the
					 encoded array that maps from
					 a document ID to the offset
					 of the document record within
					 the index file. */
  int doc_ID_list_size;               /* The allocated size of the
					 above buffer, measured in
					 multiples of
					 sizeof(SquatInt32) (i.e., 4) */
  int current_doc_ID;                 /* The current document
					 ID. Document IDs are numbered
					 starting at zero and
					 incremented by 1 every time
					 we finish processing a source
					 document. */
  int current_doc_len;                /* The total number of bytes
					 processed in the current
					 source document. */ 
  SquatWordTable doc_word_table;      /* The root of the trie being
					 built for the current
					 document or for the current
					 initial byte. */
  char runover_buf[SQUAT_WORD_SIZE];  /* holds the last runover_len
					 bytes of the current source
					 document */
  int runover_len;
  WordDocEntry* word_doc_allocator;   /* A preallocated buffer of
					 WordDocEntries; this pointer
					 is bumped up one every
					 allocation */
  unsigned char valid_char_bits[32];  /* Saved valid_char_bits option */
  SquatStatsCallback stats_callback;  /* Saved stats_callback option */
  void* stats_callback_closure;

  /* put the big structures at the end */

  SquatWriteBuffer index_buffers[256]; /* Buffers for the temporary
					  files, one for each first
					  byte of words occurring in
					  the source documents */
  int total_num_words[256];  /* total number of words starting with
				given char */
  int doc_words[256];        /* number of words in current document
				starting with given char */
};

/* Initally, before we see a document, there are no words for the document. */
static void init_doc_word_table(SquatWordTable* t) {
  t->first_valid_entry = 256;
  t->last_valid_entry = 0;
  memset(t->entries, 0, sizeof(t->entries));
}

SquatIndex* squat_index_init(int fd, SquatOptions const* options) {
  SquatIndex* index;
  int i;
  int path_len;
  char* buf;
  char const* tmp_path;

  squat_set_last_error(SQUAT_ERR_OK);

  index = (SquatIndex*)malloc(sizeof(SquatIndex));
  if (index == NULL) {
    squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
    return NULL;
  }

  /* Copy processed options into the SquatIndex */
  if (options != NULL && (options->option_mask & SQUAT_OPTION_TMP_PATH) != 0) {
    tmp_path = options->tmp_path;
  } else {
    tmp_path = "/tmp";
  }
  path_len = strlen(tmp_path);
  index->tmp_path = malloc(path_len + 1 + 12);
  if (index->tmp_path == NULL) {
    squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
    goto cleanup_index;
  }
  memcpy(index->tmp_path, tmp_path, path_len);
  strcpy(index->tmp_path + path_len, "/squatXXXXXX");

  if (options != NULL &&
      (options->option_mask & SQUAT_OPTION_VALID_CHARS) != 0) {
    int i;

    memset(index->valid_char_bits, 0, sizeof(index->valid_char_bits));
    for (i = 0; options->valid_chars[i] != 0; i++) {
      int ch = (unsigned char)options->valid_chars[i];

      index->valid_char_bits[ch >> 3] |= 1 << (ch & 7);
    }
  } else {
    memset(index->valid_char_bits, 255, sizeof(index->valid_char_bits));
  }

  if (options != NULL &&
      (options->option_mask & SQUAT_OPTION_STATISTICS) != 0) {
    index->stats_callback = options->stats_callback;
    index->stats_callback_closure = options->stats_callback_closure;
  } else {
    index->stats_callback = NULL;
  }

  /* Finish initializing the SquatIndex */
  for (i = 0; i < 256; i++) {
    index->index_buffers[i].buf = NULL;
  }

  index->doc_ID_list_size = 1000;
  index->doc_ID_list = (char*)malloc(index->doc_ID_list_size*sizeof(SquatInt32));
  if (index->doc_ID_list == NULL) {
    squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
    goto cleanup_tmp_path;
  }

  /* Use a 128K write buffer for the main index file */
  if (init_write_buffer(&index->out, 128*1024, fd) != SQUAT_OK) {
    goto cleanup_doc_ID_list;
  }

  /* Write out a dummy header. This will be replaced by the real header at the
     end of the process. */
  buf = prepare_buffered_write(&index->out, sizeof(SquatDiskHeader));
  if (buf == NULL) {
    goto cleanup_out_buffer;
  }
  memset(buf, 0, sizeof(SquatDiskHeader));
  complete_buffered_write(&index->out, buf + sizeof(SquatDiskHeader));

  index->current_doc_ID = 0;
  init_doc_word_table(&index->doc_word_table);

  memset(index->total_num_words, 0, sizeof(index->total_num_words));

  return index;

cleanup_out_buffer:
  free(index->out.buf);

cleanup_doc_ID_list:
  free(index->doc_ID_list);

cleanup_tmp_path:
  free(index->tmp_path);

cleanup_index:
  free(index);  
  return NULL;
}

/* Initialize a write buffer for a temporary file. We generate the
   temporary file name here. The file is unlinked right away so if we
   crash, the temporary file doesn't need to be cleaned up. */
static int init_write_buffer_to_temp(SquatIndex* index, SquatWriteBuffer* b) {
  int fd = mkstemp(index->tmp_path);

  if (fd < 0) {
    squat_set_last_error(SQUAT_ERR_SYSERR);
    return SQUAT_ERR;
  }

  if (unlink(index->tmp_path) < 0) {
    squat_set_last_error(SQUAT_ERR_SYSERR);
    goto cleanup_fd;
  }
  
  strcpy(index->tmp_path + strlen(index->tmp_path) - 6, "XXXXXX");

  if (init_write_buffer(b, 64*1024, fd) != SQUAT_OK) {
    goto cleanup_fd;
  }

  return SQUAT_OK;

cleanup_fd:
  close(b->fd);
  return SQUAT_ERR;
}

int squat_index_open_document(SquatIndex* index, char const* name) {
  int name_len;
  char* buf;

  squat_set_last_error(SQUAT_ERR_OK);

  /* Grow the document ID array as necessary */
  if (index->current_doc_ID >= index->doc_ID_list_size) {
    index->doc_ID_list_size *= 2;
    index->doc_ID_list =
      (char*)realloc(index->doc_ID_list, index->doc_ID_list_size*sizeof(SquatInt32));

    if (index->doc_ID_list == NULL) {
      squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
      return SQUAT_ERR;
    }
  }

  /* Store the offset of the new document record into the array */
  squat_encode_32(index->doc_ID_list + index->current_doc_ID*4,
                  index->out.total_output_bytes - sizeof(SquatDiskHeader));

  /* Now write the new document name out to the file. Later we will
     write the document length right after this. Nobody writes to the
     file in the interim. */
  name_len = strlen(name) + 1;
  if ((buf = prepare_buffered_write(&index->out, name_len)) == NULL) {
    return SQUAT_ERR;
  }
  strcpy(buf, name);
  complete_buffered_write(&index->out, buf + name_len);

  index->current_doc_len = 0;
  index->runover_len = 0;
  memset(index->doc_words, 0, sizeof(index->doc_words));

  return SQUAT_OK;
}

/* Destroy the SquatWordTable. The leaf data and the internal nodes are free'd. */
static void delete_doc_word_table(SquatWordTable* t, int depth) {
  if (depth > 2) {
    int i;

    depth--;
    for (i = 0; i < 256; i++) {
      SquatWordTableEntry* e = t->entries + i;
      
      if (e->table != NULL) {
        delete_doc_word_table(e->table, depth);
      }
    }
  } else {
    int i;

    /* this happens to work whether the leaf entries are leaf_presence
       or leaf_docs. This is ugly but acceptable :-) */
    for (i = 0; i < 256; i++) {
      SquatWordTableEntry* e = t->entries + i;
      
      if (e->leaf_presence != NULL && ((int)e->leaf_presence & 1) == 0) {
        free(e->leaf_presence);
      }
    }
  }
  free(t);
}

#define SQUAT_ADD_NEW_WORD (SQUAT_LAST_BUILTIN + 1)

/* Add an entry to the compressed presence set. We maintain
   first_valid_entry and last_valid_entry.
   This is faster than scanning to compute them later.
   We return SQUAT_ADD_NEW_WORD if the bit wasn't already set. */
static int set_presence_bit(SquatWordTableLeafPresence* p, int ch) {
  int mask = 1 << (ch & 7);
  char* ptr = p->presence + (ch >> 3);

  if (ch < p->first_valid_entry) {
    p->first_valid_entry = ch;
  }
  if (ch > p->last_valid_entry) {
    p->last_valid_entry = ch;
  }

  if ((*ptr & mask) == 0) {
    *ptr |= mask;
    return SQUAT_ADD_NEW_WORD;
  } else {
    return SQUAT_OK;
  }
}

/* Add a word to the SquatWordTable trie.
   If word_entry is NULL then we are in "per document" mode and just record
   the presence or absence of a word, not the actual document.
   We return SQUAT_ADD_NEW_WORD if this is the first occurrence of the
   word in the trie. */
static int add_to_table(SquatIndex* index, char const* data, int data_len,
                        WordDocEntry* word_entry) {
  SquatWordTable* t = &index->doc_word_table;
  int ch;
  SquatWordTableEntry* e;

  while (data_len > 2) {
    /* Follow the branch node down to the next level of the trie. */
    ch = (unsigned char)data[0];
    /* Maintain the valid_entry variables so that we don't have to
       perform expensive scans of the 256-element arrays
       later. Surprisingly, this optimization really matters! */
    if (ch < t->first_valid_entry) {
      t->first_valid_entry = ch;
    }
    if (ch > t->last_valid_entry) {
      t->last_valid_entry = ch;
    }

    e = t->entries + ch;
    t = e->table;
    /* Allocate the next branch node if it doesn't already exist. */
    if (t == NULL) {
      t = (SquatWordTable*)malloc(sizeof(SquatWordTable));
      if (t == NULL) {
        squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
        return SQUAT_ERR;
      }
      e->table = t;
      /* Initially there are no valid entries. Set things up so that
	 the obvious tests will set first_valid_entry and
	 last_valid_entry correctly. */
      t->first_valid_entry = 256;
      t->last_valid_entry = 0;
      memset(t->entries, 0, sizeof(t->entries));
    }

    data++;
    data_len--;
  }

  /* Follow the branch node down to the leaf level */
  ch = (unsigned char)data[0];
  if (ch < t->first_valid_entry) {
    t->first_valid_entry = ch;
  }
  if (ch > t->last_valid_entry) {
    t->last_valid_entry = ch;
  }
  e = t->entries + ch;

  ch = (unsigned char)data[1];

  if (word_entry == NULL) {
    /* We are in "per document" mode. */
    if (((int)e->leaf_presence & 1) != 0) {
      /* We currently have a singleton here. */
      int oldch = e->leaf_presence_singleton >> 1;

      /* If the singleton indicates the same word as the current word,
	 then we don't have to do anything. */
      if (oldch != ch) {
	/* Otherwise we have to add the new word. This means we have
	   to convert the singleton to a bit vector. */
        SquatWordTableLeafPresence* p;

	/* Make an empty bit vector. */
        p = (SquatWordTableLeafPresence*)
          malloc(sizeof(SquatWordTableLeafPresence));
        if (p == NULL) {
          squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
          return SQUAT_ERR;
        }
        p->first_valid_entry = 256;
        p->last_valid_entry = 0;
        memset(p->presence, 0, sizeof(p->presence));
        e->leaf_presence = p;

	/* Update the bit vector */
        set_presence_bit(p, ch);
        return set_presence_bit(p, oldch); /* will always be SQUAT_ADD_NEW_WORD */
      }
    } else if (e->leaf_presence == NULL) {
      /* There's nothing here. Let's make a singleton. */
      /* this next step might be necessary if sizeof(void*) >
	 sizeof(int). We make sure that the low bit of the pointer in
	 leaf_presence is definitely 1. */
      e->leaf_presence = (void*)1;
      e->leaf_presence_singleton = (ch << 1) | 1;
      return SQUAT_ADD_NEW_WORD;
    } else {
      /* We already have the bit vector, so let's just set another bit in it. */
      return set_presence_bit(e->leaf_presence, ch);
    }
  } else {
    /* We are in "all documents" mode. */
    SquatWordTableLeafDocs* docs = e->leaf_docs;
    WordDocEntry** entry_ptr;

    /* Make a new leaf table if we don't already have one. */
    if (docs == NULL) {
      docs = (SquatWordTableLeafDocs*)
        malloc(sizeof(SquatWordTableLeafDocs));
      if (docs == NULL) {
        squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
        return SQUAT_ERR;
      }
      docs->first_valid_entry = 256;
      docs->last_valid_entry = 0;
      memset(docs->docs, 0, sizeof(docs->docs));
      e->leaf_docs = docs;
    }

    entry_ptr = docs->docs + ch;

    if (*entry_ptr == NULL) {
      /* Adding a new word, so may need to update the valid_entry markers */
      if (ch < docs->first_valid_entry) {
	docs->first_valid_entry = ch;
      }
      if (ch > docs->last_valid_entry) {
	docs->last_valid_entry = ch; 
      }
      /* Create the linked list with the single element 'word_entry'. */
      word_entry->next = word_entry; /* make it circular */
      *entry_ptr = word_entry;
      return SQUAT_ADD_NEW_WORD;
    } else {
      /* Just add the document to the linked list. word_entry will be
	 the new last element since the document IDs are strictly
	 increasing as we build the trie from its temporary file. */
      word_entry->next = (*entry_ptr)->next; /* (*entry_ptr)->next is
						(still) the first
						element of the list */
      (*entry_ptr)->next = word_entry;       /* the old last element's
						next now points to the
						new last element. */
      *entry_ptr = word_entry;               /* save the new last element */
    }
  }

  return SQUAT_OK;
}

/* Add 'doc_ID' to the list of document IDs for word 'word_ptr'
   in the "all documents" trie. */
static int add_word_to_trie(SquatIndex* index, char const* word_ptr,
                            int doc_ID) {
  WordDocEntry* word_entry = index->word_doc_allocator++;

  word_entry->doc_ID = doc_ID;
  add_to_table(index, word_ptr, SQUAT_WORD_SIZE - 1, word_entry);

  return SQUAT_OK;
}

/* Add the word 'data' to the "per document" trie for the current document. */
static int add_word_to_table(SquatIndex* index, char const* data) {
  int r;
  int i;
  
  /* Just ignore the word if it uses an invalid character. */
  for (i = 0; i < SQUAT_WORD_SIZE; i++) {
    int ch = (unsigned char)data[i];

    if ((index->valid_char_bits[ch >> 3] & (1 << (ch & 7))) == 0) {
      /* this word contains an invalid character and need not be indexed,
         since search strings will never contain such a character. */
      return SQUAT_OK;
    }
  }

  r = add_to_table(index, data, SQUAT_WORD_SIZE, NULL);
  if (r == SQUAT_ADD_NEW_WORD) {
    /* Remember how many unique words in this document started with
       the given first character. */
    index->doc_words[(unsigned char)data[0]]++;
    return SQUAT_OK;
  } else {
    return r;
  }
}

int squat_index_append_document(SquatIndex* index, char const* data,
                                int data_len) {
  int i;
  char buf[SQUAT_WORD_SIZE];
  int new_runover;
  int new_runover_data;

  assert(data_len >= 0);

  squat_set_last_error(SQUAT_ERR_OK);

  if (data_len == 0) {
    return SQUAT_OK;
  }

  /* Scan runover */
  for (i = 0; i < index->runover_len; i++) {
    /* Check if we can make a whole word starting with runover bytes
       from offset i within the runover buffer and with the remaining
       bytes taken from the new text */
    if (index->runover_len - i + data_len >= SQUAT_WORD_SIZE) {
      /* Yep. Build the complete word into 'buf' and then add it. */
      memcpy(buf, index->runover_buf + i, index->runover_len - i);
      memcpy(buf + index->runover_len - i, data,
             SQUAT_WORD_SIZE - (index->runover_len - i));
      if (add_word_to_table(index, buf) != SQUAT_OK) {
        return SQUAT_ERR;
      }
    }
  }

  /* Scan main text */
  for (i = 0; i <= data_len - SQUAT_WORD_SIZE; i++) {
    if (add_word_to_table(index, data + i) != SQUAT_OK) {
      return SQUAT_ERR;
    }
  }

  /* Fill runover. We have to be careful to handle all the cases,
     particularly we just saw less than SQUAT_WORD_SIZE bytes and we
     need to copy some data from the old runover buffer into the new
     runover buffer. */
  new_runover = index->runover_len + data_len;
  if (new_runover > SQUAT_WORD_SIZE) {
    new_runover = SQUAT_WORD_SIZE;
  }
  new_runover_data = data_len;
  if (new_runover_data > new_runover) {
    new_runover_data = new_runover;
  }
  /* Copy data from the old runover buffer into its new position in
     the new runover buffer */
  memcpy(index->runover_buf,
         index->runover_buf + index->runover_len -
           (new_runover - new_runover_data),
         new_runover - new_runover_data);
  /* Copy data from the new text into the new runover buffer */
  memcpy(index->runover_buf + new_runover - new_runover_data,
         data + data_len - new_runover_data, new_runover_data);
  index->runover_len = new_runover;
    
  /* Tracking how much data we've seen for this document in total */
  index->current_doc_len += data_len;

  return SQUAT_OK;
}

/* Write the word to the given temporary file. Since each temporary
   file is dedicated to a given initial byte, the word passed to us
   has the initial byte removed. */
static int output_word(SquatWriteBuffer* b, char const* word) {
  char* buf = prepare_buffered_write(b, SQUAT_WORD_SIZE - 1);
  
  if (buf == NULL) {
    return SQUAT_ERR;
  }
  memcpy(buf, word, SQUAT_WORD_SIZE - 1);
  complete_buffered_write(b, buf + SQUAT_WORD_SIZE - 1);

  return SQUAT_OK;
}

/* Write the word data from the trie 't' into the temporary file
   accessed through 'b'. Words to write are assembled starting at
   'word'; we assume that 'len' bytes have already been assembled
   leading up to 'word'. This function clears the word data after
   writing it out. This makes it ready to handle the next document
   without reallocating everything. */
static int write_words(SquatIndex* index, SquatWriteBuffer* b,
                       SquatWordTable* t, int len, char* word) {
  if (len == 2) {
    /* Handle a branch node that refers to leaves. */
    int i;

    for (i = t->first_valid_entry; i <= t->last_valid_entry; i++) {
      SquatWordTableEntry* e = t->entries + i;

      word[0] = (char)i;

      if (((int)e->leaf_presence & 1) != 0) {
	/* Got a singleton at this branch point. Just output the single word. */
        word[1] = (char)(e->leaf_presence_singleton >> 1);
        e->leaf_presence = NULL; /* clear the leaf out */
        if (output_word(b, word - (SQUAT_WORD_SIZE - 3)) != SQUAT_OK) {
          return SQUAT_ERR;
        }
      } else if (e->leaf_presence != NULL) {
	/* Got a bit vector array which we have to scan. */
        /* The following code is performance critical. It can dominate
	   the performance of the entire indexer. That's why we need
	   the valid_entry fields! */
        SquatWordTableLeafPresence* p = e->leaf_presence;
        int i;
        int last_byte = p->last_valid_entry >> 3;

        for (i = p->first_valid_entry >> 3; i <= last_byte; i++) {
          int bits = (unsigned char)p->presence[i];
          int j;

          for (j = 0; bits > 0; j++, bits >>= 1) {
            if ((bits & 1) != 0) {
	      /* Output a word for each bit that is set */
              word[1] = (char)(i*8 + j);
              if (output_word(b, word - (SQUAT_WORD_SIZE - 3)) != SQUAT_OK) {
                return SQUAT_ERR;
              }
            }
          }
        }
        free(p);
        e->leaf_presence = NULL;
      }
    }
  } else {
    /* Handle an interior branch node. A simple matter of recursion. */
    int i;

    for (i = t->first_valid_entry; i <= t->last_valid_entry; i++) {
      SquatWordTable* new_t = t->entries[i].table;

      if (new_t != NULL) {
        word[0] = (char)i;
        if (write_words(index, b, new_t, len - 1, word + 1)
            != SQUAT_OK) {
          return SQUAT_ERR;
        }
      }
    }
  }

  /* This effectively clears the array because we trust these entries. */
  t->first_valid_entry = 256;
  t->last_valid_entry = 0;

  return SQUAT_OK;
}

int squat_index_close_document(SquatIndex* index) {
  char* buf;
  int i;
  
  squat_set_last_error(SQUAT_ERR_OK);

  /* Write out the length of the current document to the index file,
     just after the document's name. */
  if ((buf = prepare_buffered_write(&index->out, 10)) == NULL) {
    return SQUAT_ERR;
  }
  buf = squat_encode_I(buf, index->current_doc_len);
  complete_buffered_write(&index->out, buf);

  if (index->stats_callback != NULL) {
    SquatStatsEvent event;

    event.generic.type = SQUAT_STATS_COMPLETED_DOC;
    event.completed_doc.num_unique_words = index->doc_words;
    index->stats_callback(index->stats_callback_closure, &event);
  }

  /* For each byte that started a word in the source document, we need
     to dump all the words that occurred starting with that byte to
     the corresponding temporary file. */
  for (i = 0; i < 256; i++) {
    if (index->doc_words[i] > 0) {
      char* write_ptr;
      char word_buf[SQUAT_WORD_SIZE - 1];
      int cur_offset;

      if (index->index_buffers[i].buf == NULL) {
	/* This is the first document that used a word starting with this byte.
	   We need to create the temporary file. */
        if (init_write_buffer_to_temp(index, index->index_buffers + i)
            != SQUAT_OK) {
          return SQUAT_ERR;
        }
      }

      index->total_num_words[i] += index->doc_words[i];

      /* Write out the document ID and the number of words in this
	 document that start with the initial byte. Then we write out
	 the list of words themselves, SQUAT_WORD_SIZE-1 bytes
	 each. Very simple format for the temporary files. We could
	 compress them more but why bother? */
      write_ptr = prepare_buffered_write(index->index_buffers + i, 20);
      if (write_ptr == NULL) {
        return SQUAT_ERR;
      }
      write_ptr = squat_encode_I(write_ptr, index->current_doc_ID);
      write_ptr = squat_encode_I(write_ptr, index->doc_words[i]);
      complete_buffered_write(index->index_buffers + i, write_ptr);
        
      cur_offset = index->index_buffers[i].total_output_bytes;
      if (write_words(index, index->index_buffers + i,
                      index->doc_word_table.entries[i].table,
                      SQUAT_WORD_SIZE - 1, word_buf)
          != SQUAT_OK) {
        return SQUAT_ERR;
      }
      /* Make sure that we actually output the exact number of words
	 we thought we added to the trie. It's really easy to break
	 this invariant with bugs in the above code! */
      assert(index->index_buffers[i].total_output_bytes - cur_offset
             == (SQUAT_WORD_SIZE - 1)*index->doc_words[i]);
    }
  }

  index->current_doc_len = -1;

  index->current_doc_ID++;

  return SQUAT_OK;
}

/* Dump out a branch node of an "all documents" trie to the index
   file. It's dumped as a presence table (telling us which branches
   are non-NULL) followed by a list of relative file offsets in
   I-format pointing to the subtries for the non-NULL branches. */
static int dump_word_table_offsets(SquatIndex* index, SquatWordTable* t,
                                   int *offset_buf) {
  int start_present = t->first_valid_entry;
  int end_present = t->last_valid_entry;
  char* buf;
  int present_count;  /* We store here the actual number of present branches */

  if (start_present > end_present) {
    /* There are no non-empty branches so just write an empty presence table */
    if ((buf = prepare_buffered_write(&index->out, 2)) == NULL) {
      return SQUAT_ERR;
    } else {
      buf[0] = buf[1] = 0;
      complete_buffered_write(&index->out, buf + 2);
      return SQUAT_OK;
    }
  }

  /* If there is just one valid entry but its index is < 32, then we
     can't use the one-byte representation for a singleton presence
     because it would be mistaken for the first byte of a (count,
     start) presence vector header. A singleton whose index is >= 32
     can be written out without ambiguity. */
  if (end_present == start_present && end_present >= 32) {
    if ((buf = prepare_buffered_write(&index->out, 1)) == NULL) {
      return SQUAT_ERR;
    } else {
      *buf++ = (char)end_present;
      present_count = 1;
    }
  } else {
    /* We're going to use the presence bit vector format. */
    int first_byte = start_present >> 3;
    int byte_count = (end_present >> 3) - first_byte + 1;

    if ((buf = prepare_buffered_write(&index->out, 2 + byte_count)) == NULL) {
      return SQUAT_ERR;
    } else {
      int i;

      *buf++ = (char)first_byte;
      *buf++ = (char)byte_count - 1; /* subtract 1 to avoid ambiguity
					over the value '32' (we
					wouldn't use 0 anyway) */
      /* Clear the vector */
      memset(buf, 0, byte_count);
      present_count = 0;
      for (i = start_present; i <= end_present; i++) {
        if (offset_buf[i] > 0) {
          present_count++;
	  /* Set the bit in the vector. */
          buf[(i >> 3) - first_byte] |= 1 << (i & 7);
        }
      }
      buf += byte_count;
    }
  }
  complete_buffered_write(&index->out, buf);
  
  /* Now we write out the actual offset table in I-format. */
  if ((buf = prepare_buffered_write(&index->out, 10*present_count)) == NULL) {
    return SQUAT_ERR;
  } else {
    int i;

    for (i = start_present; i <= end_present; i++) {
      int off = offset_buf[i];

      if (off > 0) {
        buf = squat_encode_I(buf, off);
      }
    }
  }
  complete_buffered_write(&index->out, buf);

  return SQUAT_OK;
}

/* Write out the presence table for an "all documents" trie leaf. */
static int dump_doc_list_present_bits(SquatIndex* index,
                                      SquatWordTableLeafDocs* docs) {
  int start_present = docs->first_valid_entry;
  int end_present = docs->last_valid_entry;
  char* buf;
  int present_count;

  /* If the leaf is empty, we should never get here! */
  assert(start_present <= end_present);

  /* if it's a singleton < 32, then we can't use the one-byte
     representation because it would be mistaken for a starting byte */
  if (end_present == start_present && end_present >= 32) {
    if ((buf = prepare_buffered_write(&index->out, 1)) == NULL) {
      return SQUAT_ERR;
    } else {
      *buf++ = (char)end_present;
      present_count = 1;
    }
  } else {
    int first_byte = start_present >> 3;
    int byte_count = (end_present >> 3) - first_byte + 1;

    if ((buf = prepare_buffered_write(&index->out, 2 + byte_count)) == NULL) {
      return SQUAT_ERR;
    } else {
      int i;

      *buf++ = (char)first_byte;
      *buf++ = (char)byte_count - 1;
      memset(buf, 0, byte_count);
      present_count = 0;
      for (i = start_present; i <= end_present; i++) {
        if (docs->docs[i] != NULL) {
          present_count++;
          buf[(i >> 3) - first_byte] |= 1 << (i & 7);
        }
      }
      buf += byte_count;
    }
  }
  complete_buffered_write(&index->out, buf);
  
  return SQUAT_OK;
}

/* Write out the document lists for an "all documents" trie leaf. */
static int dump_doc_list_docs(SquatIndex* index,
                              SquatWordTableLeafDocs* docs) {
  int i;
  WordDocEntry** doc_list = docs->docs;

  for (i = docs->first_valid_entry; i <= docs->last_valid_entry; i++) {
    if (doc_list[i] != NULL) {
      WordDocEntry* first_doc;
      WordDocEntry* doc;
      int run_size = 0;   /* Bytes required to store the doclist for this word */
      int last_doc_ID;
      int run_seq_delta = 0;
      int run_seq_count;
      int doc_count = 0;  /* number of documents containing this word */
      char* buf;

      doc = first_doc = doc_list[i]->next;

      last_doc_ID = 0;
      run_seq_count = 0;
      /* First compute the run_size bytes required to store the doclist */
      do {
        if (doc->doc_ID == last_doc_ID + 1 && run_seq_count > 0) {
          run_seq_count++;
        } else {
          if (run_seq_count > 0) {
            if (run_seq_count > 1) {
              run_size += squat_count_encode_I(run_seq_count << 1)
                + squat_count_encode_I(run_seq_delta);
            } else {
              run_size += squat_count_encode_I((run_seq_delta << 1) | 1);
            }
          }
          run_seq_count = 1;
          run_seq_delta = doc->doc_ID - last_doc_ID;
        }
        last_doc_ID = doc->doc_ID;
        doc = doc->next;
        doc_count++;
      } while (doc != first_doc);
      if (run_seq_count > 0) {
        if (run_seq_count > 1) {
          run_size += squat_count_encode_I(run_seq_count << 1)
            + squat_count_encode_I(run_seq_delta);
        } else {
          run_size += squat_count_encode_I((run_seq_delta << 1) | 1);
        }
      }

      /* reserve more than enough space in the buffer */
      if ((buf = prepare_buffered_write(&index->out, 10 + run_size))
          == NULL) {
        return SQUAT_ERR;
      }

      /* If there's only one document, use singleton document format */
      if (doc_count == 1) {
        buf = squat_encode_I(buf, (doc->doc_ID << 1) | 1);
      } else {
	/* Store the entire document list, with its size first. */
        buf = squat_encode_I(buf, run_size << 1);

        last_doc_ID = 0;
        run_seq_count = 0;
	/* This logic should mirror the logic above that counts the bytes. */
        do {
          if (doc->doc_ID == last_doc_ID + 1 && run_seq_count > 0) {
            run_seq_count++;
          } else {
            if (run_seq_count > 0) {
              if (run_seq_count > 1) {
                buf = squat_encode_I(buf, run_seq_count << 1);
                buf = squat_encode_I(buf, run_seq_delta);
              } else {
                buf = squat_encode_I(buf, (run_seq_delta << 1) | 1);
              }
            }
            run_seq_count = 1;
            run_seq_delta = doc->doc_ID - last_doc_ID;
          }
          last_doc_ID = doc->doc_ID;
          doc = doc->next;
        } while (doc != first_doc);
        if (run_seq_count > 0) {
          if (run_seq_count > 1) {
            buf = squat_encode_I(buf, run_seq_count << 1);
            buf = squat_encode_I(buf, run_seq_delta);
          } else {
            buf = squat_encode_I(buf, (run_seq_delta << 1) | 1);
          }
        }
      }

      complete_buffered_write(&index->out, buf);
    }
  }

  return SQUAT_OK;
}

/* Write an "all documents" subtrie to the index file.
   'result_offset' is an absolute offset within the file where this
   subtrie was stored. We free the trie leaves as we go. */
static int write_trie_word_data(SquatIndex* index, SquatWordTable* t, int len,
                                int* result_offset) {
  int i;
  int offsets[256];  /* Collect the offsets of the subtries in this array. */
  int off;
  SquatWordTableEntry* entries = t->entries;
  int r;

  memset(offsets, 0, t->first_valid_entry*sizeof(int));
  if (len > 2) {
    /* interior branch */
    for (i = t->first_valid_entry; i <= t->last_valid_entry; i++) {
      SquatWordTable* new_t = entries[i].table;

      if (new_t != NULL) {
        if (write_trie_word_data(index, new_t, len - 1, offsets + i)
            != SQUAT_OK) {
          return SQUAT_ERR;
        }
      } else {
        offsets[i] = 0;
      }
    }
  } else {
    /* Leaf case */
    for (i = t->first_valid_entry; i <= t->last_valid_entry; i++) {
      SquatWordTableLeafDocs* leaf_docs = entries[i].leaf_docs;

      if (leaf_docs != NULL) {
        offsets[i] = index->out.total_output_bytes;
 
        if (dump_doc_list_present_bits(index, leaf_docs) != SQUAT_OK
            || dump_doc_list_docs(index, leaf_docs) != SQUAT_OK) {
          return SQUAT_ERR;
        }
        free(entries[i].leaf_docs);
        entries[i].leaf_docs = NULL;
      } else {
        offsets[i] = 0;
      }
    }
  }
  memset(offsets + i, 0, (256 - i)*sizeof(int));

  /* Now we've written out our subtries, we know where our branch
     table is going to be. */
  *result_offset = off = index->out.total_output_bytes;

  /* Relativize the offsets. This is just to reduce the probable
     magnitude of the numbers so they will pack better into I-format. */
  for (i = t->first_valid_entry; i <= t->last_valid_entry; i++) {
    if (offsets[i] != 0) {
      offsets[i] = off - offsets[i];
    }
  }

  r = dump_word_table_offsets(index, t, offsets);

  /* Mark this subtrie as empty. */
  t->first_valid_entry = 256;
  t->last_valid_entry = 0;

  return r;
}

/* Dump out a complete trie for the given initial byte from its temporary file.
   The absolute offset of the trie's root table within the file is
   returned in 'result_offset'. */
static int dump_index_trie_words(SquatIndex* index, int first_char,
                                 int* result_offset) {
  SquatWriteBuffer* buf = index->index_buffers + first_char;
  int num_words = index->total_num_words[first_char];
  WordDocEntry* doc_table;
  char const* word_list_ptr;
  int r = SQUAT_OK;
  char const* word_ptr;
  
  /* Allocate all the necessary document-ID linked list entries at once. */
  doc_table = (WordDocEntry*)malloc(sizeof(WordDocEntry)*num_words);
  if (doc_table == NULL) {
    squat_set_last_error(SQUAT_ERR_OUT_OF_MEMORY);
    return SQUAT_ERR;
  }
  index->word_doc_allocator = doc_table;

  /* mmap the temporary file. */
  word_list_ptr = mmap(NULL, buf->total_output_bytes, PROT_READ, MAP_SHARED,
                       buf->fd, 0);
  if (word_list_ptr == MAP_FAILED) {
    squat_set_last_error(SQUAT_ERR_SYSERR);
    r = SQUAT_ERR;
    goto cleanup;
  }
  word_ptr = word_list_ptr;

  /* Scan through the file */
  while (num_words > 0) {
    /* For each document, add all its words to the trie with this document ID */
    int doc_ID = (int)squat_decode_I(&word_ptr);
    int doc_words = (int)squat_decode_I(&word_ptr);
   
    num_words -= doc_words;

    while (doc_words > 0) {
      if (add_word_to_trie(index, word_ptr, doc_ID)
          != SQUAT_OK) {
        r = SQUAT_ERR;
        goto cleanup_map;
      }
      word_ptr += SQUAT_WORD_SIZE - 1;
      doc_words--;
    }
  }

  /* Make sure we used exactly as many linked list entries as we
     thought we would. */
  assert(index->word_doc_allocator - doc_table
         == index->total_num_words[first_char]);
  /* Make sure we read all the bytes from the temporary file. */
  assert(word_ptr - word_list_ptr == buf->total_output_bytes);
 
  /* Now dump the trie to the index file. */
  r = write_trie_word_data(index, &index->doc_word_table,
                           SQUAT_WORD_SIZE - 1, result_offset);

cleanup_map:
  if (munmap((void*)word_list_ptr, buf->total_output_bytes) != 0
    && r == SQUAT_OK) {
    squat_set_last_error(SQUAT_ERR_SYSERR);
    r = SQUAT_ERR;
  }

cleanup:
  free(doc_table);

  return r;
}

/* This does the grunt work of completing the index. If OK is false we
   just take the cleanup path ... this is used by squat_index_destroy. */
static int index_close_internal(SquatIndex* index, int OK) {
  int r = SQUAT_OK;
  int doc_list_offset;
  int doc_ID_list_offset;
  int word_list_offset;
  char* buf;
  int i;
  SquatDiskHeader* header;
  int offset_buf[256];
  
  squat_set_last_error(SQUAT_ERR_OK);

  if (!OK) {
    goto cleanup;
  }

  /* Close any open document ... this would really be a client bug. */
  if (index->current_doc_len >= 0) {
    squat_index_close_document(index);
  }

  /* Clear the current trie. We are now going to use it to build
     all-documents tries. */
  delete_doc_word_table(&index->doc_word_table, SQUAT_WORD_SIZE);
  init_doc_word_table(&index->doc_word_table);

  /* Write out the array that maps document IDs to offsets of the
     document records. */
  doc_list_offset = sizeof(SquatDiskHeader);
  doc_ID_list_offset = index->out.total_output_bytes + 1;
  if ((buf = prepare_buffered_write(&index->out,
         SQUAT_SAFETY_ZONE + ((index->current_doc_ID + 1)*4))) == NULL) {
    r = SQUAT_ERR;
    goto cleanup;
  }
  *buf++ = 0;
  memcpy(buf, index->doc_ID_list, index->current_doc_ID*4);
  buf += index->current_doc_ID*4;
  memset(buf, 0, 4);
  complete_buffered_write(&index->out, buf + 4);

  /* Now write out the trie for every initial byte that we saw. The
     offsets are collected in 'offset_buf'. */
  memset(offset_buf, 0, sizeof(offset_buf));
  for (i = 0; i < 256; i++) {
    if (index->stats_callback != NULL) {
      SquatStatsEvent event;

      event.generic.type = SQUAT_STATS_COMPLETED_INITIAL_CHAR;
      event.completed_initial_char.completed_char = i;
      event.completed_initial_char.num_words = index->total_num_words[i];
      if (index->index_buffers[i].buf != NULL) {
        event.completed_initial_char.temp_file_size =
          index->index_buffers[i].total_output_bytes;
      } else {
        event.completed_initial_char.temp_file_size = 0;
      }
      index->stats_callback(index->stats_callback_closure, &event);
    }

    if (index->index_buffers[i].buf != NULL) {
      /* We have to flush the temporary file output buffer before we try to use
	 the temporary file. */
      if (flush_and_reset_buffered_writes(index->index_buffers + i) != SQUAT_OK
          || dump_index_trie_words(index, i, offset_buf + i) != SQUAT_OK) {
        r = SQUAT_ERR;
        goto cleanup;
      }
      /* Close files and free memory as we go. This could be important
	 if disk space is low and we're generating a huge index. */
      if (close(index->index_buffers[i].fd) < 0) {
        squat_set_last_error(SQUAT_ERR_SYSERR);
        r = SQUAT_ERR;
      }
      free(index->index_buffers[i].buf);
      index->index_buffers[i].buf = NULL;
    } else {
      offset_buf[i] = 0;
    }
  }

  /* Save the offset where the root of the index trie is going to go. */
  word_list_offset = index->out.total_output_bytes;

  /* Relativize the subtrie offsets. */
  for (i = 0; i < 256; i++) {
    if (offset_buf[i] != 0) {
      offset_buf[i] = word_list_offset - offset_buf[i];

      if (i < index->doc_word_table.first_valid_entry) {
        index->doc_word_table.first_valid_entry = i;
      }
      index->doc_word_table.last_valid_entry = i;
    }
  }

  /* Dump out the offset buffer at last. */
  if (dump_word_table_offsets(index, &index->doc_word_table, offset_buf)
      != SQUAT_OK) {
    r = SQUAT_ERR;
    goto cleanup;
  }

  /* finally, write trailing zeroes and the header ... now that we know
     we initialized the file with no errors */
  if ((buf = prepare_buffered_write(&index->out, SQUAT_SAFETY_ZONE)) == NULL) {
    r = SQUAT_ERR;
    goto cleanup;
  }
  memset(buf, 0, SQUAT_SAFETY_ZONE);
  complete_buffered_write(&index->out, buf + SQUAT_SAFETY_ZONE);

  /* Flush writes before we seek back to the start to write the header */
  if (flush_and_reset_buffered_writes(&index->out) != SQUAT_OK) {
    r = SQUAT_ERR;
    goto cleanup;
  }

  /* Blat out the header */
  if ((header = (SquatDiskHeader*)prepare_buffered_write(&index->out,
         sizeof(SquatDiskHeader))) == NULL) {
    r = SQUAT_ERR;
    goto cleanup;
  }
  memcpy(header->header_text, squat_index_file_header, 8);
  squat_encode_64(header->doc_list_offset, doc_list_offset);
  squat_encode_64(header->doc_ID_list_offset, doc_ID_list_offset);
  squat_encode_64(header->word_list_offset, word_list_offset);
  memcpy(header->valid_char_bits, index->valid_char_bits,
         sizeof(header->valid_char_bits));
  complete_buffered_write(&index->out, (char*)(header + 1));

  /* Flush out the header */
  if (flush_and_reset_buffered_writes(&index->out) != SQUAT_OK) {
    r = SQUAT_ERR;
    goto cleanup;
  }

  /* WOOHOO! It's done! */

cleanup:
  free(index->out.buf);
  delete_doc_word_table(&index->doc_word_table, SQUAT_WORD_SIZE - 1);
  /* If we're bailing out because of an error, we might not have
     released all the temporary file resources. */
  for (i = 0; i < 256; i++) {
    if (index->index_buffers[i].buf != NULL) {
      close(index->index_buffers[i].fd);
      free(index->index_buffers[i].buf);
    }
  }
  free(index->tmp_path);
  free(index->doc_ID_list);
  free(index);

  return r;
}

int squat_index_finish(SquatIndex* index) {
  return index_close_internal(index, 1);
}

int squat_index_destroy(SquatIndex* index) {
  return index_close_internal(index, 0);
}
