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
 * $Id: squat_internal.h,v 1.1 2001/09/25 16:49:51 ken3 Exp $
 */

/*
  SQUAT internal utility functions and definitions, used only by other
  SQUAT components.
  Robert O'Callahan

  IMPLEMENTATION NOTES:

  In the following, I assume that SQUAT_WORD_SIZE has its default value of 4.

  For each 'word' (string of 4 consecutive bytes) occurring in the
  source documents, the SQUAT index records which documents the word
  occurs in. To search for an arbitrary string of K >= 4 bytes, SQUAT
  computes the set of documents which contain all K-3 words that the
  substring contains.

  For example, if we search for "a kitty", SQUAT will return every
  document which contains each of the substrings "a ki", " kit",
  "kitt", and "itty". Obviously every document containing "a kitty"
  also contains those substrings, but other documents may be returned
  which do not contain "a kitty". (For example, the document "a killer
  kitty" would also be returned.) However, experiments on an email
  corpus seem to show that such false matches are very uncommon.

  The index contains three main data structures. There is a doc-list
  structure which simply records the name and size of each source
  document. Each entry in this structure has variable length; it is
  designed to be traversed sequentially by squat_search_list_docs.

  There is a doc-ID-list structure which is an array, indexed by the
  doc-ID, of offsets to the doc-list element for that doc-ID. This is
  designed to allow for efficient recovery of the name of a document
  given its ID.

  The rest of the file is a trie, describing the documents containing
  each words. Each trie is exactly 3 levels deep, indexed by the first
  three characters of each word. Each leaf of a trie is a list of
  lists of documents, one list of documents per last character of a
  word. The 256-way branch tables within the tries, and the document
  lists, are stored using mildly clever encodings to reduce space
  consumption.

  The file contains SQUAT_SAFETY_ZONE (currently 16) zero bytes at the
  end. They are there to stop runaway decoding loops from segfaulting;
  these loops can assume the bytes are there, scan away with
  guaranteed termination, and then detect errors after the fact. We
  check that these safety bytes are there and zero when we open an
  index for reading!

  Any words containing any 'invalid characters' as specified by the
  index creator are simply dropped from the index. The invalid
  characters are recorded so that clients can get a meaningful error
  if they try to perform a search using those characters (otherwise
  they'd just get no documents returned).
*/

#ifndef __SQUAT_INTERNAL_H
#define __SQUAT_INTERNAL_H

#include "squat.h"

#define SQUAT_SAFETY_ZONE 16

/* The format of a SQUAT index file. This record is stored at the
   beginning of the file. */
typedef struct {
  char header_text[8];       /* "SQUAT 1\n" */
  char doc_list_offset[8];   /* offset to a doc-list structure (see below) */
  char doc_ID_list_offset[8];/* offset to a doc-ID-list structure (see below) */
  char word_list_offset[8];  /* offset to a word-list structure (see below) */
  char valid_char_bits[32];  /* a bitmap recording which characters
				appear in the index. The client
				promises that query strings will not
				contain characters which don't have
				their bits set in the bitmap. */
} SquatDiskHeader;

/* Index file format

   "I" means an unsigned integer decoded as N bytes as follows:
     The low 7 bits of each byte encode the integer (most significant byte
     first). The high 8th bit of the first N-1 bytes is 1 and the high 8th bit
     of the Nth byte is 0.
   "N" means a null-terminated UTF8 string.
   "8" means an 8-bit byte.
   "32" means a 32-bit signed integer in big-endian format.
   "64" means a 64-bit signed integer in big-endian format.

   K = SQUAT_WORD_SIZE-1

   <doc-ID-list> = 32"doc-ID-offset"* 0 0 0 0

   <doc-list> = <document-info>* 0
   <document-info> = S"name" I"length"

   <word-list> = <word-list-trie-1>* <trie-index>
   <trie-index> = <present-bits> I<subtrie-backwards-offset>*
   <present-bits> = 8"singleton"
                  | 8"start-byte" 8"count-bytes-minus-one" 8"present-bytes"*
   <word-list-trie-1> = <word-list-trie-2>* <trie-index>
   ...
   <word-list-trie-K> = <present-bits> <word-trie-info>*
   <word-trie-info> = <index-run>"documents"
   <index-run> = I"adjusted-single-index"
               | I"adjusted-run-size" <index-run-list>*
   <index-run-list> = I"adjusted-single-index-delta"
                    = I"adjusted-run-length" I"first-index-delta"

   The adjusted-single-index is the actual index shifted left one bit with the
   bottom bit set to 1.
   The adjusted-run-size is the actual run size (in bytes) shifted left one
   bit with the bottom bit set to 0.
   The adjusted-single-index-delta is the actual index shifted left one bit
   with the bottom bit set to 1.
   The adjusted-run-length is the length of the run of consecutive indices
   shifted left one bit with the bottom bit set to 0.

   The last SQUAT_SAFETY_ZONE bytes of the index file must be 0.
   This helps protect us against corrupt index files.
*/

void squat_set_last_error(int err);

/* Decode and encode a 32-bit quantity into a 4-byte field in an
   architecture-independent (big-endian) format. */
SquatInt32 squat_decode_32(char const* s);
/* We return s + 4. */
char* squat_encode_32(char* s, SquatInt32 v);

/* Decode and encode a 64-bit quantity into an 8-byte field in an
   architecture-independent (big-endian) format. */
SquatInt64 squat_decode_64(char const* s);
/* We return s + 8. */
char* squat_encode_64(char* s, SquatInt64 v);

/* Decode and encode a 64-bit quantity into a variable length field in
   an architecture-independent format. We use one byte for every 7
   significant bits of the value.
   For safety when encoding, make sure there are at least 10 bytes of
   space available at s.
   For safety when decoding, make sure that there is at least one zero
   byte following the data at s.
   Only non-negative integers can be encoded using these
   routines. Negative integers might be returned from decoding if the
   data was corrupted. */
/* *s is incremented to point past the decoded value. */
SquatInt64 squat_decode_I(char const** s);
/* num_to_skip encoded values are decoded and discarded. We return a
   pointer past the end of the decoded values. */
char const* squat_decode_skip_I(char const* s, int num_to_skip);
/* We return a pointer past the encoded value. */
char* squat_encode_I(char* s, SquatInt64 v);
/* We return the number of bytes required to encode the given value. */
int squat_count_encode_I(SquatInt64 v64);

#endif
