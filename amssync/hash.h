/* amssync.c -- synchronize AMS bboard into IMAP
 *
 *	(C) Copyright 1996 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/*
 * instant hash table library
 * Tim Showalter
 *
 */

/* relies on stdlib.h (for size_t)
 */

/* We'll use seperate chaining.  It's a little expensive, but we may
   want to delete someting someday.
   */
typedef struct ht_entry_s {
    void* v;
    struct ht_entry_s *next;
} ht_entry;

typedef struct ht_table_s {
    ht_entry **a ; /* array of pointers to hash table entries */
    unsigned long sz;
    size_t szof;
    unsigned long (*h)(void*) ; /* hash function */
    int (*cmp)(void*, void*); /* compare function; first arg, a struct;
				second arg, just a key value */
    void (*fr)(void*) ; /* function to free an entry */
} ht_table;

ht_table* ht_create(unsigned long (*h)(void*),
		    unsigned long sz,
		    size_t szof,
		    int (*cmp)(void*, void*),
		    void (*fr)(void*));
int ht_add(ht_table* ht, void* data, void* key);
void* ht_find(ht_table* ht, void* key);

void ht_remove(ht_table*, void*);
void ht_delete(ht_table*);
void ht_foreach(ht_table* ht, void (*fn)(void*));
