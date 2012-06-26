/* +++Date last modified: 05-Jul-1997 */
/* $Id: hash.h,v 1.9 2003/10/22 18:50:12 rjs3 Exp $ */

#ifndef __CYRUS_HASHU64_H__
#define __CYRUS_HASHU64_H__

#include <stddef.h>           /* For size_t     */

#define HASHU64_TABLE_INITIALIZER {0, NULL, NULL}

/*
** A hash table consists of an array of these buckets.  Each bucket
** holds a copy of the key, a pointer to the data associated with the
** key, and a pointer to the next bucket that collided with this one,
** if there was one.
*/

typedef struct bucketu64 {
    uint64_t key;
    void *data;
    struct bucketu64 *next;
} bucketu64;

/*
** This is what you actually declare an instance of to create a table.
** You then call 'construct_table' with the address of this structure,
** and a guess at the size of the table.  Note that more nodes than this
** can be inserted in the table, but performance degrades as this
** happens.  Performance should still be quite adequate until 2 or 3
** times as many nodes have been inserted as the table was created with.
*/

typedef struct hashu64_table {
    size_t size;
    bucketu64 **table;
    struct mpool *pool;
} hashu64_table;

/*
** This is used to construct the table.  If it doesn't succeed, it sets
** the table's size to 0, and the pointer to the table to NULL.
*/

hashu64_table *construct_hashu64_table(hashu64_table *table, size_t size,
				 int use_mpool);

/*
** Inserts a pointer to 'data' in the table, with a copy of 'key' as its
** key.  Note that this does NOT make a copy of the
** associated data.
*/

void *hashu64_insert(uint64_t key,void *data,hashu64_table *table);

/*
** Returns a pointer to the data associated with a key.  If the key has
** not been inserted in the table, returns NULL.
*/

void *hashu64_lookup(uint64_t key,hashu64_table *table);

/*
** Deletes an entry from the table.  Returns a pointer to the data that
** was associated with the key so the calling code can dispose of it
** properly.
*/
/* Warning: use this function judiciously if you are using memory pools,
 * since it will leak memory until you get rid of the entire hash table */
void *hashu64_del(uint64_t key,hashu64_table *table);

/*
** Goes through a hash table and calls the function passed to it
** for each node that has been inserted.  The function is passed
** a pointer to the key, a pointer to the data associated
** with it and 'rock'.
*/

void hashu64_enumerate(hashu64_table *table,void (*func)(uint64_t ,void *,void *),
		    void *rock);

/*
** Frees a hash table.  For each node that was inserted in the table,
** it calls the function whose address it was passed, with a pointer
** to the data that was in the table.  The function is expected to
** free the data.  Typical usage would be:
** free_table(&table, free);
** if the data placed in the table was dynamically allocated, or:
** free_table(&table, NULL);
** if not.  ( If the parameter passed is NULL, it knows not to call
** any function with the data. )
*/

void free_hashu64_table(hashu64_table *table, void (*func)(void *));

#endif /* __CYRUS_HASHU64_H__ */
