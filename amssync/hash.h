/* hash.h -- part of amssync
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
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
