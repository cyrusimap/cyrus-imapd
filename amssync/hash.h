/* hash.h -- part of amssync
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
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
