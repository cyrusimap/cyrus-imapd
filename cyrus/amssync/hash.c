/*
 * instant hash table library
 * Tim Showalter
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include "util.h"
#include "hash.h"

#define dprint(x) 

/*
 * Create a new hash table.
 * hash function stored = h
 * size of table = sz
 * compare function = cmp (compares an object and a key, in that order!)
 * free member function = fr
 */
ht_table* ht_create(unsigned long (*h)(void*), unsigned long sz,
		    size_t szof,
		    int (*cmp)(void*, void*),
		    void (*fr)(void*)) {
    int i;
    ht_table* table = malloc(sizeof(ht_table));

    if (! table) {
	debug(puts("ht_create: Can't allocate memory for table structure."));
	return 0;
    }

    table->sz = sz;
    table->szof = szof;
    table->h = h;
    table->fr = fr;
    table->cmp = cmp;

    table->a = malloc(sizeof(ht_entry) * sz);

    if (! table->a) {
	dprint("ht_create: can't allocate memory for table array.\n");
	return 0;
    }

    for(i=0; i<sz; i++) {
	table->a[i] = NULL;
    }

    return table;
}

/*
 * add entry to table with data and key=vkey
 */
int ht_add(ht_table* ht, void* data, void* vkey) {
    unsigned long key;
    ht_entry* e;

    /* first we look up the key */
    key = (*(ht->h))(vkey) % ht->sz;

    /* and wrap it in an entry struct */
    if (!(e = malloc(sizeof(ht_entry)))) {
	dprint("ht_add: can't allocate struct to add entry to table\n");
	return 0;
    }
    
    /* poke the entry into the top of entry at ht->a[key] */
    e->v = data;
    e->next = ht->a[key];
    ht->a[key] = e;

    return 1;
}

/*
 * ht_find looks up and tries to find an entry matching key (where key
 * is cmp arg 2)
 */
void* ht_find(ht_table* ht, void* key) {
    ht_entry* e;

    for(e = ht->a[ (*(ht->h))(key) % ht->sz ];
	e != NULL;
	e = e->next) {

	if(!(*ht->cmp)(e->v, key)) {
	    break;
	}
    }
    return e==NULL? 0 : e->v;
}

/* do something for each entry in hash table.
 * args: ht_table* ht, int(*fn)(void*) -- thing to call;
 * void argument is a pointer to struct stored inside hash table
 */
void ht_foreach(ht_table* ht, void (*fn)(void*)) {

    ht_entry* e;
    ht_entry* d;
    int i;

    for(i=0; i < ht->sz; i++) {
	e = ht->a[i];
	if (e != NULL) {
	    while( e != NULL ) {
		d = e->next;
		(*fn)(e->v);
		e = d;
	    }
	}
    }
}

/* Deletes the hash table, frees all member junk, and trashes the
 * struct.
 */
void ht_delete(ht_table* ht) {
    unsigned long i;
    ht_entry *e, *d;

    for(i=0; i < ht->sz; i++) {
	e = ht->a[i];
	if (e != NULL) {
	    while( e != NULL ) {
		d = e->next;
		(*ht->fr)(e->v);
		free(e);
		e = d;
	    }
	}
    }

    free(ht->a);
    free(ht);
}

/* Remove all entries matching vkey from ht.  vkey is a key (ht->cmp arg 2)
 */
void ht_remove(ht_table* ht, void* vkey) {
    unsigned long ikey;
    ht_entry *e, *p, *d;
    
    ikey = (*(ht->h))(vkey) % ht->sz ;

    e = ht->a[ikey];
    p = NULL;

    while( e != NULL ) {
	if ((*ht->cmp)(e->v, vkey)) {
	    /* no match */
	    p = e;
	    e = e->next;
	} else {
	    d = e->next;

	    if (p==NULL) {
		ht->a[ikey] = d;
	    } else {
		p->next = d;
	    }

	    (*ht->fr)(e->v);
	    free(e);
	    e = d;
	}
    }
}

