/* +++Date last modified: 05-Jul-1997 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "assert.h"
#include "hash.h"
#include "mpool.h"
#include "strhash.h"
#include "xmalloc.h"

/*
** public domain code by Jerry Coffin, with improvements by HenkJan Wolthuis.
**
** Tested with Visual C 1.0 and Borland C 3.1.
** Compiles without warnings, and seems like it should be pretty
** portable.
**
** Modified for use with libcyrus by Ken Murchison.
**  - prefixed functions with 'hash_' to avoid symbol clashing
**  - use xmalloc() and xstrdup()
**  - cleaned up free_hash_table(), doesn't use enumerate anymore
**  - added 'rock' to hash_enumerate()
**
** Further modified by Rob Siemborski.
**  - xmalloc can never return NULL, so don't worry about it
**  - sort the buckets for faster searching
**  - actually, we'll just use a memory pool for this sucker
**    (atleast, in the cases where it is advantageous to do so)
*/

/* Initialize the hash_table to the size asked for.  Allocates space
** for the correct number of pointers and sets them to NULL.  If it
** can't allocate sufficient memory, signals error by setting the size
** of the table to 0.
*/

EXPORTED hash_table *construct_hash_table(hash_table *table, size_t size, int use_mpool)
{
      assert(table);
      assert(size);

      table->size = size;
      table->seed = rand(); /* might be zero, that's okay */

      /* Allocate the table -- different for using memory pools and not */
      if (use_mpool) {
          /* Allocate an initial memory pool for 32 byte keys + the hash table
           * + the buckets themselves */
          table->pool =
              new_mpool(size * (32 + sizeof(bucket*) + sizeof(bucket)));
          table->table =
              (bucket **)mpool_malloc(table->pool,sizeof(bucket *) * size);
      } else {
          table->pool = NULL;
          table->table = xmalloc(sizeof(bucket *) * size);
      }

      /* Allocate the table and initialize it */
      memset(table->table, 0, sizeof(bucket *) * size);

      return table;
}

/*
** Insert 'key' into hash table.
** Returns a non-NULL pointer which is either the passed @data pointer
** or, if there was already an entry for @key, the old data pointer.
*/

EXPORTED void *hash_insert(const char *key, void *data, hash_table *table)
{
      unsigned val = strhash_seeded(table->seed, key) % table->size;
      bucket *ptr, *newptr;
      bucket **prev;

      /*
      ** NULL means this bucket hasn't been used yet.  We'll simply
      ** allocate space for our new bucket and put our data there, with
      ** the table pointing at it.
      */
      if (!((table->table)[val]))
      {
          if(table->pool) {
              (table->table)[val] =
                  (bucket *)mpool_malloc(table->pool, sizeof(bucket));
              (table->table)[val] -> key = mpool_strdup(table->pool, key);
          } else {
              (table->table)[val] = (bucket *)xmalloc(sizeof(bucket));
              (table->table)[val] -> key = xstrdup(key);
          }
          (table->table)[val] -> next = NULL;
          (table->table)[val] -> data = data;
          return (table->table)[val] -> data;
      }

      /*
      ** This spot in the table is already in use.  See if the current string
      ** has already been inserted, and if so, increment its count.
      */
      for (prev = &((table->table)[val]), ptr=(table->table)[val];
           ptr;
           prev=&(ptr->next),ptr=ptr->next) {
          int cmpresult = strcmp(key,ptr->key);
          if (!cmpresult) {
              /* Match! Replace this value and return the old */
              void *old_data;

              old_data = ptr->data;
              ptr -> data = data;
              return old_data;
          } else if (cmpresult < 0) {
              /* The new key is smaller than the current key--
               * insert a node and return this data */
              if(table->pool) {
                  newptr = (bucket *)mpool_malloc(table->pool, sizeof(bucket));
                  newptr->key = mpool_strdup(table->pool, key);
              } else {
                  newptr = (bucket *)xmalloc(sizeof(bucket));
                  newptr->key = xstrdup(key);
              }
              newptr->data = data;
              newptr->next = ptr;
              *prev = newptr;
              return data;
          }
      }

      /*
      ** This key is the largest one so far.  Add it to the end
      ** of the list (*prev should be correct)
      */
      if(table->pool) {
          newptr=(bucket *)mpool_malloc(table->pool,sizeof(bucket));
          newptr->key = mpool_strdup(table->pool,key);
      } else {
          newptr=(bucket *)xmalloc(sizeof(bucket));
          newptr->key = xstrdup(key);
      }
      newptr->data = data;
      newptr->next = NULL;
      *prev = newptr;
      return data;
}


/*
** Look up a key and return the associated data.  Returns NULL if
** the key is not in the table.
*/

EXPORTED void *hash_lookup(const char *key, hash_table *table)
{
      unsigned val;
      bucket *ptr;

      if (!table->size)
          return NULL;

      val = strhash_seeded(table->seed, key) % table->size;

      if (!(table->table)[val])
            return NULL;

      for ( ptr = (table->table)[val];NULL != ptr; ptr = ptr->next )
      {
          int cmpresult = strcmp(key, ptr->key);
          if (!cmpresult)
              return ptr->data;
          else if(cmpresult < 0) /* key < ptr->key -- we passed it */
              return NULL;
      }
      return NULL;
}

/*
** Delete a key from the hash table and return associated
** data, or NULL if not present.
*/
/* Warning: use this function judiciously if you are using memory pools,
 * since it will leak memory until you get rid of the entire hash table */
EXPORTED void *hash_del(const char *key, hash_table *table)
{
      unsigned val = strhash_seeded(table->seed, key) % table->size;
      bucket *ptr, *last = NULL;

      if (!(table->table)[val])
            return NULL;

      /*
      ** Traverse the list, keeping track of the previous node in the list.
      ** When we find the node to delete, we set the previous node's next
      ** pointer to point to the node after ourself instead.  We then delete
      ** the key from the present node, and return a pointer to the data it
      ** contains.
      */

      for (last = NULL, ptr = (table->table)[val];
            NULL != ptr;
            last = ptr, ptr = ptr->next)
      {
          int cmpresult = strcmp(key, ptr->key);
          if (!cmpresult)
          {
              void *data = ptr->data;
              if (last != NULL )
              {
                  last -> next = ptr -> next;
              }

              /*
              ** If 'last' still equals NULL, it means that we need to
              ** delete the first node in the list. This simply consists
              ** of putting our own 'next' pointer in the array holding
              ** the head of the list.  We then dispose of the current
              ** node as above.
              */

              else
              {
                  (table->table)[val] = ptr->next;
              }
              if(!table->pool) {
                  free(ptr->key);
                  free(ptr);
              }
              return data;
          }
          if (cmpresult < 0) {
              /* its not here! */
              return NULL;
          }
      }

      /*
      ** If we get here, it means we didn't find the item in the table.
      ** Signal this by returning NULL.
      */
      return NULL;
}

/*
** Frees a complete table by iterating over it and freeing each node.
** the second parameter is the address of a function it will call with a
** pointer to the data associated with each node.  This function is
** responsible for freeing the data, or doing whatever is needed with
** it.
*/

EXPORTED void free_hash_table(hash_table *table, void (*func)(void *))
{
      unsigned i;
      bucket *ptr, *temp;

      if (!table) return;

      /* If we have a function to free the data, apply it everywhere */
      /* We also need to traverse this anyway if we aren't using a memory
       * pool */
      if(func || !table->pool) {
          for (i=0;i<table->size; i++)
          {
              ptr = (table->table)[i];
              while (ptr)
              {
                  temp = ptr;
                  ptr = ptr->next;
                  if (func)
                      func(temp->data);
                  if(!table->pool) {
                      free(temp->key);
                      free(temp);
                  }
              }
          }
      }

      /* Free the main structures */
      if(table->pool) {
          free_mpool(table->pool);
          table->pool = NULL;
      } else {
          free(table->table);
      }
      table->table = NULL;
      table->size = 0;
}

/*
** Simply invokes the function given as the second parameter for each
** node in the table, passing it the key, the associated data and 'rock'.
*/

EXPORTED void hash_enumerate(hash_table *table, void (*func)(const char *, void *, void *),
                    void *rock)
{
      unsigned i;
      bucket *temp, *temp_next;

      for (i=0;i<table->size; i++)
      {
            if ((table->table)[i] != NULL)
            {
                  for (temp = (table->table)[i];
                        NULL != temp;
                        temp = temp_next)
                  {
                        temp_next = temp->next;
                        func(temp -> key, temp->data, rock);
                  }
            }
      }
}

EXPORTED strarray_t *hash_keys(hash_table *table)
{
    unsigned i;
    bucket *temp;

    strarray_t *sa = strarray_new();

    for (i = 0; i < table->size; i++) {
        temp = (table->table)[i];
        while (temp) {
            strarray_append(sa, temp->key);
            temp = temp->next;
        }
    }

    return sa;
}

EXPORTED int hash_numrecords(hash_table *table)
{
    unsigned i;
    bucket *temp;
    int count = 0;

    for (i = 0; i < table->size; i++) {
        temp = (table->table)[i];
        while (temp) {
            count++;
            temp = temp->next;
        }
    }

    return count;
}

EXPORTED void hash_enumerate_sorted(hash_table *table, void (*func)(const char *, void *, void *),
                    void *rock, strarray_cmp_fn_t *cmp)
{
    strarray_t *sa = hash_keys(table);
    strarray_sort(sa, cmp);
    int i;
    for (i = 0; i < strarray_size(sa); i++) {
        const char *key = strarray_nth(sa, i);
        void *val = hash_lookup(key, table);
        func(key, val, rock);
    }
    strarray_free(sa);
}


struct hash_iter {
    hash_table *table;
    size_t i;
    bucket *peek;
    bucket *curr;
};

EXPORTED hash_iter *hash_table_iter(hash_table *table)
{
    hash_iter *iter = xzmalloc(sizeof(struct hash_iter));
    iter->table = table;
    hash_iter_reset(iter);
    return iter;
}

EXPORTED void hash_iter_reset(hash_iter *iter)
{
    hash_table *table = iter->table;
    iter->curr = NULL;
    iter->peek = NULL;
    for (iter->i = 0; iter->i < table->size; iter->i++) {
        if ((iter->peek = table->table[iter->i])) {
            break;
        }
    }
}

EXPORTED int hash_iter_has_next(hash_iter *iter)
{
    return iter->peek != NULL;
}

EXPORTED const char *hash_iter_next(hash_iter *iter)
{
    hash_table *table = iter->table;
    iter->curr = iter->peek;
    iter->peek = NULL;
    if (iter->curr == NULL)
        return NULL;
    else if (iter->curr->next)
        iter->peek = iter->curr->next;
    else if (iter->i < table->size) {
        for (iter->i = iter->i + 1; iter->i < table->size; iter->i++) {
            if ((iter->peek = table->table[iter->i])) {
                break;
            }
        }
    }
    return iter->curr->key;
}

EXPORTED const char *hash_iter_key(hash_iter *iter)
{
    return iter->curr->key;
}

EXPORTED void *hash_iter_val(hash_iter *iter)
{
    return iter->curr->data;
}

EXPORTED void hash_iter_free(hash_iter **iterptr)
{
    if (iterptr) {
        free(*iterptr);
        *iterptr = NULL;
    }
}
