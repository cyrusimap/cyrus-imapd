/* +++Date last modified: 05-Jul-1997 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "assert.h"
#include "hashu64.h"
#include "mpool.h"
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

/* Initialize the hashu64_table to the size asked for.  Allocates space
** for the correct number of pointers and sets them to NULL.  If it
** can't allocate sufficient memory, signals error by setting the size
** of the table to 0.
*/

static inline int u64cmp(uint64_t a, uint64_t b)
{
    return (a < b ? -1 : (a > b ? 1 : 0));
}

EXPORTED hashu64_table *construct_hashu64_table(hashu64_table *table, size_t size, int use_mpool)
{
      assert(table);
      assert(size);

      table->size  = size;

      /* Allocate the table -- different for using memory pools and not */
      if(use_mpool) {
          /* Allocate an initial memory pool for 32 byte keys + the hash table
           * + the buckets themselves */
          table->pool =
              new_mpool(size * (32 + sizeof(bucketu64*) + sizeof(bucketu64)));
          table->table =
              (bucketu64 **)mpool_malloc(table->pool,sizeof(bucketu64 *) * size);
      } else {
          table->pool = NULL;
          table->table = xmalloc(sizeof(bucketu64 *) * size);
      }

      /* Allocate the table and initialize it */
      memset(table->table, 0, sizeof(bucketu64 *) * size);

      return table;
}

/*
** Insert 'key' into hashu64 table.
** Returns a non-NULL pointer which is either the passed @data pointer
** or, if there was already an entry for @key, the old data pointer.
*/

EXPORTED void *hashu64_insert(uint64_t key, void *data, hashu64_table *table)
{
      unsigned val = key % table->size;
      bucketu64 *ptr, *newptr;
      bucketu64 **prev;

      /*
      ** NULL means this bucket hasn't been used yet.  We'll simply
      ** allocate space for our new bucket and put our data there, with
      ** the table pointing at it.
      */
      if (!((table->table)[val]))
      {
          if(table->pool) {
              (table->table)[val] =
                  (bucketu64 *)mpool_malloc(table->pool, sizeof(bucketu64));
              (table->table)[val] -> key = key;
          } else {
              (table->table)[val] = (bucketu64 *)xmalloc(sizeof(bucketu64));
              (table->table)[val] -> key = key;
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
          int cmpresult = u64cmp(key, ptr->key);
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
                  newptr = (bucketu64 *)mpool_malloc(table->pool, sizeof(bucketu64));
                  newptr->key = key;
              } else {
                  newptr = (bucketu64 *)xmalloc(sizeof(bucketu64));
                  newptr->key = key;
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
          newptr=(bucketu64 *)mpool_malloc(table->pool,sizeof(bucketu64));
          newptr->key = key;
      } else {
          newptr=(bucketu64 *)xmalloc(sizeof(bucketu64));
          newptr->key = key;
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

EXPORTED void *hashu64_lookup(uint64_t key, hashu64_table *table)
{
      unsigned val = key % table->size;
      bucketu64 *ptr;

      if (!(table->table)[val])
            return NULL;

      for ( ptr = (table->table)[val];NULL != ptr; ptr = ptr->next )
      {
          int cmpresult = u64cmp(key, ptr->key);
          if (!cmpresult)
              return ptr->data;
          else if(cmpresult < 0) /* key < ptr->key -- we passed it */
              return NULL;
      }
      return NULL;
}

/*
** Delete a key from the hashu64 table and return associated
** data, or NULL if not present.
*/
/* Warning: use this function judiciously if you are using memory pools,
 * since it will leak memory until you get rid of the entire hash table */
EXPORTED void *hashu64_del(uint64_t key, hashu64_table *table)
{
      unsigned val = key % table->size;
      void *data;
      bucketu64 *ptr, *last = NULL;

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
          int cmpresult = u64cmp(key, ptr->key);
          if (!cmpresult)
          {
              if (last != NULL )
              {
                  data = ptr -> data;
                  last -> next = ptr -> next;
                  if(!table->pool) {
                      free(ptr);
                  }
                  return data;
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
                  data = ptr->data;
                  (table->table)[val] = ptr->next;
                  if(!table->pool) {
                      free(ptr);
                  }
                  return data;
              }
          } else if (cmpresult < 0) {
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

EXPORTED void free_hashu64_table(hashu64_table *table, void (*func)(void *))
{
      unsigned i;
      bucketu64 *ptr, *temp;

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

EXPORTED void hashu64_enumerate(hashu64_table *table,
                                void (*func)(uint64_t, void *, void *),
                                void *rock)
{
      unsigned i;
      bucketu64 *temp, *temp_next;

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

