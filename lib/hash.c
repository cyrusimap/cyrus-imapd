#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdbool.h>

#include "assert.h"
#include "hash.h"
#include "mpool.h"
#include "strhash.h"
#include "util.h"
#include "xmalloc.h"

/* What we're aiming at is that the header has the definition:
 * inline size_t hash_count(...) { ... };
 * and this C file has a decaration with `extern`, causing one implementation to
 * be compiled into this object file, and available to the linker for all the
 * cases that can't be inlined.
 *
 * However...
 * We set the default for our visibility to be hidden. Hence we need to mark
 * this definition as EXPORTED so that it's visible to the linker to use in
 * other files. (Without this an unoptimised build immediately breaks)
 * gcc is forgiving, but clang insists that the first declaration it sees for
 * the function is marked EXPORTED, so if the declaration implied by the
 * definition (in the header) is seen first, that needs EXPORTED
 * If we don't include config.h then EXPORTED isn't defined as anything, so it's
 * left in place as-is, and it's a syntax error.
 * sieve-lex.o transitively includes hash.h, but doesn't itself include config.h
 * so we try to fix that by including config.h in hash.h
 * We can make that work, but then example_libcyrus_min.c (and the test for it)
 * break because that uses installed headers, and we don't install config.h
 *
 * One solution that clang and gcc both are happy with is to move the
 * declaration ahead of the definition, by moving it before the header include
 * here. However, to make that work, we also need a forward definition of
 * hash_table.
 *
 * We opted not to go with this as it's not a natural order to the human reader.
 * Given that Cyrus removed support for compilers without __attribute__(...) in
 * 2015 (without complaints) instead we simply define EXPORTED in hash.h
 */

extern inline size_t hash_count(const hash_table *table);
extern inline bool hash_constructed(const hash_table *table);

#include "hash_priv.h"

struct bucket {
    void *data;
    struct bucket *next;
    uint32_t hash;
    char key[];
};

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
** can't allocate sufficient memory it will terminate the program with the
** diagnostic "Virtual memory exhausted"
*/

static size_t table_size(const hash_table *table) {
    return table && table->table ? (1ULL << table->size_log2) : 0;
}

/* The arithmetic in this code is 64 bit so that
 * 1) it's future proof if we move to a 64 bit hash
 * 2) it's consistent with the hashu64 code
 * 3) the known working sizeof(size_t) doesn't need changing and debugging
 *
 * Multiplying by 9e3779b97f4a7c15ULL and shifting is Fibonacci Hashing
 * It's not great in itself, but it's computationally cheap. We use this as a
 * final mixing stage as djbx33x lacks one, hence leaves all the recent entropy
 * in the lowest bits of the hash.
 */

static size_t table_index(const hash_table *table, uint32_t hash) {
    /* Ensure we truncate this to 64 bits, even on a platform with 128 bit
     * long longs. At some point, some joker is going to throw that at us:
     */
    uint64_t mixed = hash * 0x9e3779b97f4a7c15ULL;
    return mixed >> (64 - table->size_log2);
}

/* We've changed the hash table size from "whatever the user asked for" to
 * power of two (and therefore sizes must round up to the next power of two).
 * This permits us to use a bitmask to map the hash code to the bucket, which is
 * *considerably* faster than integer modulo.
 *
 * For example:
 * https://johnnysswlab.com/make-your-programs-run-faster-avoid-expensive-instructions/
 *
 *       To test the speed difference, we implemented an open addressing hash
 *       map whose size is always the power of two. We used working sets of
 *       several sizes and tested it. The results are in the table below:
 *
 * and shifting is between 12% and 40% faster.
 *
 * This does, however, rely on a good hash function which properly mixes all the
 * entropy into the low bits of the hash code. For example, the pre-2021
 * algorithm is not:
 *
 *       ret_val ^= i;
 *       ret_val <<= 1;
 *
 * The second operation in the loop is is "multiply by two". There is no final
 * mixing step, so it will always generate an even number. Masking this would
 * leave half the buckets unreachable!
 *
 * This doesn't matter if instead of masking, one uses modulo of an odd number
 * to find the bucket. Hence the other "classic" approach is constraining the
 * table size to be a prime number, and choosing the bucket modulo that.
 *
 * Compiler writers know a bunch of integer maths tricks to make modulo of an
 * integer constant fast (by not actually using the CPU modulo operation).
 * But modulo of a run time integer is slow. So one way to get speed back is:
 *
 *
 *       So then how do we solve the problem of the slow integer modulo? For
 *       this I’m using a trick that I copied from boost::multi_index: I make
 *       all integer modulos use a compile time constant. I don’t allow all
 *       possible prime numbers as sizes for the table. Instead I have a
 *       selection of pre-picked prime numbers and will always grow the table to
 *       the next largest one out of that list. Then I store the index of the
 *       number that your table has. When it later comes time to do the integer
 *       modulo to assign the hash value to a slot, you will see that my code
 *       does this:
 *
 *       switch(prime_index)
 *       {
 *       case 0:
 *           return 0llu;
 *       case 1:
 *           return hash % 2llu;
 *       case 2:
 *           return hash % 3llu;
 *       case 3:
 *           return hash % 5llu;
 * ...
 *
 * https://probablydance.com/2017/02/26/i-wrote-the-fastest-hashtable/
 *
 * which would result in code much much longer than this comment.
 *
 * So we go with integer sizes and a good enough hash function as a reasonable
 * speed/size trade off.
 */

EXPORTED hash_table *construct_hash_table(hash_table *table, size_t size, int use_mpool)
{
      assert(table);
      assert(size);

      uint8_t size_log2 = hash_base2_size_for_entries(size);
      size = 1ULL << size_log2;
      table->size_log2 = size_log2;
      table->count = 0;
      table->seed = rand(); /* might be zero, that's okay */
      table->hash_load_warned_at = 0;

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

#define check_load_factor(table) do {                                   \
    hash_table *t = (table);                                            \
    const double load_factor = t->count * 1.0 / table_size(t);          \
    if (load_factor > 3.0) {                                            \
        if (t->hash_load_warned_at == 0                                 \
            || (int) load_factor > t->hash_load_warned_at) {            \
            xsyslog(LOG_DEBUG, "hash table load factor exceeds 3.0",    \
                               "table=<%p> entries=<" SIZE_T_FMT ">"    \
                               " buckets=<" SIZE_T_FMT "> load=<%.2g>", \
                    t, t->count, table_size(t), load_factor);           \
            t->hash_load_warned_at = (int) load_factor;                 \
        }                                                               \
    }                                                                   \
    else {                                                              \
        t->hash_load_warned_at = 0;                                     \
    }                                                                   \
} while(0)

/*
** Insert 'key' into hash table.
** Returns a non-NULL pointer which is either the passed @data pointer
** or, if there was already an entry for @key, the old data pointer.
*/
EXPORTED void *hash_insert(const char *key, void *data, hash_table *table)
{
      uint32_t hash = strhash_seeded(table->seed, key);
      size_t val = table_index(table, hash);
      bucket *ptr, *newptr;

      /*
      ** See if the current string has already been inserted, and if so,
      ** replace its data
      */
      for (ptr=(table->table)[val];
           ptr;
           ptr=ptr->next) {
          if (hash == ptr->hash && !strcmp(key, ptr->key)) {
              /* Match! Replace this value and return the old */
              void *old_data;

              old_data = ptr->data;
              ptr -> data = data;
              return old_data;
          }
      }

      /*
      ** Add new keys to the start of the list (which might be empty)
      */

      /*
      ** sizeof(bucket) is 24 on 64 bit systems, as it has to allow for padding.
      ** whereas offsetof(...) is 20. So using it saves 4 bytes on average
      */
      size_t key_len = strlen(key) + 1; /* including the trailing NUL byte */
      size_t wanted = offsetof(bucket, key) + key_len;

      /* Code reviewers observed that for short keys the above calculation
         might result in an allocation smaller than the (fully padded) struct.
         We believe that this is all fine by the C standard, but compilers are
         software too, and this sort of thing might trigger bugs (or false
         positive warnings from UBSAN etc). So we play it safe: */
      if(wanted < sizeof(bucket))
          wanted = sizeof(bucket);

      if(table->pool) {
          newptr=(bucket *)mpool_malloc(table->pool,wanted);
      } else {
          newptr=(bucket *)xmalloc(wanted);
      }
      memcpy(newptr->key,key,key_len);
      newptr->hash = hash;
      newptr->data = data;
      newptr->next = (table->table)[val];
      (table->table)[val] = newptr;
      table->count++;
      check_load_factor(table);
      return data;
}

/*
** Look up a key and return the associated data.  Returns NULL if
** the key is not in the table.
*/

EXPORTED void *hash_lookup(const char *key, hash_table *table)
{
      bucket *ptr;

      if (!table->table || !table->count)
          return NULL;

      uint32_t hash = strhash_seeded(table->seed, key);
      size_t val = table_index(table, hash);

      if (!(table->table)[val])
            return NULL;

      for ( ptr = (table->table)[val];NULL != ptr; ptr = ptr->next )
      {
          if (hash == ptr->hash && !strcmp(key, ptr->key))
              return ptr->data;
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
      uint32_t hash = strhash_seeded(table->seed, key);
      size_t val = table_index(table, hash);
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
          if (hash == ptr->hash && !strcmp(key, ptr->key))
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
                  free(ptr);
              }
              table->count--;
              return data;
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
      size_t i;
      bucket *ptr, *temp;
      size_t size = table_size(table);

      if (!table) return;

      /* If we have a function to free the data, apply it everywhere */
      /* We also need to traverse this anyway if we aren't using a memory
       * pool */
      if(func || !table->pool) {
          for (i=0;i<size; i++)
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
      table->size_log2 = 0;
      table->count = 0;
}

/*
** Simply invokes the function given as the second parameter for each
** node in the table, passing it the key, the associated data and 'rock'.
*/

EXPORTED void hash_enumerate(hash_table *table, void (*func)(const char *, void *, void *),
                    void *rock)
{
      size_t i;
      bucket *temp, *temp_next;
      size_t size = table_size(table);

      for (i=0;i<size; i++)
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

EXPORTED strarray_t *hash_keys(const hash_table *table)
{
    const bucket *temp;
    size_t i;
    size_t size = table_size(table);

    strarray_t *sa = strarray_new();

    for (i = 0; i < size; i++) {
        temp = (table->table)[i];
        while (temp) {
            strarray_append(sa, temp->key);
            temp = temp->next;
        }
    }

    return sa;
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
    size_t size = table_size(table);
    iter->curr = NULL;
    iter->peek = NULL;
    for (iter->i = 0; iter->i < size; iter->i++) {
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
    else {
        size_t size = table_size(table);

        if (iter->i < size) {
            for (iter->i = iter->i + 1; iter->i < size; iter->i++) {
                if ((iter->peek = table->table[iter->i])) {
                    break;
                }
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
