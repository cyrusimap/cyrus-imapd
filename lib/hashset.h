#ifndef __CYRUS_HASHSET_H__
#define __CYRUS_HASHSET_H__

#include <stddef.h> /* For size_t */
#include <stdint.h> /* For uint32_t */

struct hashset
{
    uint32_t starts[65536];
    size_t bytesize;
    size_t recsize;
    size_t alloc;
    size_t count;
    void *data;
};

struct hashset *hashset_new(size_t bytesize);

// returns 1 if added, 0 if not added (already there)
int hashset_add(struct hashset *hs, const void *data);

// returns 1 if exists, 0 if not present
int hashset_exists(struct hashset *hs, const void *data);

// XXX: add iterator and foreacher
// void hashset_foreach(struct hashset *hs, int (*)(void *, void *), void *rock);

void hashset_free(struct hashset **hsp);

#endif /* __CYRUS_HASHSET_H__ */
