#ifndef __CYRUS_HASH_PRIV_H__
#define __CYRUS_HASH_PRIV_H__

/* Private helper functions shared between hash.c and hashu64.c */

#include <sysexits.h>

/* Resize the hash when we hit this: */
#define HASH_LOAD_FACTOR 1
/* 8 entries: */
#define HASH_MIN_SIZE_BASE_2 3

/* Adapted (considerably) from the log_base2 function.
 * https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
 * -- Individually, the code snippets here are in the public domain
 * -- (unless otherwise noted)
 * This one was not marked with any special copyright restriction.
 * What we need is to round the value rounded up to the next power of 2, and
 * then the log base 2 of that.
 *
 * The code there is devoid of any explanation of how it works
 * The (conventional) approach, described in
 * https://web.archive.org/web/20150129233016/http://7ooo.mooo.com/text/ComputingTrailingZerosHOWTO.html
 * linked from https://en.wikipedia.org/wiki/De_Bruijn_sequence is
 *
 * 0) encode a binary De Bruijn sequence into an integer constant
 * 1) do some bit manipulation tricks that convert the input into values that
 *    are powers of 2 (so exactly 1 bit is set) - 2 ** $n
 * 2) multiply the two (which is equivalent to a logical left shift)
 * 3) take the top $n bits (shift down) and index those into an array
 * 4) which gives the value of $n
 *
 * However, *that* code has been changed:
 * ... shaved off a couple operations by requiring v be rounded up to one less
 *     than the next power of 2 rather than the power of 2.
 * so that the multiplicand is 0x00000001, 0x00000003, 0x00000007 etc
 * which works for the constant given (0x077CB531U) but there is no explanation
 * of how to generate that
 *
 * Hence this version is structured roughly the same, but has to ++v; at the end
 * (those likely being the "shaved off" operations)
 * This version is 64 bit.
 *
 * I realise that the code predates superscalar architectures. All the bitshift
 * operations below depend on the immediate previous value, so will be likely 1
 * clock cycle per operation. I've not found online anyone's "welcome to the new
 * normal" improved version that parallelises.
 */

static uint64_t round_up_log_base2(uint64_t v) {
  static const uint8_t MultiplyDeBruijnBitPosition[64] = {
    0, 1, 2, 7, 3, 13, 8, 19, 4, 25, 14, 28, 9, 34, 20, 40, 5, 17, 26, 38, 15,
    46, 29, 48, 10, 31, 35, 54, 21, 50, 41, 57, 63, 6, 12, 18, 24, 27, 33, 39,
    16, 37, 45, 47, 30, 53, 49, 56, 62, 11, 23, 32, 36, 44, 52, 55, 61, 22, 43,
    51, 60, 42, 59, 58
  };

  --v;
  /* This rounds up the value now in v to 1 below the immediate next power of 2,
   * by propagating the leftmost (highest) set bit into all the bits below it
   * So 9 (0b00001001) becomes 15 (0x00001111),
   *   42 (0b00101010) becomes 63 (0b00111111)
   * etc.
   */
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v |= v >> 32;
  /* and this gets us to a power of 2. ie, an integer with exactly 1 bit set */
  ++v;

  /* Combined all the above, and the input value is:
   *   unchanged if it's a power of 2
   *   rounded up to the next power of 2 otherwise
   * (input values 0 and ~0 would not be correct, but our caller filters those)
   */

  /* And this is the De Bruijn lookup trick described above that converts that
   * power of 2 integer into an index into a table to find its log base 2
   */
  return MultiplyDeBruijnBitPosition[(uint64_t)(v * 0x218a392cd3d5dbfULL) >> 58];
}

/* realistically you don't want to go below 0.5, but coded like this so that
 * the logic just below is good enough to catch all overflow possiblities. */
_Static_assert(1 < sizeof(void *) * HASH_LOAD_FACTOR,
               "HASH_LOAD_FACTOR is too small");

static uint8_t hash_base2_size_for_entries(uint64_t entries) {
  if (entries <= (1 << HASH_MIN_SIZE_BASE_2) / (1.0 / HASH_LOAD_FACTOR))
    return HASH_MIN_SIZE_BASE_2;

  if (entries * sizeof(void *) < entries) {
    /* unsigned integer overflow - there's no way this request could fit into
     * the address space */
    fatal("Requested hash table size is too large", EX_SOFTWARE);
  }

  /* Minimum size we need to allocate, given the load factor. */
  uint64_t min_needed = entries * (1.0 / HASH_LOAD_FACTOR);

  return round_up_log_base2(min_needed);
}

#endif /* __CYRUS_HASH_PRIV_H__ */
