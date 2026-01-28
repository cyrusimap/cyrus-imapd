/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_sieve_props.gperf  */
/* Computed positions: -k'' */

#line 1 "imap/jmap_sieve_props.gperf"

/* jmap_sieve_props.h -- Lookup functions for JMAP Sieve properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    SIEVE_PROP_TOTAL_KEYWORDS = 4,
    SIEVE_PROP_MIN_WORD_LENGTH = 2,
    SIEVE_PROP_MAX_WORD_LENGTH = 8,
    SIEVE_PROP_MIN_HASH_VALUE = 2,
    SIEVE_PROP_MAX_HASH_VALUE = 8
  };

/* maximum key range = 7, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
/*ARGSUSED*/
static unsigned int
sieve_prop_hash (register const char *str, register size_t len)
{
  (void) str;
  return len;
}

static const unsigned char sieve_prop_lengths[] =
  {
     0,  0,  2,  0,  4,  0,  6,  0,  8
  };

static const jmap_property_t sieve_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 27 "imap/jmap_sieve_props.gperf"
    {"id",       NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0},
#line 28 "imap/jmap_sieve_props.gperf"
    {"name",     NULL, 0},
    {(char*)0,NULL,0},
#line 30 "imap/jmap_sieve_props.gperf"
    {"blobId",   NULL, 0},
    {(char*)0,NULL,0},
#line 29 "imap/jmap_sieve_props.gperf"
    {"isActive", NULL, JMAP_PROP_SERVER_SET}
  };

const jmap_property_t *
sieve_prop_lookup (register const char *str, register size_t len)
{
  if (len <= SIEVE_PROP_MAX_WORD_LENGTH && len >= SIEVE_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = sieve_prop_hash (str, len);

      if (key <= SIEVE_PROP_MAX_HASH_VALUE)
        if (len == sieve_prop_lengths[key])
          {
            register const char *s = sieve_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &sieve_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 31 "imap/jmap_sieve_props.gperf"


static const jmap_prop_hash_table_t jmap_sieve_props_map = {
    sieve_prop_array,
    SIEVE_PROP_TOTAL_KEYWORDS,
    SIEVE_PROP_MIN_HASH_VALUE,
    SIEVE_PROP_MAX_HASH_VALUE,
    &sieve_prop_lookup
};
