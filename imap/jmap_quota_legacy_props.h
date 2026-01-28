/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_quota_legacy_props.gperf  */
/* Computed positions: -k'' */

#line 1 "imap/jmap_quota_legacy_props.gperf"

/* jmap_quota_legacy_props.h -- Lookup functions Legacy JMAP Quota properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    QUOTA_LEGACY_PROP_TOTAL_KEYWORDS = 3,
    QUOTA_LEGACY_PROP_MIN_WORD_LENGTH = 2,
    QUOTA_LEGACY_PROP_MAX_WORD_LENGTH = 5,
    QUOTA_LEGACY_PROP_MIN_HASH_VALUE = 2,
    QUOTA_LEGACY_PROP_MAX_HASH_VALUE = 5
  };

/* maximum key range = 4, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
/*ARGSUSED*/
static unsigned int
quota_legacy_prop_hash (register const char *str, register size_t len)
{
  (void) str;
  return len;
}

static const unsigned char quota_legacy_prop_lengths[] =
  {
     0,  0,  2,  0,  4,  5
  };

static const jmap_property_t quota_legacy_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 27 "imap/jmap_quota_legacy_props.gperf"
    {"id",    NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 28 "imap/jmap_quota_legacy_props.gperf"
    {"used",  NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 29 "imap/jmap_quota_legacy_props.gperf"
    {"total", NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE}
  };

const jmap_property_t *
quota_legacy_prop_lookup (register const char *str, register size_t len)
{
  if (len <= QUOTA_LEGACY_PROP_MAX_WORD_LENGTH && len >= QUOTA_LEGACY_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = quota_legacy_prop_hash (str, len);

      if (key <= QUOTA_LEGACY_PROP_MAX_HASH_VALUE)
        if (len == quota_legacy_prop_lengths[key])
          {
            register const char *s = quota_legacy_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &quota_legacy_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 30 "imap/jmap_quota_legacy_props.gperf"


static const jmap_prop_hash_table_t jmap_quota_legacy_props_map = {
    quota_legacy_prop_array,
    QUOTA_LEGACY_PROP_TOTAL_KEYWORDS,
    QUOTA_LEGACY_PROP_MIN_HASH_VALUE,
    QUOTA_LEGACY_PROP_MAX_HASH_VALUE,
    &quota_legacy_prop_lookup
};
