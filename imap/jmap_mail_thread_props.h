/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_mail_thread_props.gperf  */
/* Computed positions: -k'' */

#line 1 "imap/jmap_mail_thread_props.gperf"

/* jmap_mail_thread_props.h -- Lookup functions for JMAP Thread properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    THREAD_PROP_TOTAL_KEYWORDS = 2,
    THREAD_PROP_MIN_WORD_LENGTH = 2,
    THREAD_PROP_MAX_WORD_LENGTH = 8,
    THREAD_PROP_MIN_HASH_VALUE = 2,
    THREAD_PROP_MAX_HASH_VALUE = 8
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
thread_prop_hash (register const char *str, register size_t len)
{
  (void) str;
  return len;
}

static const unsigned char thread_prop_lengths[] =
  {
     0,  0,  2,  0,  0,  0,  0,  0,  8
  };

static const jmap_property_t thread_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 27 "imap/jmap_mail_thread_props.gperf"
    {"id",       NULL, JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_mail_thread_props.gperf"
    {"emailIds", NULL, 0}
  };

const jmap_property_t *
thread_prop_lookup (register const char *str, register size_t len)
{
  if (len <= THREAD_PROP_MAX_WORD_LENGTH && len >= THREAD_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = thread_prop_hash (str, len);

      if (key <= THREAD_PROP_MAX_HASH_VALUE)
        if (len == thread_prop_lengths[key])
          {
            register const char *s = thread_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &thread_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 29 "imap/jmap_mail_thread_props.gperf"


static const jmap_prop_hash_table_t jmap_thread_props_map = {
    thread_prop_array,
    THREAD_PROP_TOTAL_KEYWORDS,
    THREAD_PROP_MIN_HASH_VALUE,
    THREAD_PROP_MAX_HASH_VALUE,
    &thread_prop_lookup
};
