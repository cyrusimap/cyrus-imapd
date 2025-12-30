/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_contact_group_props.gperf  */
/* Computed positions: -k'' */

#line 1 "imap/jmap_contact_group_props.gperf"

/* jmap_contact_group_props.h --
   Lookup functions for JMAP ContactGroup properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    GROUP_PROP_TOTAL_KEYWORDS = 7,
    GROUP_PROP_MIN_WORD_LENGTH = 2,
    GROUP_PROP_MAX_WORD_LENGTH = 22,
    GROUP_PROP_MIN_HASH_VALUE = 2,
    GROUP_PROP_MAX_HASH_VALUE = 22
  };

/* maximum key range = 21, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
/*ARGSUSED*/
static unsigned int
group_prop_hash (register const char *str, register size_t len)
{
  (void) str;
  return len;
}

static const unsigned char group_prop_lengths[] =
  {
     0,  0,  2,  3,  4,  0,  6,  0,  0,  0, 10,  0,  0, 13,
     0,  0,  0,  0,  0,  0,  0,  0, 22
  };

static const jmap_property_t group_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_contact_group_props.gperf"
    {"id",          NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#line 29 "imap/jmap_contact_group_props.gperf"
    {"uid",        NULL, JMAP_PROP_IMMUTABLE},
#line 30 "imap/jmap_contact_group_props.gperf"
    {"name",       NULL, 0},
    {(char*)0,NULL,0},
#line 36 "imap/jmap_contact_group_props.gperf"
    {"x-href",                 JMAP_CONTACTS_EXTENSION,JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 31 "imap/jmap_contact_group_props.gperf"
    {"contactIds", NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 34 "imap/jmap_contact_group_props.gperf"
    {"addressbookId",          JMAP_CONTACTS_EXTENSION, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 38 "imap/jmap_contact_group_props.gperf"
    {"otherAccountContactIds", JMAP_CONTACTS_EXTENSION, 0}
  };

const jmap_property_t *
group_prop_lookup (register const char *str, register size_t len)
{
  if (len <= GROUP_PROP_MAX_WORD_LENGTH && len >= GROUP_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = group_prop_hash (str, len);

      if (key <= GROUP_PROP_MAX_HASH_VALUE)
        if (len == group_prop_lengths[key])
          {
            register const char *s = group_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &group_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 39 "imap/jmap_contact_group_props.gperf"


static const jmap_prop_hash_table_t jmap_group_props_map = {
    group_prop_array,
    GROUP_PROP_TOTAL_KEYWORDS,
    GROUP_PROP_MIN_HASH_VALUE,
    GROUP_PROP_MAX_HASH_VALUE,
    &group_prop_lookup
};
