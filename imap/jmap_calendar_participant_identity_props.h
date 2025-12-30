/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_calendar_participant_identity_props.gperf  */
/* Computed positions: -k'' */

#line 1 "imap/jmap_calendar_participant_identity_props.gperf"

/* jmap_calendar_participant_identity_props.h --
   Lookup functions for JMAP ParticipantIdentity properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    PARTICIPANTIDENTITY_PROP_TOTAL_KEYWORDS = 3,
    PARTICIPANTIDENTITY_PROP_MIN_WORD_LENGTH = 2,
    PARTICIPANTIDENTITY_PROP_MAX_WORD_LENGTH = 6,
    PARTICIPANTIDENTITY_PROP_MIN_HASH_VALUE = 2,
    PARTICIPANTIDENTITY_PROP_MAX_HASH_VALUE = 6
  };

/* maximum key range = 5, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
/*ARGSUSED*/
static unsigned int
participantidentity_prop_hash (register const char *str, register size_t len)
{
  (void) str;
  return len;
}

static const unsigned char participantidentity_prop_lengths[] =
  {
     0,  0,  2,  0,  4,  0,  6
  };

static const jmap_property_t participantidentity_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_calendar_participant_identity_props.gperf"
    {"id",     NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0},
#line 29 "imap/jmap_calendar_participant_identity_props.gperf"
    {"name",   NULL, 0},
    {(char*)0,NULL,0},
#line 30 "imap/jmap_calendar_participant_identity_props.gperf"
    {"sendTo", NULL, 0}
  };

const jmap_property_t *
participantidentity_prop_lookup (register const char *str, register size_t len)
{
  if (len <= PARTICIPANTIDENTITY_PROP_MAX_WORD_LENGTH && len >= PARTICIPANTIDENTITY_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = participantidentity_prop_hash (str, len);

      if (key <= PARTICIPANTIDENTITY_PROP_MAX_HASH_VALUE)
        if (len == participantidentity_prop_lengths[key])
          {
            register const char *s = participantidentity_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &participantidentity_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 31 "imap/jmap_calendar_participant_identity_props.gperf"


static const jmap_prop_hash_table_t jmap_participantidentity_props_map = {
    participantidentity_prop_array,
    PARTICIPANTIDENTITY_PROP_TOTAL_KEYWORDS,
    PARTICIPANTIDENTITY_PROP_MIN_HASH_VALUE,
    PARTICIPANTIDENTITY_PROP_MAX_HASH_VALUE,
    &participantidentity_prop_lookup
};
