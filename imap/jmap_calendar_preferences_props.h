/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_calendar_preferences_props.gperf  */
/* Computed positions: -k'' */

#line 1 "imap/jmap_calendar_preferences_props.gperf"

/* jmap_calendar_preferences_props.h --
   Lookup functions for JMAP CalendarPreferences properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    CALENDARPREFERENCES_PROP_TOTAL_KEYWORDS = 3,
    CALENDARPREFERENCES_PROP_MIN_WORD_LENGTH = 2,
    CALENDARPREFERENCES_PROP_MAX_WORD_LENGTH = 28,
    CALENDARPREFERENCES_PROP_MIN_HASH_VALUE = 2,
    CALENDARPREFERENCES_PROP_MAX_HASH_VALUE = 28
  };

/* maximum key range = 27, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
/*ARGSUSED*/
static unsigned int
calendarpreferences_prop_hash (register const char *str, register size_t len)
{
  (void) str;
  return len;
}

static const unsigned char calendarpreferences_prop_lengths[] =
  {
     0,  0,  2,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0, 17,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    28
  };

static const jmap_property_t calendarpreferences_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_calendar_preferences_props.gperf"
    {"id",                           NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 29 "imap/jmap_calendar_preferences_props.gperf"
    {"defaultCalendarId",            NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 30 "imap/jmap_calendar_preferences_props.gperf"
    {"defaultParticipantIdentityId", NULL, 0}
  };

const jmap_property_t *
calendarpreferences_prop_lookup (register const char *str, register size_t len)
{
  if (len <= CALENDARPREFERENCES_PROP_MAX_WORD_LENGTH && len >= CALENDARPREFERENCES_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = calendarpreferences_prop_hash (str, len);

      if (key <= CALENDARPREFERENCES_PROP_MAX_HASH_VALUE)
        if (len == calendarpreferences_prop_lengths[key])
          {
            register const char *s = calendarpreferences_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &calendarpreferences_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 31 "imap/jmap_calendar_preferences_props.gperf"


static const jmap_prop_hash_table_t jmap_calendarpreferences_props_map = {
    calendarpreferences_prop_array,
    CALENDARPREFERENCES_PROP_TOTAL_KEYWORDS,
    CALENDARPREFERENCES_PROP_MIN_HASH_VALUE,
    CALENDARPREFERENCES_PROP_MAX_HASH_VALUE,
    &calendarpreferences_prop_lookup
};
