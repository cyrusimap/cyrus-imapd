/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_calendar_props.gperf  */
/* Computed positions: -k'2' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "imap/jmap_calendar_props.gperf"

/* jmap_calendar_props.h -- Lookup functions for JMAP Calendar properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    CALENDAR_PROP_TOTAL_KEYWORDS = 22,
    CALENDAR_PROP_MIN_WORD_LENGTH = 2,
    CALENDAR_PROP_MAX_WORD_LENGTH = 24,
    CALENDAR_PROP_MIN_HASH_VALUE = 2,
    CALENDAR_PROP_MAX_HASH_VALUE = 44
  };

/* maximum key range = 43, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
calendar_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45,  0, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45,  0, 45, 45,
       0, 20, 45, 45, 25,  5, 45, 45, 45, 45,
      15, 20, 45, 45,  0, 10, 45, 45,  5, 45,
      45,  0, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
      45, 45, 45, 45, 45, 45
    };
  return len + asso_values[(unsigned char)str[1]];
}

static const unsigned char calendar_prop_lengths[] =
  {
     0,  0,  2,  0,  4,  0,  6,  0,  8,  9, 10, 11,  0,  8,
     9, 15,  0,  0,  0,  9,  0, 21, 12,  0, 14,  5, 16,  0,
     0,  9,  0, 11,  0,  0,  9,  0, 21,  0,  0,  0,  0, 21,
     0,  0, 24
  };

static const jmap_property_t calendar_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 27 "imap/jmap_calendar_props.gperf"
    {"id",                       NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0},
#line 28 "imap/jmap_calendar_props.gperf"
    {"name",                     NULL, 0},
    {(char*)0,NULL,0},
#line 50 "imap/jmap_calendar_props.gperf"
    {"x-href",           JMAP_DEBUG_EXTENSION,     JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 40 "imap/jmap_calendar_props.gperf"
    {"myRights",                 NULL, JMAP_PROP_SERVER_SET},
#line 48 "imap/jmap_calendar_props.gperf"
    {"calDavUrl",        JMAP_CALENDARS_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_EXTERNAL},
#line 43 "imap/jmap_calendar_props.gperf"
    {"syncedFrom",       JMAP_CALENDARS_EXTENSION, JMAP_PROP_EXTERNAL},
#line 47 "imap/jmap_calendar_props.gperf"
    {"freeBusyUrl",      JMAP_CALENDARS_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_EXTERNAL},
    {(char*)0,NULL,0},
#line 37 "imap/jmap_calendar_props.gperf"
    {"timeZone",                 NULL, 0},
#line 46 "imap/jmap_calendar_props.gperf"
    {"eventsUrl",        JMAP_CALENDARS_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_EXTERNAL},
#line 49 "imap/jmap_calendar_props.gperf"
    {"mailboxUniqueId",  JMAP_CALENDARS_EXTENSION, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 32 "imap/jmap_calendar_props.gperf"
    {"isVisible",                NULL, 0},
    {(char*)0,NULL,0},
#line 38 "imap/jmap_calendar_props.gperf"
    {"participantIdentities",    NULL, 0},
#line 33 "imap/jmap_calendar_props.gperf"
    {"isSubscribed",             NULL, 0},
    {(char*)0,NULL,0},
#line 44 "imap/jmap_calendar_props.gperf"
    {"isEventsPublic",   JMAP_CALENDARS_EXTENSION, JMAP_PROP_EXTERNAL},
#line 30 "imap/jmap_calendar_props.gperf"
    {"color",                    NULL, 0},
#line 45 "imap/jmap_calendar_props.gperf"
    {"isFreeBusyPublic", JMAP_CALENDARS_EXTENSION, JMAP_PROP_EXTERNAL},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 31 "imap/jmap_calendar_props.gperf"
    {"sortOrder",                NULL, 0},
    {(char*)0,NULL,0},
#line 29 "imap/jmap_calendar_props.gperf"
    {"description",              NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 39 "imap/jmap_calendar_props.gperf"
    {"shareWith",                NULL, 0},
    {(char*)0,NULL,0},
#line 34 "imap/jmap_calendar_props.gperf"
    {"includeInAvailability",    NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 35 "imap/jmap_calendar_props.gperf"
    {"defaultAlertsWithTime",    NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 36 "imap/jmap_calendar_props.gperf"
    {"defaultAlertsWithoutTime", NULL, 0}
  };

const jmap_property_t *
calendar_prop_lookup (register const char *str, register size_t len)
{
  if (len <= CALENDAR_PROP_MAX_WORD_LENGTH && len >= CALENDAR_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = calendar_prop_hash (str, len);

      if (key <= CALENDAR_PROP_MAX_HASH_VALUE)
        if (len == calendar_prop_lengths[key])
          {
            register const char *s = calendar_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &calendar_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 51 "imap/jmap_calendar_props.gperf"


static const jmap_prop_hash_table_t jmap_calendar_props_map = {
    calendar_prop_array,
    CALENDAR_PROP_TOTAL_KEYWORDS,
    CALENDAR_PROP_MIN_HASH_VALUE,
    CALENDAR_PROP_MAX_HASH_VALUE,
    &calendar_prop_lookup
};
