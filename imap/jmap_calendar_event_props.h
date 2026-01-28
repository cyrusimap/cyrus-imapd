/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_calendar_event_props.gperf  */
/* Computed positions: -k'1,3' */

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

#line 1 "imap/jmap_calendar_event_props.gperf"

/* jmap_calendar_event_props.h --
   Lookup functions for JMAP CalendarEvent properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    CALENDAREVENT_PROP_TOTAL_KEYWORDS = 52,
    CALENDAREVENT_PROP_MIN_WORD_LENGTH = 2,
    CALENDAREVENT_PROP_MAX_WORD_LENGTH = 23,
    CALENDAREVENT_PROP_MIN_HASH_VALUE = 6,
    CALENDAREVENT_PROP_MAX_HASH_VALUE = 76
  };

/* maximum key range = 71, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
calendarevent_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 35, 77, 77, 77,  5, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 30,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 55, 15,  5,
      40, 10,  5, 77, 15, 35, 77,  0,  0, 35,
      35,  0,  0,  0,  0,  0, 15, 20, 60, 77,
      15,  5, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
      77, 77, 77, 77, 77, 77
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[2]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval;
}

static const unsigned char calendarevent_prop_lengths[] =
  {
     0,  0,  0,  0,  0,  0,  6,  7,  8,  9,  5,  6, 12,  8,
     9, 15, 11, 12, 13,  0, 15,  6,  7,  8, 19, 20, 11,  0,
    23, 14, 10,  6,  0,  8,  0,  5,  6,  2, 23,  0,  5,  6,
     7,  8,  0,  5, 16,  7,  8,  0,  0, 11,  0, 13,  0, 15,
     6,  0,  8,  0,  5,  6, 22,  3,  0,  0, 11,  7, 13,  0,
     0,  6,  0,  8,  0,  0, 16
  };

static const jmap_property_t calendarevent_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 35 "imap/jmap_calendar_event_props.gperf"
    {"prodId",                  NULL, 0},
#line 59 "imap/jmap_calendar_event_props.gperf"
    {"replyTo",                 NULL, 0},
#line 38 "imap/jmap_calendar_event_props.gperf"
    {"sequence",                NULL, 0},
#line 34 "imap/jmap_calendar_event_props.gperf"
    {"relatedTo",               NULL, 0},
#line 49 "imap/jmap_calendar_event_props.gperf"
    {"color",                   NULL, 0},
#line 46 "imap/jmap_calendar_event_props.gperf"
    {"locale",                  NULL, 0},
#line 60 "imap/jmap_calendar_event_props.gperf"
    {"participants",            NULL, 0},
#line 47 "imap/jmap_calendar_event_props.gperf"
    {"keywords",                NULL, 0},
#line 43 "imap/jmap_calendar_event_props.gperf"
    {"locations",               NULL, 0},
#line 70 "imap/jmap_calendar_event_props.gperf"
    {"showWithoutTime",         NULL, 0},
#line 29 "imap/jmap_calendar_event_props.gperf"
    {"calendarIds",             NULL, 0},
#line 50 "imap/jmap_calendar_event_props.gperf"
    {"recurrenceId",            NULL, 0},
#line 63 "imap/jmap_calendar_event_props.gperf"
    {"localizations",           NULL, 0},
    {(char*)0,NULL,0},
#line 52 "imap/jmap_calendar_event_props.gperf"
    {"recurrenceRules",         NULL, 0},
#line 85 "imap/jmap_calendar_event_props.gperf"
    {"blobId",                  JMAP_CALENDARS_EXTENSION, JMAP_PROP_SERVER_SET},
#line 36 "imap/jmap_calendar_event_props.gperf"
    {"created",                 NULL, 0},
#line 54 "imap/jmap_calendar_event_props.gperf"
    {"excluded",                NULL, 0},
#line 53 "imap/jmap_calendar_event_props.gperf"
    {"recurrenceOverrides",     NULL, 0},
#line 51 "imap/jmap_calendar_event_props.gperf"
    {"recurrenceIdTimeZone",    NULL, 0},
#line 81 "imap/jmap_calendar_event_props.gperf"
    {"baseEventId",             JMAP_URN_CALENDARS,       JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 86 "imap/jmap_calendar_event_props.gperf"
    {"cyrusimap.org:iCalProps", JMAP_CALENDARS_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_SKIP_GET},
#line 57 "imap/jmap_calendar_event_props.gperf"
    {"freeBusyStatus",          NULL, 0},
#line 48 "imap/jmap_calendar_event_props.gperf"
    {"categories",              NULL, 0},
#line 76 "imap/jmap_calendar_event_props.gperf"
    {"utcEnd",                  JMAP_URN_CALENDARS,       JMAP_PROP_SKIP_GET},
    {(char*)0,NULL,0},
#line 75 "imap/jmap_calendar_event_props.gperf"
    {"utcStart",                JMAP_URN_CALENDARS,       JMAP_PROP_SKIP_GET},
    {(char*)0,NULL,0},
#line 40 "imap/jmap_calendar_event_props.gperf"
    {"title",                   NULL, 0},
#line 84 "imap/jmap_calendar_event_props.gperf"
    {"x-href",                  JMAP_CALENDARS_EXTENSION, 0},
#line 28 "imap/jmap_calendar_event_props.gperf"
    {"id",                      NULL, JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#line 55 "imap/jmap_calendar_event_props.gperf"
    {"excludedRecurrenceRules", NULL, 0},
    {(char*)0,NULL,0},
#line 45 "imap/jmap_calendar_event_props.gperf"
    {"links",                   NULL, 0},
#line 64 "imap/jmap_calendar_event_props.gperf"
    {"sentBy",                  NULL, 0},
#line 58 "imap/jmap_calendar_event_props.gperf"
    {"privacy",                 NULL, 0},
#line 56 "imap/jmap_calendar_event_props.gperf"
    {"priority",                NULL, 0},
    {(char*)0,NULL,0},
#line 32 "imap/jmap_calendar_event_props.gperf"
    {"@type",                   NULL, 0},
#line 61 "imap/jmap_calendar_event_props.gperf"
    {"useDefaultAlerts",        NULL, 0},
#line 74 "imap/jmap_calendar_event_props.gperf"
    {"isDraft",                 JMAP_URN_CALENDARS,       0},
#line 69 "imap/jmap_calendar_event_props.gperf"
    {"duration",                NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 41 "imap/jmap_calendar_event_props.gperf"
    {"description",             NULL, 0},
    {(char*)0,NULL,0},
#line 77 "imap/jmap_calendar_event_props.gperf"
    {"mayInviteSelf",           JMAP_URN_CALENDARS,       0},
    {(char*)0,NULL,0},
#line 78 "imap/jmap_calendar_event_props.gperf"
    {"mayInviteOthers",         JMAP_URN_CALENDARS,       0},
#line 39 "imap/jmap_calendar_event_props.gperf"
    {"method",                  NULL, 0},
    {(char*)0,NULL,0},
#line 68 "imap/jmap_calendar_event_props.gperf"
    {"timeZone",                NULL, 0},
    {(char*)0,NULL,0},
#line 67 "imap/jmap_calendar_event_props.gperf"
    {"start",                   NULL, 0},
#line 71 "imap/jmap_calendar_event_props.gperf"
    {"status",                  NULL, 0},
#line 42 "imap/jmap_calendar_event_props.gperf"
    {"descriptionContentType",  NULL, 0},
#line 33 "imap/jmap_calendar_event_props.gperf"
    {"uid",                     NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 87 "imap/jmap_calendar_event_props.gperf"
    {"debugBlobId",             JMAP_DEBUG_EXTENSION,     JMAP_PROP_SERVER_SET},
#line 37 "imap/jmap_calendar_event_props.gperf"
    {"updated",                 NULL, 0},
#line 79 "imap/jmap_calendar_event_props.gperf"
    {"hideAttendees",           JMAP_URN_CALENDARS,       0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 62 "imap/jmap_calendar_event_props.gperf"
    {"alerts",                  NULL, 0},
    {(char*)0,NULL,0},
#line 80 "imap/jmap_calendar_event_props.gperf"
    {"isOrigin",                JMAP_URN_CALENDARS,       0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 44 "imap/jmap_calendar_event_props.gperf"
    {"virtualLocations",        NULL, 0}
  };

const jmap_property_t *
calendarevent_prop_lookup (register const char *str, register size_t len)
{
  if (len <= CALENDAREVENT_PROP_MAX_WORD_LENGTH && len >= CALENDAREVENT_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = calendarevent_prop_hash (str, len);

      if (key <= CALENDAREVENT_PROP_MAX_HASH_VALUE)
        if (len == calendarevent_prop_lengths[key])
          {
            register const char *s = calendarevent_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &calendarevent_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 88 "imap/jmap_calendar_event_props.gperf"


static const jmap_prop_hash_table_t jmap_calendarevent_props_map = {
    calendarevent_prop_array,
    CALENDAREVENT_PROP_TOTAL_KEYWORDS,
    CALENDAREVENT_PROP_MIN_HASH_VALUE,
    CALENDAREVENT_PROP_MAX_HASH_VALUE,
    &calendarevent_prop_lookup
};
