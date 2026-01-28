/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_mailbox_props.gperf  */
/* Computed positions: -k'1,6' */

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

#line 1 "imap/jmap_mailbox_props.gperf"

/* jmap_mailbox_props.h -- Lookup functions for JMAP Mailbox properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    MAILBOX_PROP_TOTAL_KEYWORDS = 27,
    MAILBOX_PROP_MIN_WORD_LENGTH = 2,
    MAILBOX_PROP_MAX_WORD_LENGTH = 18,
    MAILBOX_PROP_MIN_HASH_VALUE = 4,
    MAILBOX_PROP_MAX_HASH_VALUE = 41
  };

/* maximum key range = 38, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
mailbox_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 28, 42, 42, 42, 30,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 15,
      42, 42, 42, 42,  0, 42, 42, 25, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 15, 42,  0,
       5,  0, 42, 25, 10,  5, 42, 42,  0, 10,
      15,  5,  0, 42,  5,  0,  0,  5, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
      42, 42, 42, 42, 42, 42
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[5]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 5:
      case 4:
      case 3:
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval;
}

static const unsigned char mailbox_prop_lengths[] =
  {
     0,  0,  0,  0,  4,  5,  0,  2,  8,  4,  0, 11, 12,  8,
     9,  0, 11, 12, 18,  4,  0, 11, 12, 13,  9,  0, 16,  0,
     8,  9,  0,  6, 12, 18,  9,  0, 11,  0,  0, 11,  0, 11
  };

static const jmap_property_t mailbox_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 42 "imap/jmap_mailbox_props.gperf"
    {"sort",               JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
#line 53 "imap/jmap_mailbox_props.gperf"
    {"color",              JMAP_MAIL_EXTENSION, 0},
    {(char*)0,NULL,0},
#line 27 "imap/jmap_mailbox_props.gperf"
    {"id",            NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#line 29 "imap/jmap_mailbox_props.gperf"
    {"parentId",      NULL, 0},
#line 30 "imap/jmap_mailbox_props.gperf"
    {"role",          NULL, 0},
    {(char*)0,NULL,0},
#line 54 "imap/jmap_mailbox_props.gperf"
    {"showAsLabel",        JMAP_MAIL_EXTENSION, 0},
#line 34 "imap/jmap_mailbox_props.gperf"
    {"totalThreads",  NULL, JMAP_PROP_SERVER_SET},
#line 55 "imap/jmap_mailbox_props.gperf"
    {"uniqueId",           JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 31 "imap/jmap_mailbox_props.gperf"
    {"sortOrder",     NULL, 0},
    {(char*)0,NULL,0},
#line 40 "imap/jmap_mailbox_props.gperf"
    {"isCollapsed",        JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
#line 37 "imap/jmap_mailbox_props.gperf"
    {"isSubscribed",  NULL, 0},
#line 49 "imap/jmap_mailbox_props.gperf"
    {"suppressDuplicates", JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
#line 28 "imap/jmap_mailbox_props.gperf"
    {"name",          NULL, 0},
    {(char*)0,NULL,0},
#line 43 "imap/jmap_mailbox_props.gperf"
    {"identityRef",        JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
#line 33 "imap/jmap_mailbox_props.gperf"
    {"unreadEmails",  NULL, JMAP_PROP_SERVER_SET},
#line 35 "imap/jmap_mailbox_props.gperf"
    {"unreadThreads", NULL, JMAP_PROP_SERVER_SET},
#line 44 "imap/jmap_mailbox_props.gperf"
    {"autoLearn",          JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
    {(char*)0,NULL,0},
#line 48 "imap/jmap_mailbox_props.gperf"
    {"onlyPurgeDeleted",   JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
    {(char*)0,NULL,0},
#line 36 "imap/jmap_mailbox_props.gperf"
    {"myRights",      NULL, JMAP_PROP_SERVER_SET},
#line 46 "imap/jmap_mailbox_props.gperf"
    {"autoPurge",          JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
    {(char*)0,NULL,0},
#line 41 "imap/jmap_mailbox_props.gperf"
    {"hidden",             JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
#line 51 "imap/jmap_mailbox_props.gperf"
    {"isSeenShared",       JMAP_MAIL_EXTENSION, 0},
#line 47 "imap/jmap_mailbox_props.gperf"
    {"purgeOlderThanDays", JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
#line 50 "imap/jmap_mailbox_props.gperf"
    {"shareWith",          JMAP_MAIL_EXTENSION, 0},
    {(char*)0,NULL,0},
#line 52 "imap/jmap_mailbox_props.gperf"
    {"storageUsed",        JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 45 "imap/jmap_mailbox_props.gperf"
    {"learnAsSpam",        JMAP_MAIL_EXTENSION, JMAP_PROP_EXTERNAL},
    {(char*)0,NULL,0},
#line 32 "imap/jmap_mailbox_props.gperf"
    {"totalEmails",   NULL, JMAP_PROP_SERVER_SET}
  };

const jmap_property_t *
mailbox_prop_lookup (register const char *str, register size_t len)
{
  if (len <= MAILBOX_PROP_MAX_WORD_LENGTH && len >= MAILBOX_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = mailbox_prop_hash (str, len);

      if (key <= MAILBOX_PROP_MAX_HASH_VALUE)
        if (len == mailbox_prop_lengths[key])
          {
            register const char *s = mailbox_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &mailbox_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 56 "imap/jmap_mailbox_props.gperf"


static const jmap_prop_hash_table_t jmap_mailbox_props_map = {
    mailbox_prop_array,
    MAILBOX_PROP_TOTAL_KEYWORDS,
    MAILBOX_PROP_MIN_HASH_VALUE,
    MAILBOX_PROP_MAX_HASH_VALUE,
    &mailbox_prop_lookup
};
