/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_mail_props.gperf  */
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

#line 1 "imap/jmap_mail_props.gperf"

/* jmap_mail_props.h -- Lookup functions for JMAP Email properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    EMAIL_PROP_TOTAL_KEYWORDS = 39,
    EMAIL_PROP_MIN_WORD_LENGTH = 2,
    EMAIL_PROP_MAX_WORD_LENGTH = 21,
    EMAIL_PROP_MIN_HASH_VALUE = 2,
    EMAIL_PROP_MAX_HASH_VALUE = 86
  };

/* maximum key range = 85, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
email_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87,  0, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 10, 25, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87,  0, 35, 10,
       0,  0,  5, 10, 15, 25, 87,  0,  5, 10,
      87, 35, 30, 87, 10,  0,  0, 87,  5, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87
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

static const unsigned char email_prop_lengths[] =
  {
     0,  0,  2,  0,  4,  0,  6,  7,  8,  4, 10, 11,  2, 13,
     0,  0,  6,  7,  8,  9, 10,  0, 12, 13, 14, 10, 11,  2,
    13,  9,  0,  0,  7,  8,  9,  0,  0,  7,  3,  9,  0,  6,
     7,  8,  9, 10,  0,  0, 13,  0, 10,  0,  0,  0,  0, 10,
     0,  0,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0, 21
  };

static const jmap_property_t email_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 41 "imap/jmap_mail_props.gperf"
    {"to",            NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 32 "imap/jmap_mail_props.gperf"
    {"size",          NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 46 "imap/jmap_mail_props.gperf"
    {"sentAt",        NULL, JMAP_PROP_IMMUTABLE},
#line 64 "imap/jmap_mail_props.gperf"
    {"snoozed",               JMAP_MAIL_EXTENSION, 0},
#line 29 "imap/jmap_mail_props.gperf"
    {"threadId",      NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 40 "imap/jmap_mail_props.gperf"
    {"from",          NULL, JMAP_PROP_IMMUTABLE},
#line 56 "imap/jmap_mail_props.gperf"
    {"addedDates",            JMAP_MAIL_EXTENSION, 0},
#line 67 "imap/jmap_mail_props.gperf"
    {"deliveredTo",           JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET},
#line 42 "imap/jmap_mail_props.gperf"
    {"cc",            NULL, JMAP_PROP_IMMUTABLE},
#line 58 "imap/jmap_mail_props.gperf"
    {"trustedSender",         JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 39 "imap/jmap_mail_props.gperf"
    {"sender",        NULL, JMAP_PROP_IMMUTABLE},
#line 45 "imap/jmap_mail_props.gperf"
    {"subject",       NULL, JMAP_PROP_IMMUTABLE},
#line 31 "imap/jmap_mail_props.gperf"
    {"keywords",      NULL, 0},
#line 59 "imap/jmap_mail_props.gperf"
    {"spamScore",             JMAP_MAIL_EXTENSION, JMAP_PROP_IMMUTABLE},
#line 38 "imap/jmap_mail_props.gperf"
    {"references",    NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 57 "imap/jmap_mail_props.gperf"
    {"removedDates",          JMAP_MAIL_EXTENSION, 0},
#line 66 "imap/jmap_mail_props.gperf"
    {"createdModseq",         JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 60 "imap/jmap_mail_props.gperf"
    {"calendarEvents",        JMAP_MAIL_EXTENSION, JMAP_PROP_IMMUTABLE},
#line 33 "imap/jmap_mail_props.gperf"
    {"receivedAt",    NULL, JMAP_PROP_IMMUTABLE},
#line 51 "imap/jmap_mail_props.gperf"
    {"attachments",   NULL, JMAP_PROP_IMMUTABLE},
#line 27 "imap/jmap_mail_props.gperf"
    {"id",            NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#line 52 "imap/jmap_mail_props.gperf"
    {"hasAttachment", NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 36 "imap/jmap_mail_props.gperf"
    {"messageId",     NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 34 "imap/jmap_mail_props.gperf"
    {"headers",       NULL, JMAP_PROP_IMMUTABLE  | JMAP_PROP_SKIP_GET},
#line 35 "imap/jmap_mail_props.gperf"
    {"header:*",      NULL, JMAP_PROP_IMMUTABLE  | JMAP_PROP_SKIP_GET},
#line 62 "imap/jmap_mail_props.gperf"
    {"isDeleted",             JMAP_MAIL_EXTENSION, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 53 "imap/jmap_mail_props.gperf"
    {"preview",       NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 43 "imap/jmap_mail_props.gperf"
    {"bcc",           NULL, JMAP_PROP_IMMUTABLE},
#line 37 "imap/jmap_mail_props.gperf"
    {"inReplyTo",     NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 28 "imap/jmap_mail_props.gperf"
    {"blobId",        NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 44 "imap/jmap_mail_props.gperf"
    {"replyTo",       NULL, JMAP_PROP_IMMUTABLE},
#line 49 "imap/jmap_mail_props.gperf"
    {"textBody",      NULL, JMAP_PROP_IMMUTABLE},
#line 63 "imap/jmap_mail_props.gperf"
    {"imageSize",             JMAP_MAIL_EXTENSION, 0},
#line 48 "imap/jmap_mail_props.gperf"
    {"bodyValues",    NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 47 "imap/jmap_mail_props.gperf"
    {"bodyStructure", NULL, JMAP_PROP_IMMUTABLE  | JMAP_PROP_SKIP_GET},
    {(char*)0,NULL,0},
#line 65 "imap/jmap_mail_props.gperf"
    {"bimiBlobId",            JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 30 "imap/jmap_mail_props.gperf"
    {"mailboxIds",    NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 50 "imap/jmap_mail_props.gperf"
    {"htmlBody",      NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 61 "imap/jmap_mail_props.gperf"
    {"previousCalendarEvent", JMAP_MAIL_EXTENSION, JMAP_PROP_IMMUTABLE}
  };

const jmap_property_t *
email_prop_lookup (register const char *str, register size_t len)
{
  if (len <= EMAIL_PROP_MAX_WORD_LENGTH && len >= EMAIL_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = email_prop_hash (str, len);

      if (key <= EMAIL_PROP_MAX_HASH_VALUE)
        if (len == email_prop_lengths[key])
          {
            register const char *s = email_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &email_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 68 "imap/jmap_mail_props.gperf"


static const jmap_prop_hash_table_t jmap_email_props_map = {
    email_prop_array,
    EMAIL_PROP_TOTAL_KEYWORDS,
    EMAIL_PROP_MIN_HASH_VALUE,
    EMAIL_PROP_MAX_HASH_VALUE,
    &email_prop_lookup
};
