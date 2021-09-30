%{
/* sieve.l -- sieve lexer
 * Larry Greenfield
 * Ken Murchison
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "util.h"

#include "sieve/tree.h"
#include "sieve/sieve_interface.h"
#include "sieve/sieve.h"

#define YY_NO_INPUT
#define YY_DECL int yylex(YYSTYPE *yylval, sieve_script_t *sscript)

static struct buf buf;   /* buffer for multi-line text and quoted strings */
extern int encoded_char; /* used to receive encoded-char feedback from parser */

static unsigned long long tonum(const char *str);
static int decode_string(struct buf *sbuf);
extern void sieveerror(sieve_script_t *, const char *);/* XXX gak! public prototypes! */
extern void sieveerror_f(sieve_script_t *, const char *fmt, ...);/* XXX gak! public prototypes! */
%}

%option yylineno
%option noyywrap
%option nounput
%option prefix="sieve" outfile="lex.yy.c"

    /* linebreak */
CRLF            (\r\n|\r|\n)
    
    /* non-linebreaking whitespace */
ws              [ \t]+

%state MULTILINE
%state QSTRING
%state QCOLLATION
%state QRELATION
%state QIMPORTANCE

%%
    /* dot stuffing */
<MULTILINE>^\.\.              buf_putc(&buf, yytext[1]);

    /* end of multi-line text */
<MULTILINE>^\.{CRLF}          |

    /* end of quoted string */
<QSTRING>\"                   {
                                  BEGIN INITIAL;
                                  if (encoded_char && !decode_string(&buf)) {
                                      sieveerror_f(sscript,
                                                   "invalid unicode encoding: %s",
                                                   buf_cstring(&buf));
                                  }
                                  yylval->sval = buf_release(&buf);
                                  return STRING;
                              }

    /* escaped character */
<QSTRING>\\.                  buf_putc(&buf, yytext[1]);

    /* any character (including LF) */
<QSTRING,MULTILINE>(.|\n)     buf_putc(&buf, yytext[0]);

    /* premature EOF */
<QSTRING,MULTILINE><<EOF>>    {
                                  BEGIN INITIAL;
                                  sieveerror(sscript,
                                             "unexpected end of file in string");
                                  buf_free(&buf);
                                  yyterminate();
                              }

    /* beginning of multi-line text */
<INITIAL>text:{ws}?(#.*)?{CRLF} {
                                  BEGIN MULTILINE;
                                  buf_reset(&buf);
                              }

    /* beginning of quoted string */
<INITIAL>\"                   {
                                  BEGIN QSTRING;
                                  buf_reset(&buf);
                              }

    /* number with optional power of 2 suffix */
<INITIAL>[0-9]+[KMGkmg]?      {
                                  unsigned long long val = tonum(yytext);
                                  if (val > INT_MAX) {
                                      sieveerror_f(sscript,
                                                   "number too large %s",
                                                   yytext);
                                  }
                                  yylval->nval = val;
                                  return NUMBER;
                              }

    /* standard control commands - RFC 5228 */
<INITIAL>if                   return IF;
<INITIAL>elsif                return ELSIF;
<INITIAL>else                 return ELSE;
<INITIAL>require              return REQUIRE;
<INITIAL>stop                 return STOP;

    /* standard tests - RFC 5228 */
<INITIAL>anyof                return ANYOF;
<INITIAL>allof                return ALLOF;
<INITIAL>exists               return EXISTS;
<INITIAL>false                return SFALSE;
<INITIAL>true                 return STRUE;
<INITIAL>not                  return NOT;
<INITIAL>header               return HEADERT;
<INITIAL>address              return ADDRESS;
<INITIAL>envelope             return ENVELOPE;
<INITIAL>size                 return SIZE;
<INITIAL>:over                return yylval->nval = OVER;
<INITIAL>:under               return yylval->nval = UNDER;

    /* standard action commands - RFC 5228 */
<INITIAL>discard              return DISCARD;
<INITIAL>keep                 return KEEP;
<INITIAL>fileinto             return FILEINTO;
<INITIAL>redirect             return REDIRECT;

    /* copy - RFC 3894 */
<INITIAL>:copy                return COPY;

    /* comparator-types - RFC 5228 */
<INITIAL>:comparator          { BEGIN QCOLLATION; return COMPARATOR; }

<QCOLLATION>[ \t\n\r] ;       /* ignore whitespace */
<QCOLLATION>\"i;octet\"       {
                                  BEGIN INITIAL;
                                  return yylval->nval = OCTET;
                              }
<QCOLLATION>\"i;ascii-casemap\" {
                                  BEGIN INITIAL;
                                  return yylval->nval = ASCIICASEMAP;
                              }
<QCOLLATION>\"i;ascii-numeric\" {
                                  BEGIN INITIAL;
                                  return yylval->nval = ASCIINUMERIC;
                              }
<QCOLLATION>\"[^\"]*\"        {
                                  BEGIN INITIAL;
                                  sieveerror_f(sscript,
                                               "unknown comparator-name %s",
                                               yytext);
                              }

    /* match-types - RFC 5228 */
<INITIAL>:is                  return yylval->nval = IS;
<INITIAL>:contains            return yylval->nval = CONTAINS;
<INITIAL>:matches             return yylval->nval = MATCHES;

    /* regex - draft-ietf-sieve-regex */
<INITIAL>:regex               return yylval->nval = REGEX;
<INITIAL>:quoteregex          return yylval->nval = QUOTEREGEX;

    /* extlists - RFC 6134 */
<INITIAL>:list                return yylval->nval = LIST;
<INITIAL>valid_ext_list       return VALIDEXTLIST;

    /* address-parts - RFC 5228 */
<INITIAL>:all                 return yylval->nval = ALL;
<INITIAL>:localpart           return yylval->nval = LOCALPART;
<INITIAL>:domain              return yylval->nval = DOMAIN;

    /* subaddress - RFC 5233 */
<INITIAL>:user                return yylval->nval = USER;
<INITIAL>:detail              return yylval->nval = DETAIL;

    /* body - RFC 5173 */
<INITIAL>body                 return BODY;
<INITIAL>:raw                 return yylval->nval = RAW;
<INITIAL>:text                return yylval->nval = TEXT;
<INITIAL>:content             return yylval->nval = CONTENT;

    /* environment - RFC 5183 */
<INITIAL>environment          return ENVIRONMENT;

    /* variables - RFC 5229 */
<INITIAL>string               return STRINGT;
<INITIAL>set                  return SET;
<INITIAL>:lower               return yylval->nval = LOWER;
<INITIAL>:upper	              return yylval->nval = UPPER;
<INITIAL>:lowerfirst          return yylval->nval = LOWERFIRST;
<INITIAL>:upperfirst          return yylval->nval = UPPERFIRST;
<INITIAL>:quotewildcard       return yylval->nval = QUOTEWILDCARD;
<INITIAL>:length              return yylval->nval = LENGTH;

    /* vacation - RFC 5230 */
<INITIAL>vacation             return VACATION;
<INITIAL>:days                return DAYS;
<INITIAL>:addresses           return ADDRESSES;
<INITIAL>:subject             return SUBJECT;
<INITIAL>:from                return FROM;
<INITIAL>:handle              return HANDLE;
<INITIAL>:mime                return MIME;

    /* vacation-seconds - RFC 6131 */
<INITIAL>:seconds             return SECONDS;

    /* relational - RFC 5231 */
<INITIAL>:count               { BEGIN QRELATION; return yylval->nval = COUNT; }
<INITIAL>:value               { BEGIN QRELATION; return yylval->nval = VALUE; }

<QRELATION>[ \t\n\r] ;        /* ignore whitespace */
<QRELATION>\"eq\"             { BEGIN INITIAL; return yylval->nval = EQ; }
<QRELATION>\"ne\"             { BEGIN INITIAL; return yylval->nval = NE; }
<QRELATION>\"gt\"             { BEGIN INITIAL; return yylval->nval = GT; }
<QRELATION>\"ge\"             { BEGIN INITIAL; return yylval->nval = GE; }
<QRELATION>\"lt\"             { BEGIN INITIAL; return yylval->nval = LT; }
<QRELATION>\"le\"             { BEGIN INITIAL; return yylval->nval = LE; }
<QRELATION>\"[^\"]*\"         {
                                  BEGIN INITIAL;
                                  sieveerror_f(sscript,
                                               "invalid relational-match %s",
                                               yytext);
                              }

    /* imap4flags - RFC 5232 */
<INITIAL>setflag              return yylval->nval = SETFLAG;
<INITIAL>addflag              return yylval->nval = ADDFLAG;
<INITIAL>removeflag           return yylval->nval = REMOVEFLAG;
<INITIAL>hasflag              return yylval->nval = HASFLAG;
<INITIAL>:flags               return FLAGS;

    /* imapflags - draft-melnikov-sieve-imapflags-04 */
<INITIAL>mark                 return yylval->nval = MARK;
<INITIAL>unmark               return yylval->nval = UNMARK;

    /* date - RFC 5260 */
<INITIAL>date                 return DATE;
<INITIAL>:originalzone        return ORIGINALZONE;
<INITIAL>:zone                return ZONE;
<INITIAL>currentdate          return CURRENTDATE;

    /* index - RFC 5260 */
<INITIAL>:index               return INDEX;
<INITIAL>:last                return LAST;

    /* editheader - RFC 5293 */
<INITIAL>addheader            return ADDHEADER;
<INITIAL>deleteheader         return DELETEHEADER;
    /*   :index               defined in 'index' */
    /*   :last                defined in 'index' */

    /* [e]reject - RFC 5429 */
<INITIAL>reject               return yylval->nval = REJCT;
<INITIAL>ereject              return yylval->nval = EREJECT;

    /* enotify - RFC 5435 */
<INITIAL>notify_method_capability  return NOTIFYMETHODCAPABILITY;
<INITIAL>valid_notify_method  return VALIDNOTIFYMETHOD;
<INITIAL>notify               return NOTIFY;
<INITIAL>:options             return OPTIONS;
<INITIAL>:message             return MESSAGE;
<INITIAL>:encodeurl           return yylval->nval = ENCODEURL;
<INITIAL>:importance          { BEGIN QIMPORTANCE; return IMPORTANCE; }

<QIMPORTANCE>[ \t\n\r] ;      /* ignore whitespace */
<QIMPORTANCE>\"1\"            { BEGIN INITIAL; return yylval->nval = HIGH;   }
<QIMPORTANCE>\"2\"            { BEGIN INITIAL; return yylval->nval = NORMAL; }
<QIMPORTANCE>\"3\"            { BEGIN INITIAL; return yylval->nval = LOW;    }
<QIMPORTANCE>\"[^\"]*\"       {
                                  BEGIN INITIAL;
                                  sieveerror_f(sscript,
                                               "invalid importance %s", yytext);
                              }

    /* notify - draft-martin-sieve-notify-01 */
<INITIAL>denotify             return DENOTIFY;
<INITIAL>:method              return METHOD;
<INITIAL>:id                  return ID;
<INITIAL>:low                 return yylval->nval = LOW;
<INITIAL>:normal              return yylval->nval = NORMAL;
<INITIAL>:high                return yylval->nval = HIGH;

    /* ihave - RFC 5463 */
<INITIAL>ihave                return IHAVE;
<INITIAL>error                return ERROR;

    /* mailbox - RFC 5490 */
<INITIAL>mailboxexists        return MAILBOXEXISTS;
<INITIAL>:create              return CREATE;

    /* mboxmetadata - RFC 5490 */
<INITIAL>metadata             return yylval->nval = METADATA;
<INITIAL>metadataexists       return METADATAEXISTS;

    /* servermetadata - RFC 5490 */
<INITIAL>servermetadata       return yylval->nval = SERVERMETADATA;
<INITIAL>servermetadataexists return SERVERMETADATAEXISTS;

    /* redirect-deliverby - RFC 6009 */
<INITIAL>:bytimerelative      return BYTIMEREL;
<INITIAL>:bytimeabsolute      return BYTIMEABS;
<INITIAL>:bymode              return BYMODE;
<INITIAL>:bytrace             return BYTRACE;

    /* redirect-dsn - RFC 6009 */
<INITIAL>:notify              return DSNNOTIFY;
<INITIAL>:ret                 return DSNRET;

    /* include - RFC 6609 */
<INITIAL>include              return INCLUDE;
<INITIAL>:personal            return yylval->nval = PERSONAL;
<INITIAL>:global              return yylval->nval = GLOBAL;
<INITIAL>:optional            return OPTIONAL;
<INITIAL>:once                return ONCE;
<INITIAL>return               return RETURN;

    /* duplicate - RFC 7352 */
<INITIAL>duplicate            return DUPLICATE;
<INITIAL>:header              return yylval->nval = HEADER;
<INITIAL>:uniqueid            return yylval->nval = UNIQUEID;
    /*   :handle              defined in 'vacation'         */
    /*   :seconds             defined in 'vacation-seconds' */
    /*   :last                defined in 'index'            */

    /* special-use - RFC 8579 */
<INITIAL>specialuse_exists     return SPECIALUSEEXISTS;
<INITIAL>:specialuse           return SPECIALUSE;

    /* fcc - RFC 8580 */
<INITIAL>:fcc                  return FCC;

    /* draft-gondwana-sieve-mailboxid */
<INITIAL>mailboxidexists       return MAILBOXIDEXISTS;
<INITIAL>:mailboxid            return MAILBOXID;

    /* vnd.cyrus.log */
<INITIAL>log                   return LOG;

    /* vnd.cyrus.jmapquery */
<INITIAL>jmapquery             return JMAPQUERY;

    /* vnd.cyrus.snooze */
<INITIAL>snooze                return SNOOZE;
<INITIAL>:mailbox              return MAILBOX;
<INITIAL>:addflags             return ADDFLAGS;
<INITIAL>:removeflags          return REMOVEFLAGS;
<INITIAL>:weekdays             return WEEKDAYS;
<INITIAL>:tzid                 return TZID;
    /*   :create               defined in 'mailbox'     */
    /*   :mailboxid            defined in 'mailboxid'   */
    /*   :specialuse           defined in 'special-use' */

<INITIAL>"/*"([^\*]|\*[^\/])*\*?"*/" ;  /* ignore bracketed comments */
<INITIAL>#.* ;                /* ignore hash comments */
<INITIAL>[ \t\n\r] ;          /* ignore whitespace */
.                             return yytext[0];

%%

/* convert numerical string w/units to unsigned long */
static unsigned long long tonum(const char *str)
{
    char *units;
    unsigned long long val = strtoull(str, &units, 10);

    if (*units && errno != ERANGE) {
        switch (toupper(*units)) {
        case 'K': val *= (1ULL << 10); break;
        case 'M': val *= (1ULL << 20); break;
        case 'G': val *= (1ULL << 30); break;
            /* for future use */
        case 'T': val *= (1ULL << 40); break;
        case 'P': val *= (1ULL << 50); break;
        case 'E': val *= (1ULL << 60); break;
        default: break;
        }
    }

    return val;
}

/* convert unicode to sequence of UTF-8 characters */
static size_t unicode_to_utf8(unsigned char ubuf[], unsigned int code)
{
    if (code <= 0x7F) {
        ubuf[0] = code;
        return 1;
    }
    if (code <= 0x7FF) {
        ubuf[0] = 0xC0 | (code >> 6);            /* 110xxxxx */
        ubuf[1] = 0x80 | (code & 0x3F);          /* 10xxxxxx */
        return 2;
    }
    if (code < 0xE000 && code > 0xD7FF) return 0;
    if (code <= 0xFFFF) {
        ubuf[0] = 0xE0 | (code >> 12);           /* 1110xxxx */
        ubuf[1] = 0x80 | ((code >> 6) & 0x3F);   /* 10xxxxxx */
        ubuf[2] = 0x80 | (code & 0x3F);          /* 10xxxxxx */
        return 3;
    }
    if (code <= 0x10FFFF) {
        ubuf[0] = 0xF0 | (code >> 18);           /* 11110xxx */
        ubuf[1] = 0x80 | ((code >> 12) & 0x3F);  /* 10xxxxxx */
        ubuf[2] = 0x80 | ((code >> 6) & 0x3F);   /* 10xxxxxx */
        ubuf[3] = 0x80 | (code & 0x3F);          /* 10xxxxxx */
        return 4;
    }
    return 0;
}

/*
  Decode "encoded-character" strings having one of the following two forms:

  encoded-arb-octets   =  "${hex:" hex-pair-seq "}"
  hex-pair-seq         =  *blank hex-pair *(1*blank hex-pair) *blank
  hex-pair             =  1*2HEXDIG

  encoded-unicode-char =  "${unicode:" unicode-hex-seq "}"
  unicode-hex-seq      =  *blank unicode-hex *(1*blank unicode-hex) *blank
  unicode-hex          =  1*HEXDIG
   
  blank                =  WSP / CRLF
  WSP                  =  SP / HTAB 
  HEXDIG               =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
*/
static int decode_string(struct buf *sbuf)
{
    static struct buf decode_buf = BUF_INITIALIZER;
    const char *cp, *enc_start;

    for (cp = buf_cstring(sbuf); (enc_start = strstr(cp, "${")); ) {
        unsigned is_unicode = 0;
        size_t len;

        cp = enc_start + 2;

        if (!strncasecmp(cp, "hex:", 4)) {
            cp += 4;
        }
        else if (!strncasecmp(cp, "unicode:", 8)) {
            is_unicode = 1;
            cp += 8;
        }
        else {
            /* not coded */
            continue;
        }

        /* eat leading whitespace */
        while (isspace(*cp)) cp++;

        /* sanity check "encoded" data (being liberal in accepting 'a' - 'f') */
        len = strspn(cp, "0123456789ABCDEFabcdef \t\r\n");
        if (!isxdigit(*cp) || cp[len] != '}') continue;

        /* decode characters */
        buf_reset(&decode_buf);
        do {
            unsigned int ndigits, code;

            for (ndigits = 0, code = 0; isxdigit(*cp); ndigits++, cp++) {
                unsigned int digit = 
                    (*cp > '9') ? 10 + toupper(*cp) - 'A' : *cp - '0';

                code = (code << 4) + digit;
            }

            if (is_unicode) {
                unsigned char utf8[4];

                len = unicode_to_utf8(utf8, code);
                if (!len) {
                    /* invalid UTF-8 encoding - error */
                    return 0;
                }

                /* append decoded unicode char(s) to buffer */
                buf_appendmap(&decode_buf, (char *) utf8, len);
            }
            else if (ndigits > 2) {
                /* too many hex digits - treat as not coded */
                buf_reset(&decode_buf);
                cp += len + 1;
                break;
            }
            else {
                /* append decoded hex char to buffer */
                buf_putc(&decode_buf, code);
            }

            /* eat trailing whitespace */
            while (isspace(*cp)) cp++;

        } while (*cp != '}');

        if ((len = buf_len(&decode_buf))) {
            /* replace the encoded string with its decoded value */
            size_t offset = enc_start - buf_base(sbuf);

            buf_remove(sbuf, offset, cp - enc_start + 1);
            buf_insert(sbuf, offset, &decode_buf);

            /* buffer may have been reallocated - reposition our pointer */
            cp = buf_cstring(sbuf) + offset + len;
        }
    }

    return 1;
}
