/* Definitions internal to charset.c and chartable.c */

/*
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */

/* $Id: chartable.h,v 1.3.4.1 2002/12/27 14:00:34 ken3 Exp $ */

/* note that these are all uppercase letters. since the translation
   tables canonicalize to lower case letters, we never see these bytes
   in the output UTF-8 and they're safely used as control codes to the
   character decoder. */

/* note that currently we never return a character that is represented
 * by more than 3 octets in UTF-8, since we only deal with characters
 * in UCS-2. this means that 11110xxx, 111110xx, and 1111110x never
 * appear in our outgoing tables, and could be used instead of the following.
 */

#define XLT 'N'			/* Long translation */
#define U7F 'O'			/* UTF-7 first base64 character */
#define U7N 'P'			/* UTF-7 subsquent base64 character */
#define U83 'Q'			/* UTF-8 3-char sequence */
#define U83_2 'R'		/* second char of same */
#define U83_3 'S'		/* third char of same */
#define JSR 'T'
#define JMP 'U'
#define RET 'V'
#define END 'W'

struct charset {
    char *name;
    const unsigned char (*table)[256][4];
};


