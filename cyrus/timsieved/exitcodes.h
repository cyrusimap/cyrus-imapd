/* exitcodes.h -- wrapper around sysextis.h
 * $Id: exitcodes.h,v 1.2 2000/01/28 22:09:56 leg Exp $
 *
 *        Copyright 1998 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* Sendmail has some weird ideas on what constitutes permenant failure.  On
   more than one occasion, we have gotten burned by this moving users around
   through various inadvisable means, screwing up the mailboxes file,
   whatever.
   
   We don't want to fail out permenantly on things like EX_USAGE, EX_SOFTWARE, 
   etc., because that generally means someone was just screwing with the mail
   store and we don't want to lose mail.

   Instead, we map these EC_* codes to EX_* codes, thereby lying to Sendmail,
   since we don't derive any benefit from Sendmail knowing what the error was.
   We just want it to retry all the time anyway.  This way, should sendmail's
   behavior be different and we start deriving benefit from Sendmail knowing
   stuff, we can easily change it back.

   So other code uses the EC_* error, then we maybe change it to TEMPFAIL if
   we don't agree on whether the error should be permenant or not.
   
   Comments below stolen from sysexits.h.  */

#ifndef INCLUDED_EXITCODES_H
#define INCLUDED_EXITCODES_H

#include <sysexits.h>

#define EC_OK          0		/* successful termination */

#define EC_USAGE       EX_TEMPFAIL	/* command line usage error */
#define EC_DATAERR     EX_DATAERR	/* data format error */
#define EC_NOINPUT     EX_TEMPFAIL	/* cannot open input */
#define EC_NOUSER      EX_NOUSER	/* addressee unknown */
#define EC_NOHOST      EX_TEMPFAIL	/* host name unknown */
#define EC_UNAVAILABLE EX_TEMPFAIL	/* service unavailable */
#define EC_SOFTWARE    EX_TEMPFAIL	/* internal software error */
#define EC_OSERR       EX_TEMPFAIL	/* system error (e.g., can't fork) */
#define EC_OSFILE      EX_TEMPFAIL	/* critical OS file missing */
#define EC_CANTCREAT   EX_TEMPFAIL	/* can't create (user) output file */
#define EC_IOERR       EX_TEMPFAIL	/* input/output error */
#define EC_TEMPFAIL    EX_TEMPFAIL	/* user is invited to retry */
#define EC_PROTOCOL    EX_TEMPFAIL	/* remote error in protocol */
#define EC_NOPERM      EX_TEMPFAIL	/* permission denied */
#define EC_CONFIG      EX_TEMPFAIL	/* configuration error */

#endif /* INCLUDED_EXITCODES_H */
