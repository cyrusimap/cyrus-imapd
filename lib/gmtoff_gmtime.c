/* gmtoff_tm.c - Get offset from GMT by calling gmtime and subtracting
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <time.h>

/*
 * Returns the GMT offset of the struct tm 'tm', obtained from 'time'.
 */
int gmtoff_of(tm, time)
struct tm *tm;
time_t time;
{
    struct tm local, gmt;
    struct tm *gtm;
    long offset;

    local = *tm;
    gtm = gmtime(&time);
    gmt = *gtm;

    /* Assume we are never more than 24 hours away. */
    offset = gmt.tm_yday - local.tm_yday;
    if (offset > 1) {
	offset = -24;
    } else if (offset < -1) {
	offset = 24;
    } else {
	offset *= 24;
    }

    /* Scale in the hours and minutes; ignore seconds. */
    offset += gmt.tm_hour - local.tm_hour;
    offset *= 60;
    offset += gmt.tm_min - local.tm_min;

    /* Restore the data in the struct 'tm' points to */
    *tm = local;
    return offset * 60;
}
