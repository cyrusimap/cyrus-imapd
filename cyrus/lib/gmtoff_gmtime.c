/* gmtoff_tm.c - Get offset from GMT by calling gmtime and subtracting
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
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
    offset = local.tm_yday - gmt.tm_yday;
    if (offset > 1) {
	offset = -24;
    } else if (offset < -1) {
	offset = 24;
    } else {
	offset *= 24;
    }

    /* Scale in the hours and minutes; ignore seconds. */
    offset += local.tm_hour - gmt.tm_hour;
    offset *= 60;
    offset += local.tm_min - gmt.tm_min;

    /* Restore the data in the struct 'tm' points to */
    *tm = local;
    return offset * 60;
}
