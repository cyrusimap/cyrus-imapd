/* gmtoff_tm.c - Get offset from GMT from the tm_gmtoff struct member
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
    return tm->tm_gmtoff;
}
