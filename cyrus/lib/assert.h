/* assert.h -- assert() macro that can exit cleanly
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

#ifndef INCLUDED_ASSERT_H
#define INCLUDED_ASSERT_H

#ifdef __STDC__
#define assert(ex)	{if (!(ex))assertionfailed(__FILE__, __LINE__, #ex);}
int assertionfailed(const char *file, int line, const char *expr);
#else
#define assert(ex)	{if (!(ex))assertionfailed(__FILE__, __LINE__, (char*)0);}
#endif

#endif /* INCLUDED_ASSERT_H */
