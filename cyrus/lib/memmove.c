/* memmove.c -- replacement memmove() routine
 * Only handles overlapping strings when moving data upwards
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
 */

void *memmove(s, ct, n)
void *s;
const void *ct;
unsigned int n;
{
    char *c_s = s;
    const char *c_ct = ct;

    if (c_s <= c_ct) {
	while (n--) {
	    *c_s++ = *c_ct++;
	}
    }
    else {
	while (n--) {
	    c_s[n] = c_ct[n];
	}
    }

    return s;
}

