/* lsort.c -- linked list (merge) sort
 *
 * public domain code by Ray Gardner.
 *
 * Modified by Ken Murchison to use getnext(), setnext() and call_data
 * parameters.
 */

/* $Id: lsort.c,v 1.2.4.1 2003/02/27 18:12:12 rjs3 Exp $ */

#include "lsort.h"
#include <stdlib.h>

/* merge two sorted lists */
static void *lmerge(void *p, void *q,
		    void *(*getnext)(void *),
		    void (*setnext)(void *, void *), 
		    int (*compar)(void *, void *, void *),
		    void *call_data)
{
    void *r, *m;

    /* the lowest item in p/q starts the new list */
    if (compar(p, q, call_data) < 0) {
      m = r = p;
      p = getnext(p);
    }
    else {
      m = r = q;
      q = getnext(q);
    }

    /* merge the rest of p/q */
    while (p && q) {
	if (compar(p, q, call_data) < 0) {
	    setnext(r, p);
	    r = p;
	    p = getnext(p);
	}
	else {
	    setnext(r, q);
	    r = q;
	    q = getnext(q);
	}
    }

    /* tack remainder of p/q onto the end */
    setnext(r, p ? p : q);

    return m;
}

void *lsort(void *p,
	    void *(*getnext)(void *),
	    void (*setnext)(void *, void *), 
	    int (*compar)(void *, void *, void *),
	    void *call_data)
{
    void *q, *r;

    if (p) {
	/* split list in half */
	q = p;
	for (r = getnext(q); r && (r = getnext(r)) != NULL; r = getnext(r))
	    q = getnext(q);
	r = getnext(q);
	setnext(q, NULL);

	/* sort each half recursively and merge the results */
	if (r)
	    p = lmerge(lsort(p, getnext, setnext, compar, call_data),
		       lsort(r, getnext, setnext, compar, call_data),
		       getnext, setnext, compar, call_data);
    }
    return p;
}
