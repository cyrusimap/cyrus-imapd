/* lsort.h -- linked list (merge) sort
 */

/* $Id: lsort.h,v 1.2.4.1 2003/02/27 18:12:12 rjs3 Exp $ */

#ifndef INCLUDED_LSORT_H
#define INCLUDED_LSORT_H

/*
 * returns: head of the sorted list
 *
 * list: head of the linked list
 * getnext: function that returns the next node of the given node
 * setnext: function that sets the next node of the first arg to the second arg
 * compar: function that compares two nodes (first two args).  The third arg
 *   is a pointer to user data that may be used in comparing the nodes
 * call_data: pointer to user data that is passed to compar()
 */
extern void *lsort(void *list,
		   void *(*getnext)(void *),
		   void (*setnext)(void *, void *),
		   int (*compar)(void *, void *, void *), 
		   void *call_data);

#endif /* INCLUDED_LSORT_H */
