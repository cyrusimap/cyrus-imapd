/* parseaddr.h -- RFC 822 address parser
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

#ifndef INCLUDED_PARSEADDR_H
#define INCLUDED_PARSEADDR_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

struct address {
    char *name;
    char *route;
    char *mailbox;
    char *domain;
    struct address *next;
    char *freeme;		/* If non-nil, free */
};

extern void parseaddr_list P((const char *s, struct address **addrp));
extern void parseaddr_free P((struct address *addr));


#endif /* INCLUDED_PARSEADDR_H */
