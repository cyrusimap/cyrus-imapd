/* prot.h -- stdio-like module that handles IMAP protection mechanisms
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

#ifndef INCLUDED_PROT_H
#define INCLUDED_PROT_H

#include <time.h>

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#define PROT_BUFSIZE 4096

struct protstream;

typedef void prot_readcallback_t P((struct protstream *s, void *rock));

struct protstream {
    unsigned char buf[PROT_BUFSIZE+4];
    unsigned char *ptr;
    int cnt;
    unsigned char *leftptr;
    unsigned char leftcnt;
    int fd;
    int write;
    int logfd;
    time_t *log_timeptr;
    const char *(*func)();
    void *state;
    int maxplain;
    const char *error;
    int eof;
    int read_timeout;
    struct protstream *flushonread;
    prot_readcallback_t *readcallback_proc;
    void *readcallback_rock;
};

#define prot_getc(s) ((s)->cnt-- > 0 ? (int)*(s)->ptr++ : prot_fill(s))
#define prot_ungetc(c, s) ((s)->cnt++, (*--(s)->ptr = (c)))
#define prot_putc(c, s) ((*(s)->ptr++ = (c)), --(s)->cnt == 0 ? prot_flush(s) : 0)

extern struct protstream *prot_new P((int fd, int write));
extern int prot_free P((struct protstream *s));
extern int prot_setlog P((struct protstream *s, int fd));
extern int prot_setlogtime P((struct protstream *s, time_t *ptr));
extern int prot_setfunc P((struct protstream *s,
			   const char *(*func)(), void *state, int maxplain));
extern int prot_settimeout P((struct protstream *s, int timeout));
extern int prot_setflushonread P((struct protstream *s,
				  struct protstream *flushs));
extern int prot_setreadcallback P((struct protstream *s,
				   prot_readcallback_t *proc, void *rock));
extern const char *prot_error P((struct protstream *s));
extern int prot_rewind P((struct protstream *s));
extern int prot_fill P((struct protstream *s));
extern int prot_flush P((struct protstream *s));
extern int prot_write P((struct protstream *s, const char *buf, unsigned len));
#ifdef __STDC__
extern int prot_printf(struct protstream *, const char *, ...);
#endif
extern int prot_read P((struct protstream *s, char *buf, unsigned size));
extern char *prot_fgets P((char *buf, unsigned size, struct protstream *s));

#endif /* INCLUDED_PROT_H */
