#ifndef YYSTYPE
#define YYSTYPE int
#endif
#define	ATOM	257
#define	QTEXT	258
#define	DTEXT	259


extern YYSTYPE addrlval;

/* xxx should this be implemented somewhere? */
int addrerror(char *msg);
