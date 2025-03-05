%option prefix="cron" outfile="lex.yy.c"
%option noinput nounput noyywrap

%{
#include "lib/cron-parse.h"

#include <errno.h>
#include <stdint.h>
%}

%%

 /* XXX named months/days of week */

[[:digit:]]+ {
    unsigned long u;

    errno = 0;
    u = strtoul(yytext, NULL, 10);

    if (errno) {
        /* XXX ?? */
    }

    cronlval = u;
    return NUM;
}

. { return *yytext; }
