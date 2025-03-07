%option prefix="cron" outfile="lex.yy.c"
%option noinput nounput noyywrap
%option case-insensitive

%{
#include "lib/cron.h"
#include "lib/cron-parse.h"

#include <errno.h>
#include <stdint.h>
%}

%%

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

[[:blank:]]+ { return SP; }

sun { cronlval = 0; return NAMED_WEEKDAY; }
mon { cronlval = 1; return NAMED_WEEKDAY; }
tue { cronlval = 2; return NAMED_WEEKDAY; }
wed { cronlval = 3; return NAMED_WEEKDAY; }
thu { cronlval = 4; return NAMED_WEEKDAY; }
fri { cronlval = 5; return NAMED_WEEKDAY; }
sat { cronlval = 6; return NAMED_WEEKDAY; }

jan { cronlval =  0; return NAMED_MONTH; }
feb { cronlval =  1; return NAMED_MONTH; }
mar { cronlval =  2; return NAMED_MONTH; }
apr { cronlval =  3; return NAMED_MONTH; }
may { cronlval =  4; return NAMED_MONTH; }
jun { cronlval =  5; return NAMED_MONTH; }
jul { cronlval =  6; return NAMED_MONTH; }
aug { cronlval =  7; return NAMED_MONTH; }
sep { cronlval =  8; return NAMED_MONTH; }
oct { cronlval =  9; return NAMED_MONTH; }
nov { cronlval = 10; return NAMED_MONTH; }
dec { cronlval = 11; return NAMED_MONTH; }

. { return *yytext; }
