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

sun { cronlval = UINT64_C(1) << 0; return NAMED_WEEKDAY; }
mon { cronlval = UINT64_C(1) << 1; return NAMED_WEEKDAY; }
tue { cronlval = UINT64_C(1) << 2; return NAMED_WEEKDAY; }
wed { cronlval = UINT64_C(1) << 3; return NAMED_WEEKDAY; }
thu { cronlval = UINT64_C(1) << 4; return NAMED_WEEKDAY; }
fri { cronlval = UINT64_C(1) << 5; return NAMED_WEEKDAY; }
sat { cronlval = UINT64_C(1) << 6; return NAMED_WEEKDAY; }

jan { cronlval = UINT64_C(1) <<  1; return NAMED_MONTH; }
feb { cronlval = UINT64_C(1) <<  2; return NAMED_MONTH; }
mar { cronlval = UINT64_C(1) <<  3; return NAMED_MONTH; }
apr { cronlval = UINT64_C(1) <<  4; return NAMED_MONTH; }
may { cronlval = UINT64_C(1) <<  5; return NAMED_MONTH; }
jun { cronlval = UINT64_C(1) <<  6; return NAMED_MONTH; }
jul { cronlval = UINT64_C(1) <<  7; return NAMED_MONTH; }
aug { cronlval = UINT64_C(1) <<  8; return NAMED_MONTH; }
sep { cronlval = UINT64_C(1) <<  9; return NAMED_MONTH; }
oct { cronlval = UINT64_C(1) << 10; return NAMED_MONTH; }
nov { cronlval = UINT64_C(1) << 11; return NAMED_MONTH; }
dec { cronlval = UINT64_C(1) << 12; return NAMED_MONTH; }

. { return *yytext; }
