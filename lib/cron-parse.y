%{
#include "lib/xmalloc.h"

#include <assert.h>
#include <stdint.h>
#include <sysexits.h>

#define BIT(n) (1 << (n))

#define CRONSTYPE uint64_t

extern int yylex(void);
extern void yyerror(const char *);
%}

%define api.prefix {cron}
%token NUM

%%

list : range;

list : list ',' range {
    $$ = $1 | $3;
};

range : '*' {
    $$ = UINT64_MAX;
};

range : NUM '-' NUM {
    $$ = 0;
    unsigned i;
    assert($1 <= $3);
    assert($1 < 64);
    assert($3 < 64);
    for (i = $1; i <= $3; i++) {
        $$ |= BIT(i);
    }
};

range : NUM { $$ = BIT($1); };

range : range '/' NUM {
    unsigned i;

    for (i = 0; i < 64; i++) {
        if ((i % $3) == 0) continue;
        $$ &= ~BIT(i);
    }
}

%%

void yyerror(const char *err)
{
    fatal(err, EX_DATAERR);
}
