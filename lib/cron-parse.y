%{
#include <config.h>

#include "lib/cron.h"

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sysexits.h>

#define BIT(n) (UINT64_C(1) << (n))

#define VALID_MINUTES       (BIT(60) - 1)
#define VALID_HOURS         (BIT(24) - 1)
#define VALID_DAYS_OF_MONTH (BIT(31) - 1)
#define VALID_MONTHS        (BIT(12) - 1)
#define VALID_DAYS_OF_WEEK  (BIT(7) - 1)

/* XXX this needs to be a union of either the final struct cron_spec
 * XXX or an intermediate value so that yyerror can accept a sane
 * XXX first argument (which we won't use anyway)
 */
#define CRONSTYPE uint64_t

static void yyerror(uint64_t *, const char **, const char *);

extern int yylex(void);
extern struct yy_buffer_state *cron_scan_bytes(const char *bytes, int len);
extern void cron_delete_buffer(struct yy_buffer_state *b);
%}

%define api.prefix {cron}

/* XXX don't pass result here, let the main rule set the struct field.
 * XXX will need to define the types for each token and non-terminal
 */
%parse-param { struct cron_spec *result } { const char **err }

%token NUM
%token SP
%token NAMED_MONTH
%token NAMED_WEEKDAY

%%

spec : minutes SP hours SP doms SP months SP dows YYEOF {
    result->minutes = $1;
    result->hours = $3;
    result->days_of_month = $5;
    result->months = $7;
    result->days_of_week = $9;
    *err = NULL;
};

minutes : list {
    if (($1 & ~VALID_MINUTES)) {
        *err = "minutes out of range";
        YYERROR;
    }
    $$ = $1 & VALID_MINUTES;
};

hours : list {
    if (($1 & ~VALID_HOURS)) {
        *err = "hours out of range";
        YYERROR;
    }
    $$ = $1 & VALID_HOURS;
};

doms : list {
    if (($1 & ~VALID_DAYS_OF_MONTH)) {
        *err = "days of month out of range";
        YYERROR;
    }
    $$ = $1 & VALID_DAYS_OF_MONTH;
};

months : months_check {
    if (($1 & ~VALID_MONTHS)) {
        *err = "months out of range";
        YYERROR;
    }
    $$ = $1 & VALID_MONTHS;
};

months_check : list
             | NAMED_MONTH
             ;

dows : dows_check {
    if (($1 & ~VALID_DAYS_OF_WEEK)) {
        *err = "days of week out of range";
        YYERROR;
    }
    $$ = $1 & VALID_DAYS_OF_WEEK;
};

dows_check : list
           | NAMED_WEEKDAY
           ;

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

static void yyerror(uint64_t *result __attribute__((unused)),
                    const char **perr,
                    const char *err)
{
    if (perr) *perr = err;
}

EXPORTED int cron_parse_spec(const char *spec,
                             struct cron_spec *presult,
                             const char **perr)
{
    struct yy_buffer_state *state;
    struct cron_spec result;
    const char *err = NULL;
    int r;

    state = cron_scan_bytes(spec, strlen(spec));
    r = cronparse(&result, &err);
    cron_delete_buffer(state);

    if (!r && presult)
        *presult = result;

    if (r && perr)
        *perr = err;

    return r;
}
