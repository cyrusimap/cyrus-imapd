%{
#include <config.h>

#include "lib/cron.h"

#include <stdbool.h>
#include <string.h>

#define BIT(n) (UINT64_C(1) << (n))

extern int yylex(void);
extern struct yy_buffer_state *cron_scan_bytes(const char *bytes, int len);
extern void cron_delete_buffer(struct yy_buffer_state *b);

static bool range_saw_asterisk = false;
static bool range_saw_step = false;

static void yyerror(struct cron_spec *result, const char **, const char *);
%}

%define api.prefix {cron}
%define api.value.type {uint64_t}

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
    YYACCEPT;
};

minutes : list {
    if (!range_saw_asterisk && ($1 & ~CRON_ALL_MINUTES)) {
        *err = "minutes out of range";
        YYERROR;
    }
    $$ = $1 & CRON_ALL_MINUTES;
};

hours : list {
    if (!range_saw_asterisk && ($1 & ~CRON_ALL_HOURS)) {
        *err = "hours out of range";
        YYERROR;
    }
    $$ = $1 & CRON_ALL_HOURS;
};

doms : list {
    /* accept values 1-31, but set bits 0-30.
     * interpret 0 as 31, except for stepped range
     */
    if (!range_saw_step && ($1 & BIT(0)))
        $1 |= BIT(31);
    $1 >>= 1;

    if (!range_saw_asterisk && ($1 & ~CRON_ALL_DAYS_OF_MONTH)) {
        *err = "days of month out of range";
        YYERROR;
    }
    $$ = $1 & CRON_ALL_DAYS_OF_MONTH;
};

months : months_check {
    /* accept values 1-12, but set bits 0-11.
     * interpret 0 as 12, except for stepped range
     */
    if (!range_saw_step && ($1 & BIT(0)))
        $1 |= BIT(12);
    $1 >>= 1;

    if (!range_saw_asterisk && ($1 & ~CRON_ALL_MONTHS)) {
        *err = "months out of range";
        YYERROR;
    }
    $$ = $1 & CRON_ALL_MONTHS;
};

months_check : list
             | NAMED_MONTH
             ;

dows : dows_check {
    /* accept values 0-6 for sun-sat, and treat 7 as sunday too */
    if (($1 & BIT(7))) {
        $1 &= ~BIT(7);
        $1 |= BIT(0);
    }

    if (!range_saw_asterisk && ($1 & ~CRON_ALL_DAYS_OF_WEEK)) {
        *err = "days of week out of range";
        YYERROR;
    }
    $$ = $1 & CRON_ALL_DAYS_OF_WEEK;
};

dows_check : list
           | NAMED_WEEKDAY
           ;

list : range;

list : list ',' range {
    $$ = $1 | $3;
};

range : '*' {
    range_saw_asterisk = true;
    range_saw_step = false;
    $$ = UINT64_MAX;
};

range : NUM '-' NUM {
    unsigned i;

    if ($1 > 63 || $3 > 63) {
        *err = "value out of range";
        YYERROR;
    }

    if ($1 > $3) {
        *err = "range back to front";
        YYERROR;
    }

    range_saw_asterisk = false;
    range_saw_step = false;

    $$ = 0;
    for (i = $1; i <= $3; i++) {
        $$ |= BIT(i);
    }
};

range : NUM {
    range_saw_asterisk = false;
    range_saw_step = false;
    $$ = BIT($1);
};

range : range '/' NUM {
    unsigned i;

    range_saw_step = true;
    for (i = 0; i < 64; i++) {
        if ((i % $3) == 0) continue;
        $$ &= ~BIT(i);
    }
}

%%

static void yyerror(struct cron_spec *result __attribute__((unused)),
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
    struct cron_spec result = {0};
    const char *err = NULL;
    int r;

    state = cron_scan_bytes(spec, strlen(spec));
    r = cronparse(&result, &err);
    cron_delete_buffer(state);

    if (!r && presult)
        *presult = result;

    if (r && perr)
        *perr = err;

    return r ? -1 : 0;
}
