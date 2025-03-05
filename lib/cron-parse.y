%{
#include <config.h>

#include "lib/xmalloc.h" /* XXX only for fatal */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sysexits.h>

#define BIT(n) (UINT64_C(1) << (n))

#define CRONSTYPE uint64_t

static void yyerror(uint64_t *, const char *);

extern int yylex(void);
extern struct yy_buffer_state *cron_scan_bytes(const char *bytes, int len);
extern void cron_delete_buffer(struct yy_buffer_state *b);
%}

%define api.prefix {cron}
%parse-param { uint64_t *result }
%token NUM

%%

start : datetime YYEOF {
    *result = $$ = $1;
};

datetime : list; /* XXX also accept month, weekday names here */

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

static void yyerror(uint64_t *result, const char *err)
{
    fprintf(stderr, "%s: result=<%" PRIu64 "> err=<%s>\n",
                    __func__, *result, err);
}

EXPORTED int cron_parse_datetime(const char *datetime, unsigned max_value,
                                 uint64_t *presult)
{
    struct yy_buffer_state *state;
    uint64_t mask, result;
    int r;

    state = cron_scan_bytes(datetime, strlen(datetime));
    r = cronparse(&result);
    cron_delete_buffer(state);

    if (max_value) {
        /* XXX 64? 63? */
        assert(max_value < 64);
        mask = BIT(max_value) - 1;
        result &= mask;
    }

    if (!r && presult)
        *presult = result;

    return r;
}
