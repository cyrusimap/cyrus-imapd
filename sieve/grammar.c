/*
 * grammar.c
 *
 *  Created on: Nov 6, 2014
 *      Author: James Cassell
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "grammar.h"
#include "xmalloc.h"


HIDDEN int is_identifier(char *s)
{
    /* identifier         = (ALPHA / "_") *(ALPHA / DIGIT / "_") */

    int i = 0;
    while (s && s[i]) {
        if (s[i] == '_' || (s[i] >= 'a' && s[i] <= 'z')
            || (s[i] >= 'A' && s[i] <= 'Z')
            || (i && (s[i] >= '0' && s[i] <= '9'))) {
            i++;
        } else {
            return 0;
        }
    }
    return 1;
}

static int is_number(char *s)
{
    char *tail;

    if (s && *s && (strtol(s, &tail, 10) || !*tail) && !*tail) {
        return 1;
    }
    return 0;
}

/* TODO: implement parse_string() with a proper yacc/bison lexer/parser */
HIDDEN char *parse_string(const char *s, variable_list_t *vars)
{
    strarray_t stringparts = STRARRAY_INITIALIZER;
    variable_list_t *variable = NULL;
    char *test_str;
    int is_match_var;
    int match_var;
    int fail = 0;

    /* protect against being called with no string - this is possible in some places */
    if (!s) return NULL;

    /*
     * variable-ref        =  "${" [namespace] variable-name "}"
     * namespace           =  identifier "." *sub-namespace
     * sub-namespace       =  variable-name "."
     * variable-name       =  num-variable / identifier
     * num-variable        =  1*DIGIT
     * identifier          =  (ALPHA / "_") *(ALPHA / DIGIT / "_")
     */
    strarray_append(&stringparts, s);
    test_str = stringparts.data[stringparts.count-1];
    while (test_str && *test_str) {
        char *variable_ref_begin, *variable_ref_end;
        /* find the beginning of a variable-ref */
        while (*test_str && *(test_str+1)
               && !('$' == *test_str && '{' == *(test_str+1))) {
            test_str++;
        }
        /* if we've reached the end of the string, we're done */
        if (!(*test_str && *(test_str+1))) {
            break;
        }
        /* save the beginning of the variable-ref */
        variable_ref_begin = variable_ref_end = test_str;
        test_str += 2;
        variable_ref_end += 2;
        /* find the end of the variable-ref */
        while (*variable_ref_end && !('}' == *variable_ref_end)) {
            variable_ref_end++;
        }
        /* if we've reached the end of the string, we're done */
        if (!*variable_ref_end) {
            break;
        }
        /* create a null-terminated string for comparison */
        *variable_ref_end = '\0';
        /* check if the string is a number */
        is_match_var = is_number(test_str);
        /* if we've found a valid variable, add its value to stringparts */
        if (is_identifier(test_str) || is_match_var) {
            /* capture the match_var variable number */
            match_var = strtol(test_str, NULL, 10);
            /* NULL-terminate the previous stringpart */
            *variable_ref_begin = '\0';
            /* attempt to find the variable */
            if (is_match_var) {
                variable = varlist_select(vars, VL_MATCH_VARS);
                if (match_var >= variable->var->count) {
                    variable = NULL;
                }
            } else {
                variable = varlist_select(vars, test_str);
            }
            /* add the value of the requested variable to stringparts if
             * the variable is found
             */
            if (variable) {
                char *temp;
                if (is_match_var) {
                    temp = xstrdup(variable->var->data[match_var]);
                } else {
                    temp = strarray_join(variable->var, " ");
	       	}
                if (temp) {
                    strarray_append(&stringparts, temp);
                    free (temp);
	       	}
            }
            /* continue search for variable-ref's after the current one */
            test_str = variable_ref_end + 1;
            /* add the remainder of the original string to stringparts */
            if (*test_str) {
                strarray_append(&stringparts, test_str);
                test_str = stringparts.data[stringparts.count-1];
            }
        } else {
            /* first check if this is a namespace, which we don't yet support.
               RFC 5229, Sieve: Variables Extension, Section 3. Interpretation of Strings:
               References to namespaces without a prior require statement for the
               relevant extension MUST cause an error.
            */
            {
                char *dot;
                if ((dot = strchr(test_str, '.'))) {
                    *dot = '\0';
                    if (is_identifier(test_str)) {
                        fail = 1;
                    } else {
                        *dot = '.';
                    }
                }
            }
            /* if we haven't found a valid variable, restore the overwritten
             * character
             */
            *variable_ref_end = '}';
            /* continue the search after the non-valid identifier */
            test_str = variable_ref_begin + 2;
        }
    }
    if ((test_str = strarray_join(&stringparts, ""))) {
        strarray_appendm(varlist_select(vars, VL_PARSED_STRINGS)->var, test_str);
    } else {
        test_str = xstrdup("");
        strarray_appendm(varlist_select(vars, VL_PARSED_STRINGS)->var, test_str);
    }
    strarray_fini(&stringparts);

    /* TODO: test this in the sieve parser, not at script runtime */
    if (0 && fail) {
        free(test_str);
        test_str = NULL;
    }

    return test_str;
}
