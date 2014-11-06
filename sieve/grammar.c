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


EXPORTED int is_identifier(char *s)
{
    /* identifier         = (ALPHA / "_") *(ALPHA / DIGIT / "_") */

    int i = 0;
    while (s && s[i]) {
        if (s[i] == '_' || (s[i] >= 'a' && s[i] <= 'z')
            || (s[i] >= 'A' && s[i] <= 'A')
            || (i && (s[i] >= '0' && s[i] <= '9'))) {
            i++;
        } else {
            return 0;
        }
    }
    return 1;
}

/* TODO: implement parse_string() with a proper yacc/bison lexer/parser */
EXPORTED char *parse_string(const char *s, variable_list_t *vars)
{
    /*
     * variable-ref        =  "${" [namespace] variable-name "}"
     * namespace           =  identifier "." *sub-namespace
     * sub-namespace       =  variable-name "."
     * variable-name       =  num-variable / identifier
     * num-variable        =  1*DIGIT
     * identifier          =  (ALPHA / "_") *(ALPHA / DIGIT / "_")
     */
    strarray_t stringparts = STRARRAY_INITIALIZER;
    variable_list_t *variable = NULL;
    char *test_str;
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
        /* if we've found a valid variable, add its value to stringparts */
        if (is_identifier(test_str)) {
            /* NULL-terminate the previous stringpart */
            *variable_ref_begin = '\0';
            /* add the value of the requested variable to stringparts if
             * the variable is found
             */
            if ((variable = varlist_select(vars, test_str))) {
       		char *temp;
	       	temp = strarray_join(variable->var, " ");
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

    return test_str;
}
