#include "../glob.h"
#include <stdio.h>

struct pattern_test {
   const char *pattern;
   int successes; /* How many matches? */
   int exacts;    /* How many EXACT matches? */
};

struct pattern_test patterns[] = {
  { "*", 9, 9 }, { "%", 9, 2 }, { "*%", 9, 2 }, { "%*", 9, 9 },
  { "test", 5, 1 }, { "test.rjs3", 4, 1 }, { "test.*%", 4, 1 },
  { "test.rjs3*", 4, 4 }, { "test.rjs3.*", 3, 3 },
  { "test.rjs3%", 4, 1 }, { "test.rjs3.%", 3, 2 },
  { "test.%.foo", 2, 1 }, { "test.*.foo", 2, 2 },
  { "test.*%.foo", 2, 2 }, { "test.%*.foo", 2, 2 },
  { "test.rjs*.foo", 2, 2 }, { "test.rjs%.foo", 2, 1 },
  { "test.*3.foo", 2, 1 }, { "test.%3.foo", 2, 1 },
  { "INBOX", 4, 1 },
  { "INBOX*", 4, 4 }, { "INBOX.foo", 2, 1 }, { "INBOX.%.foo", 1, 1 },
  { NULL, 0 }
};

const char *strings[] = {
  "test",
  "test.rjs3",
  "test.rjs3.foo",
  "test.rjs3.foo.foo",
  "test.rjs3.bar",
  "user.rjs3",
  "user.rjs3.foo",
  "user.rjs3.foo.foo",
  "user.rjs3.bar",
  NULL
};

int main (argc, argv)
    int argc;
    char* argv[];
{
    char text[1024];
    int i, j;
    int failed = 0;
    glob *g;

    for(i=0;patterns[i].pattern;i++) {
	const char *pattern = patterns[i].pattern;
	int succ = 0;
	int exact = 0;
	g = glob_init_suppress(pattern, GLOB_INBOXCASE|GLOB_HIERARCHY, "user.rjs3");
	printf("%s/%d/%s/%s\n", pattern, g->flags, g->inbox, g->str);

	for(j=0;strings[j];j++) {
	    const char *string = strings[j];
	    int len = strlen(string);
	    long min = 0;
	    int result = glob_test(g, string, len, &min);

	    if(result != -1) {
		printf("  %s: %d\n", string, result);	
		succ++;
	    }

	    if(result == len) {
		exact++;
	    }
	}

	if(succ == patterns[i].successes && exact == patterns[i].exacts) {
	    printf("PASS! (got %d successes & %d exact)\n", succ, exact);
	} else {
	    printf("FAIL! (got %d/%d successes & %d/%d exact)\n",
		succ, patterns[i].successes, exact, patterns[i].exacts);
	    failed++;
	}

	glob_free(&g);
    }

    if(!failed) {
	printf("All tests pass!\n");
    } else {
	printf("ERROR: %d tests failed!\n", failed);
    }
}

void fatal(char *s) {
	exit(1);
}
