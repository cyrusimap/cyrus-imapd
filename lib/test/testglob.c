#include "glob.h"
#include <stdio.h>

int main (argc, argv)
    int argc;
    char* argv[];
{
    glob *g = glob_init(argv[1], GLOB_INBOXCASE|GLOB_HIERARCHY);

    char text[1024];
    int len;
    long min;

    if (g) {
	printf("%d/%s/%s\n", g->flags, g->inbox, g->str);
	while (fgets(text, sizeof (text), stdin) != NULL) {
	    len = strlen(text) - 1;
	    text[len] = '\0';
	    min = 0;
	    while (min >= 0) {
		printf("%d\n", glob_test(g, text, len, &min));
	    }
	}
    }
}

void fatal(char *s) {
	exit(1);
}
