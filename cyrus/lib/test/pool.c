/* This is a fairly stupid test of the memory pool stuff */

#include <stdio.h>
#include <cyrus/mpool.h>
#include <stdlib.h>

void fatal(char *s, int code) 
{
    fprintf(stderr, "%d:%s\n", code, s);
    exit(1);
}

	

int main(void) {
	int i;
	struct mpool *p;
	char *s;
	p = new_mpool(25);
	for(i=1; i<26; i++) {
		s = mpool_malloc(&p,i);
		if(s[0]) fatal("error!\n",0);

		memset(s,(char)i + 'a',i);
		printf("(%d)%d: %s\n", s, i, s);
	}
	free_mpool(p);
}
