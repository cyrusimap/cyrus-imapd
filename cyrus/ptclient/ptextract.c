/*
 */

#include <sys/types.h>
#include <krb.h>
#include <sysexits.h>

#include "auth.h"
#include "auth_krb_pts.h"

/* from auth_krb_pts.c */
struct auth_state {
    char userid[PR_MAXNAMELEN];
    char name[PR_MAXNAMELEN];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    int ngroups;
    char (*groups)[PR_MAXNAMELEN];
};

int main(int argc, char* argv[]) {
    struct auth_state* auth_state;
    char* user = 0, *cacheid = 0;
    int i;
    
    if (argv[1] && *argv[1]) {
	user = argv[1];
	if (argv[2] && *argv[2]) cacheid = argv[2];
    }

    if (! user || ! cacheid) {
	fatal("Not enough arguments.\n", EX_CONFIG);
    }
    
    printf("extracting record...\n");

    auth_state = auth_newstate(user, cacheid);

    if (auth_state) {
	for (i = 0; i < auth_state->ngroups; i++) {
	    printf("group %s\n", auth_state->groups[i]);
	}
    } else {
	printf("Extracting failed.\n");
    }
}

void fatal(char* message, int rc) {
    fprintf(stderr, "fatal error: %s\n", message);
    exit(rc);
}
