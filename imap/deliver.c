/*
 * Program to deliver mail to a folder
 */

#include <stdio.h>
#include <sysexits.h>

#include <acl.h>
#include "folder.h"

extern int optind;
extern char *optarg;

main(argc, argv)
{
    int opt;
    char *dir = "/usr/user/cyrus/test";
    int touser = 0;

    while ((opt = getopt(argc, argv, "df:r:")) != EOF) {
	switch(opt) {
	case 'd':
	    touser = 1;
	    break;

	case 'r':
	case 'f':
	    /* Ignore -- /bin/mail compatibility flags */
	    break;

	default:
	    usage();
	}
    }
    /* XXX handle changing "dir" */
    /* XXX handle multiple users & multiple bboards -- copy to temp file */
    deliver(dir);
}

usage()
{
    fprintf(stderr, "usage: deliver [-r ignored] [-d ignored] [-d] user\n");
    exit(EX_USAGE);
}

deliver(path)
char *path;
{
    int r;
    struct folder folder;
    
    r = append_setup(&folder, path, FOLDER_FORMAT_NORMAL, ACL_POST, 0);
    if (r) exit(1);
    
    r = append_fromstream(&folder, stdin);
    exit(r);
}
