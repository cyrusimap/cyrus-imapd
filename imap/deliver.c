#include <stdio.h>
#include "folder.h"
#include "acl.h"

main(argc, argv)
{
    int r;
    struct folder folder;

    r = append_setup(&folder, "/usr/user/cyrus/test", FOLDER_FORMAT_NORMAL,
		     ACL_POST, 0);
    if (r) exit(1);
    
    r = append_fromstream(&folder, stdin);
    exit(r);
}
