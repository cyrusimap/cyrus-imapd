#include <stdio.h>
#include <assert.h>
#include "acl.h"
#include "folder.h"
#include "message.h"

int append_setup(folder, path, format, aclcheck, quotacheck)
struct folder *folder;
char *path;
int format;
long aclcheck;
long quotacheck;
{
    int r;

    r = folder_open_header(path, folder);
    if (r) return r;

    r = folder_lock_header(folder);
    if (r) return r;

    if ((folder->myacl & aclcheck) != aclcheck) {
	return 1;		/* Permission denied */
    }

    r = folder_open_index(folder);
    if (r) return r;

    if (folder->format != format) {
	return 1;		/* XXX wrong folder format */
    }

    r = folder_lock_index(folder);
    if (r) return r;

    r = folder_lock_quota(folder);
    if (r) return r;

    if (folder->quota_limit >= 0 &&
	folder->quota_used + quotacheck > folder->quota_limit * QUOTA_UNITS) {
	return 1;		/* XXX over quota */
    }

    return 0;
}

int append_fromstream(folder, messagefile)
struct folder *folder;
FILE *messagefile;
{
    struct index_record message_index;
    static struct index_record zero_index;
    char fname[MAX_FOLDER_PATH];
    FILE *destfile;
    int r;

    assert(folder->format == FOLDER_FORMAT_NORMAL);

    message_index = zero_index;
    message_index.uid = folder->last_uid + 1;
    message_index.last_updated = message_index.internaldate = time(0);
    if (message_index.internaldate <= folder->last_internaldate) {
	message_index.internaldate = folder->last_internaldate + 1; /* XXX needed? */
    }

    strcpy(fname, folder->path);
    strcat(fname, "/");
    strcat(fname, message_fname(folder, message_index.uid));
    destfile = fopen(fname, "w+");
    if (!destfile) {
	return 1;		/* XXX can't write file */
    }

    r = message_copy_stream(messagefile, destfile);
    if (!r) r = message_parse(destfile, folder, &message_index);
    fclose(destfile);
    if (r) {
	unlink(fname);
	return r;
    }

    r = folder_append_index(folder, &message_index, 1);
    if (r) {
	unlink(fname);
	/* XXX leak cache entry */
	return r;
    }
    
    /* XXX move above folder_append_index? */
    folder->last_uid = message_index.uid;
    folder->last_internaldate = message_index.internaldate;
    folder->quota_folder_used += message_index.size;

    r = folder_write_index_header(folder);
    if (r) {
	abort();		/* XXX in big trouble */
    }
    
    folder->quota_used += message_index.size;
    r = folder_write_quota(folder);
    if (r) {
	abort();		/* XXX in big trouble */
    }
    
    return 0;
}
