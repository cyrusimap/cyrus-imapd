/*
 * Routines for appending messages to a folder
 */

#include <stdio.h>
#include <assert.h>

#include <acl.h>
#include "folder.h"
#include "message.h"

/*
 * Open a folder for appending
 *
 * Arguments:
 *	path	   - pathname of folder directory
 *	format     - folder must be of this format
 *	aclcheck   - user must have these rights on folder ACL
 *	quotacheck - folder must have this much quota left
 *		     (-1 means don't care about quota)
 *
 * On success, the struct pointed to by 'folder' is set up.
 *
 */
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

    if ((folder->my_acl & aclcheck) != aclcheck) {
	folder_close(folder);
	return 1;		/* XXX Permission denied */
    }

    r = folder_lock_header(folder);
    if (r) {
	folder_close(folder);
	return r;
    }

    /* In case it changed */
    if ((folder->my_acl & aclcheck) != aclcheck) {
	folder_close(folder);
	return 1;		/* XXX Permission denied */
    }

    r = folder_open_index(folder);
    if (r) {
	folder_close(folder);
	return r;
    }

    if (folder->format != format) {
	folder_close(folder);
	return 1;		/* XXX wrong folder format */
    }

    r = folder_lock_index(folder);
    if (r) {
	folder_close(folder);
	return r;
    }

    r = folder_lock_quota(folder);
    if (r) {
	folder_close(folder);
	return r;
    }

    if (folder->quota_limit >= 0 && quotacheck >= 0  &&
	folder->quota_used + quotacheck > folder->quota_limit * QUOTA_UNITS) {
	return 1;		/* XXX over quota */
    }

    return 0;
}

/*
 * Append to 'folder' from the stdio stream 'messagefile'
 * 'folder' must have been opened with append_setup()
 */
int append_fromstream(folder, messagefile)
struct folder *folder;
FILE *messagefile;
{
    struct index_record message_index;
    static struct index_record zero_index;
    char fname[MAX_FOLDER_PATH];
    FILE *destfile;
    int r;
    long last_cacheoffset;

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

    fseek(folder->cache, 0L, 2);
    last_cacheoffset = ftell(folder->cache);

    r = message_copy_stream(messagefile, destfile);
    if (!r) r = message_parse(destfile, folder, &message_index);
    fclose(destfile);
    if (r) {
	unlink(fname);
	return r;
    }

    folder->last_uid = message_index.uid;
    folder->last_internaldate = message_index.internaldate;
    folder->quota_folder_used += message_index.size;

    r = folder_write_index_header(folder);
    if (r) {
	unlink(fname);
	ftruncate(fileno(folder->cache), last_cacheoffset);
	return r;
    }

    r = folder_append_index(folder, &message_index, 1);
    if (r) {
	unlink(fname);
	ftruncate(fileno(folder->cache), last_cacheoffset);

	/* Try to back out index header changes */
	folder->last_uid--;
	folder->quota_folder_used -= message_index.size;
	(void) folder_write_index_header(folder);

	return r;
    }
    
    
    folder->quota_used += message_index.size;
    r = folder_write_quota(folder);
    if (r) {
	/* XXX syslog it */
    }
    
    return 0;
}
