#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "acl.h"
#include "folder.h"
#include "xmalloc.h"

folder_open_header(path, folder)
char *path;
struct folder *folder;
{
    char fnamebuf[MAX_FOLDER_PATH];
    int r;
    static struct folder zerofolder;

    *folder = zerofolder;

    strcpy(fnamebuf, path);
    strcat(fnamebuf, FNAME_HEADER);
    folder->header = fopen(fnamebuf, "r+");
    
    if (!folder->header) {
	return 1;		/* XXX can't open folder */
    }

    folder->path = strsave(path);

    r = folder_read_header(folder);
    if (r) {
	folder_close(folder);
	return r;
    }

    return 0;
}

#define MAXTRIES 60

folder_open_index(folder)
struct folder *folder;
{
    char fnamebuf[MAX_FOLDER_PATH];
    bit32 index_gen, cache_gen;
    int tries = 0;

    do {
	strcpy(fnamebuf, folder->path);
	strcat(fnamebuf, FNAME_INDEX);
	folder->index = fopen(fnamebuf, "r+");
    
	strcpy(fnamebuf, folder->path);
	strcat(fnamebuf, FNAME_CACHE);
	folder->cache = fopen(fnamebuf, "r+");
    
	if (!folder->index || !folder->cache) {
	    return 1;		/* XXX can't open */
	}

	if (fread((char *)&index_gen, sizeof(index_gen), 1,
		  folder->index) != 1 ||
	    fread((char *)&cache_gen, sizeof(cache_gen), 1,
		  folder->cache) != 1) {
	    return 1;		/* XXX bad format */
	}
	
	if (index_gen != cache_gen) {
	    fclose(folder->index);
	    fclose(folder->cache);
	    sleep(1);
	}
    } while (index_gen != cache_gen && tries++ < MAXTRIES);

    if (index_gen != cache_gen) {
	folder->index = folder->cache = NULL;
	return 1;		/* XXX bad format/out of synch */
    }
    folder->generation_no = index_gen;

    return folder_read_index_header(folder);
}

folder_close(folder)
struct folder *folder;
{
    static struct folder zerofolder;
    int flag;

    fclose(folder->header);
    if (folder->index) fclose(folder->index);
    if (folder->cache) fclose(folder->cache);
    if (folder->seen) fclose(folder->seen);
    if (folder->quota) fclose(folder->quota);
    free(folder->path);
    if (folder->quota_path) free(folder->quota_path);

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (folder->flagname[flag]) free(folder->flagname[flag]);
    }

    if (folder->acl) free(folder->acl);
    
    *folder = zerofolder;
    return 0;
}

folder_read_header(folder)
struct folder *folder;
{
    char buf[4096];
    int flag;
    char *name, *p;
    struct stat sbuf;
    int aclbufsize, n;

    /* Check magic number */
    n = fread(buf, 1, strlen(FOLDER_HEADER_MAGIC), folder->header);
    buf[n] = '\0';
    if (n != strlen(FOLDER_HEADER_MAGIC) || strcmp(buf, FOLDER_HEADER_MAGIC)) {
	return 1;		/* XXX bad magic no */
    }

    fstat(fileno(folder->header), &sbuf);
    folder->header_mtime = sbuf.st_mtime;

    if (!fgets(buf, sizeof(buf), folder->header)) {
	return 1;		/* XXX bad format */
    }
    buf[strlen(buf)-1] = '\0';
    if (folder->quota_path) {
	if (strcmp(folder->quota_path, buf) != 0) {
	    assert(folder->quota_lock_count != 0);
	    if (folder->quota) fclose(folder->quota);
	    folder->quota = NULL;
	}
	free(folder->quota_path);
    }
    folder->quota_path = strsave(buf);

    if (!fgets(buf, sizeof(buf), folder->header)) {
	return 1;		/* XXX bad format */
    }
    buf[strlen(buf)-1] = '\0';
    name = buf;
    flag = 0;
    while (name && flag < MAX_USER_FLAGS) {
	p = strchr(name, ' ');
	if (p) *p++ = '\0';
	if (folder->flagname[flag]) free(folder->flagname[flag]);
	folder->flagname[flag++] = *name ? strsave(name) : NULL;
	name = p;
    }
    while (flag < MAX_USER_FLAGS) {
	if (folder->flagname[flag]) free(folder->flagname[flag]);
	folder->flagname[flag++] = NULL;
    }

    if (folder->acl) free(folder->acl);
    aclbufsize = 3 /* 128 */;
    p = folder->acl = xmalloc(aclbufsize);
    while (fgets(p, aclbufsize - (p - folder->acl), folder->header)) {
	if (*p == '\n' && (p == folder->acl || p[-1] = '\n')) {
	    *p = '\0';
	    break;
	}
	p += strlen(p);
	if (p - folder->acl + 1 >= aclbufsize) {
	    n = p - folder->acl;
	    aclbufsize *= 2;
	    folder->acl = xrealloc(folder->acl, aclbufsize);
	    p = folder->acl + n;
	}
    }
    folder->myacl = acl_myacl(folder->acl);

    return 0;
}

folder_read_index_header(folder)
struct folder *folder;
{
    struct stat sbuf;
    char buf[1024];
    int n;

    fstat(fileno(folder->index), &sbuf);
    folder->index_mtime = sbuf.st_mtime;
    folder->index_blksize = sbuf.st_blksize;

    rewind(folder->index);
    n = fread(buf, sizeof(bit32), 7, folder->index);
    if (n != 7) {
	return 1;		/* XXX short file */
    }

    folder->format = ntohl(*((bit32 *)(buf+4)));
    folder->start_offset = ntohl(*((bit32 *)(buf+8)));
    folder->record_size = ntohl(*((bit32 *)(buf+12)));
    folder->last_internaldate = ntohl(*((bit32 *)(buf+16)));
    folder->last_uid = ntohl(*((bit32 *)(buf+20)));
    folder->quota_folder_used = ntohl(*((bit32 *)(buf+24)));

    return 0;
}

folder_read_quota(folder)
struct folder *folder;
{
    char buf[4096];

    assert(folder->quota_path);

    if (!folder->quota) {
	folder->quota = fopen(folder->quota_path, "r+");
	if (!folder->quota) return 1; /* XXX no quota file */
    }
    
    rewind(folder->quota);
    if (!fgets(buf, sizeof(buf), folder->quota)) {
	return 1;		/* XXX bad format */
    }
    folder->quota_used = atol(buf);
    if (!fgets(buf, sizeof(buf), folder->quota)) {
	return 1;		/* XXX bad format */
    }
    folder->quota_limit = atoi(buf);

    return 0;
}

folder_lock_header(folder)
struct folder *folder;
{
    char fnamebuf[MAX_FOLDER_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (folder->header_lock_count++) return 0;

    assert(folder->index_lock_count == 0);
    assert(folder->seen_lock_count == 0);
    assert(folder->quota_lock_count == 0);

    strcpy(fnamebuf, folder->path);
    strcat(fnamebuf, FNAME_HEADER);

    for (;;) {
	r = flock(fileno(folder->header), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    folder->header_lock_count--;
	    return 1;		/* XXX os error */
	}

	fstat(fileno(folder->header), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    folder_unlock_header(folder);
	    return 1;		/* XXX os error */
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(folder->header);
	folder->header = fopen(fnamebuf, "r+");
	if (!folder->header) {
	    return 1;		/* XXX where it go? */
	}
    }

    if (sbuffd.st_mtime != folder->header_mtime) {
	rewind(folder->header);
	r = folder_read_header(folder);
	if (r) {
	    folder_unlock_header(folder);
	    return r;		/* XXX read screwup */
	}
    }

    return 0;
}

folder_lock_index(folder)
struct folder *folder;
{
    char fnamebuf[MAX_FOLDER_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (folder->index_lock_count++) return 0;

    assert(folder->seen_lock_count == 0);
    assert(folder->quota_lock_count == 0);

    strcpy(fnamebuf, folder->path);
    strcat(fnamebuf, FNAME_INDEX);

    for (;;) {
	r = flock(fileno(folder->index), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    folder->index_lock_count--;
	    return 1;		/* XXX os error */
	}

	fstat(fileno(folder->index), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    folder_unlock_index(folder);
	    return 1;		/* XXX os error */
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(folder->index);
	fclose(folder->cache);
	if (r = folder_open_index(folder)) {
	    return 1;		/* XXX where it go? */
	}
    }

    if (sbuffd.st_mtime != folder->index_mtime) {
	rewind(folder->index);
	r = folder_read_index_header(folder);
	if (r) {
	    folder_unlock_index(folder);
	    return r;		/* XXX read screwup */
	}
    }

    return 0;
}

folder_lock_quota(folder)
struct folder *folder;
{
    struct stat sbuffd, sbuffile;
    int r;

    assert(folder->header_lock_count != 0);

    if (folder->quota_lock_count++) return 0;

    if (!folder->quota) {
	folder->quota = fopen(folder->quota_path, "r+");
	if (!folder->quota) return 1; /* XXX no quota file */
    }

    for (;;) {
	r = flock(fileno(folder->quota), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    folder->quota_lock_count--;
	    return 1;		/* XXX os error */
	}
	fstat(fileno(folder->quota), &sbuffd);
	r = stat(folder->quota_path, &sbuffile);
	if (r == -1) {
	    folder_unlock_quota(folder);
	    return 1;		/* XXX os error */
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(folder->quota);
	folder->quota = fopen(folder->quota_path, "r+");
	if (!folder->quota) {
	    return 1;		/* XXX where it go? */
	}
    }
    return folder_read_quota(folder);
}

folder_unlock_header(folder)
struct folder *folder;
{
    assert(folder->header_lock_count != 0);

    if (--folder->header_lock_count == 0) {
	flock(fileno(folder->header), LOCK_UN);
    }
    return 0;
}

folder_unlock_index(folder)
struct folder *folder;
{
    assert(folder->index_lock_count != 0);

    if (--folder->index_lock_count == 0) {
	flock(fileno(folder->index), LOCK_UN);
    }
    return 0;
}

folder_unlock_quota(folder)
struct folder *folder;
{
    assert(folder->quota_lock_count != 0);

    if (--folder->quota_lock_count == 0) {
	flock(fileno(folder->quota), LOCK_UN);
    }
    return 0;
}

folder_write_index_header(folder)
struct folder *folder;
{
    char buf[1024];
    int n;

    assert(folder->index_lock_count != 0);

    rewind(folder->index);
    
    *((bit32 *)buf) = folder->generation_no;
    *((bit32 *)(buf+4)) = htonl(folder->format);
    *((bit32 *)(buf+8)) = htonl(folder->start_offset);
    *((bit32 *)(buf+12)) = htonl(folder->record_size);
    *((bit32 *)(buf+16)) = htonl(folder->last_internaldate);
    *((bit32 *)(buf+20)) = htonl(folder->last_uid);
    *((bit32 *)(buf+24)) = htonl(folder->quota_folder_used);

    n = fwrite(buf, sizeof(bit32), 7, folder->index);
    if (n != 7) {
	return 1;		/* XXX write error */
    }
    fflush(folder->index);
    if (ferror(folder->index) || fsync(fileno(folder->index))) {
	return 1;		/* XXX write error */
    }
    return 0;
}

folder_append_index(folder, record, num)
struct folder *folder;
struct index_record *record;
int num;
{
    int i, j, len;
    char *buf, *p;
    long last_offset;

    assert(folder->index_lock_count != 0);

    if (folder->record_size < (7 + (MAX_USER_FLAGS/32)) * 4) {
	return 1;		/* XXX bad format--too small */
    }

    len = num * folder->record_size;
    buf = xmalloc(len);
    bzero(buf, len);

    for (i = 0; i < num; i++) {
	p = buf + i*folder->record_size;
	*((bit32 *)p) = htonl(record[i].uid);
	*((bit32 *)(p+4)) = htonl(record[i].internaldate);
	*((bit32 *)(p+8)) = htonl(record[i].size);
	*((bit32 *)(p+12)) = htonl(record[i].body_offset);
	*((bit32 *)(p+16)) = htonl(record[i].cache_offset);
	*((bit32 *)(p+20)) = htonl(record[i].last_updated);
	*((bit32 *)(p+24)) = htonl(record[i].system_flags);
	p += 28;
	for (j = 0; j < MAX_USER_FLAGS/32; j++, p += 4) {
	    *((bit32 *)p) = htonl(record[i].user_flags[j]);
	}
    }

    last_offset = fseek(folder->index, 0L, 2);
    fwrite(buf, len, 1, folder->index);
    if (ferror(folder->index) || fsync(fileno(folder->index))) {
	ftruncate(fileno(folder->index), last_offset);
	return 1;		/* XXX os error */
    }

    free(buf);
    return 0;
}

folder_write_quota(folder)
struct folder *folder;
{
    int r;
    char buf[MAX_FOLDER_PATH];
    FILE *newfile;

    assert(folder->quota_lock_count != 0);

    strcpy(buf, folder->quota_path);
    strcat(buf, ".NEW");

    newfile = fopen(buf, "w+");
    if (!newfile) {
	return 1;		/* XXX can't create */
    }
    r = flock(fileno(newfile), LOCK_EX);
    if (r) {
	return 1;		/* XXX os error */
    }

    fprintf(newfile, "%lu\n%d\n", folder->quota_used, folder->quota_limit);
    fflush(newfile);
    if (ferror(newfile) || fsync(fileno(newfile))) {
	return 1;		/* XXX os error */
    }

    if (rename(buf, folder->quota_path)) {
	return 1;		/* XXX os error */
    }
    fclose(folder->quota);
    folder->quota = newfile;

    return 0;
}


