
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sysexits.h>
#include <stdlib.h>
#include <string.h>

#define SLOP (1024 * 8)

struct mf {
	char *fname;
	int fd;
	char *map_base;
	size_t map_size;
	size_t len;
};

void mf_open(const char *fname, struct mf **mfp)
{
	struct mf *mf = malloc(sizeof(struct mf));	

	mf->fd = open(fname, O_RDWR | O_CREAT, 0644);
	mf->fname = strdup(fname);
	mf->map_base = NULL;
	mf->map_size = 0;
	mf->len = 0;


	*mfp = mf;
}

void mf_ensure(struct mf *mf, size_t offset)
{
	if (offset <= mf->map_size)
	       return;

	if (mf->map_size)
		munmap(mf->map_base, mf->map_size);

	mf->map_size = (offset + 2*SLOP - 1) & ~(SLOP-1);
	mf->map_base = (char *)mmap((caddr_t)0, mf->map_size, PROT_READ, MAP_SHARED | MAP_FILE, mf->fd, 0L);
	mf->len = offset;
}

void mf_close(struct mf *mf)
{
	
}

void remap(struct mf *mf, size_t offset)
{

}

int main(int argc, char **argv)
{

}
