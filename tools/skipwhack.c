
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sysexits.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <errno.h>
#include <time.h>

#include "skipwhack_crc32.c"

#define SLOP (1024 * 8)

#define MAGIC "THIS IS A HEADER......................"

struct mf {
	char *fname;
	int fd;
	char *map_base;
	size_t map_size;
	size_t len;
	uint64_t seq;
};

uint32_t csum(const char *base, size_t len)
{
	uint32_t sum = crc32_map(base, len);
}

void mf_lock(struct mf *mf, int type)
{
	struct flock fl;
	fl.l_type = type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	for (;;) {
		int r = fcntl(mf->fd, F_SETLKW, &fl);
		if (r != -1) return;
		if (errno == EINTR) continue;
		abort();
	}
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

void read_header(struct mf *mf)
{
	if (memcmp(mf->map_base, MAGIC, 24)) {
		printf("INVALID MAGIC! %s\n", mf->fname);
		abort();
	}

	size_t seq = be64toh(*((uint64_t *)(mf->map_base + 24)));
	size_t end = be64toh(*((uint64_t *)(mf->map_base + 32)));

	if (end < mf->len) {
		printf("WRONG LENGTH %s: %llX %llX\n", mf->fname,
		       (long long unsigned)end, (long long unsigned)mf->len);
		ftruncate(mf->fd, end);
		mf->len = end;
	}

	uint32_t sum = be32toh(*((uint32_t *)(mf->map_base + 124)));
	if (sum != csum(mf->map_base, 124)) {
		printf("WRONG HEADER CHECKSUM %s (got %llX expected %llX)\n", mf->fname, (long long unsigned)sum, (long long unsigned)csum(mf->map_base, 124));
		abort();
	}

	mf->seq = seq;
}

void mf_write(struct mf *mf, size_t offset, const char *bytes, size_t len)
{
	if (offset % 128) {
		printf("CALLED WITH BAD OFFSET %s %llX", mf->fname, (long long unsigned)offset);
		abort();
	}
	if (lseek(mf->fd, offset, SEEK_SET) < 0)
		abort();
	if (write(mf->fd, bytes, len) != len)
		abort();

	mf_ensure(mf, offset + len);
}

void write_header(struct mf *mf)
{
	char buf[128];
	memset(buf, 0, sizeof(buf));

	memcpy(buf, MAGIC, 24);
	*((uint64_t *)(buf + 24)) = htobe64(mf->seq);
	*((uint64_t *)(buf + 32)) = htobe64(mf->len);
	for (int i = 6; i < 15; i++)
		*((uint64_t *)(buf + 8*i)) = htobe64(mf->seq);

	uint32_t sum = csum(buf, 124);
	*((uint32_t *)(buf + 124)) = htobe32(sum);

	mf_write(mf, 0, buf, 128);
}

void append_one(struct mf *mf, size_t end)
{
	char buf[128];
	memset(buf, 0, sizeof(buf));
	buf[0] = '+';
	mf->seq++;
	*((uint64_t *)(buf + 8)) = htobe64(mf->seq);
	*((uint64_t *)(buf + 16)) = htobe64(mf->seq);
	*((uint64_t *)(buf + 24)) = htobe64(end);
	for (int i = 4; i < 16; i++) {
		*((uint64_t *)(buf + 8*i)) = htobe64(end);
	}

	*((uint32_t *)(buf + 32)) = htobe32(csum(buf, 32));
	*((uint32_t *)(buf + 36)) = htobe32(csum(buf + 40, 88));

	mf_write(mf, end, (char *)buf, 128);
	mf->len = end + 128;
}

void check_one(struct mf *mf, size_t pos)
{
	if (pos + 128 > mf->map_size) {
		printf("WILL READ PAST END OF MAP! %s %llX %llX %llX\n", mf->fname,
		       (long long unsigned)pos, (long long unsigned)mf->map_size,
			(long long unsigned)mf->len);
		abort();
	}
	if (mf->map_base[pos] != '+') {
		printf("INVALID CHAR %s at %llX (%c)\n",
		        mf->fname, (long long unsigned)pos, mf->map_base[pos]);
		abort();
	}
	size_t at = be64toh(*((uint64_t *)(mf->map_base + pos + 24)));
	if (at != pos) {
		printf("INVALID first location %s at %llX (%llX)\n",
		        mf->fname, (long long unsigned)pos, (long long unsigned)at);
		abort();
	}
	uint32_t sum1 = be32toh(*((uint32_t *)(mf->map_base + pos + 32)));
	uint32_t sum2 = be32toh(*((uint32_t *)(mf->map_base + pos + 36)));
	if (csum(mf->map_base + pos, 32) != sum1) {
		printf("INVALID head csum %s at %llX\n",
		        mf->fname, (long long unsigned)pos);
		abort();
	}
	if (csum(mf->map_base + pos + 40, 88) != sum2) {
		printf("INVALID tail csum %s at %llX\n",
		        mf->fname, (long long unsigned)pos);
		abort();
	}
	size_t at2 = be64toh(*((uint64_t *)(mf->map_base + pos + 88)));
	if (at2 != pos) {
		printf("INVALID end location %s at %llX (%llX)\n",
		        mf->fname, (long long unsigned)pos, (long long unsigned)at2);
		abort();
	}
}

void rewrite_one(struct mf *mf, size_t pos)
{
	char buf[128];
	check_one(mf, pos);
	memcpy(buf, mf->map_base + pos, 128);
	*((uint64_t *)(buf + 16)) = htobe64(mf->seq);
	*((uint32_t *)(buf + 32)) = htobe32(csum(buf, 32));
	mf_write(mf, pos, (char *)buf, 48);
}

size_t stitch_one(struct mf *mf, size_t end)
{
	if (!end) return 0;
	size_t newpos = ((end / 2) + (int)(rand() % (end / 2))) - 1 & ~127;
	if (newpos < 256) return 0;
	rewrite_one(mf, newpos);
	return newpos;
}

struct mf *mf_open(const char *fname)
{
	struct stat sbuf;
	struct mf *mf = malloc(sizeof(struct mf));

	mf->fd = open(fname, O_RDWR | O_CREAT, 0644);
	if (mf->fd == -1) {
		printf("failed to open %s\n", fname);
		abort();
	}

	mf_lock(mf, F_WRLCK);

	mf->fname = strdup(fname);
	mf->map_base = NULL;
	mf->map_size = 0;
	mf->len = 0;
	mf->seq = 0;

	// map in the file
	if (!fstat(mf->fd, &sbuf))
		mf_ensure(mf, sbuf.st_size);

	if (mf->len) {
		read_header(mf);
	}
	else {
		mf->seq = 1;
		mf->len = 128;
		write_header(mf);
	}

	return mf;
}

void mf_close(struct mf **mfp)
{
	struct mf *mf = *mfp;

	if (mf->map_size)
		munmap(mf->map_base, mf->map_size);

	if (fsync(mf->fd) < 0)
		abort();
	if (close(mf->fd) < 0)
		abort();

	free(mf->fname);
	free(mf);

	*mfp = NULL;
}

void mf_check(struct mf *mf)
{
	for (size_t offset = 128; offset < mf->len; offset += 128) {
		check_one(mf, offset);
	}
}

void mf_repack(struct mf **mfp)
{
	struct mf *mf = *mfp;
	mf_check(mf);

	// we don't actually copy anything from the previous file, we just create a new one
	char *newname = malloc(strlen(mf->fname) + 5);
	sprintf(newname, "%s.NEW", mf->fname);
	struct mf *newmf = mf_open(newname);

	// create a file between the same length and about 1/4 in size (we don't actually copy, just recreate)
	int div = 128 + (rand() % 512);
	for (int i = 0; i < mf->len / div; i++)
		append_one(newmf, newmf->len);
	write_header(newmf);

	printf("Repacked %s from %d to %d\n", mf->fname, (int)mf->len, (int)newmf->len);
	const char *dir = dirname(newname);
	int dirfd = open(dir, O_RDONLY, 0600);
	if (dirfd < 0) {
		printf("FAILED TO OPEN DIR %s\n", dir);
		abort();
	}
	if (rename(newmf->fname, mf->fname) < 0) {
		printf("FAILED TO rename %s to %s\n", newmf->fname, mf->fname);
		abort();
	}
	if (fsync(dirfd) < 0) {
		printf("FAILED TO FSYNC DIR %s\n", dir);
		abort();
	}
	// set the correct name after the rename
	free(newmf->fname);
	newmf->fname = strdup(mf->fname);
	mf_close(&mf);
	free(newname);

	*mfp = newmf;
}

void run_file(const char *fname)
{
	printf("run file %s\n", fname);
	struct mf *mf = mf_open(fname);
	mf_check(mf);
	for (;;) {
		size_t end = mf->len;
		append_one(mf, end);
		for(int num = rand() % 8; num; num--)
			end = stitch_one(mf, end);

		if (rand() % 100000 == 0) {
			write_header(mf);
			if (mf->len > 10000000)
				mf_repack(&mf);
			mf_check(mf);
			mf_close(&mf);
			return;
		}
	}
}

int main(int argc, char **argv)
{
	const char *base = argv[1];
	char fname[1024];
	srand(time(NULL));
	if (!base)
		abort();

	for(;;) {
		int num = rand() % 64;
		snprintf(fname, 1024, "%s/data-%d", base, num);
		run_file(fname);
	}
}
