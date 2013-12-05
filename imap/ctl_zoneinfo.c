/* ctl_zoneinfo.c -- Program to perform operations on zoneinfo db
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libical/ical.h>

#include "annotate.h" /* for strlist functionality */
#include "global.h"
#include "hash.h"
#include "map.h"
#include "util.h"
#include "xmalloc.h"
#include "zoneinfo_db.h"

extern int optind;
extern char *optarg;

/* config.c stuff */
const int config_need_data = 0;

int verbose = 0;

/* forward declarations */
void usage(void);
void free_zoneinfo(void *data);
void store_zoneinfo(const char *tzid, void *data, void *rock);
void do_zonedir(const char *prefix, struct hash_table *tzentries,
		struct zoneinfo *info);
void shut_down(int code);


int main(int argc, char **argv)
{
    int opt, r = 0;
    char *alt_config = NULL, *version = NULL;
    enum { REBUILD, NONE } op = NONE;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:r:v")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'r':
	    if (op == NONE) {
		op = REBUILD;
		version = optarg;
	    }
	    else usage();
	    break;

	case 'v':
	    verbose = 1;
	    break;

	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "ctl_zoneinfo", 0);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    switch (op) {
    case REBUILD: {
	struct hash_table tzentries;
	struct zoneinfo *zi;
	struct txn *tid = NULL;
	char prefix[2048];

	construct_hash_table(&tzentries, 500, 1);

	/* Add INFO record (overall lastmod and TZ DB source version) */
	zi = xzmalloc(sizeof(struct zoneinfo));
	zi->type = ZI_INFO;
	appendstrlist(&zi->data, version);
	hash_insert(INFO_TZID, zi, &tzentries);

	snprintf(prefix, sizeof(prefix), "%s%s", config_dir, FNAME_ZONEINFODIR);

	do_zonedir(prefix, &tzentries, zi);

	zoneinfo_open(NULL);

	hash_enumerate(&tzentries, &store_zoneinfo, &tid);

	zoneinfo_close(tid);

	free_hash_table(&tzentries, &free_zoneinfo);
	break;
    }

    case NONE:
	r = 2;
	usage();
	break;
    }

    cyrus_done();

    return r;
}


void usage(void)
{
    fprintf(stderr,
	    "usage: zoneinfo_reconstruct [-C <alt_config>] [-v]"
	    " -r <version-string>\n");
    exit(EC_USAGE);
}


/* Add all ZONEs and LINKs in the given directory to the hash table */
void do_zonedir(const char *dir, struct hash_table *tzentries,
		struct zoneinfo *info)
{
    DIR *dirp;
    struct dirent *dirent;

    signals_poll();

    if (verbose) printf("Rebuilding %s\n", dir);

    dirp = opendir(dir);
    if (!dirp) {
	fprintf(stderr, "can't open zoneinfo directory %s\n", dir);
    }

    while ((dirent = readdir(dirp))) {
	char path[2048], *tzid;
	int plen;
	struct stat sbuf;
	struct zoneinfo *zi;

	if (*dirent->d_name == '.') continue;	    

	plen = snprintf(path, sizeof(path), "%s/%s", dir, dirent->d_name);
	lstat(path, &sbuf);

	if (S_ISDIR(sbuf.st_mode)) {
	    /* Path is a directory (region) */
	  do_zonedir(path, tzentries, info);
	}
	else if (S_ISLNK(sbuf.st_mode)) {
	    /* Path is a symlink (alias) */
	    char link[1024], *alias;
	    ssize_t llen;

	    /* Isolate tzid in path */
	    if ((llen = readlink(path, link, sizeof(link))) < 0) continue;
	    link[llen-4] = '\0';  /* Trim ".ics" */
	    for (tzid = link; !strncmp(tzid, "../", 3); tzid += 3);

	    /* Isolate alias in path */
	    path[plen-4] = '\0';  /* Trim ".ics" */
	    alias = path + strlen(config_dir) + strlen("zoneinfo") + 2;

	    if (verbose) printf("\tLINK: %s -> %s\n", alias, tzid);

	    /* Create hash entry for alias */
	    if (!(zi = hash_lookup(alias, tzentries))) {
		zi = xzmalloc(sizeof(struct zoneinfo));
		hash_insert(alias, zi, tzentries);
	    }
	    zi->type = ZI_LINK;
	    appendstrlist(&zi->data, tzid);

	    /* Create/update hash entry for tzid */
	    if (!(zi = hash_lookup(tzid, tzentries))) {
		zi = xzmalloc(sizeof(struct zoneinfo));
		hash_insert(tzid, zi, tzentries);
	    }
	    zi->type = ZI_ZONE;
	    appendstrlist(&zi->data, alias);
	}
	else if (S_ISREG(sbuf.st_mode)) {
	    /* Path is a regular file (zone) */
	    int fd;
	    const char *base = NULL;
	    unsigned long len = 0;
	    icalcomponent *ical, *comp;
	    icalproperty *prop;

	    /* Parse the iCalendar file for important properties */
	    if ((fd = open(path, O_RDONLY)) == -1) continue;
	    map_refresh(fd, 1, &base, &len, MAP_UNKNOWN_LEN, path, NULL);
	    close(fd);

	    ical = icalparser_parse_string(base);
	    map_free(&base, &len);

	    comp = icalcomponent_get_first_component(ical,
						     ICAL_VTIMEZONE_COMPONENT);
	    prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
	    tzid = (char *) icalproperty_get_value_as_string(prop);

	    if (verbose) printf("\tZONE: %s\n", tzid);

	    /* Create/update hash entry for tzid */
	    if (!(zi = hash_lookup(tzid, tzentries))) {
		zi = xzmalloc(sizeof(struct zoneinfo));
		hash_insert(tzid, zi, tzentries);
	    }
	    zi->type = ZI_ZONE;
	    prop = icalcomponent_get_first_property(comp,
						    ICAL_LASTMODIFIED_PROPERTY);
	    zi->dtstamp = icaltime_as_timet(icalproperty_get_lastmodified(prop));

	    icalcomponent_free(ical);

	    /* Check overall lastmod */
	    if (zi->dtstamp > info->dtstamp) info->dtstamp = zi->dtstamp;
	}
	else {
	    fprintf(stderr, "unknown path type %s\n", path);
	}
    }

    closedir(dirp);
}


/* Free a malloc'd struct zoneinfo */
void free_zoneinfo(void *data)
{
    struct zoneinfo *zi = (struct zoneinfo *) data;

    freestrlist(zi->data);
    free(zi);
}


/* Store a struct zoneinfo into zoneinfo.db using the given txn */
void store_zoneinfo(const char *tzid, void *data, void *rock)
{
    struct zoneinfo *zi = (struct zoneinfo *) data;
    struct txn **tid = (struct txn **) rock;

    zoneinfo_store(tzid, zi, tid);
}


/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    exit(code);
}
