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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libical/ical.h>
#include <libxml/tree.h>

#include "annotate.h" /* for strlist functionality */
#include "global.h"
#include "hash.h"
#include "map.h"
#include "util.h"
#include "xmalloc.h"
#include "xml_support.h"
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
    char *alt_config = NULL, *pub = NULL, *ver = NULL, *winfile = NULL;
    const char *zoneinfo_dir = NULL;
    enum { REBUILD, WINZONES, NONE } op = NONE;

    while ((opt = getopt(argc, argv, "C:r:vw:")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'r':
            if (op == NONE) {
                op = REBUILD;
                pub = optarg;
                ver = strchr(optarg, ':');
                if (ver) *ver++ = '\0';
                else usage();
            }
            else usage();
            break;

        case 'v':
            verbose = 1;
            break;

        case 'w':
            if (op == NONE) {
                op = WINZONES;
                winfile = optarg;
            }
            else usage();
            break;

        default:
            usage();
        }
    }

    cyrus_init(alt_config, "ctl_zoneinfo", 0, 0);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    zoneinfo_dir = config_getstring(IMAPOPT_ZONEINFO_DIR);
    if (!zoneinfo_dir) {
        fprintf(stderr, "zoneinfo_dir must be set for tzdist service\n");
        cyrus_done();
        return EX_CONFIG;
    }

    switch (op) {
    case REBUILD: {
        struct hash_table tzentries;
        struct zoneinfo *info;
        struct txn *tid = NULL;
        char buf[3000];
        FILE *fp;

        construct_hash_table(&tzentries, 500, 1);

        /* Add INFO record (overall lastmod and TZ DB source version) */
        info = xzmalloc(sizeof(struct zoneinfo));
        info->type = ZI_INFO;
        strarray_append(&info->data, pub);
        strarray_append(&info->data, ver);
        hash_insert(INFO_TZID, info, &tzentries);

        /* Add LEAP record (last updated and hash) */
        snprintf(buf, sizeof(buf), "%s%s", zoneinfo_dir, FNAME_LEAPSECFILE);
        if (verbose) printf("Processing leap seconds file %s\n", buf);
        if (!(fp = fopen(buf, "r"))) {
            fprintf(stderr, "Could not open leap seconds file %s\n", buf);
        }
        else {
            struct zoneinfo *leap = xzmalloc(sizeof(struct zoneinfo));
            leap->type = ZI_INFO;

            while(fgets(buf, sizeof(buf), fp)) {
                if (buf[0] == '#') {
                    /* comment line */

                    if (buf[1] == '$') {
                        /* last updated */
                        unsigned long last;

                        sscanf(buf+2, "\t%lu", &last);
                        leap->dtstamp = last - NIST_EPOCH_OFFSET;
                    }
                    else if (buf[1] == 'h') {
                        /* hash */
                        char *p, *hash = buf+3 /* skip "#h\t" */;

                        /* trim trailing whitespace */
                        for (p = hash + strlen(hash); isspace(*--p); *p = '\0');
                        strarray_append(&leap->data, hash);
                    }
                }
            }
            fclose(fp);

            hash_insert(LEAP_TZID, leap, &tzentries);
            info->dtstamp = leap->dtstamp;
        }

        /* Add ZONE/LINK records */
        do_zonedir(zoneinfo_dir, &tzentries, info);

        zoneinfo_open(NULL);

        /* Store records */
        hash_enumerate(&tzentries, &store_zoneinfo, &tid);

        zoneinfo_close(tid);

        free_hash_table(&tzentries, &free_zoneinfo);
        break;
    }

    case WINZONES: {
        xmlParserCtxtPtr ctxt;
        xmlDocPtr doc;
        xmlNodePtr node;
        struct buf tzidbuf = BUF_INITIALIZER;
        struct buf aliasbuf = BUF_INITIALIZER;

        if (verbose) printf("Processing Windows Zone file %s\n", winfile);

        /* Parse the XML file */
        ctxt = xmlNewParserCtxt();
        if (!ctxt) {
            fprintf(stderr, "Failed to create XML parser context\n");
            break;
        }

        doc = xmlCtxtReadFile(ctxt, winfile, NULL, 0);
        xmlFreeParserCtxt(ctxt);
        if (!doc) {
            fprintf(stderr, "Failed to parse XML document\n");
            break;
        }

        node = xmlDocGetRootElement(doc);
        if (!node || xmlStrcmp(node->name, BAD_CAST "supplementalData")) {
            fprintf(stderr, "Incorrect root node\n");
            goto done;
        }

        for (node = xmlFirstElementChild(node);
             node && xmlStrcmp(node->name, BAD_CAST "windowsZones");
             node = xmlNextElementSibling(node));
        if (!node) {
            fprintf(stderr, "Missing windowsZones node\n");
            goto done;
        }

        node = xmlFirstElementChild(node);
        if (!node || xmlStrcmp(node->name, BAD_CAST "mapTimezones")) {
            fprintf(stderr, "Missing mapTimezones node\n");
            goto done;
        }

        if (chdir(zoneinfo_dir)) {
            fprintf(stderr, "chdir(%s) failed\n", zoneinfo_dir);
            goto done;
        }

        for (node = xmlFirstElementChild(node);
             node;
             node = xmlNextElementSibling(node)) {
            if (!xmlStrcmp(node->name, BAD_CAST "mapZone") &&
                !xmlStrcmp(xmlGetProp(node, BAD_CAST "territory"),
                           BAD_CAST "001")) {
                const char *tzid, *alias;

                buf_setcstr(&tzidbuf,
                            (const char *) xmlGetProp(node, BAD_CAST "type"));
                buf_appendcstr(&tzidbuf, ".ics");
                tzid = buf_cstring(&tzidbuf);
                buf_setcstr(&aliasbuf,
                            (const char *) xmlGetProp(node, BAD_CAST "other"));
                buf_appendcstr(&aliasbuf, ".ics");
                alias = buf_cstring(&aliasbuf);

                if (verbose) printf("\tLINK: %s -> %s\n", alias, tzid);

                if (symlink(tzid, alias)) {
                    if (errno == EEXIST) {
                        struct stat sbuf;

                        if (stat(alias, &sbuf)) {
                            fprintf(stderr, "stat(%s) failed: %s\n",
                                    alias, strerror(errno));
                            errno = EEXIST;
                        }
                        else if (sbuf.st_mode & S_IFLNK) {
                            char link[MAX_MAILBOX_PATH+1];
                            int n = readlink(alias, link, MAX_MAILBOX_PATH);

                            if (n == -1) {
                                fprintf(stderr, "readlink(%s) failed: %s\n",
                                        alias, strerror(errno));
                                errno = EEXIST;
                            }
                            else if (n == (int) strlen(tzid) &&
                                     !strncmp(tzid, link, n)) {
                                errno = 0;
                            }
                        }
                    }

                    if (errno) {
                        fprintf(stderr, "symlink(%s, %s) failed: %s\n",
                                tzid, alias, strerror(errno));
                    }
                }
            }
        }

  done:
        buf_free(&aliasbuf);
        buf_free(&tzidbuf);
        xmlFreeDoc(doc);
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
            "usage: ctl_zoneinfo [-C <alt_config>] [-v]"
            " -r <publisher>:<version> | -w <file>\n");
    exit(EX_USAGE);
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
            alias = path + strlen(dir) + 1;

            if (verbose) printf("\tLINK: %s -> %s\n", alias, tzid);

            /* Create hash entry for alias */
            if (!(zi = hash_lookup(alias, tzentries))) {
                zi = xzmalloc(sizeof(struct zoneinfo));
                hash_insert(alias, zi, tzentries);
            }
            zi->type = ZI_LINK;
            strarray_append(&zi->data, tzid);

            /* Create/update hash entry for tzid */
            if (!(zi = hash_lookup(tzid, tzentries))) {
                zi = xzmalloc(sizeof(struct zoneinfo));
                hash_insert(tzid, zi, tzentries);
            }
            zi->type = ZI_ZONE;
            strarray_append(&zi->data, alias);
        }
        else if (S_ISREG(sbuf.st_mode)) {
            /* Path is a regular file (zone) */
            int fd;
            const char *base = NULL;
            size_t len = 0;
            icalcomponent *ical, *comp;
            icalproperty *prop;
            char *alias = NULL;

            /* Parse the iCalendar file for important properties */
            if ((fd = open(path, O_RDONLY)) == -1) continue;
            map_refresh(fd, 1, &base, &len, MAP_UNKNOWN_LEN, path, NULL);
            close(fd);

            ical = icalparser_parse_string(base);
            map_free(&base, &len);

            if (!ical) continue;  /* skip non-iCalendar files */

            comp = icalcomponent_get_first_component(ical,
                                                     ICAL_VTIMEZONE_COMPONENT);
            prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
            tzid = (char *) icalproperty_get_value_as_string(prop);

            prop = icalcomponent_get_first_property(comp,
                                                    ICAL_TZIDALIASOF_PROPERTY);
            if (prop) {
                alias = tzid;
                tzid = (char *) icalproperty_get_value_as_string(prop);

                if (verbose) printf("\tLINK: %s -> %s\n", alias, tzid);
            }
            else if (verbose) printf("\tZONE: %s\n", tzid);

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

            if (alias) {
                /* Add alias to the list for this tzid */
                strarray_append(&zi->data, alias);

                /* Create hash entry for alias */
                if (!(zi = hash_lookup(alias, tzentries))) {
                    zi = xzmalloc(sizeof(struct zoneinfo));
                    hash_insert(alias, zi, tzentries);
                }
                zi->type = ZI_LINK;
                strarray_append(&zi->data, tzid);
            }
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

    strarray_fini(&zi->data);
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
