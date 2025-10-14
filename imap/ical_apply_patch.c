/*
 * Program for testing VPATCH application
 */

#include <stdio.h>
#include <libical/ical.h>

#include "ical_support.h"

extern int optind, opterr;
extern char *optarg;

static char *read_stream(char *s, size_t size, void *d)
{
    return fgets(s, (int) size, (FILE *) d);
}

static icalcomponent *parse_file(const char *fname)
{
    icalcomponent *component = NULL;
    FILE *stream = fopen(fname, "r");

    if (!stream) {
        return NULL;
    }

    icalparser *parser = icalparser_new();
    icalparser_set_gen_data(parser, stream);

    component = icalparser_parse(parser, read_stream);

    icalparser_free(parser);
    fclose(stream);

    return component;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <VCALENDAR_file> <VPATCH_file>\n", argv[0]);
        exit(0);
    }

    icalcomponent *resource = parse_file(argv[1]);
    icalcomponent *patch = parse_file(argv[2]);

    icalcomponent_apply_vpatch(resource, patch, NULL, NULL);

    printf("%s", icalcomponent_as_ical_string(resource));
    icalcomponent_free(resource);
    icalcomponent_free(patch);

    exit(0);
}
