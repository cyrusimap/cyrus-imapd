#include <stdio.h>
#include "folder.h"

char *message_fname(folder, uid)
struct folder *folder;
unsigned long uid;
{
    static char buf[64];

    sprintf(buf, "%lu%s", uid, folder->format == FOLDER_FORMAT_NETNEWS ? "" : ".");
    return buf;
}

message_copy_stream(from, to)
FILE *from, *to;
{
    char buf[4096], *p;

    while (fgets(buf, sizeof(buf)-1, from)) {
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	}
	fputs(buf, to);
    }
    if (ferror(from) || ferror(to)) return 1; /* XXX copy error */
    return 0;
}

message_parse(message, folder, message_index)
FILE *message;
struct folder *folder;
struct index_record *message_index;
{
    char buf[4096];
    int message_format = folder->format;
    int linelen, size = 0;
    int inheader = 1;

    rewind(message);
    while (fgets(buf, sizeof(buf), message)) {
	linelen = strlen(buf);
	size += linelen;
	if (message_format == FOLDER_FORMAT_NETNEWS && buf[linelen-1] == '\n') {
	  size++;
	}
	if (inheader && (*buf == '\r' || *buf == '\n')) {
	    message_index->body_offset = ftell(message);
	    inheader = 0;
	}
    }
    if (inheader) {
	message_index->body_offset = ftell(message);
    }
    message_index->size = size;
    return 0;
}

	

	

    
