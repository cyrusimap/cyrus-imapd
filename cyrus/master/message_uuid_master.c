#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "message_uuid_master.h"

/* Four possible forms of messageID:
 *
 * Private:
 *   Used for internal manipulation. Not visible to clients.
 *
 * Public:
 *   Opaque handle to byte sequence that Cyrus can pass around
 *
 * Packed:
 *   Byte sequence of known length (MESSAGE_UUID_PACKED_SIZE) which can
 *   be stored on disk. At the moment public and packed essentially
 *   the same thing but makes sense (I think!) to divide into two roles.
 *
 * Textual:
 *   Textual represenatation for Message-UUID for passing over the wire
 *   Currently 24 byte hex string + '\0', propose switch to BASE64 alike.
 *   
 */

/* Private interface */

/* master only worries about schema 1 */

struct uuid_info {
    unsigned short schema;                /*  8 bits used */
    unsigned short machine;               /*  8 bits used */
    unsigned short timestamp_generation;  /*  8 bits used */
    unsigned long  master_start_time;     /* 32 bits used */
    unsigned long  child_counter;         /* 16 bits used */
    unsigned long  count;                 /* 24 bits used */
};

static struct uuid_info uuid_private;

/* Couple of small utility functions for struct uuid_info */

static void
uuid_info_clear(struct uuid_info *uuid_info)
{
    memset(uuid_info, 0, sizeof(struct uuid_info));
}

static int
uuid_info_compare(struct uuid_info *u1, struct uuid_info *u2)
{
    return(((u1->schema == u2->schema) &&
            (u1->machine == u2->machine) &&
            (u1->timestamp_generation == u2->timestamp_generation) &&
            (u1->master_start_time==u2->master_start_time) &&
            (u1->child_counter == u2->child_counter) &&
            (u1->count == u2->count)) ? 1 : 0);
}

/* ====================================================================== */

#define UUID_SCHEMA_MAX  (255)
#define UUID_MACHINE_MAX (255)
#define UUID_TIMESTAMP_GENERATION_MAX (255)
#define UUID_CHILD_COUNTER_MAX (65535)

#define UUID_COUNT_MAX ((256*256*256)-1)

/* Routines for manipulating private values. Byte encoding is:
 *
 * Byte Offset       Use
 *
 * 0           Current UUID schema (following is schema 1)
 * 1           Machine ID within cluster (256 enough for single cluster?)
 * 2           Timestamp generation number
 *             (to cope with emergency restarts when system time broken).
 *             (also allows for overflow from 32 bit time_t if ever an issue).
 * 3->6        32 bit counter initialised as time that master starts
 * 7->8        16 bit process counter for UUID range.
 * 9-11      24 bit counter for UUID prefix within child process.
 *             (means max 1048576 messages per child process)
 *
 * Numbers stored big-endian.
 */

/* Following was more relative when limit was 256 processes/sec sustained.
 *
 * 16 bits for process counter gives us maximum sustained rate from master
 * as 65536 processes per second. Unlikely to be a problem in practice as:
 *
 * 1) master builds up a buffer of available UUIDs after a few seconds
 *    of idle time, and a huge buffer overnight.
 *
 * 2) Cyrus Prefork model means that imapd, lmtp process are reused.
 *    65536 processes isn't maximum transaction rate.
 *
 * 3) master has own rate limiting code to avoid resource stavation.
 *    (which could probably be improved to reduce DOS attacks from
 *     single IP address).
 */

/* message_uuid_extract() ************************************************
 *
 * Convert message_uuid_structure into public UID
 * Returns: boolean success
 *
 ************************************************************************/

static int
message_uuid_extract(struct message_uuid *uuid)
{
   unsigned char *s = &uuid->value[0];

   if (uuid_private.schema == 0) {
       message_uuid_set_null(uuid);
       return(1);
   }

   if ((uuid_private.schema != 1) ||
       (uuid_private.machine > UUID_MACHINE_MAX) ||
       (uuid_private.timestamp_generation > UUID_TIMESTAMP_GENERATION_MAX) ||
       (uuid_private.count > UUID_COUNT_MAX)) {

       message_uuid_set_null(uuid);
       return(0);
   }

   s[0] = (uuid_private.schema & 0xff);
   s[1] = (uuid_private.machine & 0xff);
   s[2] = (uuid_private.timestamp_generation & 0x00ff);

   s[3] = (uuid_private.master_start_time & 0xff000000) >> 24;
   s[4] = (uuid_private.master_start_time & 0x00ff0000) >> 16;
   s[5] = (uuid_private.master_start_time & 0x0000ff00) >> 8;
   s[6] = (uuid_private.master_start_time & 0x000000ff);

   s[7]  = (uuid_private.child_counter & 0xff00) >> 8;
   s[8]  = (uuid_private.child_counter & 0x00ff);
   s[9]  = (uuid_private.count & 0xff0000) >> 24;
   s[10] = (uuid_private.count & 0x00ff00) >> 8;
   s[11] = (uuid_private.count & 0x0000ff);

   return(1);
}     

/* ====================================================================== */

static int
master_value_isnumeric(char *s)
{
    while (*s) {
        if (!isdigit((unsigned char)*s)) return(0);
        s++;
    }
    return(1);
}

static void
master_chomp(char *s)
{
    if (!(s && *s))
        return;

    while (s[1])
        s++;

    if (*s == '\n') *s = '\0';
}

/* ====================================================================== */

/* Utility function to read MASTER_MACHINE_FILE */

#define MASTER_MACHINE_MAX_LINE (512)

static int
master_machine_read(unsigned long *machinep, char *filename)
{
    FILE *file;
    char buf[MASTER_MACHINE_MAX_LINE], *s;

    if ((file=fopen(filename, "r")) == NULL) {
        syslog(LOG_ERR, "Failed to open %s: %m", filename);
        return(0);
    }

    if (fgets(buf, MASTER_MACHINE_MAX_LINE, file) == NULL) {
        syslog(LOG_ERR, "Unexpected end of file in %s", filename);
        fclose(file);
        return(0);
    }
    fclose(file);

    master_chomp(buf);

    if ((s=strchr(buf, '=')) &&
        !strncmp(buf, "machine", s-buf) &&
        master_value_isnumeric(s+1)) {
        *machinep = strtoul(s+1, NULL, 10);
        return(1);
    }

    syslog(LOG_ERR, "Invalid line in %s: %s", filename, buf);
    return(0);
}

/* ====================================================================== */

/* Utility functions to read/write UUID master file */

#define MASTER_UUID_MAX_LINE (512)

static int
master_uuid_read_worker(struct uuid_info *uuid_info, char *line)
{
    char *s;
    unsigned long value;
    int keylen;

    if ((s=strchr(line, '=')) == NULL) return(0);
    if (!master_value_isnumeric(s+1)) return(0);

    keylen = s-line;
    value  = strtoul(s+1, NULL, 10);

    if (!strncmp(line, "schema", keylen)) {
        if (value > UUID_SCHEMA_MAX) return(0);
        uuid_info->schema = (unsigned char)value;
        return(1);
    }

    if (!strncmp(line, "machine", keylen)) {
        if (value > UUID_MACHINE_MAX) return(0);
        uuid_info->machine = (unsigned char)value;
        return(1);
    }

    if (!strncmp(line, "timestamp_generation=", keylen)) {
        if (value > UUID_TIMESTAMP_GENERATION_MAX) return(0);
        uuid_info->timestamp_generation = value;
        return(1);
    } 

    if (!strncmp(line, "master_start_time", keylen)) {
        uuid_info->master_start_time = value;
        return(1);
    }
    return(0);
}

static int
master_uuid_read(struct uuid_info *uuid_info, char *filename)
{
    FILE *file;
    char buf[MASTER_UUID_MAX_LINE];
    int error=0;

    uuid_info_clear(uuid_info);

    if ((file=fopen(filename, "r")) == NULL) {
        syslog(LOG_ERR, "Failed to open %s: %m", filename);
        return(0);
    }

    while (fgets(buf, MASTER_UUID_MAX_LINE, file)) {
        master_chomp(buf);

        if (!master_uuid_read_worker(uuid_info, buf)) {
            error = 1;
            break;
        }
    }
    fclose(file);

    if (error) {
        uuid_info_clear(uuid_info);
        syslog(LOG_ERR, "Invalid line in %s: %s", filename, buf);
        fclose(file);
        return(0);
    }

    if (uuid_info->schema != 1) {
        uuid_info_clear(uuid_info);
        syslog(LOG_ERR, "Invalid schema in %s", filename);
        return(0);
    }

    uuid_info->child_counter = 0;
    uuid_info->count         = 0;
    return(1);
}

static int
master_uuid_write(struct uuid_info *uuid_info, char *filename)
{
    FILE *file;

    if ((file=fopen(filename, "w")) == NULL)
        return(0);

    fprintf(file, "schema=%lu\n",
            (unsigned long)uuid_info->schema);

    fprintf(file, "machine=%lu\n",
            (unsigned long)uuid_info->machine);

    fprintf(file, "timestamp_generation=%lu\n",
            (unsigned long)uuid_info->timestamp_generation);

    fprintf(file, "master_start_time=%lu\n",
            (unsigned long)uuid_info->master_start_time);

    if (fflush(file) || fsync(fileno(file))) {
        fclose(file);
        return(0);
    }

    fclose(file);
    return(1);
}

static int
master_uuid_write_and_test(struct uuid_info *uuid_info)
{
    struct uuid_info uuid_tmp;

    uuid_info_clear(&uuid_tmp);

    if (!master_uuid_write(uuid_info, MASTER_UUID_FILE"-NEW")) {
        uuid_info_clear(uuid_info);
        return(0);
    }

    /* Ultra paranoid: read file back in and test values the same */
    
    if (!master_uuid_read(&uuid_tmp, MASTER_UUID_FILE"-NEW")) {
        syslog(LOG_ERR, "Failed to read in %s: %m",
               MASTER_UUID_FILE"-NEW");
        return(0);
    }

    if (!uuid_info_compare(&uuid_private, &uuid_tmp)) {
        syslog(LOG_ERR, "Sanity check failed on %s",
               MASTER_UUID_FILE"-NEW");
        return(0);
    }

    if (rename(MASTER_UUID_FILE"-NEW", MASTER_UUID_FILE) < 0) {
        syslog(LOG_ERR, "Failed to commit: %s -> %s: %m",
               MASTER_UUID_FILE"-NEW", MASTER_UUID_FILE);
        return(0);
    }

    return(1);
}

/* ====================================================================== */

/* message_uuid_master_init() ********************************************
 *
 * Initialise master process.
 *
 * Will require time() and current generation number.
 ************************************************************************/

int
message_uuid_master_init()
{
    struct uuid_info uuid_tmp;
    unsigned long machine = 0;

    uuid_info_clear(&uuid_private);
    uuid_info_clear(&uuid_tmp);

    if (!master_machine_read(&machine, MASTER_MACHINE_FILE))
        return(0);

    if (!master_uuid_read(&uuid_private, MASTER_UUID_FILE))
        return(0);

    if (uuid_private.machine != machine) {
        syslog(LOG_ERR, "Machine mismatch: %lu |= %lu",
               (unsigned long)machine, 
               (unsigned long)uuid_private.machine);
        return(0);
    }

    if (uuid_private.master_start_time >= time(NULL))
        return(0);

    uuid_private.master_start_time = time(NULL);
    uuid_private.child_counter = 0;
    uuid_private.count = 0;

    if (!master_uuid_write_and_test(&uuid_private)) {
        uuid_info_clear(&uuid_private);
        return(0);
    }

    return(1);
}

/* message_uuid_master_next_child() **************************************
 *
 * Bump child_counter.
 *
 ************************************************************************/

int
message_uuid_master_next_child(struct message_uuid *uuid)
{
    if (uuid_private.schema != 1)
        return(0);

    uuid_private.child_counter++;

    if (uuid_private.child_counter > UUID_CHILD_COUNTER_MAX) {
        while (uuid_private.master_start_time >= time(NULL))
            sleep(1); /* 1/10th second might be safer */

        uuid_private.master_start_time++;
        uuid_private.child_counter = 0;

        if (!master_uuid_write_and_test(&uuid_private)) {
            uuid_info_clear(&uuid_private);
            return(0);
        }
    }

    if (!message_uuid_extract(uuid)) {
        uuid_info_clear(&uuid_private);
        return(0);
    }
 
    return(1);
}

/* message_uuid_master_checksum() ****************************************
 *
 * Bump child_counter.
 *
 ************************************************************************/

int
message_uuid_master_checksum(struct message_uuid *uuid)
{
    unsigned char *s = &uuid->value[0];
    unsigned long count = 0;

    /* Compute 24 bit checksum from first 9 bytes */
    count += (s[0] << 16) + (s[1] << 8) + s[2];
    count += (s[3] << 16) + (s[4] << 8) + s[5];
    count += (s[6] << 16) + (s[7] << 8) + s[8];
    count &= 0x00ffffff;

    /* Store checksum in last 3 bytes */
    s[9]  = (count & 0xff0000) >> 16;
    s[10] = (count & 0x00ff00) >> 8;
    s[11] = (count & 0x0000ff);
 
   return(1);
}

/* message_uuid_set_null() ***********************************************
 *
 * Create NULL UUID
 *
 ************************************************************************/

int
message_uuid_set_null(struct message_uuid *dst)
{
    memset(dst, 0, MESSAGE_UUID_SIZE);
    return(1);
}

/* message_uuid_text() ***************************************************
 *
 * Returns ptr to '\0' terminated static char * which can be strdup()ed
 * NULL => error. Should be impossible as entire range covered
 *
 ************************************************************************/

char *
message_uuid_text(struct message_uuid *uuid)
{
    static char buf[MESSAGE_UUID_TEXT_SIZE+1];
    static char *hex = "0123456789abcdef";
    unsigned char *value = &uuid->value[0];
    char *p = buf;
    int i;

    for (i = 0 ; i < MESSAGE_UUID_SIZE ; i++) {
        *p++ = hex[(value[i] & 0xf0) >> 4];
        *p++ = hex[value[i]  & 0x0f];
    }
    *p = '\0';

    return(buf);
}

