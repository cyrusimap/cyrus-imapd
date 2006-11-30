#ifndef MESSAGE_UUID_H
/* Public interface */

#define MESSAGE_UUID_SIZE         (12)    /* Size of UUID byte sequence */
#define MESSAGE_UUID_PACKED_SIZE  (12)    /* Size on disk */
#define MESSAGE_UUID_TEXT_SIZE    (24)    /* UUID as hex */

struct message_uuid {
   unsigned char value[MESSAGE_UUID_SIZE]; /* Matches packed encoding */
};

int
message_uuid_client_init(char *uuid_prefix);
  /* Initialise private UUID system
   * (sets fields from message_uuid, clears uuid_suffix) */

int
message_uuid_assign(struct message_uuid *uuid);
  /* Assign next UUID to preallocated structure */
  /* Returns: Cyrus error code, 0 on sucess */

struct message_uuid *
message_uuid_alloc();
  /* Allocate and assign next UUID using xmalloc */
  /* Returns NULL Message-UUID if allocation exhaused */
  /* NULL => alloc failed */

void
message_uuid_free(struct message_uuid **uuidp);
  /* Free Message UUID structure */

int
message_uuid_compare(struct message_uuid *uuid1, struct message_uuid *uuid2);
  /* Compare a pair of UUIDs: Returns 1 => match */

int
message_uuid_copy(struct message_uuid *dst, struct message_uuid *src);
  /* Copy a UUID */

unsigned long
message_uuid_hash(struct message_uuid *uuid, int hash_size);
  /* Convert UUID into hash value for hash table lookup */
  /* Returns: positive int in range [0, hash_size-1] */

int
message_uuid_set_null(struct message_uuid *dst);
  /* Create a NULL UUID */

int
message_uuid_isnull(struct message_uuid *uuid);
  /* Returns 1 if UUID is NULL value */

/* Routines for manipulating packed values */

int
message_uuid_pack(struct message_uuid *uuid, char *packed);
  /* Store Message UID as packed sequence (MESSAGE_UUID_PACKED_SIZE)
   * (Wrapper for memcpy() with current implementation) */

int
message_uuid_unpack(struct message_uuid *uuid, const unsigned char *packed);
  /* Fetch Message UID from packed sequence (MESSAGE_UUID_PACKED_SIZE)
   * (Wrapper for memcpy() with current implementation) */

/* Routines for manipulating text value */

char *
message_uuid_text(struct message_uuid *uuid);
  /* Returns ptr to '\0' terminated static char * which can be strdup()ed */
  /* NULL => error. Should be impossible as entire range covered */

int
message_uuid_from_text(struct message_uuid *uuid, const char *text);
  /* Sets Message UUID from text form. Returns 1 if valid */
  /* Returns: Cyrus error code, 0 on sucess */

int
message_uuid_text_valid(const char *text);
  /* Returns 1 if test valid format for Message UUID */

int
message_uuid_text_isnull(const char *text);
  /* Returns 1 if Textual UUID is NULL value */

#define MESSAGE_UUID_H (1)
#endif
