/* Public interface */

#define MASTER_UUID_FILE    "master_uuid"
#define MASTER_MACHINE_FILE "master_machine"

#define MESSAGE_UUID_SIZE         (12)    /* Size of UUID byte sequence */
#define MESSAGE_UUID_PACKED_SIZE  (12)    /* Size on disk */
#define MESSAGE_UUID_TEXT_SIZE    (24)    /* UUID as hex */

struct message_uuid {
   unsigned char value[MESSAGE_UUID_SIZE]; /* Matches packed encoding */
};

int
message_uuid_master_init(/* PARAMETERS? */);
  /* Initialise master process. Will require time() and current generation
   * number */

int
message_uuid_master_next_child(struct message_uuid *uuid);
  /* Return next UUID prefix for master */

int
message_uuid_master_checksum(struct message_uuid *uuid);

int
message_uuid_client_init(char *uuid_prefix);
  /* Initialise private UUID system
   * (sets fields from message_uuid, clears uuid_suffix) */

int
message_uuid_set_null(struct message_uuid *dst);
  /* Create a NULL UUID */

char *
message_uuid_text(struct message_uuid *uuid);
  /* Returns ptr to '\0' terminated static char * which can be strdup()ed */
  /* NULL => error. Should be impossible as entire range covered */

