In addition to the mailbox and message data, Cyrus stores various
metadata in the mail spool, such as indexes, annotations, etc.  It may
be useful in some circumstances to separate this metadata into its own
partitions.  For each partition to be split in this way, one must
define a metadata partition for each data partition, using the same
name, so Cyrus knows how to relate them to each other.

As well as specifying locations for the metadata, one must also tell
Cyrus which metadata files to place in these special partitions.  The
default behaviour is to locate *all* metadata in the data partition(s).
