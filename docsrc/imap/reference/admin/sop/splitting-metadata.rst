Splitting Metadata from Partitions
==================================

.. important::
   This only applies to Cyrus IMAP version 2.4 and 2.5

.. todo::
   Find out when exactly the metapartition-* options were added to imapd.conf

The traditional layout for a Cyrus IMAP mailbox spool directory is to include the mailbox message data and mailbox metadata in the same directory tree. The mailbox message data and mailbox metadata differ in size and frequency of updating, which in larger deployments may justify using different storage layers for each.

The mailbox message data, which consists of many (small) message files, is not updated as frequently and does not require as much storage performance as the mailbox metadata, which consists of databases that are updated frequently and have a high volume of accesses and updates. The mailbox message data usually requires significant storage volumes, while the mailbox metadata does not.

To transition from the traditional Cyrus IMAP mailbox spool directory tree layout to a split setup, use the following procedure.

**Procedure 13.1. Transition from Traditional Mail Spool to Split Data Mail Spool**
 
     Create a new partition in **/etc/imapd.conf**, aptly named **splitmeta** in the following example configuration snippet::
 
         metapartition_files: header index cache expunge squat
         metapartition-default: /var/spool/imap
         metapartition-splitmeta: /var/spool/splitmeta/metadata
         partition-default: /var/spool/imap
         partition-splitmeta: /var/spool/splitmeta/partition
 
     Create the directory tree being referred to in the new configuration::
 
         # su -s /bin/bash - cyrus -c '/usr/lib/cyrus-imapd/mkimap /etc/imapd.conf'
 
     Reload the Cyrus IMAP service. Please refer to :ref:`Reloading Cyrus IMAP Services<sop_reloading>` for more details on doing so.

     Rename all mailboxes, using the new partition as the location for the renamed mailbox. One example rename command is included below::
 
         cyradm> renamemailbox user/john.doe@example.org user/john.doe@example.org splitmeta
 
