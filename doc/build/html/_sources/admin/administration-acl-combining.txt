Combining Access Rights
-----------------------

Access rights can combined to set a typical set of "read", "write" and "full control", potentially making it easier for client implementors to present their users with an interface to administer the ACLs to their mailboxes easily.

Common sets of ACLs include:

<aci> lrs

The set of rights often referred to as "read-only". The ACI subject is allowed to lookup the folder, read its contents and maintain \\Seen flags on messages. Meanwhile, the \Recent flags are maintained for the ACI subject as well.

<aci> lirstw

The set of rights often that could arguably be referred to "semi-full". The ACI subject is allowed to lookup the folder, read its contents and maintain flags on messages, as well as insert new messages in to the folder, and flag messages as \\Deleted, but not expunge the folder's contents.

Allowing ACI subjects to flag messages as \\Deleted but not delegating the right to **EXPUNGE** the folder's contents enables messages to quickly be restored by ACI subjects themselves, if the client used can be configured to show or hide messages flagged \\Deleted.

Please note that the configuration value of **/vendor/cmu/cyrus-imapd/sharedseen** on the folder has no bearing on the \\Deleted flag, but only on the \\Seen flag. To be more precise, all flags other than \\Seen are global. 


Features and Combined Access Rights
+++++++++++++++++++++++++++++++++++

For most features, ACI subjects need certain access rights on a folder in order to perform or control the feature.

METADATA

In order to be allowed to retrieve and/or set annotations on a folder, the ACI subject requires the ``l`` right, and any of ``r``, ``s``, ``w``, ``i`` or ``p`` rights. 
