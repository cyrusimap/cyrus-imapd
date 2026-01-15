.. _imap-admin-quotas-types:

Supported Quota Types
=====================

The Cyrus IMAP server supports quotas on Storage (KB), Messages (#),
Folders (#) and Annotation Storage (KB).  These types each have their
own identifier:

    * STORAGE
    * MESSAGE
    * X-NUM-FOLDERS
    * X-ANNOTATION-STORAGE

Storage Quotas
--------------

Storage quotas are defined as the number of kilobytes (KB) of the
relevant :rfc:`822` messages located within a quota root. Each copy of
a message is counted independently, even when the server can conserve
disk space use by making hard links to message files. The additional
disk space overhead used by mailbox index and cache files is not
charged against a quota. On servers with ``delete_mode: delayed``
and/or ``expunge_mode:delayed`` space used by deleted mailboxes or
expunged messages are not charged against quota.

Numeric Quotas
--------------

Numeric Quotas are quite simply a limit on the number of a particular
class of object.  Cyrus IMAP currently supports quotas on the number of
messages and/or folders below a given quota root.
