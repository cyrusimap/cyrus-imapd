.. _imap-developer-guidance-special-chars:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Special Characters
=====================================

This document is supposed to be a repository of "special characters"
used in Cyrus naming of users, folders, directory paths, etc.

Current Uses
------------

|
| Character: +

-  (LMTP) Separation of postuser and target mailbox for delivery
-  (LMTP) Separation of username and submailbox for delivery
-  (IMAP) Flag at end of login name that indicates that LIST should
   return LSUB results (when imapmagicplus is set)
-  (POP3) POP a subfolder directly (e.g. rjs3+foo POPs user.rjs3.foo)

|
| Character: . /

-  [mailbox names] Hierarchy separators

|
| Character: ^

-  [mailbox names] In unixhierarchysep, ^ is the part of the internal
   name that represents a '.'

|
| Characters: @ %

-  [usernames] These are realm separators for the purposes of
   authentication

|

Future Uses
-----------

| Character: +

-  IMAP LIST filters (e.g. rjs3+foo will only list folders that match
   foo\*)
-  possibly other interpretations here:
   - rjs3+foo will do an effective chroot(foo.)
   - rjs3+foo will only list folders in user.rjs3.foo\*
