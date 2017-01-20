.. _imap-admin-access-control-combining-rights:

=======================
Combining Access Rights
=======================

Access rights can combined to set a typical set of "read", "write" and
"full control", potentially making it easier for client implementors to
present their users with an interface to administer the ACLs to their
mailboxes easily.

.. NOTE::

    :rfc:`4314` defines combinations of rights that should resulted in
    an untagged ``READ-ONLY`` or ``READ-WRITE`` response to a ``SELECT``
    command, depending on whether the user has flag modification rights
    such as the :ref:`imap-admin-access-control-right-t` for maintaining
    ``\Deleted`` flags on messages, and the
    :ref:`imap-admin-access-control-right-w` right for maintaining non-
    system flags on messages.

    Cyrus IMAP responds with ``READ-ONLY`` if the mailbox's
    ``/vendor/cmu/cyrus-imapd/sharedseen`` annotation is set to ``true``
    and the user selecting the mailbox is not given the
    :ref:`imap-admin-access-control-right-e`,
    :ref:`imap-admin-access-control-right-i`,
    :ref:`imap-admin-access-control-right-n`,
    :ref:`imap-admin-access-control-right-t` or
    :ref:`imap-admin-access-control-right-w` right.

lrs
===

The set of rights often referred to as "read-only". The ACI subject is
allowed to lookup the folder, read its contents and maintain ``\Seen``
flags on messages. Meanwhile, the ``\Recent`` flags are maintained for
the ACI subject as well.

lirstw
======

The set of rights that could arguably be referred to "semi-full".

The ACI subject is allowed to lookup the folder, read its contents and
maintain flags on messages, as well as insert new messages in to the
folder, and flag messages as ``\Deleted``, but not expunge the folder's
contents.

Allowing ACI subjects to flag messages as ``\Deleted`` but not
delegating the right to ``EXPUNGE`` the folder's contents enables
messages to quickly be restored by ACI subjects themselves, if the
client used can be configured to show or hide messages flagged
``\Deleted``.

.. seealso::

    *   :ref:`imap-admin-sop-restoring-expunged-messages`

Please note that the configuration value of
``/vendor/cmu/cyrus-imapd/sharedseen`` on the folder has no bearing on
the ``\Deleted`` flag, but only on the ``\Seen`` flag. To be more
precise, all flags other than ``\Seen`` are global.

ACL "Macros"
============

Cyrus adminitration supports short-hand macros you may use:

none
----

    Remove any existing ACL for this ACI

read (lrs)
----------

    Grant the ACI read-only access to the mailbox (*lookup*, *read* and
    *seen*).

post (lrsp)
-----------

    Give the ACI read access to the mailbox, and allow them to post to
    the mailbox using the delivery system (*lookup*, *read*, *seen* and
    *post*).

    Most delivery systems do not provide authentication, so the ``p``
    right usually has meaning only for the "anonymous" user.

append (lrsip)
--------------

    The ACI can read and append to the mailbox, either through IMAP, or
    through the delivery system.

write (lrswipkxtecd)
--------------------

    The ACI may do pretty much anything with a mailbox, and folders
    within it.

delete (lrxte)
--------------

    The ACI may list, read, delete and expunge messages and delete
    folders.

all (lrswipkxtecda)
-------------------

    Same as write, plus admin rights.
    
Features and Combined Access Rights
===================================

For most features, ACI subjects need certain access rights on a folder
in order to perform or control the feature.

METADATA
++++++++

In order to be allowed to retrieve and/or set annotations on a folder,
the ACI subject requires the :ref:`imap-admin-access-control-right-l`
right, and any one of the :ref:`imap-admin-access-control-right-r`,
:ref:`imap-admin-access-control-right-s`,
:ref:`imap-admin-access-control-right-w`,
:ref:`imap-admin-access-control-right-i` or
:ref:`imap-admin-access-control-right-p` rights.
