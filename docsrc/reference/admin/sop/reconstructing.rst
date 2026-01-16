.. _reconstructing-mailboxes:

Reconstructing Mailboxes
========================

Individual mailboxes or folders
-------------------------------

If you have a mailbox within the filesystem but the folders and/or messages do not show up via IMAP or the cyradm utility, you may need to run ``reconstruct`` on the mailbox. This will rebuild the cyrus.* cache files and add any new folders to the internal cyrus mailbox list.

.. note::
    The ``-k`` switch preserves expunged messages so they can be undeleted if required. Without it, anything expunged will be permanently removed (Applies to Cyrus IMAP 2.3 and below.) On Cyrus IMAP 2.4.0 and above, this is not required as preserving the expunged messages is the only mode of operation.

::

    cyrus $ /usr/lib/cyrus-imapd/reconstruct -k -r -f user/jdoe@example.com
    discovered example.com!user.jdoe.Drafts
    discovered example.com!user.jdoe.Trash
    discovered example.com!user.jdoe.Sent
    user/jdoe@example.com
    user/jdoe/Sent@example.com
    user/jdoe/Trash@example.com
    user/jdoe/Drafts@example.com

The above output shows the 3 sub-folders Sent, Trash and Drafts were found in addition to the top level INBOX. Sub-folders are only detected by the presence of a cyrus.header file.

Once this has been done, the client will probably need to subscribe to the newly discovered folders.

.. note::

    After restoring folders using reconstruct, you may need to recalculate the quota usage for the mailbox since this is not done by the reconstruct command.

.. todo::
    Any advanced notes and other examples?

Recovering a complete spool directory
-------------------------------------

.. warning::
   Use the -m switch with caution!

When invoked with the -m switch, ``reconstruct`` will rebuild the master mailboxes file. This can (in theory) be used to recover from almost any sort of data corruption.

.. todo:: Is it possible to make things worse? For example if the system is still receiving emails because you forgot to turn off SMTP/LMTP first?
