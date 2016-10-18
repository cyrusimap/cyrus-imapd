===============================
Automatic Creation of Mailboxes
===============================

Cyrus IMAP features the ability to create mailboxes automatically;

*   for successful login events,

*   for email messages that arrive for a user,

*   when a Sieve script uses the "fileinto" action.

.. NOTE::

    Cyrus IMAP documentation is a work in progress, and the completion
    of this part of the documentation is pending the resolution of
    :task:`41`.

When operating an IT infrastructure, Cyrus IMAP may only be one part of
such larger environment. When adding a user
*John Doe <john.doe@example.org>*, several pieces may need to fall or
put in place to ensure the account is fully functional.

Cyrus IMAP allows the automatic creation of John's INBOX, and selected
sub-folders, either when John first logs in to Cyrus IMAP, or when the
first message is to be delivered to John's INBOX.

Additional features of this functionality include;

*   the automatic creation of a Sieve script for
    :ref:`imap-features-server-side-filtering`.

*   setting a storage quota and message quota for the user,

*   automatic subscription to folders in the
    :ref:`imap-features-namespaces-personal`,

*   automatic subscription to a selection of or all shared folders.

.. IMPORTANT::

    Third party solutions incorporating Cyrus IMAP, and distributors of
    Cyrus IMAP (such as your Linux distribution) may have disabled this
    functionality altogether, during the building of the packages --
    most likely because they employ different means to get user's
    mailboxes created.

    Cyrus IMAP does not currently strip options from man-pages that are
    rendered irrelevant by the functionality not being built in, so
    while the man-page on your system may refer to settings related to
    this functionality, the actual functionality may not be available.

To enable the automatic creation of mailboxes, set the following options
in :cyrusman:`imapd.conf(5)`.

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_quota
    :end-before: endblob autocreate_quota


.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_post
    :end-before: endblob autocreate_post

Other settings in :cyrusman:`imapd.conf(5)` affecting automatic
options.

Autocreation of mailboxes
-------------------------

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_inbox_folders
    :end-before: endblob autocreate_inbox_folders

Automatic quota settings
------------------------

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_quota_messages
    :end-before: endblob autocreate_quota_messages


Autocreation of Sieve scripts
-----------------------------

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_sieve_folders
    :end-before: endblob autocreate_sieve_folders

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_sieve_script
    :end-before: endblob autocreate_sieve_script

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_sieve_script_compile
    :end-before: endblob autocreate_sieve_script_compile

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_sieve_script_compiled
    :end-before: endblob autocreate_sieve_script_compiled

Automated folder subscriptions
------------------------------

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_subscribe_folders
    :end-before: endblob autocreate_subscribe_folders

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_subscribe_sharedfolders
    :end-before: endblob autocreate_subscribe_sharedfolders

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_subscribe_sharedfolders_all
    :end-before: endblob autocreate_subscribe_sharedfolders_all

Autocreation of users
---------------------

.. include:: /imap/admin/configs/imapd.conf.rst
    :start-after: startblob autocreate_users
    :end-before: endblob autocreate_users

See :cyrusman:`imapd.conf(5)` for the full documentation of
all options.

.. seealso::

    *   :ref:`imap-features-murder`
    *   :ref:`imap-features-mailbox-distribution`
    *   :ref:`imap-features-quota`

Limitations to the Automatic Creation of Mailboxes
==================================================

#.  A user may in fact be able to succesfully login to IMAP with both a
    full primary recipient email address such as
    ``john.doe@example.org``, as well as a secondary recipient email
    address such as ``jdoe@example.org``.

    Unless a process known as login username canonification is used,
    this could result in two different mailbox hierarchies being
    created;

    *   ``user/john.doe@example.org``

    *   ``user/jdoe@example.org``

#.  When a user *Jane Gi <jane.gi@example.org>* marries *John Doe* and
    adopts her new husband's surname, her primary recipient email
    address may change to become ``jane.doe@example.org``.

    Note that *John Doe* does not need to be an ``example.org`` user for
    such event to occur, and that many countries allow the husband to
    take the maiden name of their spouse instead -- so even if the
    employees and/or associates of an organization running Cyrus IMAP
    are exclusively male, this may still apply to that organization.

    The functionality stated in this document does **not** rename
    ``user/jane.gi@example.org`` to become
    ``user/jane.doe@example.org``.

Back to :ref:`imap-features`
