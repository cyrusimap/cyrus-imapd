.. _webdav:

======
WebDAV
======

Configuration
=============

.. sidebar:: davdriveprefix

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob davdriveprefix
       :end-before: endblob davdriveprefix

When enabled, the WebDAV module allows Cyrus to function as a storage server.
This module uses a subset of the mailbox hierarchy as collections, the toplevel
of which is specified by the ``davdriveprefix`` option. The public storage hierarchy
lives at the toplevel of the shared mailbox namespace. A user's personal
storage hierarchy will be a child of their Inbox.

For example, using the default value for davdriveprefix, a collection named photos
for user "murch" would reside in the mailbox named ``user.murch.#drive.photos``.
A user would access their storage at
``https://<servername>/dav/<davdriveprefix>/user/<userid>``, which for
the example above, comes to: ``https://<servername>/dav/drive/user/murch``.

.. warning::

    Note that mailboxes in the storage hierarchies (those under `davdriveprefix`)
    **should not** be accessed with an IMAP client as doing so will leave a mailbox
    in a state unsuitable for WebDAV. To this end, storage mailboxes will not
    returned by Cyrus imapd in response to an IMAP client's request for the
    available mailbox list, but Cyrus imapd can not otherwise prevent an IMAP client
    from accessing them.

Administration
==============

Provisioning
------------

The WebDAV module will automatically create a toplevel (root) collection for a
user the first time that the user authenticates to the WebDAV server. Note that
the user MUST have an existing IMAP Inbox in order for the root collection to be
created.

Storage access controls
-----------------------

Cyrus uses the same :ref:`access controls for storage <calendar_ACL>`  as it
does for calendars, except that the scheduling rights (7, 8, 9) have no use with
storage and are ignored.
