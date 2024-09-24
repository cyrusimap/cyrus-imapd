.. _carddav:

=======
CardDAV
=======

Configuration
=============

.. sidebar:: addressbookprefix

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob addressbookprefix
       :end-before: endblob addressbookprefix

When enabled, the CardDAV module allows Cyrus to function as a contacts server.
This module uses a subset of the mailbox hierarchy as addressbook collections,
the toplevel of which is specified by the ``addressbookprefix`` option. The public
addressbook hierarchy will reside at the toplevel of the shared mailbox
namespace. A user's personal addressbook hierarchy will be a child of their
Inbox.

For example, using the default value for addressbookprefix, an
addressbook named Default for user "murch" would reside in the mailbox named
``user.murch.#addressbooks.Default``.

.. warning::

    Note that mailboxes in the addressbook hierarchies (those under
    addressbookprefix) **should not** be accessed with an IMAP client as doing so will
    leave a mailbox in a state unsuitable for CardDAV. To this end, addressbook
    mailboxes will not returned by Cyrus imapd in response to an IMAP client's
    request for the available mailbox list, but Cyrus imapd can not otherwise
    prevent an IMAP client from accessing them.

Administration
==============

The CardDAV module will *automatically* create a default addressbook for a user
the first time that the user authenticates to the CardDAV server. Note that the
user MUST have an existing IMAP Inbox in order for the addressbook to be
created.

.. sidebar:: carddav_allowaddressbookadmin

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
      :start-after: startblob carddav_allowaddressbookadmin
      :end-before: endblob carddav_allowaddressbookadmin

There is also a Cyrus web GUI for managing addressbook resources.
It allows you to:

    * Create new collections
    * Delete existing collections
    * Download existing collections via prepared URLs
    * Set to “Public”, which toggles the `lrw9` rights for the `anyone` user.

To delete the value of a property, click on ✎ and then submit empty new value.

The Cyrus web GUI for addressbook management is disabled by default,
but can be enabled with the "carddav_allowaddressbookadmin" option.

To access the Cyrus web GUI for addressbook management, point
a web browser at ``https://<servername>/dav/addressbooks/user/<username>``

Addressbook access controls
---------------------------

Cyrus uses the same :ref:`access controls for addressbooks <calendar_ACL>`  as it
does for calendars, except that the scheduling rights (7, 8, 9) have no use with
addressbooks and are ignored.
