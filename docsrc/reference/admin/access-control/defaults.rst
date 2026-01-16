.. _imap-admin-access-control-defaults:

Access Control Defaults
=======================

Administrators
--------------

Regardless of the ACL on a mailbox, users who are listed in the
``admins`` configuration option in :cyrusman:`imapd.conf(5)` implicitly
have the ``l`` and ``a`` rights on all mailboxes.

Administrators can also see across domains which normal users cannot.
 
.. warning::

    An admin user should not be a normal email account. 
 
Mailbox owners
-------------- 

The user who owns a mailbox folder has additional rights which are set
regardless of any additional ACLs. These are:

* **l** - :ref:`lookup <imap-admin-access-control-right-l>`
* **k** - :ref:`create subfolders <imap-admin-access-control-right-k>`
* **x** - :ref:`delete this folder <imap-admin-access-control-right-x>`
* **a** - :ref:`administer <imap-admin-access-control-right-a>`

These are set in ``implicit_owner_rights`` of :cyrusman:`imapd.conf(5)`.
 
Default
-------

For all other mailboxes not owned by a user, any user accessing these
mailboxes have the following default privileges:

* **l** - :ref:`lookup <imap-admin-access-control-right-l>`
* **r** - :ref:`read contents <imap-admin-access-control-right-r>`
* **s** - :ref:`seen <imap-admin-access-control-right-s>`

These are set in ``defaultacl`` of :cyrusman:`imapd.conf(5)`.

Initial ACLs for Newly Created Mailboxes
----------------------------------------

When a mailbox is created, its ACL starts off with a copy of the ACL of its closest parent mailbox. When a user is created, the ACL on the user's ``INBOX`` starts off with a single entry granting all rights to the user. When a non-user mailbox is created and does not have a parent, its ACL is initialized to the value of the ``defaultacl`` option in :cyrusman:`imapd.conf(5)`.

Other Implicit Rights
---------------------

Note that some rights are available implicitly, for example 'anonymous'
always has 'p' on user INBOXes, and users always have ``la`` rights on
mailboxes within their INBOX hierarchy.
