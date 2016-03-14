.. _imap-admin-access-control-defaults:

Access Control Defaults
=======================

Administrators
--------------
The admin users (:cyrusman:`imapd.conf(5)` variable "admins") get automatic go-everywhere, do-everything privileges on every mailbox. They can also see across domains which normal users can't.
 
.. note::

    An admin user should not be a normal email account. 
 
Mailbox owners
-------------- 

The user who owns a mailbox folder has additional rights which are set regardless of any additional ACLs. These are: 

* **l** - :ref:`lookup <imap-admin-access-control-right-l>`
* **k** - :ref:`create subfolders <imap-admin-access-control-right-k>`
* **x** - :ref:`delete this folder <imap-admin-access-control-right-x>`
* **a** - :ref:`administer <imap-admin-access-control-right-a>`

These are set in **implicit_owner_rights** of :cyrusman:`imapd.conf(5)`.
 
Default
-------

For all other mailboxes not owned by a user, any user accessing these mailboxes have the following default privileges:

* **l** - :ref:`lookup <imap-admin-access-control-right-l>`
* **r** - :ref:`read contents <imap-admin-access-control-right-r>`
* **s** - :ref:`seen <imap-admin-access-control-right-s>`

These are set in **defaultacl** of :cyrusman:`imapd.conf(5)`.

