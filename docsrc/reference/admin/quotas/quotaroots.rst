.. _imap-admin-quotas-roots:

Quota Roots
===========

Quotas are applied to quota roots, which can be at any level of the mailbox hierarchy. Quota roots need not also be mailboxes.

Quotas on a quota root apply to the sum of the usage of any mailbox at that level and any sub-mailboxes of that level that are not underneath a quota root on a sub-hierarchy. This means that each mailbox is limited by at most one quota root.

For example, if the mailboxes

::

   user/bovik
   user/bovik/list/imap
   user/bovik/list/info-cyrus
   user/bovik/saved
   user/bovik/todo

exist and the quota roots

::

   user/bovik
   user/bovik/list
   user/bovik/saved

exist, then the quota root ``user/bovik`` applies to the mailboxes ``user/bovik`` and ``user/bovik/todo``; the quota root ``user/bovik/list`` applies to the mailboxes ``user/bovik/list/imap`` and ``user/bovik/list/info-cyrus``; and the quota root ``user/bovik/saved`` applies to the mailbox ``user/bovik/saved``.

Quota roots are created automatically when they are mentioned in the
:ref:`imap-reference-manpages-systemcommands-cyradm-setquota` command. Quota
roots may not be deleted through the protocol, see Removing Quota Roots
for instructions on how to delete them.
