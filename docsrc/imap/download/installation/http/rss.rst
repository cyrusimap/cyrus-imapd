.. _rss:

=========
RSS Feeds
=========

About RSS Feeds
===============

Use the RSS module to allow read-only access to some mailboxes over RSS.

An authenticated user can see the list of available mailboxes at the `/rss/`
URL on the Cyrus server. The mailbox list for RSS is limited to only the
mailboxes the RSS module has been configured to expose **and** the mailboxes
the authenticated user has permission to see, according to the normal mailbox
:ref:`ACLs <imap-admin-access-control-lists>`.

Configuration
=============

List of mailboxes: rss_feeds
----------------------------

.. sidebar:: rss_feeds

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob rss_feeds
       :end-before: endblob rss_feeds

The list of available RSS feeds can be obtained by clients by accessing the
``/rss/`` URL on the Cyrus server.

The rss_feeds option uses the
`wildmat <https://tools.ietf.org/html/rfc3977#section-4>`_ format to specify
which mailboxes/folders will be made available via RSS. This list is further
limited to only those mailboxes and folders that the authenticated user has
permissions to see.

The rss_feeds option uses the
:ref:`internal namespace <mailbox-namespaces>`, which uses "." as a hierarchy
separator, regardless of what ``unixhierarchysep`` is set to.

Examples:

* ``user.bob`` - will serve only user "Bob"'s inbox.
* ``rss.*`` - will serve all folders under the shared mailbox called "rss".
* ``rss*`` - will serve all content under mailboxes that start with "rss":
  rss-cool and rss-important will be included, for example.
* ``*,!user`` - will serve all shared mailboxes, but no personal mailboxes.
* ``*`` - will serve all shared and personal mailboxes.

Display of mailbox list: rss_feedlist_template
----------------------------------------------

.. sidebar:: rss_feedlist_template

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob rss_feedlist_template
       :end-before: endblob rss_feedlist_template


By default, the server will present the list as a
simple unordered list in an HTML document. To customize the look and feel of the
feed list, the ``rss_feedlist_template`` option can be used to point to a HTML
template file. This file can use Cascading Style Sheets, JavaScript, etc.
All content that the template uses **must** reside under the
``httpdocroot``. Consult :cyrusman:`imapd.conf(5)` for specifics on the
required contents of this custom file.

Note that for sites running Cyrus Murder, ``rss_feedlist_template`` only needs
to be set on frontend servers, since only those servers have the complete
mailbox list.
