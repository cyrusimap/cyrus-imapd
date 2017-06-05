.. cyrusman:: rmnews(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-rmnews:

==========
**rmnews**
==========

Expunge and remove news articles

Synopsis
========

.. parsed-literal::

    **rmnews** [ **-C** *config-file* ]

Description
===========

**rmnews** reads article data from the standard input.  It then expunges
and removes the listed articles.  **rmnews** is designed to be used by
InterNetNews to remove canceled, superseded, and expired news articles.

The input is processed as an INN :manpage:`expirerm(8)` file listing or
an INN cancel stream written as a \`\`WC'' entry in the
:manpage:`newsfeeds(5)` file. This data consists of lines of text, each
containing a list of relative article pathnames, with a single space
between entries.  If a listed file is contained in an IMAP news
mailbox, it is expunged out of that mailbox.  In any case, each listed
file is unlinked.

**rmnews** |default-conf-text| The optional ``newsprefix`` option
specifies a prefix to be prepended to newsgroup names to make the
corresponding IMAP mailbox names.  The required ``partition-news``
option specifies the pathname prefix to the IMAP news mailboxes.  The
value of ``partition-news`` concatenated with the
dots-to-slashes-converted value of ``newsprefix`` must be the pathname
of the news spool directory.

Options
=======

.. program:: rmnews

.. option:: -C config-file

    |cli-dash-c-text|

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
