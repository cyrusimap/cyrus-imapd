.. _imap-admin-commands-mbtool:

==========
**mbtool**
==========

intro

Synopsis
========

.. parsed-literal::

    **mbtool** [ **-C** *config-file* ] **-t** *mailboxes*...

Description
===========

**mbtool** is a tool for performing various actions on the indexes of a 
list of mailboxes. The only action currently supported is **-t**, which 
will normalize the ``internaldate`` time stamp of each record in the 
index to GMT.

It is intended that **mbtool** will be extended over time to perform 
more such actions.

**mbtool** |default-conf-text|

Options
=======

.. program:: mbtool

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -t

    Normalize ``internaldate`` on all index records of all listed
    *mailbox*\ es to GMT.

Examples
========

.. parsed-literal::

    **mbtool -t** user.jsmith

..

        Normalize ``internaldate`` on all index records in *user.jsmith*
        to GMT.

.. only:: html

    ::
    
        Working on user.jsmith...
        00000001: Mon, 07 Jul 2014 15:44:18 -0500 => Mon, 07 Jul 2014 20:44:18 +0000
        00000002: Fri Aug 30 14:46:03 CDT 2013 => Fri, 30 Aug 2013 19:46:03 +0000
        <...>

Files
=====

/etc/imapd.conf

See Also
========

:manpage:`imapd.conf(5)`
