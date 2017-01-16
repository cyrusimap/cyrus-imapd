.. cyrusman:: ptdump(8)

.. _imap-reference-manpages-systemcommands-ptdump:

==========
**ptdump**
==========

Program to to dump the current PTS (protection database authorization)
cache.

Synopsis
========

.. parsed-literal::

    **ptdump** [**-C** *filename*] 

Description
===========

The **ptdump** program outputs a list of entries from the PTS DB.

**ptdump** |default-conf-text|

Options
=======

.. program:: ptdump

.. option:: -C config-file

    |cli-dash-c-text|

Files
=====

/etc/imapd.conf

See Also
========
:cyrusman:`imapd.conf(5)`
