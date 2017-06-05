.. cyrusman:: cvt_cyrusdb(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-cvt_cyrusdb:

===============
**cvt_cyrusdb**
===============

Convert a database file between cyrus database formats

Synopsis
========

.. parsed-literal::

    **cvt_cyrusdb** [ **-C** *config-file* ] *old-file* *old-fileformat* *new-file* *new-file-format*

Description
===========

**cvt_cyrusdb** is used to convert a cyrusdb file between different
database backends.  Note that you should not attempt to use the same
file for input and output.

Running without any options will list the available database backends.

**cvt_cyrusdb** |default-conf-text|

.. NOTE::
    Note that the file locations are NOT read out of the configuration
    file, and must be supplied on the command line.


Options
=======

.. program:: cvt_cyrusdb

.. option:: -C config-file

    |cli-dash-c-text|

Examples
========

.. parsed-literal::

    **cvt_cyrusdb**

..

        Display list of available backends.

.. only:: html

    ::

        Usage: /usr/lib/cyrus/bin/cvt_cyrusdb [-C altconfig] <old db> <old db backend> <new db> <new db backend>
        Usable Backends:  berkeley, berkeley-nosync, berkeley-hash, berkeley-hash-nosync, flat, skiplist, quotalegacy

.. parsed-literal::

    **cvt_cyrusdb** /var/lib/imap/mailboxes.db skiplist /tmp/mailboxes.db berkeley-nosync

..

        Convert */var/lib/imap/mailboxes.db* from **skiplist** format to
        */tmp/mailboxes.db* in **berkeley-nosync** format.

.. only:: html

    ::

        Converting from /var/lib/imap/mailboxes.db (skiplist) to /tmp/mailboxes.db (berkeley-nosync)

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
