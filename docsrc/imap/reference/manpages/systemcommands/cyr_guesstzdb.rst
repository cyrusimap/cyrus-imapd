.. cyrusman:: cyr_guesstzdb(8)

.. _imap-reference-manpages-systemcommands-cyr_guesstzdb:

==========
**cyr_guesstzdb**
==========

Create a database to guess the IANA timezone equivalent of a VTIMEZONE.

Synopsis
========

.. parsed-literal::

    **cyr_guesstzdb** **-c** [ **-C** *config-file* ] [ **-F** *alt-file* ] [ **-R** *start,end* ]
    **cyr_guesstzdb** **-p** [ **-C** *config-file* ] [ **-F** *alt-file* ]

Description
===========

**cyr_guesstzdb** creates or prints a database to support mapping a given
VTIMEZONE to its IANA timezone equivalent. The mapping itself is performed
within Cyrus (see the guesstz headers and implementation files).

**cyr_guesstzdb** examines the VTIMEZONE definitions found in *zoneinfo_dir*
as specified in *config-file*. By default, it stores the database in a file
named *guesstz.db* in the zone directory.

**cyr_guesstzdb** |default-conf-text|

Options
=======

.. program:: cyr_guesstzdb

.. option:: -c

    create the database

.. option:: -p

    print the database

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -F alt-file

    create or print the generated datase in the file *alt-file*

.. option:: -R start,end

    define the time range in which to guess timezones.

    The *start* and *end* arguments must be valid UTC datetimes as specified
    in RFC 5545, section 3.3.5, FORM #2.
    The default range is 20000101T000000Z to 20380101T000000Z.


Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
