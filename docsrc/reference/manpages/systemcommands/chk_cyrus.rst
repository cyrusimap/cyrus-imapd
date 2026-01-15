.. cyrusman:: chk_cyrus(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-chk_cyrus:

=============
**chk_cyrus**
=============

Perform a consistency check of the Cyrus IMAP mail spool.

Synopsis
========

.. parsed-literal::

    **chk_cyrus** [ **-C** *config-file* ] [ **-P** *partition* | **-M** *mailbox* ]

Description
===========

**chk_cyrus** is used to perform a consistency check on the cyrus
datastore, and output a list of files/directories that are expected to
exist, but do not.  Status messages are output to stderr, the list of
files/directories is output to stdout.  This list can be passed to a
backup program to aid a partial restoration, for instance.

**chk_cyrus** |default-conf-text|

Options
=======

.. program:: chk_cyrus

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -P partition, --partition=partition

    Limit to partition *partition*.  May not be specified with **-M**.

.. option:: -M mailbox, --mailbox=mailbox

    Only check mailbox *mailbox*.  May not be specified with **-P**.

    .. IMPORTANT::

        The mailbox must be specified in the internal format, so rather
        than specifying ``user/john/Trash@example.org``, you will want
        to specify ``example.org!user.john.Trash``.

Examples
========

.. parsed-literal::

    **chk_cyrus -P** *default*

..

        Perform consistency checks on *default* partition.

.. parsed-literal::

    **chk_cyrus -C** */usr/local/etc/imapd-slot1.conf* **-P** *default*

..

        Perform consistency checks on *default* partition using specified
        configuration file.

.. parsed-literal::

    **chk_cyrus -M** *user.marysmith*

..

        Perform consistency checks on mailbox *user.marysmith*.

See Also
========
:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
