.. cyrusman:: cyr_dbtool(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)
.. author: Bron Gondwana (Fastmail)

.. _imap-reference-manpages-systemcommands-cyr_dbtool:

==============
**cyr_dbtool**
==============

Manage Cyrus databases

Synopsis
========

.. parsed-literal::

    **cyr_dbtool** [ **-C** *config-file* ] [ **-b** ] [ **-c** ] [ **-N** ] [ **-n** ] [ **-R** ] [ **-S** ] [ **-T** ] [ **-t** ]
            *db-file* *db-backend* *action* [ *key* ] [ *value* ]

Description
===========

**cyr_dbtool** is used to manage a cyrusdb file. The usable actions are:

    **show** *[<prefix>]*

    **get** *<key>*

    **set** *<key> <value>*

    **delete** *<key>*

    **consistent**

    **repack**

    **damage**

    **batch**

You may omit *key* or *key/value* and specify one per line on stdin.
Keys are terminated by tab or newline, values are terminated by newline.

Running without any options will list the available database backends and
usable actions.

The *consistent* action runs a consistency check on the DB by calling
'myconsistent' on it.

The *repack* action will compress the database by removing stale data
on backends which support it.  It's a NOOP otherwise.

The *damage* action makes the file dirty and then crashes, so it will need
to be repaired.  It's useful for testing crash recovery speed.

The *batch* action takes commands as bastrings on stdin, and writes results
back out as bastrings.

**cyr_dbtool** |default-conf-text|

.. Note::
    Note that the file locations are NOT read out of the configuration
    file, and must be supplied on the command line.

.. Tip::
    The format of all Cyrus databases is detailed in the distribution in
    file doc/internal/database-formats.html.  Please consult that for
    details.

Options
=======

.. program:: cyr_dbtool

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -b, --base64

    If specified, all keys and values are provided in base64 format, making
    automation easier, particularly with batch.  NOTE: the commands in batch
    mode are still in plain text, just the keys and values are encoded.

.. option:: -c, --convert

    Convert the database file if the specified format on the command line
    doesn't match the database file's format.

.. option:: -N, --no-checksum

    When reading, don't check checksums, and if the database supports it,
    create with a NULL checksum engine.

.. option:: -n, --create

    Create the database file if it doesn't already exist.

.. option:: -R, --readonly

    Open the database readonly.  Even if --create is specified, will not
    create a database if it doesn't exists (since that needs writing).
    NOTE: you MUST use '-T' with '-R' as you'll stay in a read-only
    transaction for the entire time.

    With the twom backend, this will use an MVCC transaction which can
    run slowly without blocking any other processes.

.. option:: -S, --no-sync

    If the backend supports it, don't fsync on commit (DANGEROUS).  Useful
    for benchmarking.

.. option:: -T, --use-transaction

    Use a transaction to do the action (most especially for 'show') - the
    default is to run without transactions

.. option:: -t, --no-transaction

    A noop, since no transaction is already the default.


Examples
========

This series of examples address manipulating the *user_deny.db*
database, which is used to deny users access to specific services.  This
is typically a Cyrus "flat" format database.

*user_deny.db* is indexed by userid and each record contains the
database version number (currently 2), a list of "wildmat" patterns
specifying Cyrus services to be denied, and a text message to be
displayed to the user upon denial. The service names to be matched are
those as used in :cyrusman:`cyrus.conf(5)`.  :cyrusman:`cyr_deny(8)`
provides more convenient way to manage *user_deny.db*.

.. Note::

    Given that *keys* are tab-delimited, these examples use the notation
    <tab> to indicate the tab character.  When entering this via the
    command line, remember to escape tabs.  In a normal shell, one can
    do so with <ctrl-v> (^v).  The sequence "<ctrl-v><ctrl-i>" (^v^i)
    works well to enter tab characters.

.. parsed-literal::

    **cyr_dbtool** /var/lib/imap/user_deny.db flat baduser "2<tab>pop3,imap<tab>Denied"

..

        Deny the user 'baduser' access to imap and pop3.

.. only:: html

    Subsequent login attempts by this user would result in authentication
    failures, and log entries like this::

        # grep baduser /var/log/mail.log
        Sep 19 14:34:57 cyrushost cyrus/imap[635]: fetching user_deny.db entry for 'baduser'
        Sep 19 14:34:57 cyrushost cyrus/imap[635]: user 'baduser' denied access to service 'imap'
        Sep 19 14:34:57 cyrushost cyrus/imap[635]: badlogin: cyrus.example.org [192.168.190.14] plaintext baduser SASL(-14): authorization failure: user 'baduser' is denied access to service 'imap'
        Sep 19 14:38:21 cyrushost cyrus/imap[816]: badlogin: cyrus.example.org [192.168.190.14] plaintext baduser SASL(-13): authentication failure: checkpass failed

.. parsed-literal::

    **cyr_dbtool** /var/lib/imap/user_deny.db flat show

..

        Show all current database records.

.. only:: html

    ::

        baduser 2       pop3,imap       Denied

.. parsed-literal::

    **cyr_dbtool** /var/lib/imap/user_deny.db flat get baduser

..

        Get the current database record(s) for user 'baduser'.

.. only:: html

    ::

        2       pop3,imap       Denied

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
