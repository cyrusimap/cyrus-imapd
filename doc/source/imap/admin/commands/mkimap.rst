.. _imap-admin-commands-mkimap:

==========
``mkimap``
==========

A (small) Perl script to aid in creating spool and configuration
directories for Cyrus IMAP installations.

Synopsis
========

.. parsed-literal::

    mkimap config-file

Description
===========

The ``mkimap`` script reads in the configuration file specified on the
command-line or uses :file:`/etc/imapd.conf` to determine a list of
directories that Cyrus IMAP would need to operate.

Among these directories are:

    *   the ``configdir`` (from :manpage:`imapd.conf`)

    *   the ``partition-$name`` directories (from :manpage:`imapd.conf`)

    *   the ``meta-partition-$name`` directories (from
        :manpage:`imapd.conf`)

.. NOTE::

    This utility needs to be executed as the user ``cyrus`` (or the user
    you run the Cyrus IMAP service as).

Options
=======

.. program:: mkimap

.. option:: config-file

    |cli-dash-c-text|

Examples
========

See Also
========
