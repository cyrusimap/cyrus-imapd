.. cyrusman:: mkimap(8)

.. _imap-admin-systemcommands-mkimap:

==========
**mkimap**
==========

A (small) Perl script to aid in creating spool and configuration
directories for Cyrus IMAP installations.

Synopsis
========

.. parsed-literal::

    **mkimap** *config-file*

Description
===========

The **mkimap** script reads in the configuration file specified on the
command-line or uses :file:`/etc/imapd.conf` to determine a list of
directories that Cyrus IMAP would need to operate.

Among these directories are:

    *   the ``configdir`` (from :cyrusman:`imapd.conf(5)`)

    *   the ``partition-$name`` directories (from :cyrusman:`imapd.conf(5)`)

    *   the ``meta-partition-$name`` directories (from
        :cyrusman:`imapd.conf(5)`)

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

.. parsed-literal::

    **mkimap** */etc/imapd.conf*

..

        Create necessary directories based on settings in
        */etc/imapd.conf*.

.. only:: html

    ::

        reading configure file /etc/imapd.conf...
        i will configure directory /var/lib/imap.
        i saw partition /var/spool/imap/mail.
        i saw partition /var/spool/imap/news.
        done
        configuring /var/lib/imap...
        creating /var/spool/imap/mail...
        creating /var/spool/imap/news...
        done

See Also
========
