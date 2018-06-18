.. cyrusman:: mkimap(8)

.. author: Jeroen van Meeuwen (Kolab Systems)
.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-mkimap:

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

    *   the ``configdirectory`` (from :cyrusman:`imapd.conf(5)`)

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
        i saw partition /var/spool/cyrus/mail.
        i saw partition /var/spool/cyrus/news.
        done
        configuring /var/lib/imap...
        creating /var/spool/cyrus/mail...
        creating /var/spool/cyrus/news...
        done

See Also
========
