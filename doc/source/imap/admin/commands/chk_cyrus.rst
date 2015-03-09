.. _imap-admin-commands-chk_cyrus:

=============
``chk_cyrus``
=============

Perform a consistency check of the Cyrus IMAP mail spool.

Synopsis
========

.. parsed-literal::

    chk_cyrus [OPTIONS]

Description
===========

The ``chk_cyrus`` program outputs a list of files and/or directories
that it expects to exist, but that in fact do not.

Options
=======

.. program:: chk_cyrus

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -P partition

    Limit to partition ``partition``.

.. option:: -M mailbox

    Only check mailbox ``mailbox``.

    .. IMPORTANT::

        The mailbox must be specified in the internal format, so rather
        than specifying ``user/john/Trash@example.org``, you will want
        to specify ``example.org!user.john.Trash``.

Examples
========

See Also
========
