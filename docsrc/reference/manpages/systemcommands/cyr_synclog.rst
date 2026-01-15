.. cyrusman:: cyr_synclog(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-cyr_synclog:

===============
**cyr_synclog**
===============

is used to append a value to the log file.  You can either specify
the log type and value, or an entire log line.

Synopsis
========

.. parsed-literal::

    **cyr_synclog** [ **-C** *config-file* ] [ *-{type}* *value* ]
    **cyr_synclog** [ **-C** *config-file* ] *"<raw-log-line>"*

Description
===========

**cyr_synclog** is used to append a value to the log file.  You can
either specify the log type and value, or an entire log line.

Running without any options will print a short usage document.

**cyr_synclog** |default-conf-text|

Options
=======

.. program:: cyr_synclog

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -u, --user          user

.. option:: -U, --unuser        unuser

.. option:: -v, --sieve         sieve

.. option:: -m, --mailbox       mailbox

.. option:: -M, --unmailbox     unmailbox

.. option:: -a, --append        append

.. option:: -c, --acl           acl

.. option:: -q, --quota         quota

.. option:: -n, --annotation    annotation

.. option:: -s, --seen          seen

.. option:: -b, --subscription  subscription

Examples
========

.. parsed-literal::

    **cyr_synclog -m** *user.brong*

..

        Add the mailbox *user.brong* to the log.

.. parsed-literal::

    **cyr_synclog -u** *brong*

..

        Add the user *brong* to the log.

.. parsed-literal::

    **cyr_synclog -C** */etc/imapd-special.conf* **-s** *user.brong* *brong*

..

        Add a log entry to mark mailbox *user.brong* as seen by user
        *brong*.

.. parsed-literal::

    **cyr_synclog** *"SEEN user.brong brong"*
..

        Add a log line, using the raw format, to mark mailbox
        *user.brong* as seen by user *brong*.

History
=======

|v3-new-command|

Files
=====

/etc/imapd.conf,
<configdirectory>/sync/log

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`sync_client(8)`
