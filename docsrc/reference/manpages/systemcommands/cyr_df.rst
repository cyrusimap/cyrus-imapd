.. cyrusman:: cyr_df(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-cyr_df:

==========
**cyr_df**
==========

Report Cyrus spool partition disk space usage

Synopsis
========

.. parsed-literal::

    **cyr_df** [ **-C** *config-file* ] [ **-m** ]

Description
===========

**cyr_df** examines the Cyrus spool partitions and reports on their
disk space usage.

**cyr_df** |default-conf-text|

Options
=======

.. program:: cyr_df

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -m, --metadata

    Report on metadata partitions rather than message file partitions.

Examples
========

.. parsed-literal::

    **cyr_df**

..

        Display partition usage.

.. only:: html

    ::

        Partition       1k-blocks         Used    Available Use% Location
        default          19610300     13460832      5153412  72% /var/spool/cyrus

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
