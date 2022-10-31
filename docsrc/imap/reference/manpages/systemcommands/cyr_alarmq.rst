.. cyrusman:: cyr_alarmq(8)

.. _imap-reference-manpages-systemcommands-cyr-alarmq:

==============
**cyr_alarmq**
==============

List pending alarms for calalarmd

Synopsis
========

.. parsed-literal::

    **cyr_alarmq** [ **-C** *config-file* ]

Description
===========

**cyr_alarmq** lists pending alarms for calalarmd

**cyr_alarmq** |default-conf-text|

Options
=======

.. program:: cyr_alarmq

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -j, --json

    Produce JSON output rather than human-readable output.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
