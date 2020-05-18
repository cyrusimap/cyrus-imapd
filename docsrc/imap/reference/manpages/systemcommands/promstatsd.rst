.. cyrusman:: promstatsd(8)

.. _imap-reference-manpages-systemcommands-promstatsd:

==============
**promstatsd**
==============

Cyrus Prometheus statistics collating daemon

Synopsis
========

.. parsed-literal::

    **promstatsd** [ **-C** *config-file* ] [ **-v** ] [ **-f** *frequency* ] [ **-d** ]

    **promstatsd** [ **-C** *config-file* ] [ **-v** ] **-c**

    **promstatsd** [ **-C** *config-file* ] [ **-v** ] **-1**

Description
===========

**promstatsd** is the Cyrus Prometheus statistics collating daemon.

When the **prometheus_enabled** :cyrusman:`imapd.conf(5)` setting is true,
various Cyrus service processes will count statistics as they run.
**promstatsd** collates these statistics into a text-based report that
Prometheus can ingest.

The report produced by **promstatsd** is served by :cyrusman:`httpd(8)` at
the "/metrics" URL, if "prometheus" has been set in **httpmodules** in
:cyrusman:`imapd.conf(5)`.

**promstatsd** |default-conf-text|

In the first synopsis, **promstatsd** will run as a daemon, updating the
report at the specified *frequency*.  If the optional **-f** *frequency*
argument is not provided, the **prometheus_update_freq** from
:cyrusman:`imapd.conf(5)` will be used, which defaults to 10 seconds.  This
invocation should be run from the DAEMON section of :cyrusman:`cyrus.conf(5)`
(see :ref:`promstatsd-examples` below).

In the second synopsis, **promstatsd** will clean up all statistics files and
exit.  The statistics Cyrus maintains are only valid while Cyrus is running,
so this invocation must be run from the START section of
:cyrusman:`cyrus.conf(5)` (see :ref:`promstatsd-examples` below) to clean up
after the previous run, before new service processes are started.

In the third synopsis, **promstatsd** will immediately update the report
once, and then exit.  This can be safely used while another **promstatsd**
process runs in daemon form.  It is useful if you need to update the report
*now* for some reason, rather than waiting for the daemon's next update.

Options
=======

.. program:: promstatsd

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -D

    Run the external debugger specified in the **debug_command**
    :cyrusman:`imapd.conf(5)` option.

.. option:: -1

    Update the report once and exit.

.. option:: -c

    Clean up the stats directory and exit.

.. option:: -d

    Debug mode -- **promstatsd** will not background itself, for aid in
    debugging.

.. option:: -f frequency

    Update the report every *frequency* seconds.  If not specified, the
    **prometheus_update_freq** from :cyrusman:`imapd.conf(5)` will be used,
    which defaults to 10 seconds.

.. option:: -v

    Increase verbosity.  Can be specified multiple times.

.. _promstatsd-examples:

Examples
========

To regularly produce a report that Prometheus can consume, **promstatsd** must
be run from the DAEMON section of :cyrusman:`cyrus.conf(5)` as per the first
synopsis, like so:

.. parsed-literal::
    DAEMON {
        **promstatsd    cmd="promstatsd"**
    }

To ensure a clean statistical state at startup, **promstatsd** must be run
from the START section of :cyrusman:`cyrus.conf(5)` as per the second synopsis,
like so:

.. parsed-literal::
    START {
        **statscleanup  cmd="promstatsd -c"**
    }

History
=======

Files
=====

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`,
:cyrusman:`httpd(8)`,
