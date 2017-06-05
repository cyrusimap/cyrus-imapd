.. cyrusman:: notifyd(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-notifyd:

===========
**notifyd**
===========

Cyrus notification server

Synopsis
========

.. parsed-literal::

    **notifyd** [ **-C** *config-file* ]  [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]

Description
===========

**notifyd** is a daemon started from :cyrusman:`master(8)` that handles
notification requests on behalf of :cyrusman:`lmtpd(8)`. **Notifyd**
accepts the request and performs the notification using the method
specified in the request.

Note that for **notifyd** to run properly you must set ``proto=udp`` in
its :cyrusman:`cyrus.conf(5)` services entry.  ``prefork=1`` is also
recommended.

**notifyd** |default-conf-text|

``notifysocket`` option is used to specify the Unix domain socket to
listen on for notifications.

Options
=======

.. program:: notifyd

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -U  uses

    The maximum number of times that the process should be used for new
    connections before shutting down.  The default is 250.

.. option:: -T  timeout

    The number of seconds that the process will wait for a new
    connection before shutting down.  Note that a value of 0 (zero)
    will disable the timeout.  The default is 60.

.. option:: -D

    Run external debugger specified in debug_command.

NOTIFICATION METHODS
====================

**null**

    Ignore the notification request.

**log**

    Log the notification to syslog (for testing).

**mailto**

    Email the notification.  This method can ONLY be used in a
    Sieve 'notify' action as it requires a *mailto:* URL to be
    specified as an *:option*.

**zephyr**

    Send the notification as a zephyrgram.  If used in a Sieve 'notify'
    action, additional recipients can be specified as *:options*.

**external**

    Send the notification via an external program.  The path to the
    program is specified using the *notify_external* option in the
    configuration file.

Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`
