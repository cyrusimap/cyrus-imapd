.. cyrusman:: cyrus.conf(5)

.. _imap-reference-manpages-configs-cyrus.conf:

==============
**cyrus.conf**
==============

Cyrus configuration file

Description
===========

**cyrus.conf** is the configuration file for the Cyrus **master**
process.  It defines the startup procedures, services and events to be
spawned by **master**.

The ``/etc/cyrus.conf`` file consists of a series of entries divided
into sections of the form

    .. parsed-literal::

        *section* {
            *name arguments
                ...
                ...
                ...*
        }

    ..

where *section* is the name of the section, *name* is the name of the
entry and *arguments* is the whitespace-separated list of arguments for
the entry.  The *name* may be any sequence of alphabetic and numeric
characters, but may not contain punctuation such as '-' or '_'.  In the
**SERVICES** section, names must be unique.

Blank lines and lines beginning with \`\`#'' are ignored.

Section Descriptions
====================

The paragraphs below detail the three sections (**START**,
**SERVICES**, **EVENTS**) that can be placed in the ``/etc/cyrus.conf``
file.  The arguments that are available for each entry within the
section are described, and each argument's default value is shown.

Arguments can appear in any order.
Some arguments have no default value, these are listed with
\`\`<no default>''.  For string arguments, the value MUST be enclosed in
double quotes.

START
-----

This section lists the processes to run before any
**SERVICES** are spawned.  This section is typically used to
initialize databases and start long running daemons.

.. parsed-literal::

    **cmd=**\ <no default>

..

    The command (with options) to spawn as a child process.  This
    string argument is required.

SERVICES
--------

This section is the heart of the **/etc/cyrus.conf** file.  It lists
the processes that should be spawned to handle client connections made
on certain Internet/UNIX sockets.

.. parsed-literal::

    **babysit=**\ 0

..

    Integer value - if non-zero, will make sure at least one process is
    pre-forked, and will set the maxforkrate to 10 if it's zero.

.. parsed-literal::

    **cmd=**\ <no default>

..

    The command (with options) to spawn as a child process.  This string
    argument is required.

.. parsed-literal::

    **listen=**\ <no default>

..

    The UNIX or internet socket to listen on.  This
    string field is required and takes one of the following forms:

    .. parsed-literal::

        *path*
        [ *host* **:** ] *port*

    ..

    where *path* is the explicit path to a UNIX socket, *host* is
    either the hostname or bracket-enclosed IP address of a network
    interface, and *port* is either a port number or service name
    (as listed in ``/etc/services``).

    If *host* is missing, 0.0.0.0 (all interfaces) is assumed.  Use
    localhost or 127.0.0.1 to restict access, i.e. when a proxy
    on the same host is front-ending Cyrus.

.. parsed-literal::

    **proto=**\ tcp

..

    The protocol used for this service (*tcp*, *tcp4*, *tcp6*,
    *udp*, *udp4*, *udp6*).  This string argument is optional.

    **tcp4**, **udp4**: These arguments are used to bind the
    service to IPv4 only.

    **tcp6**, **udp6**: These arguments are used to bind the
    service to IPv6 only, if the operating system supports this.

    **tcp**, **udp**: These arguments are used to bind to both IPv4
    and IPv6 if possible.

.. parsed-literal::

    **prefork=**\ 0

..

    The number of instances of this service to always have running
    and waiting for a connection (for faster initial response
    time).  This integer value is optional.  Note that if you are
    listening on multiple network types (i.e. ipv4 and ipv6) then
    one process will be forked for each address, causing twice as
    many processes as you might expect.

.. parsed-literal::

    **maxchild=**\ -1

..

    The maximum number of instances of this service to spawn.  A
    value of -1 means unlimited.  This integer value is optional.

.. parsed-literal::

    **maxfds=**\ 256

..

    The maximum number of file descriptors to which to limit this
    process. This integer value is optional.

.. parsed-literal::

    **maxforkrate=**\ 0

..

    Maximum number of processes to fork per second - the master
    will insert sleeps to ensure it doesn't fork faster than this
    on average.

EVENTS
------

This section lists processes that should be run at specific intervals,
similar to cron jobs.  This section is typically used to perform
scheduled cleanup/maintenance.

.. parsed-literal::

    **cmd=**\ <no default>

..

        The command (with options) to spawn as a child process.  This
        string argument is required.

.. parsed-literal::

    **period=**\ 0

..

        The interval (in minutes) at which to run the command.  This
        integer value is optional, but SHOULD be a positive integer >
        10.

.. parsed-literal::

    **at=**\ <hhmm>

..

        The time (24-hour format) at which to run the command each day.
        If set to a valid time (0000-2359), period is automatically
        set to 1440. This string argument is optional.

Examples
========

::

    # example cyrus.conf

    START {
        recover       cmd="ctl_cyrusdb -r"
    }

    SERVICES {
        imap          cmd="imapd" listen="imap" prefork=1
        imaps         cmd="imapd -s" listen="imaps" prefork=0
        lmtpunix      cmd="lmtpd" listen="/var/imap/socket/lmtp"
        lmtp          cmd="lmtpd" listen="localhost:lmtp"
    }

    EVENTS {
        checkpoint    cmd="ctl_cyrusdb -c" period=30
        delprune      cmd="cyr_expire -E 3" at=0400
        tlsprune      cmd="tls_prune" at=0400
    }

    DAEMON {
        idled         cmd="idled"
    }

Access Control
==============

When TCP Wrappers is used to control access to Cyrus services, the
*name* of the service entry should be used as the process name in
the :manpage:`hosts_access(5)` table.  For instance, in the example above,
"imap", "imaps", "lmtpunix" and "lmtp" would be used as the process
names.  This allows a single daemon such as imapd to be run in
different modes or configurations (i.e., SSL and non-SSL enabled) yet
still have separate access control rules.

See Also
========

:cyrusman:`master(8)`,
:cyrusman:`imapd(8)`,
:cyrusman:`pop3d(8)`,
:cyrusman:`lmtpd(8)`,
:cyrusman:`timsieved(8)`,
:cyrusman:`idled(8)`,
:cyrusman:`notifyd(8)`,
:cyrusman:`ctl_cyrusdb(8)`,
:cyrusman:`ctl_deliver(8)`,
:cyrusman:`tls_prune(8)`,
:manpage:`hosts_access(5)`

