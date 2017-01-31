.. cyrusman:: fud(8)

.. _imap-reference-manpages-systemcommands-fud:

=======
**fud**
=======

Provide information about user mailboxes

Synopsis
========

.. parsed-literal::

    **fud** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]

Description
===========

**fud** is a long lived datagram daemon started from master that
provides information about when a user last read their mail, when mail
last arrived in a user's mailbox, and how many messages are recent for
that user.

**fud** |default-conf-text|

**fud** will automatically proxy any and all FUD requests to the
appropriate backend server if it is runing on a Cyrus Murder frontend
machine.

To set up the FUD daemon, add this to your cyrus.conf:

``fud           cmd="fud" listen="fud" prefork=1 proto="udp"``

and to /etc/services:

``fud             4201/udp                        # Cyrus IMAP FUD Daemon``

Client
------

There is no specific FUD client. This shows how one might access FUD.

::

    #!/usr/bin/perl

    use Socket;

    print( "Enter fud hostname: " );
    $hostname = <>;
    chomp( $hostname );

    print( "Enter username to query: " );
    $username = <>;
    chomp( $username );

    socket( FUD, PF_INET, SOCK_DGRAM, getprotobyname( "udp" ) )
       or die( "failed to create udp socket: $!" );

    $ipaddr = inet_aton( $hostname );
    $portaddr = sockaddr_in( '4201', $ipaddr );

    $fud_query = $username . '|user.' . $username;

    send( FUD, "$fud_query", 0, $portaddr ) == length( $fud_query )
       or die( "failed to send fud query: $!" );

    recv( FUD, $fud_response, 512, 0 )
       or die( "recv() failed: $!" );

    print( "FUD responded: $fud_response\n" );

    exit( 0 );


Options
=======

.. program:: fud

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

Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

Bugs
====

Though not really a bug, **fud** will silently ignore any requests that
it does not consider valid.

Also not really a bug, **fud** requires that the anonymous user has the
0 (zero) right on the mailbox in question.  This is only a "bug" because
0 is not a standard IMAP ACL bit.

**fud** is an experimental interface meant to provide information to
build a finger-like service around.  Eventually it should be superceded
by a more standards-based protocol.


See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`
