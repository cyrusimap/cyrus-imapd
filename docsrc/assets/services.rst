The Cyrus IMAP server provides service interfaces via either TCP/IP
ports or Unix domain sockets.  For the former, Cyrus requires that there
are proper entries in the host's ``/etc/services`` file.  The following
are required for any host using the listed services:

::

    pop3      110/tcp  # Post Office Protocol v3
    nntp      119/tcp  # Network News Transport Protocol
    imap      143/tcp  # Internet Mail Access Protocol rev4
    nntps     563/tcp  # NNTP over TLS
    imaps     993/tcp  # IMAP over TLS
    pop3s     995/tcp  # POP3 over TLS
    kpop      1109/tcp # Kerberized Post Office Protocol
    lmtp      2003/tcp # Lightweight Mail Transport Protocol service
    smmap     2004/tcp # Cyrus smmapd (quota check) service
    csync     2005/tcp # Cyrus replication service
    mupdate   3905/tcp # Cyrus mupdate service
    sieve     4190/tcp # timsieved Sieve Mail Filtering Language service

Make sure that these lines are present or add them if they are missing.
