.. cyrusman:: fetchnews(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-fetchnews:

=============
**fetchnews**
=============

Retrieve new articles from peer and feed to Cyrus

Synopsis
========

.. parsed-literal::

    **fetchnews** [ **-C** *config-file* ] [ **-s** *servername*\ [:\ *port*\ ]]
        [ **-n** ] [ **-y** ] [ **-w** *wildmat* ] [ **-f** *tstampfile* ]
        [ **-a** *authname* [ **-p** *password* ]] *peername*

Description
===========

**fetchnews** retrieves news articles from a peer news server and
feeds them to a Cyrus server. **fetchnews** connects to the peer
specified by *peername*, requests new articles since the time stored in
*tstampfile* and feeds them to *servername*.

**fetchnews** |default-conf-text|

Options
=======

.. program:: fetchnews

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -s servername, --server=servername

    Hostname of the Cyrus server (with optional port) to which articles
    should be fed.  Defaults to "localhost:nntp".

.. option:: -n, --no-newnews

    Don't use the NEWNEWS command. **fetchnews** will keep track of the
    high and low water marks for each group and use them to fetch new
    articles.

.. option:: -y, --yyyy

    Use 4 instead of 2 digits for year. 2-digits are :rfc:`977` - but not
    y2k-compliant.

.. option:: -w wildmat, --groups=wildmat

    Wildmat pattern specifying which newsgroups to search for new
    articles.  Defaults to "*".


.. option:: -f tstampfile, --newsstamp-file=tstampfile

    File in which to read/write the timestamp of when articles were
    last retrieved.  Defaults to ``<configdirectory>/newsstamp`` as
    specified by the configuration options.

.. option:: -a authname, --auth-id=authname

    Userid to use for authentication.

.. option:: -p password, --password=password

    Password to use for authentication.

Files
=====

/etc/imapd.conf

See Also
========

manpage:`imapd.conf(5)`
