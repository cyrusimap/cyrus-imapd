.. _imap-admin-commands-cyradm:

==========
``cyradm``
==========

The ``cyradm`` utility is a simple command line for performing common
administrative tasks on a Cyrus IMAP server, written in Perl.

The utility can either be executed from a client where it has been
installed and connect to the server via IMAP or it can be executed
locally via a shell on the server.

.. rubric:: Synopsis

.. parsed-literal::

    cyradm [options] server

.. rubric:: Command-Line Options

.. program:: cyradm

.. option:: -u, --user <user>

    Authenticate with the specified username.

.. option:: --authz <user>

    Authorize the connection as being the specified username.

.. option:: --norc, --rc

    (Do not) load the configuration files.

.. option:: --systemrc <file>

    Use the system configuration file specified.

.. option:: --userrc <file>

    Use the user configuration file specified.

.. option:: --port <port>

    Connect to the *server* specified on the port specified.

.. option:: --auth <mechanism>

    Use the mechanism specified to authenticate. One of PLAIN, LOGIN,
    DIGEST-MD5, etc.

.. option:: --help

    Show this help message.

.. option:: --version

    Display the version of Cyrus IMAP the current ``cyradm`` command is
    a part of.

.. option:: server

    The server address to connect to.

.. rubric:: Example Usage

.. parsed-literal::

    $ :command:`cyradm -u cyrus localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost>

.. _imap-admin-commands-cyradm-auth:

auth
----

.. _imap-admin-commands-cyradm-authenticate:

authenticate
------------

Authenticate to a server for which a connection has already been opened
either when ``cyradm`` was started or via the
:ref:`imap-admin-commands-cyradm-connect` command.

.. parsed-literal::

    localhost> :command:`authenticate` *username*

The username must be provided as a parameter.

Aliases: :ref:`imap-admin-commands-cyradm-login` and
:ref:`imap-admin-commands-cyradm-auth`.

.. _imap-admin-commands-cyradm-cd:

cd
--

See :ref:`imap-admin-commands-cyradm-chdir`

.. _imap-admin-commands-cyradm-chdir:

chdir
-----

Change the current directory (on the local system).

Aliases: :ref:`imap-admin-commands-cyradm-cd`

.. _imap-admin-commands-cyradm-connect:

connect
-------

Connect to a server if you're not already connected, or display the
current server if connected and no server name provided.

.. parsed-literal::

    localhost> :command:`connect` [<server>]

createmailbox
-------------

Creates a new mailbox. New mailboxes inherit the ACL permissions of
their parent mailbox, except for top-level mailboxes such as the user's
INBOX. Mailboxes that are the user's INBOX are assigned all to the
corresponding user.

.. rubric:: Example Usage

.. parsed-literal::

    localhost> :command:`cm user.john`
    localhost> :command:`lm`
    user.john (\HasNoChildren)
    localhost> :command:`lam user.john`
    john lrswipkxtecda


.. NOTE::

    Note that in the above example, the ``unixhierarchysep`` setting in
    :manpage:`imapd.conf(5)` is set to ``0``. When using the UNIX
    hierarchy seperator, the ``/`` (forward slash) character would be
    used as the hierarchy seperator, and the example would look as
    follows.

.. rubric:: Example Usage with ``unixhierarchysep: 1``

.. parsed-literal::

    localhost> :command:`cm user/john`
    localhost> :command:`lm`
    user/john (\HasNoChildren)
    localhost> :command:`lam user/john`
    john lrswipkxtecda

.. NOTE::

    Also note the above examples use the unqualified, shorthand user
    identifier john as the mailbox name.

    With the use of virtual domains, controlled through the
    ``virtdomains`` setting in :manpage:`imapd.conf(5)`.

.. WARNING::

    In versions prior to Cyrus IMAP 2.4.18, it was possible to create
    the mailboxes ``user.anonymous`` and ``user.anyone`` (or
    ``user/anonymous`` and ``user/anyone`` with ``unixhierarchysep: 1``)
    -- both of which have special meanings in the ACL.
    ``user.anonymous`` would be accessible by all users authenticated,
    and all users not authenticated if the SASL mechanism ``ANONYMOUS``
    was available, and the ``user.anyone`` mailbox would be accessible
    by all authenticated users.

    **This feature is disabled from 2.4.18 onwards to avoid accidents.**

Aliases: ``create`` or ``cm``

.. _imap-admin-commands-cyradm-delete:

delete
------

Alias for :ref:`imap-admin-commands-cyradm-deletemailbox`

.. _imap-admin-commands-cyradm-deleteaclmailbox:

deleteaclmailbox
----------------

Remove ACLs from mailbox

Aliases: ``deleteacl`` or ``dam``

.. _imap-admin-commands-cyradm-deletemailbox:

deletemailbox
-------------

Delete a mailbox from the server.

.. rubric:: Example Usage

.. parsed-literal::

    $ :command:`cyradm -u cyrus localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost> :command:`deletemailbox user/john.doe@example.org`

Aliases: *delete* or *dm*

disconnect
----------

Disconnects from the server, but doesn't quit **cyradm**.

.. _imap-admin-commands-cyradm-dm:

dm
--

Alias for :ref:`imap-admin-commands-cyradm-dm`

.. _imap-admin-commands-cyradm-exit:

exit
----

Disconnects from the server and exits out of **cyradm** back to the shell.

.. _imap-admin-commands-cyradm-help:

help
----

Show the commands, their aliases and a short description of each command.

.. parsed-literal::

    authenticate, login, auth         authenticate to server
    chdir, cd                         change current directory
    createmailbox, create, cm         create mailbox
    deleteaclmailbox, deleteacl, dam  remove ACLs from mailbox
    deletemailbox, delete, dm         delete mailbox
    disconnect, disc                  disconnect from current server
    exit, quit                        exit cyradm
    help, ?                           show commands
    info                              display mailbox/server metadata
    listacl, lam, listaclmailbox      list ACLs on mailbox
    listmailbox, lm                   list mailboxes
    listquota, lq                     list quotas on specified root
    listquotaroot, lqr, lqm           show quota roots and quotas for mailbox
    mboxcfg, mboxconfig               configure mailbox
    reconstruct                       reconstruct mailbox (if supported)
    renamemailbox, rename, renm       rename (and optionally relocate) mailbox
    server, servername, connect       show current server or connect to server
    setaclmailbox, sam, setacl        set ACLs on mailbox
    setinfo                           set server metadata
    setquota, sq                      set quota on mailbox or resource
    subscribe, sub                    subscribe to a mailbox
    unsubscribe, unsub                unsubscribe from a mailbox
    version, ver                      display version info of current server
    xfermailbox, xfer                 transfer (relocate) a mailbox to a different server

.. _imap-admin-commands-cyradm-info:

info
----

.. _imap-admin-commands-cyradm-listaclmailbox:

listaclmailbox
--------------

.. _imap-admin-commands-cyradm-listmailbox:

listmailbox
-----------

.. _imap-admin-commands-cyradm-listquota:

listquota
---------

.. _imap-admin-commands-cyradm-listquotaroot:

listquotaroot
-------------

.. _imap-admin-commands-cyradm-login:

login
-----

See :ref:`authenticate<imap-admin-commands-cyradm-authenticate>`

.. _imap-admin-commands-cyradm-mboxcfg:

mboxcfg
-------

.. _imap-admin-commands-cyradm-pwd:

pwd
---

Displays the current working directory.

.. _imap-admin-commands-cyradm-reconstruct:

reconstruct
-----------

.. _imap-admin-commands-cyradm-renamemailbox:

renamemailbox
-------------

.. _imap-admin-commands-cyradm-server:

server
------

.. _imap-admin-commands-cyradm-setaclmailbox:

setaclmailbox
-------------

.. _imap-admin-commands-cyradm-setinfo:

setinfo
-------

.. _imap-admin-commands-cyradm-setquota:

setquota
--------

.. _imap-admin-commands-cyradm-subscribe:

subscribe
---------

.. _imap-admin-commands-cyradm-unsubscribe:

unsubscribe
-----------

.. _imap-admin-commands-cyradm-version:

version
-------

Outputs the current version information for the connected server.

.. parsed-literal::

    name: Cyrus IMAPD
    version: v2.4.17-Kolab-2.4.17-1.el6 d1df8aff 2012-12-01
    vendor: Project Cyrus
    support-url: http://www.cyrusimap.org
    os: Linux
    os-version: 2.6.32-431.3.1.el6.x86_64
    environment: Built w/Cyrus SASL 2.1.23
                 Running w/Cyrus SASL 2.1.23
                 Built w/Berkeley DB 4.7.25: (September 12, 2013)
                 Running w/Berkeley DB 4.7.25: (September 12, 2013)
                 Built w/OpenSSL 1.0.0-fips 29 Mar 2010
                 Running w/OpenSSL 1.0.0-fips 29 Mar 2010
                 Built w/zlib 1.2.3
                 Running w/zlib 1.2.3
                 CMU Sieve 2.4
                 TCP Wrappers
                 mmap = shared
                 lock = fcntl
                 nonblock = fcntl
                 idle = idled

.. _imap-admin-commands-cyradm-xfer:

xfer
----

Alias for :ref:`imap-admin-commands-cyradm-xfermailbox`

.. _imap-admin-commands-cyradm-xfermailbox:

xfermailbox
-----------

Transfer or relocate a mailbox to a different server.

.. parsed-literal::

    xfer user/john.doe@example.org <new.server>

Aliases: :ref:`imap-admin-commands-cyradm-xfer`
