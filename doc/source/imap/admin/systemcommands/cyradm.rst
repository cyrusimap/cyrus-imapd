.. _imap-admin-commands-cyradm:

==========
**cyradm**
==========

The ``cyradm`` utility is a simple command line for performing common
administrative tasks on a Cyrus IMAP server, written in Perl.

The utility can either be executed from a client where it has been
installed and connect to the server via IMAP or it can be executed
locally via a shell on the server.

cyradm understands /bin/sh-style redirection: any command can have its 
standard or error output redirected, with all sh-style redirections 
(except \<\>) supported. It does not currently understand pipes or 
backgrounding.

If the Term::Readline::Perl or Term::Readline::GNU modules are 
available, cyradm will use it.

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


.. _imap-admin-commands-cyradm-authenticate:

authenticate
------------

Authenticate to a server for which a connection has already been opened
either when ``cyradm`` was started or via the
:ref:`imap-admin-commands-cyradm-connect` command.

.. parsed-literal::

    localhost> :command:`authenticate` *[--minssf N] [--maxssf N] [--mechanisms list] username*

The username must be provided as a parameter.

Cyrus imapd will refuse to allow you to re-authenticate once you have authenticated once.

Aliases: ``auth`` and ``login``

.. _imap-admin-commands-cyradm-chdir:

chdir
-----

Change the current directory (on the local system). A pwd builtin is not provided, but the default command action will run pwd from a shell if invoked.

.. parsed-literal::

    localhost> :command:`chdir` *directory*

Aliases: :``cd``

.. _imap-admin-commands-cyradm-connect:

connect
-------

With no arguments, show the current server. With an argument, connect to that server. 

When connected to a server, cyradm's prompt changes from cyradm> to servername>, where servername is the fully qualified domain name of the connected server.

.. parsed-literal::

    localhost> :command:`connect` [<server>]

Aliases: ``server`` ``servername``
    
.. _imap-admin-commands-createmailbox:

createmailbox
-------------

Creates a new mailbox. New mailboxes inherit the ACL permissions of
their parent mailbox, except for top-level mailboxes such as the user's
INBOX. Mailboxes that are the user's INBOX are assigned all to the
corresponding user.

Partitions can be optionally specified as follows:

.. parsed-literal::

    createmailbox [--partition partition] mailbox
    createmailbox mailbox partition

.. rubric:: Example Usage

.. parsed-literal::

    localhost> :command:`cm user.john`
    localhost> :command:`lm`
    user.john (\HasNoChildren)
    localhost> :command:`lam user.john`
    john lrswipkxtecda


Note that in the above example, the ``unixhierarchysep`` setting in
:manpage:`imapd.conf(5)` is set to ``0``. When using the UNIX
hierarchy seperator, the ``/`` (forward slash) character would be
used as the hierarchy seperator, and the example would look as
follows:

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

Remove ACLs from mailbox(es).

.. parsed-literal::

    deleteaclmailbox *<mailbox id>* *[...]*

Aliases: ``deleteacl`` or ``dam``

.. _imap-admin-commands-cyradm-deletemailbox:

deletemailbox
-------------

Delete a mailbox from the server.

Administrators do not have implicit delete rights on mailboxes. Use the :ref:`imap-admin-commands-cyradm-setaclmailbox` command to grant the **x** permission to your principal if you need to delete a mailbox you do not own.

.. rubric:: Example Usage

.. parsed-literal::

    $ :command:`cyradm -u cyrus localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost> :command:`deletemailbox user/john.doe@example.org`

Aliases: ``delete`` or ``dm``

disconnect
----------

Disconnects from the server, but doesn't quit **cyradm**.

Aliases: ``disc``

.. _imap-admin-commands-cyradm-exit:

exit
----

Exit **cyradm**, optionally with a specific exit status; the exit status of the last command will be used if one is not specified.

.. parsed-literal::

    :command:`exit` *[number]*

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
    
Aliases: ``?``    

.. _imap-admin-commands-cyradm-info:

info
----

Display the mailbox/server metadata.

.. parsed-literal::

    :command:`info` *[mailbox id]*

See :ref:`imap-admin-commands-cyradm-setinfo`.
    
.. _imap-admin-commands-cyradm-listaclmailbox:

listaclmailbox
--------------

List ACLs on the specified mailbox.

.. parsed-literal::

    :command:`listaclmailbox` *<mailboxid>*
    
Áliases: ``listacl`` and ``lam``    

See :ref:`imap-admin-commands-cyradm-setaclmailbox`.

.. _imap-admin-commands-cyradm-listmailbox:

listmailbox
-----------

List all, or all subscribed, mailboxes matching the specified pattern. The pattern may have embedded wildcards '*' or '%', which match anything or anything except the separator character, respectively.

Mailboxes returned will be relative to the specified reference if one is specified. This allows a mailbox list to be limited to a particular hierarchy.

In some cases when the '%' wildcard is used to end a pattern, it may match an entry which is not a mailbox but which contains other mailboxes. In this case, the entry will be parenthesized to indicate that it is a root for other mailboxes, as opposed to a mailbox itself.

.. parsed-literal::

    :command:`listmailbox` *[--subscribed] [pattern [reference]]*
    
Aliases: ``list`` and ``lm``
    
.. _imap-admin-commands-cyradm-listquota:

listquota
---------

List quotas on specified mailbox. If the specified mailbox path does not have a quota assigned, an error will be raised; see :ref:`imap-admin-commands-cyradm-listquotaroot` for a way to find the quota root for a mailbox.

.. parsed-literal::

    :command:`listquota` *mailbox*
   
Aliases: ``lq``   

See :ref:`imap-admin-commands-cyradm-setquota`.

.. _imap-admin-commands-cyradm-listquotaroot:

listquotaroot
-------------

Show quota roots and quotas for specified root.

.. parsed-literal::

    :command:`listquotaroot` *root*
    
Aliases: `lqm`     

.. _imap-admin-commands-cyradm-mboxcfg:

mboxconfig
----------

Set mailbox metadata. A value of "none" will remove the attribute. 

.. parsed-literal::

    :command:`mboxconfig` *mailbox attribute value*

.. program:: mboxconfig 

.. rubric:: Attributes
    
.. option:: comment description

    Sets a comment or description associated with the mailbox.
    
.. option:: condstore true|false

    Enables the IMAP CONDSTORE extension (modification sequences) on the mailbox.
    
    This annotation is only supported in the 2.3.x release
    series starting with 2.3.3 although its use is not recommended until
    2.3.8. As of the 2.4.x release series CONDSTORE functionality is
    enabled on all mailboxes regardless of annotation and attempting to set
    this annotation will result in a permission denied message. On releases
    where this annotation is supported setting a value of “true” will
    enable CONDSTORE functionality.

.. option:: expire days

    Sets the number of days after which messages will be expired from the mailbox.

.. option:: news2mail address

    Sets an email address to which messages injected into the server via NNTP will be sent.

.. option:: sharedseen true|false

    Enables the use of a shared ``\Seen`` flag on messages rather than a per-user ``\Seen`` flag. The **s** right in the mailbox ACL still controls whether a user can set the shared ``\Seen`` flag.

.. option:: sieve scriptname

    Indicates the name of the global sieve script that should be run when a message is delivered to the shared mailbox (not used for personal mailboxes).

.. option:: squat true|false

    Indicates that the mailbox should have a squat index created for it.
    
Aliases: ``mboxcfg``
    
.. _imap-admin-commands-cyradm-reconstruct:

reconstruct
-----------

.. parsed-literal::

    :command:`reconstruct` *mailboxid recurseflag*
    
.. option:: recurseflag true|false
        
        Whether to reconstruct all mailboxes in the tree under the given *mailboxid*.

.. _imap-admin-commands-cyradm-renamemailbox:

renamemailbox
-------------

Rename the specified mailbox, optionally moving it to a different partition. 
Both old-style and getopt-style usages are accepted; combining them will produce an error.

.. parsed-literal::

    :command:`renamemailbox` *[--partition partition] oldname newname*
    :command:`renamemailbox` *oldname newname [partition]*

Aliases: ``rename``, ``renm``


.. _imap-admin-commands-cyradm-setaclmailbox:

setaclmailbox
-------------

.. parsed-literal::

    :command:`setaclmailbox` *mailbox rights [mailbox rights ...]*

Set ACLs on a mailbox. The ACL may be one of the special strings ``none``, ``read`` (lrs), ``post`` (lrsp), ``append`` (lrsip), ``write`` (lrswipkxte), ``delete`` (lrxte), or ``all`` (lrswipkxte), or any combinations of the ACL codes:

.. program:: setaclmailbox
 
.. option:: l

    Lookup (mailbox is visible to LIST/LSUB, SUBSCRIBE mailbox)

.. option:: r

    Read (SELECT/EXAMINE the mailbox, perform STATUS)

.. option:: s

    Seen (set/clear \SEEN flag via STORE, also set \SEEN flag during APPEND/COPY/FETCH BODY[...])

.. option:: w

    Write flags other than \SEEN and \DELETED

.. option:: i

    Insert (APPEND, COPY destination)

.. option:: p

    Post (send mail to mailbox)

.. option:: k

    Create mailbox (CREATE new sub-mailboxes, parent for new mailbox in RENAME)

.. option:: x

    Delete mailbox (DELETE mailbox, old mailbox name in RENAME)

.. option:: t

    Delete messages (set/clear \DELETED flag via STORE, also set \DELETED flag during APPEND/COPY)

.. option:: e

    Perform EXPUNGE and expunge as part of CLOSE

.. option:: a

    Administer (SETACL/DELETEACL/GETACL/LISTRIGHTS)
    
Aliases: ``setacl`` and ``sam``.    

See :ref:`imap-admin-commands-cyradm-listaclmailbox`.

.. _imap-admin-commands-cyradm-setinfo:

setinfo
-------

.. parsed-literal::

    :command:`setinfo` *attribute value*

Set server metadata. A value of ``none`` will remove the attribute. The currently supported attributes are:

.. program:: setinfo 

.. option:: motd message

    Sets a "message of the day". The message gets displayed as an ALERT after authentication.

.. option:: comment description

    Sets a comment or description associated with the server.

.. option:: admin address

    Sets the administrator email address for the server.

.. option:: shutdown message

    Sets a shutdown message. The message gets displayed as an ALERT and all users are disconnected from the server (subsequent logins are disallowed).

.. option:: expire ndays

    Sets the number of days after which messages will be expired from the server (unless overridden by a mailbox annotation).

.. option:: squat true|false

    Indicates that all mailboxes should have a squat indexes created for them (unless overridden by a mailbox annotation).

See :ref:`imap-admin-commands-cyradm-info`.
    
.. _imap-admin-commands-cyradm-setquota:

setquota
--------

Set a quota on the specified root, which may or may not be an actual mailbox. The only resource understood by Cyrus is STORAGE. The ``value`` may be the special string ``none`` which will remove the quota.

.. parsed-literal::

    :command:`setquota` *root resource value [resource value ...]*
    
Aliases: ``sq``.


See :ref:`imap-admin-commands-cyradm-listquota`.

.. _imap-admin-commands-cyradm-subscribe:

subscribe
---------

Subscribe to a mailbox.

.. parsed-literal::

    :command:`subscribe` *mailboxid*

See :ref:`imap-admin-commands-cyradm-unsubscribe`.

.. _imap-admin-commands-cyradm-unsubscribe:

unsubscribe
-----------

Unsubscribe from a mailbox.

    :command:`unsubscribe` *mailboxid*
    
See :ref:`imap-admin-commands-cyradm-subscribe`.

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

.. _imap-admin-commands-cyradm-xfermailbox:

xfermailbox
-----------

Transfer or relocate a mailbox to a different server.

.. parsed-literal::
    
    :command:`xfermailbox` *mailbox server [partition]*
    :command:`xfermailbox` *[--partition partition] mailbox server*

.. parsed-literal::

    xfer user/john.doe@example.org <new.server>

Aliases: ``xfer``
