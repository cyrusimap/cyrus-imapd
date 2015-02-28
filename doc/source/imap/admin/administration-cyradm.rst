cyradm
======

cyradm is a simple command line utility for performing common administrative tasks to a Cyrus IMAP server. The utility can either be executed from a client where it has been installed and connect to the server via IMAP or it can be executed locally via a shell on the server.

::

    bash$ cyradm -u cyrus localhost


Commands available
------------------

.. _cyradm_auth:

auth
++++

See :ref:`authenticate<cyradm_authenticate>`

.. _cyradm_authenticate:

authenticate
++++++++++++

Authenticate to a server for which a connection has already been opened either when **cyradm** was started or via the :ref:`connect<cyradm_connect>` command.

::

    cyradm> authenticate <username>

The username must be provided as a parameter.

Aliases: :ref:`login<cyradm_login>` and :ref:`auth<cyradm_auth>`

.. _cyradm_cd:

cd
++

See :ref:`chdir<cyradm_chdir>`

.. _cyradm_chdir:

chdir
+++++

Change the current directory.

Aliases: :ref:`cd<cyradm_cd>`

.. _cyradm_connect:

connect
+++++++

Connect to a server if you're not already connected, or display the current server if connected and no server name provided.

::

    cyradm> connect [<server>]

createmailbox
+++++++++++++

Creates a new mailbox. New mailboxes inherit the ACL permissions of their parent mailbox, except for top-level mailboxes such as the user's INBOX. Mailboxes that are the user's INBOX are assigned all to the corresponding user.

.. rubric:: Example 3.1. Example use of createmailbox

::

    localhost> cm user.bovik
    localhost> lm
    user.bovik (\HasNoChildren)
    localhost> lam user.bovik
    bovik lrswipkxtecda


.. note:: **unixhierarchysep**

    Note that in the above example, the unixhierarchysep setting in ``/etc/imapd.conf`` is set to **false** (0). When using the UNIX hierarchy seperator, the forward slash character (/), as the hierarchy seperator, the example would look as follows.

.. rubric:: Example 3.2. Example use of createmailbox with unixhierachysep

::

    localhost> cm user/bovik
    localhost> lm
    user/bovik (\HasNoChildren)
    localhost> lam user/bovik
    bovik lrswipkxtecda

Notice the use of the / (forward slash) character in Example 3.2, "Example use of createmailbox with unixhierachysep" as opposed to the . (dot) character in Example 3.1, "Example use of createmailbox" to seperate the hierarchical components of the mailbox name.

.. note:: **virtdomains**

    Also note the above examples use the unqualified, shorthand user identifier bovik as the mailbox name.
    With the use of virtual domains, controlled through the virtdomains imapd.conf(5) configuration option. 

.. warning:: **Special mailbox names**

    It is possible to create the mailboxes user.anonymous and user.anyone (or user/anonymous and user/anyone with *unixhierarchysep* set **true**) - both of which have special meanings in the ACL. user.anonymous would be accessible by all users, authenticated or not, and user.anyone would be accessible by all authenticated users.

    *This feature is disabled from 2.4.18 onwards to avoid accidents.*

Aliases: ``create`` or ``cm``

deleteaclmailbox
++++++++++++++++

Remove ACLs from mailbox

Aliases: ``deleteacl`` or ``dam``

deletemailbox
+++++++++++++

Delete a mailbox from the server.

::

    cyradm> deletemailbox user/john.doe@example.org

Aliases: *delete* or *dm*

disconnect
++++++++++

Disconnects from the server, but doesn't quit **cyradm**.

exit
++++

Disconnects from the server and exits out of **cyradm** back to the shell.

help
++++

Show the commands, their aliases and a short description of each command. 

::

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

.. _cyradm_info:

info
++++

.. _cyradm_listaclmailbox:

listaclmailbox
++++++++++++++

.. _cyradm_listmailbox:

listmailbox
+++++++++++

.. _cyradm_listquota:

listquota
+++++++++

.. _cyradm_listquotaroot:

listquotaroot
+++++++++++++

.. _cyradm_login:

login
+++++

See :ref:`authenticate<cyradm_authenticate>`

mboxcfg
+++++++

pwd
+++

Displays the current working directory.

reconstruct
+++++++++++

renamemailbox
+++++++++++++

server
++++++

setaclmailbox
+++++++++++++

setinfo
+++++++

setquota
++++++++

subscribe
+++++++++

unsubscribe
+++++++++++

version
+++++++

Outputs the current version information for the connected server.

::

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


xfermailbox
+++++++++++

Transfer or relocate a mailbox to a different server.

::

    xfer user/john.doe@example.org <new.server>

Aliases: ``xfer``
