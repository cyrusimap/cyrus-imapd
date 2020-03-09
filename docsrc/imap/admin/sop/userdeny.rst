Managing user_deny.db
=====================

The user_deny database allows you to deny access via POP/IMAP even if the user can authenticate to the Cyrus server. For example, if the authentication data is also used for other network services.

If the user_deny.db file doesn't exist in %configdirectory% (often /var/lib/imap) then you'll need to create it. In the example below, /var/lib/imap/ is used.

::

    # echo "" > /tmp/user_deny.flat
    # /usr/lib/cyrus-imapd/cvt_cyrusdb /tmp/user_deny.flat flat /var/lib/imap/user_deny.db skiplist
    # chown cyrus:cyrus /var/lib/imap/user_deny.db

The database specification can be found in the file 'doc/internal/database-formats.html'
in the source distribution.

**Key:** <Userid>

**Data:** <Version>TAB<Deny List (comma-separated wildmat patterns)>TAB<Deny Message>

::

    # su - cyrus
    $ cyr_dbtool /var/lib/imap/user_deny.db skiplist set **username** "2     pop3    Can't use pop."

In order to type a tab character, you will need to escape your tabs. In bash, this is done by typing CTRL-v and then pressing Tab.

If you got it right, when you authenticate via pop3 you should see something like the following::

    $ telnet mail.example.org 110
    Trying 192.168.0.2...
    Connected to mail.example.org.
    Escape character is '^]'.
    +OK mail.example.org Cyrus POP3 v2.4.17 server ready <18418688457439930663.1399062365@mail.example.org>
    USER **username**
    +OK Name is a valid mailbox
    -ERR [SYS/TEMP] Can't use pop.
    Connection closed by foreign host.

