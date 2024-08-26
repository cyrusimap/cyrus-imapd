Ubuntu
======

Currently supported versions of Ubuntu include Cyrus IMAP packages in
the repositories configured on a stock system:

*   Cyrus IMAP |imap_precise_stock_version| for Ubuntu 12.04.5 (Precise Pangolin)
*   Cyrus IMAP |imap_trusty_stock_version| for Ubuntu 14.04.2 (Trusty Tahr) (Stable)
*   Cyrus IMAP |imap_utopic_stock_version| for Ubuntu 14.10 (Utopic Unicorn)
*   Cyrus IMAP |imap_vivid_stock_version| for Ubuntu 15.04 (Vivid Vervet) (Current)
*   Cyrus IMAP |imap_wily_stock_version| for Ubuntu 15.10 (Wily Werewolf) (Development)

.. NOTE::

    The Cyrus project does not support running any versions of the Cyrus
    IMAP software older than the version of the software shipped
    with the operating system itself.

To install the version of Cyrus IMAP that comes with the operating
system, issue the following command:

.. parsed-literal::

    # :command:`sudo apt-get install cyrus-imapd cyrus-clients-2.4 cyrus-doc-2.4 cyrus-admin-2.4 sasl2-bin`

.. Note::
    The cyrus-imapd meta-package will trigger installation of the following Cyrus packages:

    *   cyrus-common (another meta-package)
    *   cyrus-common-2.4
    *   cyrus-imapd-2.4

.. Note::
    The following non-Cyrus packages are required, and will be installed
    automatically as needed:

    *   db-util
    *   db-upgrade-util
    *   libsasl2-2
    *   libsasl2-modules
    *   libcomerr2
    *   [etc.]

.. _Debian Cyrus Team: https://launchpad.net/~pkg-cyrus-imapd-debian-devel
.. Note::
    The `Debian Cyrus Team`_ packages are split based upon functional
    requirements of the installation.  Depending upon your needs, you may also
    wish to install any or all of these packages:

    *   cyrus-pop3d-2.4
    *   cyrus-murder-2.4
    *   cyrus-replication-2.4
    *   cyrus-nntpd-2.4
    *   cyrus-caldav-2.4

Once you've decided which services to support (IMAP, POP3, NNTP, CalDav),
and whether those services shall be available in secured versions,
you'll need to edit ``/etc/cyrus.conf`` and check the ``SERVICES``
section, commenting and uncommenting as needed to enable or disable the
proper versions of those services.

Here's the stock version of the ``SERVICES`` section of
``/etc/cyrus.conf`` as shipped with these packages:

.. parsed-literal::
    SERVICES {
        # --- Normal cyrus spool, or Murder backends ---
        # add or remove based on preferences
        imap		cmd="imapd -U 30" listen="imap" prefork=0 maxchild=100
        #imaps		cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        pop3		cmd="pop3d -U 30" listen="pop3" prefork=0 maxchild=50
        #pop3s		cmd="pop3d -s -U 30" listen="pop3s" prefork=0 maxchild=50
        nntp		cmd="nntpd -U 30" listen="nntp" prefork=0 maxchild=100
        #nntps		cmd="nntpd -s -U 30" listen="nntps" prefork=0 maxchild=100
        http		cmd="httpd -U 30" listen="8008" prefork=0 maxchild=100
        #https		cmd="httpd -s -U 30" listen="8443" prefork=0 maxchild=100


        # At least one form of LMTP is required for delivery
        # (you must keep the Unix socket name in sync with imap.conf)
        #lmtp		cmd="lmtpd" listen="localhost:lmtp" prefork=0 maxchild=20
        lmtpunix	cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
        # ----------------------------------------------

        # useful if you need to give users remote access to sieve
        # by default, we limit this to localhost in Debian
        sieve		cmd="timsieved" listen="localhost:sieve" prefork=0 maxchild=100

        # this one is needed for the notification services
        notify		cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1

        # --- Murder frontends -------------------------
        # enable these and disable the matching services above,
        # except for sieve (which deals automatically with Murder)

        # mupdate database service - must prefork at least 1
        # (mupdate slaves)
        #mupdate       cmd="mupdate" listen=3905 prefork=1
        # (mupdate master, only one in the entire cluster)
        #mupdate       cmd="mupdate -m" listen=3905 prefork=1

        # proxies that will connect to the backends
        #imap		cmd="proxyd" listen="imap" prefork=0 maxchild=100
        #imaps		cmd="proxyd -s" listen="imaps" prefork=0 maxchild=100
        #pop3		cmd="pop3proxyd" listen="pop3" prefork=0 maxchild=50
        #pop3s		cmd="pop3proxyd -s" listen="pop3s" prefork=0 maxchild=50
        #lmtp		cmd="lmtpproxyd" listen="lmtp" prefork=1 maxchild=20
        # ----------------------------------------------
    }

.. Note::
    The default settings, as shown above, are for non-secure protocol
    access.

Edit ``/etc/imapd.conf`` and change the default settings as needed.
Please consult
:cyrusman:`imapd.conf(5)` for details.

*   You MUST, at the very least, uncomment the ``admins:`` line.
*   As documented in the man page, "the values ``yes``, ``on``, ``t``, ``true`` and ``1`` turn the option  on,  the  values  ``no``,  ``off``, ``f``, ``false`` and ``0`` turn the option off."
*   If you are NOT using SSL and/or STARTTLS, you MUST enable plain text logins, and set ``sasl_minimum_layer: 0`` for authentication to work, or have some other protection layer in place.
*   Consider enabling the commonly used settings ``altnamespace`` and ``unixhierarchysep`` as these will default to ``on`` beginning in version 3.0.
*   Check your ``sasl_pwcheck_method`` setting, as this defaults to ``auxprop`` with these packages, which is likely not what you want.  Change it to ``saslauthd`` or ``pwcheck`` as needed.

Next, set a password for the default administrative user ``cyrus``.
Your choice of authentication system will dictate the proper way to do
this.  Shown below are examples for \*nix password file and SASL methods:

.. parsed-literal::

    # :command:`passwd cyrus`
    Changing password for user cyrus.
    New password:
    Retype new password:
    passwd: all authentication tokens updated successfully.

    # :command:`saslpasswd2 -c cyrus`
    Password:
    Again (for verification):

    # :command:`sasldblistusers2`
    cyrus\@newhost.example.com: userPassword

To enable
:manpage:`saslauthd`, edit ``/etc/default/saslauthd`` and set
``START=yes``.  Make sure to change any other settings here as needed.

.. Note::
    If you're planning to integrate Cyrus with the Postfix MTA, it is
    necessary to either relocate the socket used by ``saslauthd``, or
    else to disable ``chroot`` as noted in ``/etc/default/saslauthd``,
    so the Postfix ``smtpd`` daemon can access it.

Start :manpage:`saslauthd` if needed:

.. parsed-literal::

    # :command:`service saslauthd start`
    * Starting SASL Authentication Daemon saslauthd              [ OK ]

You should at this moment be able to authenticate against
saslauthd:

.. parsed-literal::

    # :command:`testsaslauthd -u cyrus -p YOUR-PASSWORD`

.. todo:: If this does not succeed, see  ref `sasl-troubleshooting-saslauthd`.

Start the service, and ensure the service starts up when the system
boots:

.. parsed-literal::

    # :command:`service cyrus-imapd start`
    # :command:`update-rc.d cyrus-imapd enable`

You should now be able to login as the ``cyrus`` user, which is
configured by default as an administrator for Cyrus IMAP:

.. parsed-literal::

    # :command:`imtest -t "" -u cyrus -a cyrus localhost`
    S: * OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE STARTTLS LOGINDISABLED COMPRESS=DEFLATE] newhost.example.com Cyrus IMAP v2.4.17-caldav-beta9-Debian-2.4.17+caldav~beta9-3 server ready
    C: S01 STARTTLS
    S: S01 OK Begin TLS negotiation now
    verify error:num=19:self signed certificate in certificate chain
    TLS connection established: TLSv1 with cipher DHE-RSA-AES256-SHA (256/256 bits)
    C: C01 CAPABILITY
    S: * CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE ACL RIGHTS=kxte QUOTA MAILBOX-REFERRALS NAMESPACE UIDPLUS NO_ATOMIC_RENAME UNSELECT CHILDREN MULTIAPPEND BINARY CATENATE CONDSTORE ESEARCH SORT SORT=MODSEQ SORT=DISPLAY THREAD=ORDEREDSUBJECT THREAD=REFERENCES ANNOTATEMORE LIST-EXTENDED WITHIN QRESYNC SCAN XLIST URLAUTH URLAUTH=BINARY AUTH=PLAIN SASL-IR COMPRESS=DEFLATE IDLE
    S: C01 OK Completed
    Please enter your password:
    C: A01 AUTHENTICATE PLAIN \*\*\*\*\*\*\*\*\*\*\*\*
    S: A01 OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE ACL RIGHTS=kxte QUOTA MAILBOX-REFERRALS NAMESPACE UIDPLUS NO_ATOMIC_RENAME UNSELECT CHILDREN MULTIAPPEND BINARY CATENATE CONDSTORE ESEARCH SORT SORT=MODSEQ SORT=DISPLAY THREAD=ORDEREDSUBJECT THREAD=REFERENCES ANNOTATEMORE LIST-EXTENDED WITHIN QRESYNC SCAN XLIST URLAUTH URLAUTH=BINARY LOGINDISABLED COMPRESS=DEFLATE IDLE] Success (tls protection)
    Authenticated.
    Security strength factor: 256
    . logout
    . LIST "" "*"
    . OK Completed (0.000 secs 1 calls)
    * BYE LOGOUT received
    . OK Completed
    Connection closed.

Next, continue with :ref:`imap-configuring-the-mta`.

..
    Other Versions of Cyrus IMAP
    ----------------------------

    The following guides walk you through providing you with a version of
    the Cyrus IMAP software that is no longer mainstream, and as such the
    level of technical detail is advanced.

    *   :ref:`imap-installation-centos-last-stable`
    *   :ref:`imap-installation-centos-last-stable-next`
    *   :ref:`imap-installation-centos-current-stable`
    *   :ref:`imap-installation-centos-current-stable-next`
    *   :ref:`imap-installation-centos-latest-development`

    .. toctree::
        :glob:
        :hidden:

        ubuntu/*
