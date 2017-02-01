Red Hat Enterprise Linux
========================

Red Hat Enterprise Linux ships Cyrus IMAP packages as part of the base
operating system repositories. If the base operating system has a
subscription activated, then `Red Hat, Inc.`_ supports the package
through the usual support channels.

Currently supported versions of Red Hat Enterprise Linux include
Cyrus IMAP packages in the repositories configured on a stock system:

*   Cyrus IMAP |imap_tikanga_stock_version| for Red Hat Enterprise Linux
    5

*   Cyrus IMAP |imap_santiago_stock_version| for Red Hat Enterprise
    Linux 6

*   Cyrus IMAP |imap_maipo_stock_version| for Red Hat Enterprise Linux 7

.. NOTE::

    The Cyrus project does not support running any versions of the Cyrus
    IMAP software older than the version of the software shipped
    with the operating system itself.

To install the version of Cyrus IMAP that comes with the operating
system, issue the following command:

.. parsed-literal::

    # :command:`yum install cyrus-imapd cyrus-sasl cyrus-sasl-plain`

Next, set a password for the default administrative user ``cyrus``:

.. parsed-literal::

    # :command:`passwd cyrus`
    Changing password for user cyrus.
    New password:
    Retype new password:
    passwd: all authentication tokens updated successfully.

Start and configure to start when the system boots, the
:manpage:`saslauthd` service:

.. parsed-literal::

    # :command:`service saslauthd start`
    Starting saslauthd:                                        [  OK  ]
    # :command:`chkconfig saslauthd on`

You should at this moment be able to authenticate against
:manpage:`saslauthd`:

.. parsed-literal::

    # :command:`testsaslauthd -u cyrus -p YOUR-PASSWORD`


You should get an ``0: OK "Success."`` message.

.. todo:: If this does not succeed, see  ref `sasl-troubleshooting-saslauthd`.

Start the service, and ensure the service starts up when the system
boots:

.. parsed-literal::

    # :command:`service cyrus-imapd start`
    # :command:`chkconfig cyrus-imapd on`

You should now be able to login as the ``cyrus`` user, which is
configured by default as an administrator for Cyrus IMAP:

.. parsed-literal::

    # :command:`imtest -t "" -u cyrus -a cyrus localhost`
    S: * OK [CAPABILITY IMAP4 IMAP4rev1 LITERAL+ ID STARTTLS LOGINDISABLED COMPRESS=DEFLATE] d5ec35c1414a Cyrus IMAP v2.3.16-Fedora-RPM-2.3.16-13.el6_6 server ready
    C: S01 STARTTLS
    S: S01 OK Begin TLS negotiation now
    verify error:num=18:self signed certificate
    TLS connection established: TLSv1.2 with cipher DHE-RSA-AES256-GCM-SHA384 (256/256 bits)
    C: C01 CAPABILITY
    S: * CAPABILITY IMAP4 IMAP4rev1 LITERAL+ ID AUTH=PLAIN SASL-IR COMPRESS=DEFLATE ACL RIGHTS=kxte QUOTA MAILBOX-REFERRALS NAMESPACE UIDPLUS NO_ATOMIC_RENAME UNSELECT CHILDREN MULTIAPPEND BINARY SORT SORT=MODSEQ THREAD=ORDEREDSUBJECT THREAD=REFERENCES ANNOTATEMORE CATENATE CONDSTORE SCAN IDLE LISTEXT LIST-SUBSCRIBED X-NETSCAPE URLAUTH
    S: C01 OK Completed
    Please enter your password:
    C: A01 AUTHENTICATE PLAIN \*\*\*\*\*\*\*\*\*\*\*\*
    S: A01 OK [CAPABILITY IMAP4 IMAP4rev1 LITERAL+ ID LOGINDISABLED COMPRESS=DEFLATE ACL RIGHTS=kxte QUOTA MAILBOX-REFERRALS NAMESPACE UIDPLUS NO_ATOMIC_RENAME UNSELECT CHILDREN MULTIAPPEND BINARY SORT SORT=MODSEQ THREAD=ORDEREDSUBJECT THREAD=REFERENCES ANNOTATEMORE CATENATE CONDSTORE SCAN IDLE LISTEXT LIST-SUBSCRIBED X-NETSCAPE URLAUTH] Success (tls protection)
    Authenticated.
    Security strength factor: 256
    . LIST "" "*"
    . OK Completed (0.000 secs 1 calls)
    C: Q01 LOGOUT
    * BYE LOGOUT received
    Q01 OK Completed
    Connection closed.

Next, continue with :ref:`imap-configuring-the-mta`.

.. _Red Hat, Inc.: https://redhat.com
