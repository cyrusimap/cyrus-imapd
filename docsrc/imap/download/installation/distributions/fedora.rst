Fedora
======

Fedora is a Linux distribution that does not generally enforce a policy
of not providing you with upgrades of software during the life-cycle of
any of the distribution's released versions, or what could otherwise be
expected to constitute "stable".

While package maintainers tend to want to prevent unpleasant surprises
from being deployed to your Fedora system, and therefore generally
ship only versions of one series to any one given released distribution
version, the Cyrus project cannot guarantee you will not receive an
upgrade at some point, and cannot guarantee this upgrade will run
smoothly -- even though we do our best.

To install the version of Cyrus IMAP that comes with the operating
system, issue the following command for Fedora 18 or below:

.. parsed-literal::

    # :command:`yum install cyrus-imapd cyrus-sasl cyrus-sasl-plain`

or for Fedora 19 and above:

.. parsed-literal::

    # :command:`dnf install cyrus-imapd cyrus-sasl cyrus-sasl-plain`

Next, set a password for the default administrative user ``cyrus``:

.. parsed-literal::

    # :command:`passwd cyrus`
    Changing password for user cyrus.
    New password:
    Retype new password:
    passwd: all authentication tokens updated successfully.

Start and configure to start when the system boots, the
:manpage:`saslauthd` service. For Fedora 14 and below:

.. parsed-literal::

    # :command:`service saslauthd start`
    Starting saslauthd:                                        [  OK  ]
    # :command:`chkconfig saslauthd on`

or for Fedora 15 and above:

.. parsed-literal::

    # :command:`systemctl start saslauthd`
    # :command:`systemctl enable saslauthd`

You should at this moment be able to authenticate against
:manpage:`saslauthd`:

.. parsed-literal::

    # :command:`testsaslauthd -u cyrus -p YOUR-PASSWORD`


You should get an ``0: OK "Success."`` message.

.. todo:: If this does not succeed, see ref `sasl-troubleshooting-saslauthd`.

Start the service, and ensure the service starts up when the system
boots. For Fedora 14 and below:

.. parsed-literal::

    # :command:`service cyrus-imapd start`
    # :command:`chkconfig cyrus-imapd on`

or for Fedora 15 and above:

.. parsed-literal::

    # :command:`systemctl start cyrus-imapd`
    # :command:`systemctl enable cyrus-imapd`

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
