Why is mail being rejected with No Mailbox found due to MiXed CaSe incoming e-mail?
-----------------------------------------------------------------------------------

If you are using a newer and standard compliant MTA to deliver mail to Cyrus IMAP's LMTP agent you may run into a problem where mail will be bounced and not delivered with errors like this in your maillog::

    Feb 29 10:01:02 myhost lmtpunix[12345]: append_check() of 'MyDomain.tld!user.MyUser' failed (Mailbox does not exist)

This is due to LMTP adhering to the RFC standards and the MTA adhering to the RFC standards of preserving the case in the e-mail address. so User@MyDomain.tld is not the same as user@mydomain.tld. And this causes issues if with users who alter the case of their e-mail address when signing up for mailing lists, or sending e-mail.

However, all is not lost there is a solution. Cyrus IMAP has an option that can be added into the imapd.conf::

    lmtp_downcase_rcpt: true

Inserting that into your :cyrusman:`imapd.conf(5)` and restarting cyrus imap will cause cyrus to "downcase" the e-mail address up to the recipient delimiter of +. The result will be this::

    User@MyDomain.tld -> user@mydomain.tld
    user@mydomain.tld -> user@mydomain.tld
    User+PostFolder@MyDomain.tld -> user+PostFolder@MyDomain.tld

Someone verify that the domain will actually be downcased when a + is used

Note that this option first appeared in Cyrus IMAP 2.1.14.
