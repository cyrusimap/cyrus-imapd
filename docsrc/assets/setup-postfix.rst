Postfix
_______
Install Postfix
###############

We'll set up LMTP with the Postfix SMTP server (consider which other
Postfix related packages you may also desire)::

    sudo apt-get install -y postfix postfix-doc postfix-pcre postfix-ldap ...

We need to make Postfix aware of the fact we are using the Cyrus IMAP
server and engineer delivery via LMTP.  The following examples show the
``postconf`` commands to run to add the necessary configuration to
``/etc/postfix/main.cf``, these are not complete configurations.

.. note::

    Postfix supports a great many configurations for mail delivery
    transport, so these settings will depend on whether you're planning
    to use the ``local``, ``virtual`` or ``lmtp`` destination
    definitions.  For our examples we'll be using ``virtual``.  Adjust
    as needed for your purposes, and please consult the Postfix
    documentation at http://www.postfix.org/postconf.5.html

1.  Setup your recipient maps, thus defining for which recipients the
    ``virtual`` destination will be used::

        postconf -e "virtual_mailbox_domains=hash:/etc/postfix/virtual_recipient_domains"
        postconf -e "virtual_mailbox_maps=hash:/etc/postfix/virtual_recipients"

    or, if you have enabled smmapd you can automatically track mailboxes with::

        postconf -e "virtual_mailbox_domains=hash:/etc/postfix/virtual_recipient_domains"
        postconf -e "virtual_mailbox_maps=socketmap:unix:/run/cyrus/socket/smmap"

2.  Optional: Set the concurrency and recipient limits for LMTP delivery to the
    ``virtual`` destination::

        postconf -e "virtual_destination_concurrency_limit=300"
        postconf -e "virtual_destination_recipient_limit=300"

    The purpose of those two settings is to allow for a large number of
    simultaneous delivery threads between the MTA (Postfix) and the MDA
    (Cyrus), and to allow for a large number of recipients to be listed
    for any given message, thus avoiding splitting up delivery of messages
    with lots of recipients into many separate deliveries.

3.  Send mail for those recipients to Cyrus via LMTP.  This first
    example is for delivery via TCP to a different host::

        postconf -e "virtual_transport=lmtp:inet:lmtp.example.org:2003"

    If your Postfix and Cyrus are on the same host, then use some
    version of this, where the socket patch matches what's set in the
    ``lmtpsocket`` option in :cyrusman:`imapd.conf(5)`::

        postconf -e "virtual_transport=lmtp:unix:/run/cyrus/socket/lmtp"
