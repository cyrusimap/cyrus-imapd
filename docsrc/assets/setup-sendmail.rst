Install Sendmail
################

We'll set up LMTP with the Sendmail SMTP server.

::

    sudo apt-get install -y sendmail

We need to make Sendmail aware of the fact we are using the Cyrus IMAP server: modify the ``/etc/mail/sendmail.mc`` file. Add this line before the ``MAILER_DEFINITIONS`` section:

::

    define(`confLOCAL_MAILER', `cyrusv2')dnl

And right below ``MAILER_DEFINITIONS``, add this:

::

    MAILER(`cyrusv2')dnl

This enables the **cyrusv2** mailer for local mail delivery. This is a sendmail property that tells sendmail it's talking to Cyrus. (Cyrus 3.x works with this property, despite the naming confusion.)

Next, we run a script that takes the ``/etc/mail/sendmail.mc`` file and and prepares it for use by Sendmail. This may take some time.

::

    sudo sendmailconfig

Sendmail communication
######################

One last thing we need to do for LMTP to work with Sendmail is to create a folder that will contain the UNIX socket used by Sendmail and Cyrus to deliver/receive emails:

::

    sudo mkdir -p /var/run/cyrus/socket
    sudo chown cyrus:mail /var/run/cyrus/socket
    sudo chmod 750 /var/run/cyrus/socket
