.. _basicserver:

======================
Running a basic server
======================

Once you have :ref:`compiled and installed Cyrus <imapinstallguide>`,
you can configure your environment and start Cyrus.

At the end of this guide, you will be up and running with a local
instance of Cyrus. It will have with basic incoming and outgoing mail
flow, with CalDAV and CardDAV support.

.. note::
    These instructions are for Debian "Jessie" or newer. For other
    operating systems or distros, dependency names in package managers
    may differ, but the main concepts remain the same.

    Please note that **this guide is meant to get you a working
    environment quickly, not to allow you to customize everything**.

    This guide will set up Cyrus to work with the Sendmail SMTP server
    - and there will be no instructions for using Postfix. Once you
    have a working environment, you are welcome to experiment further
    and set up a different MTA or use different kinds of authentication
    schemes, etc.


1. Update your system
----------------------

First update the system to ensure everything is current. This may take
some time; you can check `Hacker News`_ in the meantime.

::

    sudo apt-get update
    sudo apt-get upgrade -y

.. _Hacker News: https://news.ycombinator.com/

2. Install Cyrus 3rd party dependencies
---------------------------------------
Install libraries and tools used by Cyrus IMAP. This includes a C
compiler, build tools, and some support libraries.  Just like the
previous command, this one may take a few minutes to complete.

.. include:: /assets/cyrus-build-devpkg.rst

3. Setup the cyrus:mail user and group
--------------------------------------

.. include:: /assets/cyrus-user-group.rst

4. Setting up authentication with SASL
--------------------------------------

.. include:: /assets/setup-sasl-sasldb.rst


5. Setup mail delivery from your MTA
------------------------------------

Your Cyrus IMAP server will want to receive the emails accepted by your
SMTP server (ie Sendmail, Postfix, etc). In Cyrus, this happens via a
protocol called LMTP, which is usually supported by your SMTP server.

.. include:: /assets/setup-sendmail.rst

6. Protocol ports
-----------------

.. include:: /assets/services.rst

7. Configuring Cyrus
--------------------

(Nearly there)

.. include:: /assets/setup-dir-struct.rst

Let's add some basic configuration for the Cyrus IMAP server. Two files
have to be added: ``/etc/imapd.conf`` and ``/etc/cyrus.conf``.  There
are several examples included with the software, in ``doc/examples/``.
Pick one each from the ``imapd_conf`` and ``cyrus_conf`` directories,
or create your own.

For :cyrusman:`imapd.conf(5)`, let's start with the ``normal.conf``
example:

.. literalinclude:: /../doc/examples/imapd_conf/normal.conf

Note that **configdirectory** and **partition-default** are set to the
folders we just created.

The admin user is the ``imapuser`` created in step 4, for
authentication against sasl. Change this value if you named your user
something different.

For :cyrusman:`cyrus.conf(5)`, again we'll start with the
``normal.conf`` example:

.. literalinclude:: /../doc/examples/cyrus_conf/normal.conf

Before you launch Cyrus for the first time, create the Cyrus directory
structure: use :cyrusman:`mkimap(8)`.

::

    sudo -u cyrus ./tools/mkimap

8. Launch Cyrus
---------------

::

    sudo ./master/master -d

Check ``/var/log/syslog`` for errors so you can quickly understand any
problems.

When you're ready, you can create init scripts to start and stop your
daemons. This
https://www.linux.com/learn/managing-linux-daemons-init-scripts is old,
but has a good explanation of the concepts required.

Optional: Setting up SSL certificates
-------------------------------------

Create a TLS certificate using OpenSSL. Generate the certificate and
store it in the /var/lib/cyrus/server.pem file:

::

    sudo openssl req -new -x509 -nodes -out /var/lib/cyrus/server.pem \
    -keyout /var/lib/cyrus/server.pem -days 365 \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"

This creates a TLS certificate (`-out`) and private key (`-keyout`) in
the `X.509 <https://en.wikipedia.org/wiki/X.509>`_ format (`-x509`).
The certificate is set to expire in 365 days (`-days`) and has default
information set up (`-subj ...`). The contents of the -subj is
non-trivial and defined in `RFC 5280
<http://www.ietf.org/rfc/rfc5280.txt>`_, a brief summary is available
on `stackoverflow
<http://stackoverflow.com/questions/6464129/certificate-subject-x-509>`_
which is enough to decode our sample above.

Great! You should now have a file at /var/lib/cyrus/server.pem. Give
Cyrus access to this file:

::

    sudo chown cyrus:mail /var/lib/cyrus/server.pem

Awesome! Almost done. We will now configure the Cyrus IMAP server to
actually use this TLS certificate. Open your Cyrus configuration file
``/etc/imapd.conf`` and add the following two lines at the end of it:

::

    tls_server_cert: /var/lib/cyrus/server.pem
    tls_server_key: /var/lib/cyrus/server.pem

This tells the server where to find the TLS certificate and the key. It
may seem weird to specify the same file twice, but since the file has
the x509 format, the server will know what to do. Cyrus is there for
you, always (unless your hard drive burns down) ! :-)

The other configuration file we have to edit is ``/etc/cyrus.conf``.
Open it up with your favorite text editor and in the **SERVICES**
section, add (or uncomment) this line:

::

    imaps        cmd="imapd" listen="imaps" prefork=0

Notice the `s` at the end of `imaps`. This says we are using TLS.
Similar such lines may be used for `pop3s`, `lmtps` and other protocols.
See Protocol Ports, above, for more information on these. 

If you now restart (or start) your Cyrus server, you should have Cyrus
listening on port **993** (the IMAPS port) with the **STARTTLS IMAP
extension** enabled. You can check that TLS works as expected with the
following command:

::

    imtest -t "" -u imapuser -a imapuser -w secret localhost

Make sure to replace `imapuser` with whatever user you set up with
saslpasswd2 before, and to replace `secret` with the actual password
you set for that user.

Sending a test email
--------------------

We will send a test email to our local development environment to check
if:

* The SMTP server\* accepts the incoming email,
* LMTP transmits the email to Cyrus IMAP,
* You can see the email stored on your filesystem.

..  Note:: \*SMTP servers also often called an "MTA," for Mail Transport
    Agent

But first, create a mailbox to send the test email to. We'll call this
test mailbox `example@localhost`.

::

    echo 'createmailbox user/example@localhost' | cyradm -u imapuser -w secret localhost

We seem to be creating a mailbox named ``user/example@localhost``. In
fact, Cyrus understands this to be a user called ``example@localhost``.
As usual, adjust the password via the ``-w`` option to the password you
set above.

If you have explicitly disabled ``unixhierarchysep`` in
``/etc/imapd.conf`` (it is enabled by default in 3.0+), you should
replace ``user/example@localhost`` with ``user.example@localhost``. You
can read more about ``unixhierarchysep`` in :cyrusman:`imapd.conf(5)`.

The command will produce the following output:

::

    localhost> localhost>

This happens because cyradm is normally used interactively, with a
prompt. We aren't using a prompt, so this output is expected.

Now that the mailbox exists, we can send an email using telnet with raw
SMTP commands.

First, connect to the MTA:

::

    telnet localhost smtp

You should see a prompt appear:

::

    Trying ::1...
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    220 ... ESMTP Sendmail ...

Now, we'll send the `SMTP commands <https://www.ietf.org/rfc/rfc2821.txt>`_ to the server. These are responsible for ordering the MTA to store an email:

::

    EHLO localhost
    MAIL FROM:<hello@localhost>
    RCPT TO:<example@localhost>
    DATA
    Hello world!
    .
    QUIT

If you are using Sendmail as your SMTP server, you should be able to
safely copy and paste this bit into the terminal before hitting your
ENTER key. If not, you may want to paste these commands one by one (or
make sure you enable `PIPELINING` in the SMTP config).

If you see a message like **250 2.0.0 ... Message accepted for
delivery**, you did it! You should now have a file called `1.` in the
`/var/spool/cyrus/user/example` directory, with the content of the email
you sent just before.

If not, you may want to check `syslog` to see if any error messages
show up and go through the previous steps again.

To let the example user log in via IMAP on a normal mail client, you
need to add them to SASL (as before)::

    echo 'mypassword' | saslpasswd2 -p -c example

Check your two users are there::

    sasldblistusers2

You can now configure a mail client to access your new mailserver and
connect to the mailbox for example@localhost via IMAP and see the
message.

Checking CardDAV and CardDAV
----------------------------

Modify ``/etc/cyrus.conf`` and add (or uncomment) this line in the
SERVICES section::

    http        cmd="httpd" listen="http" prefork=0

Modify ``/etc/imapd.conf`` and add (or uncomment) this line::

    httpmodules: caldav carddav

Running the following commands should return you sample entry
addressbook and calendar entry for the sample example user::

    curl -u example@[hostname]:mypassword -i -X PROPFIND -H 'Depth: 1' http://localhost:8080/dav/addressbooks/user/example@[hostname]/Default

    curl -u example@[hostname]:mypassword -i -X PROPFIND -H 'Depth: 1' http://localhost:8080/dav/principals/user/example@[hostname]/

----

Troubleshooting
---------------

Some common issues are explained below.

I have all kinds of weird Perl errors when running cyradm
#########################################################

The solution is to set the Perl library path right. To be honest, I was too lazy to figure out exactly which path was right, so I added this snippet to my ``~/.bashrc`` file:

::

    export PERL5LIB="$PERL5LIB:$(find path/to/cyrus/perl -type d | tr "\\n" ":")"

Just make sure to change **path/to/cyrus** to the actual path to the Cyrus source code directory. This should be something like ``/home/jack/cyrus-src/perl``.

I can't connect to the IMAP server
##################################

Make sure that the SASL auth daemon is running. You can start it with this command:

::

    /etc/init.d/saslauthd start

You can safely run this command even if you don't know whether the SASL auth daemon is already running or not.

Emails are not being delivered to Cyrus
#######################################

Make sure that you have started Sendmail, which you can do like this:

::

    /etc/init.d/sendmail start

My IMAP server (master) can't authenticate users to SASL
########################################################

Check that the groups setting on your cyrus user is correct.

Ubuntu uses `saslauth` group, Debian uses `sasl` group.

Check the output of `groups cyrus` to see what groups it currently belongs to.

Incorrect groups settings results in saslauthd reporting permission failures::

    SASL cannot connect to saslauthd server: Permission denied
    SASL unable to open Berkeley db /etc/sasldb2: Permission denied

Master will need to be restarted if you needed to change the groups.

Something is not working but I can't figure out why
###################################################

More information is almost always logged to **syslog**. Make sure you start syslog with this command before starting the Cyrus server:

::

    /etc/init.d/rsyslog start

My question isn't answered here
###############################

Join us in the :ref:`#cyrus IRC channel on Freenode <feedback>` or on the mailing lists if you need help or just want to chat about Cyrus, IMAP, donuts, etc.
