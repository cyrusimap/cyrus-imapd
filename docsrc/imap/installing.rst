.. _installing:

================
Installing Cyrus
================

This guide assumes you have already :ref:`compiled Cyrus <compiling>`.

Install Cyrus
=============

The ``--prefix`` option given to ``configure`` (during :ref:`compilation <compiling>`) sets where Cyrus is installed to.

If unspecified, it will go to whatever destination is your system default (often ``/usr/local``).
To check: the final output of the configure step will display where a ``make install`` will install to.

.. code-block:: bash

    make install  # optional if you're just developing on this machine

    make install-binsymlinks    # Only needed if you're testing older Cyrus versions


Optional Components
===================

.. toctree::
    :maxdepth: 2

    download/installation/manage-dav
    download/installation/virus

Setting up syslog
=================

A lot of Cyrus's debugging information gets logged with ``syslog``, so you'll want to be able to capture it and find it later (especially when debugging cassandane tests)

1. Find the correct place to edit syslog config for your system (for me, I needed to create ``/etc/rsyslog.d/cyrus.conf``)
2. Add lines like

    ``local6.*        /var/log/imapd.log``

    ``auth.debug      /var/log/auth.log``

3. Restart the rsyslog service

    ``sudo /etc/init.d/rsyslog restart``

4. Arrange to rotate ``/var/log/imapd.log`` so it doesn't get stupendously large. Create ``/etc/logrotate.d/cyrus.conf`` with content like::

    /var/log/imapd.log
    {
        rotate 4
        weekly
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
        invoke-rc.d rsyslog rotate > /dev/null
        endscript
    }

Create Cyrus environment
========================

Set up the cyrus:mail user and group
------------------------------------

.. include:: /assets/cyrus-user-group.rst

Authentication with SASL
------------------------

.. include:: /assets/setup-sasl-sasldb.rst


Mail delivery from your MTA
---------------------------

Your Cyrus IMAP server will want to receive the emails accepted by your
SMTP server (ie Sendmail, Postfix, etc). In Cyrus, this happens via a
protocol called LMTP, which is usually supported by your SMTP server.

.. include:: /assets/setup-sendmail.rst

Protocol ports
--------------

.. include:: /assets/services.rst

Cyrus config files
------------------

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

.. note::

    The admin user is the ``imapuser`` created earlier for
    authentication against sasl. Change this value if you named your user
    something different.

For :cyrusman:`cyrus.conf(5)`, again we'll start with the
``normal.conf`` example:

.. literalinclude:: /../doc/examples/cyrus_conf/normal.conf

Before you launch Cyrus for the first time, create the Cyrus directory
structure: use :cyrusman:`mkimap(8)`.

::

    sudo -u cyrus ./tools/mkimap

Optional: Setting up TLS certificates
-------------------------------------

Obtain a certificate, e.g. from
`Let’s Encrypt <https://letsencrypt.org/>`_.  You need a file with
the full chain and a private key in
`X.509 <https://en.wikipedia.org/wiki/X.509>`_ format.  Adjust the file
owner on these files with ``sudo chown cyrus:mail``.  Set the options
``tls_server_cert`` and ``tls_server_key`` in :cyrusman:`imapd.conf(5)`
to point to these files.

Open ``/etc/cyrus.conf`` and in the **SERVICES** section, add (or
uncomment) this line:

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



Prepare ephemeral (run-time) storage directories
------------------------------------------------

If you will be using ephemeral (run-time) storage locations on an OS or
distro on which the directory skeleton does not persist over reboots,
you will need to use your distro's standard method to ensure that any
such directories your installation depends upon exist `prior` to
launching the daemon.

Here's how to do so for Debian/Ubuntu.  Use the provided
``statoverride`` facility to manage the ownership and permissions of
these directories::

    sudo dpkg-statoverride cyrus mail 755 /run/cyrus
    sudo dpkg-statoverride cyrus mail 750 /run/cyrus/socket

Then you can use something like this in your init script (like those
packaged by Debian team)::

    dir=$(dpkg-statoverride --list /var/run/cyrus)
    [ -z "$dir" ] || createdir $dir

where the ``createdir()`` shell function looks like this::

    createdir() {
    # $1 = user
    # $2 = group
    # $3 = permissions (octal)
    # $4 = path to directory
        [ "$VERBOSE" = "yes" ] && OPT="-c"
        [ -d "$4" ] || mkdir -p "$4"
        chown $OPT -h "$1:$2" "$4"
        chmod $OPT "$3" "$4"
    }

Putting it all together, this blob from the stock Debian packaging
would go between pre-flight checks (checking for config sanity, file
locations, etc.) and initialization::

    createdir() {
    # $1 = user
    # $2 = group
    # $3 = permissions (octal)
    # $4 = path to directory
        [ "$VERBOSE" = "yes" ] && OPT="-c"
        [ -d "$4" ] || mkdir -p "$4"
        chown $OPT -h "$1:$2" "$4"
        chmod $OPT "$3" "$4"
    }

    missingstatoverride () {
        echo "$0: You are missing a dpkg-statoverride on $1.  Add it." >&2
        exit 1
    }

    fixdirs () {
        dir=$(dpkg-statoverride --list /run/cyrus) \
            || missingstatoverride /run/cyrus
        [ -z "$dir" ] \
            || createdir $dir
        dir=$(dpkg-statoverride --list /run/cyrus/socket) \
            || missingstatoverride /run/cyrus/socket
        [ -z "$dir" ] \
            || createdir $dir
    }


Launch Cyrus
============

::

    sudo ./master/master -d

Check ``/var/log/syslog`` for errors so you can quickly understand any
problems.

When you're ready, you can create init scripts to start and stop your
daemons. This
https://www.linux.com/learn/managing-linux-daemons-init-scripts is old,
but has a good explanation of the concepts required.

Send a test email
=================

We will send a test email to our local development environment to check
if:

* The SMTP server\* accepts the incoming email,
* LMTP transmits the email to Cyrus IMAP,
* You can see the email stored on your filesystem.

..  Note:: \*SMTP servers are also often called an "MTA," for Mail Transport
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

Checking CardDAV and CalDAV
===========================

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
===============

Some common issues are explained below.

.. rubric:: I have all kinds of weird Perl errors when running cyradm

The solution is to set the Perl library path right. To be honest, I was too lazy to figure out exactly which path was right, so I added this snippet to my ``~/.bashrc`` file:

::

    export PERL5LIB="$PERL5LIB:$(find path/to/cyrus/perl -type d | tr "\\n" ":")"

Just make sure to change **path/to/cyrus** to the actual path to the Cyrus source code directory. This should be something like ``/home/jack/cyrus-src/perl``.

.. rubric:: I can't connect to the IMAP server

Make sure that the SASL auth daemon is running. You can start it with this command:

::

    /etc/init.d/saslauthd start

You can safely run this command even if you don’t know whether the SASL auth daemon is already running or not.

.. rubric:: Emails are not being delivered to Cyrus

Make sure that you have started Sendmail, which you can do like this:

::

    /etc/init.d/sendmail start

.. rubric:: My IMAP server (master) can't authenticate users to SASL

Check that the groups setting on your cyrus user is correct.

Ubuntu uses `saslauth` group, Debian uses `sasl` group.

Check the output of `groups cyrus` to see what groups it currently belongs to.

Incorrect groups settings results in saslauthd reporting permission failures::

    SASL cannot connect to saslauthd server: Permission denied
    SASL unable to open Berkeley db /etc/sasldb2: Permission denied

Master will need to be restarted if you needed to change the groups.

.. rubric:: Something is not working but I can't figure out why

More information is almost always logged to **syslog**. Make sure you start syslog with this command before starting the Cyrus server:

::

    /etc/init.d/rsyslog start

.. rubric:: My question isn't answered here

Join us in the :ref:`#cyrus IRC channel on Freenode <feedback-irc>` or on the
:ref:`mailing lists <feedback-mailing-lists>` if you need help or just want to chat about Cyrus, IMAP, etc.

.. _FastMail : https://www.fastmail.com
