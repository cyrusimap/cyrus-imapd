.. _basicserver:

======================
Running a basic server
======================

Now you have :ref:`compiled and installed Cyrus <imapinstallguide>`, it's time to get real.

At the end of this guide, you will be up and running with a local instance of Cyrus. It will have with basic incoming and outgoing mail flow, with caldav and carddav support.

.. todo::
    Bron says: I don't care if it's a docker image with everything else and a checkout of a point in time, but it would be great to have everyone with a "real" environment that you can run a Cyrus master build in and actually use as an email / caldav / carddav server with all the bits and pieces.

.. note::
    These instructions are for Ubuntu, specifically Ubuntu 15.04. For other operating systems, dependency names in package managers may differ, but the main concepts remain the same.

    Please note that **this guide is meant to get you a working environment quickly, not to allow you to customize everything from the get go**. 

    This guide will set up Cyrus to work with the Sendmail SMTP server - and there will be no instructions for using Postfix. Once you have a working environment, you are encouraged to experiment further and set up Postfix instead of Sendmail, use different kinds of authentication schemes, etc.
  

1. Update your system
----------------------

First things first, let's update our existing system to ensure everything is current. This may take some time; you can check `Hacker News`_ in the meantime :-)

::

    sudo apt-get update  
    sudo apt-get upgrade -y

.. _Hacker News: https://news.ycombinator.com/

2. Install Cyrus 3rd party dependencies
---------------------------------------

Now, let's install libraries and tools used by Cyrus IMAP. This includes a C compiler, some Perl libraries (used for Cyrus's command line utilities such as cyradm) or C clients for various databases (ie Mysql, Postgresql, etc). Just like the previous command, this one may take a few minutes to complete. But it's worth it!

.. code-block:: bash

    sudo apt-get install -y autoconf automake autotools-dev bash-completion bison build-essential comerr-dev \
    debhelper flex g++ git gperf groff heimdal-dev libbsd-resource-perl libclone-perl libconfig-inifiles-perl \
    libcunit1-dev libdatetime-perl libdb-dev libdigest-sha-perl libencode-imaputf7-perl libfile-chdir-perl \
    libglib2.0-dev libical-dev libio-socket-inet6-perl libio-stringy-perl libjansson-dev libldap2-dev \
    libmysqlclient-dev libnet-server-perl libnews-nntpclient-perl libpam0g-dev libpcre3-dev libsasl2-dev \
    libsnmp-dev libsqlite3-dev libssl-dev libtest-unit-perl libtool libunix-syslog-perl liburi-perl \
    libxapian-dev libxml-generator-perl libxml-xpath-perl libxml2-dev libwrap0-dev libzephyr-dev lsb-base \
    net-tools perl php5-cli php5-curl pkg-config po-debconf tcl-dev \
    transfig uuid-dev vim wamerican wget xutils-dev zlib1g-dev sasl2-bin rsyslog sudo acl telnet  


3. The cyrus:mail user
----------------------

Now let's create a **special user account just for the Cyrus server** to sandbox Cyrus: called ``cyrus``. We'll also create a ``mail`` group as well. This allows Cyrus to give other programs some permissions if they are run under the ``mail`` group, again, without causing a Cyrus bug to delete all of your cat pictures. Disaster!

::

    groupadd -r mail  
    useradd -c "Cyrus IMAP Server" -d /var/lib/imap -g mail -s /bin/bash -r cyrus  

4. Setting up authentication with SASL
--------------------------------------

Now, let's set up **SASL**. This will allow you to connect to your local IMAP server and login, just like any IMAP user would before checking for new emails.

Create a ``saslauth`` group and add the ``cyrus`` user to the group, so Cyrus can access SASL.

::

    groupadd -r saslauth  
    usermod -aG saslauth cyrus
    
Change the default SASL configuration in ``/etc/default/saslauthd``.
    1. Make sure that the ``START`` option is set to *yes* ``(START=yes)`` and
    2. Set the``MECHANISMS`` option to **sasldb** ``(MECHANISMS="sasldb")``.
    
Start the SASL auth daemon:

::

    /etc/init.d/saslauthd start
    
Great! Now, we'll create the IMAP user inside SASL. This is the user you'll use to login to the IMAP server later on.

::

    echo 'secret' | saslpasswd2 -p -c imapuser
    
You can replace ``secret`` with a more suitable password you want and ``imapuser`` with the username you want. Once this is done, check that the user exists and is set up correctly:

::

    testsaslauthd -u imapuser -p secret  
    
You should get an ``0: OK "Success."`` message.

.. note::
    For some reason I don't understand yet, setting up a user like this doesn't seem to be persistent on my machine. This means I have to create the user with saslpasswd2 every time I restart my PC. This may or may not apply to you too.


5. Enabling mail delivery with LMTP
-----------------------------------

Your Cyrus IMAP server will want to receive the emails accepted by your SMTP server (ie Sendmail, Postfix, etc). In Cyrus, this happens via a protocol called LMTP, which is usually supported by your SMTP server.

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
    
This enables the **cyrusv2** mailer for local mail delivery. In case you're wondering, cyrusv2 stands for Cyrus v2.x, which means this is meant to work with versions 2.x of Cyrus IMAP. It may or may not work with Cyrus 3.x too.

Next, we run a script that takes the ``/etc/mail/sendmail.mc`` file and and prepares it for use by Sendmail. This may take some time. In the meantime, you are encouraged to read the `IMAP spec`_ one more time, because, you know, it's a fun read :-)

::

    sudo sendmailconfig  

Sendmail communication
######################
    
One last thing we need to do for LMTP to work with Sendmail is to create a folder that will contain the UNIX socket used by Sendmail and Cyrus to deliver/receive emails:

::

    sudo mkdir -p /var/run/cyrus/socket  
    sudo chown cyrus:mail /var/run/cyrus/socket  
    sudo chmod 750 /var/run/cyrus/socket  

.. note::   
    For some reason, the /var/run/cyrus/socket folder disappears when I reboot my PC. I need to recreate it when I reboot. You may or may not have to do that too.   

.. _IMAP spec: http://tools.ietf.org/html/rfc3501

6. Protocol ports
-----------------
Cyrus uses assorted protocols, which need to have their ports defined in ``/etc/services``. Make sure that these lines are present and add them if they are missing:

::

    pop3      110/tcp  
    nntp      119/tcp  
    imap      143/tcp  
    imsp      406/tcp  
    nntps     563/tcp  
    acap      674/tcp  
    imaps     993/tcp  
    pop3s     995/tcp  
    kpop      1109/tcp  
    lmtp      2003/tcp  
    sieve     4190/tcp  
    fud       4201/udp      
    
7. Configuring Cyrus
--------------------

(Nearly there)

Set up a simple directory structure for Cyrus to store emails, owned by the ``cyrus:mail`` account:

::

    sudo mkdir -p /var/imap /var/spool/imap  
    sudo chown cyrus:mail /var/imap /var/spool/imap  
    sudo chmod 750 /var/imap /var/spool/imap  

    
Let's add some basic configuration for the Cyrus IMAP server. Two files have to be added: ``/etc/imapd.conf`` and ``/etc/cyrus.conf``.

For :cyrusman:`imapd.conf(5)`, start with this:

::

    configdirectory: /var/imap  
    partition-default: /var/spool/imap  
    admins: imapuser 
    sasl_pwcheck_method: saslauthd  
    allowplaintext: yes  
    virtdomains: yes  
    defaultdomain: localhost  
    
Note that **configdirectory** and **partition-default** are set to the folders we just created.

The admin user is the ``imapuser`` created in step 4, for authentication against sasl. Change this value if you named your user something different.

For :cyrusman:`cyrus.conf(5)`, start with this:

::

    START {  
      # do not delete this entry!
      recover    cmd="ctl_cyrusdb -r"
    }

    # UNIX sockets start with a slash and are put into /var/imap/sockets
    SERVICES {  
      # add or remove based on preferences
      imap        cmd="imapd" listen="imap" prefork=0
      pop3        cmd="pop3d" listen="pop3" prefork=0

      # LMTP is required for delivery (socket is set for Sendmail MTA)
      lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0
    }

    EVENTS {  
      # this is required
      checkpoint    cmd="ctl_cyrusdb -c" period=30

      # this is only necessary if using duplicate delivery suppression
      delprune    cmd="ctl_deliver -E 3" at=0400

      # expire data older than 28 days
      deleteprune cmd="cyr_expire -E 4 -D 28" at=0430
      expungeprune cmd="cyr_expire -E 4 -X 28" at=0445

      # this is only necessary if caching TLS sessions
      tlsprune    cmd="tls_prune" at=0400
    }

Before you launch Cyrus for the first time, create the Cyrus directory structure: use :cyrusman:`mkimap(8)`.

::

    sudo -u cyrus ./tools/mkimap  
        
8. Launch Cyrus
---------------

::

    sudo ./master/master -d  

Check ``/var/log/syslog`` for errors so you can quickly understand potential problems.

Time to cheer!
 
Optional: Setting up SSL certificates
-------------------------------------

Let's set up encryption with TLS. Create a TLS certificate using OpenSSL. Generate the certificate and store it in the /var/imap/server.pem file:

::

    sudo openssl req -new -x509 -nodes -out /var/imap/server.pem \
    -keyout /var/imap/server.pem -days 365 \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"  
    
This creates a TLS certificate (`-out`) and private key (`-keyout`) in the `X.509 <https://en.wikipedia.org/wiki/X.509>`_ format (`-x509`). The certificate is set to expire in 365 days (`-days`) and has default information set up (`-subj ...`). The contents of the -subj is non-trivial and defined in `RFC 5280 <http://www.ietf.org/rfc/rfc5280.txt>`_, a brief summary is available on `stackoverflow <http://stackoverflow.com/questions/6464129/certificate-subject-x-509>`_ which is enough to decode our sample above.

Great! You should now have a file at /var/imap/server.pem. Give Cyrus access to this file:

::

    sudo chown cyrus:mail /var/imap/server.pem 
 
Awesome! Almost done. We will now configure the Cyrus IMAP server to actually use this TLS certificate. Open your Cyrus configuration file /etc/imapd.conf and add the following to lines at the end of it:

::

    tls_server_cert: /var/imap/server.pem  
    tls_server_key: /var/imap/server.pem  

This tells the server where to find the TLS certificate and the key. It may seem weird to specify the same file twice, but since the file has the x509 format, the server will know what to do. Cyrus is there for you, always (unless your hard drive burns down) ! :-)

The other configuration file we have to edit is /etc/cyrus.conf. Open it up with your favorite text editor and in the **SERVICES** section, add this line:

::

    imaps        cmd="imapd" listen="imaps" prefork=0  
    
Notice the `s` at the end of `imaps`. This says we are using TLS.   

If you now restart (or start) your Cyrus server, you should have Cyrus listening on port **993** (the IMAPS port) with the **STARTTLS IMAP extension** enabled. You can check that TLS works as expected with the following command:

::

    imtest -t "" -u imapuser -a imapuser -w secret localhost  
    
Make sure to replace `imapuser` with whatever user you set up with saslpasswd2 before, and to replace `secret` with the actual password you set for that user. 

Sending a test email
--------------------

We will now send a test email to our local development environment to see if everything works as expected:

* Sendmail should accept the incoming email,
* LMTP should transmit the email to Cyrus IMAP,
* You should be able to see the email stored on your filesystem.

But first, let's create a mailbox that we will send the test email to. We'll call this test mailbox `example@localhost`. 

::

    echo 'createmailbox user.example@localhost' | cyradm -u imapuser -w secret localhost  
    
Notice how we seem to be creating a mailbox named `user.example@localhost`. In fact, Cyrus understands this to be `example@localhost`, so we're fine. As usual, adjust the password via the `-w` option to the password you set above.

If you have explicitly enabled `unixhierarchysep` in `/etc/imapd.conf`, you should replace `user.example@localhost` with `user/example@localhost`. You can read more about unixhierarchysep in :cyrusman:`imapd.conf(5)`.

Also, note that the command above might produce some weird looking output, such as:

::

    localhost> localhost>  
    
This happens because cyradm is normally used interactively, with a prompt. We aren't using a prompt, so this output is fine and expected. 

Now that the mailbox exists, we'll send it an email. We won't be using Fastmail or Yahoo Mail or Google Mail. No, no. We will use the good old telnet with raw SMTP commands. Let's do this!

First, connect to the Sendmail SMTP server:

::

    telnet localhost smtp 
    
You should see a prompt appear:

::

    Trying ::1...  
    Trying 127.0.0.1...  
    Connected to localhost.  
    Escape character is '^]'.  
    220 ... ESMTP Sendmail ...  
    
Now, we'll send the `SMTP commands <https://www.ietf.org/rfc/rfc2821.txt>`_ to the server. These are responsible for ordering Sendmail to store an email:

::

    EHLO localhost  
    MAIL FROM:<hello@localhost>  
    RCPT TO:<example@localhost>  
    DATA  
    Hello world!  
    .
    QUIT  
    
If you are using Sendmail as your SMTP server, you should be able to safely copy and paste this bit into the terminal before hitting your ENTER key. If not, you may want to paste these commands one by one (or make sure you enable `PIPELINING` in the SMTP config).

If you see a message like **250 2.0.0 ... Message accepted for delivery**, you did it! You should now have a file called `1.` in the `/var/spool/imap/user/example` directory, with the content of the email you sent just before.

If not, you may want to check `syslog` to see if any error messages show up and go through the previous steps again.

You should also be able to hook up a regular mail client to your shiny new mailserver and access the mailbox for example@localhost via IMAP and see the message.

Checking carddav
----------------

To be written.

Checking caldav
---------------

To be written.

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
    
Something is not working but I can't figure out why
###################################################

More information is almost always logged to **syslog**. Make sure you start syslog with this command before starting the Cyrus server:

::

    /etc/init.d/rsyslog start 

My question isn't answered here
###############################

Join us on the mailing lists if you need help or just want to chat about Cyrus,
IMAP, donuts, etc.   
