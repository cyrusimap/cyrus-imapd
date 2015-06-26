==================================
Running a basic server
==================================

Now you have compiled and installed Cyrus, it's time to get real.

Let's set up and run with a local instance of Cyrus with basic incoming and outgoing mail flow, with caldav and carddav support.

.. todo::
    Bron says: I don't care if it's a docker image with everything else and a checkout of a point in time, but it would be great to have everyone with a "real" environment that you can run a Cyrus master build in and actually use as an email / caldav / carddav server with all the bits and pieces.

These instructions are for Ubuntu, specifically Ubuntu 15.04. For other operating systems, dependency names in package managers (think *yum* or *brew*) may differ, but the main concepts should remain the same.

Please note that **this guide is meant to get you a working environment quickly, not to allow you to customize everything from the get go**. 

This guide will set up Cyrus to work with the Sendmail SMTP server - and there will be no instructions for using Postfix. Once you have a working environment, you are encouraged to experiment further and set up Postfix instead of Sendmail, use different kinds of authentication schemes, etc.

.. note:: 
    This guide shows you how to install packages on your system. This requires administrator rights through the sudo command. You will be prompted for your administrator password when running some of these commands.   

1. Update your system
---------------------
First things first, let's update our existing system:

::

    sudo apt-get update  
    sudo apt-get upgrade -y
  
This may take some time; you can check `Hacker News`_ in the meantime :-)

.. _Hacker News: https://news.ycombinator.com/

2. Install Cyrus 3rd party dependencies
---------------------------------------

Now, let's install libraries and tools used by Cyrus IMAP. This includes a C compiler, some Perl libraries (used for Cyrus's command line utilities such as cyradm) or C clients for various databases (ie Mysql, Postgresql, etc). This command looks scary, but it downloads only packages from the official Ubuntu repositories and should therefore be considered safe:

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

Just like the previous command, this one may take a few minutes to complete. But it's worth it!

Already done? Awesome! You're making good progress. Let's keep that going...

3. The cyrus:mail user
----------------------

Now let's create a **special user account just for the Cyrus server**. You may be wondering: why? The reason is that Cyrus developers are humans and therefore make mistakes sometimes. If there is a bug that causes the Cyrus server to delete all of your family pictures, that would not be acceptable. Therefore, by **running the Cyrus server as the cyrus user, we protect your own user account**.

Creating the **cyrus** user is easy:

::

    groupadd -r mail  
    useradd -c "Cyrus IMAP Server" -d /var/lib/imap -g mail -s /bin/bash -r cyrus  

Notice how we are creating a ``mail`` group as well. This allows Cyrus to give other programs some permissions if they are run under the ``mail`` group, again, without causing a Cyrus bug to delete all of your cat pictures. Disaster!

4. Setting up authentication with SASL
--------------------------------------

Now, let's set up **SASL**. This will allow you to connect to your local IMAP server and login, just like any IMAP user would before checking for new emails.

Just as before, we created a user:group ``cyrus:mail`` for the Cyrus server; now, we'll create a ``saslauth`` group which will allow access to SASL specific files:

::

    groupadd -r saslauth  

We'll also make the ``cyrus`` user part of this group, so the Cyrus server can access SASL files:

::

    usermod -aG saslauth cyrus
    
Great! Now, we'll create a user inside SASL. This is the user you'll use to login to the IMAP server later on.

Next, we change the default SASL configuration in ``/etc/default/saslauthd``.
    1. Make sure that the ``START`` option is set to *yes* ``(START=yes)`` and
    2. Set the``MECHANISMS`` option to **sasldb** ``(MECHANISMS="sasldb")``.
    
OK, now we can start the SASL auth daemon:

::

    /etc/init.d/saslauthd start
    
Now, let's create the IMAP user within sasl:

::

    echo 'secret' | saslpasswd2 -p -c imapuser
    
You can replace ``secret`` with any password you want and ``imapuser`` with the username you want. Once this is done, you can check that the user exists and is set up right like this:

::

    testsaslauthd -u imapuser -p secret  
    
You should hopefully get an ``0: OK "Success."`` message.

.. note::
    For some reason I don't understand yet, setting up a user like this doesn't seem to be persistent on my machine. This means I have to create the user with saslpasswd2 every time I restart my PC. This may or may not apply to you too.


5. Enabling mail delivery with LMTP
-----------------------------------

Your Cyrus IMAP server will want to receive the emails accepted by your SMTP server (ie Sendmail, Postfix, etc). In Cyrus, this happens via a protocol called LMTP, which is usually supported by your SMTP server.

We'll setup LMTP with the Sendmail SMTP server. So first, let's install Sendmail:

::

    sudo apt-get install -y sendmail  
    
That was easy. We're not done yet though. We need to make Sendmail aware of the fact we are using the Cyrus IMAP server as opposed to some other IMAP server (ie Dovecot, etc). For this, we'll modify the ``/etc/mail/sendmail.mc`` file.

In ``/etc/mail/sendmail.mc``, add this line before the ``MAILER_DEFINITIONS`` section:

::

    define(`confLOCAL_MAILER', `cyrusv2')dnl  
    
And right under ``MAILER_DEFINITIONS``, add this:

::

    MAILER(`cyrusv2')dnl  
    
This enables the **cyrusv2** mailer for local mail delivery. In case you're wondering, cyrusv2 stands for Cyrus v2.x, which means this is meant to work with versions 2.x of Cyrus IMAP. It may or may not work with Cyrus 3.x too.

Now that we've installed and configured Sendmail, we'll run a script that takes the config file from above - ``/etc/mail/sendmail.mc`` - and converts it to some other representation used by Sendmail:

::

    sudo sendmailconfig  
    
This may take some time. In the meantime, you are encouraged to read the `IMAP spec`_ one more time, because, you know, it's a fun read :-)

One last thing we need to do for LMTP to work with Sendmail is to create a folder that will contain the UNIX socket used by Sendmail and Cyrus to deliver/receive emails:

::

    sudo mkdir -p /var/run/cyrus/socket  
    sudo chown cyrus:mail /var/run/cyrus/socket  
    sudo chmod 750 /var/run/cyrus/socket  

.. note::   
    For some reason, the /var/run/cyrus/socket folder disappears when I reboot my PC. I need to recreate it when I reboot. You may or may not have to do that too.   

.. _IMAP spec: http://tools.ietf.org/html/rfc3501

6. Awareness of protocol ports
------------------------------
On UNIX, you can discover the port used by the system a specific protocol in the ``/etc/services`` file. You can also change this file to suit your particular needs. In the case of Cyrus, we need to make our machine aware of a bunch of protocols. Some of these are already configured in ``/etc/services``, such as **imap** or **smtp**, but some may be missing.

Make sure that these lines are present in your ``/etc/services`` files and add them if they are missing:

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
I know there have been a lot of steps (6 already). But we still have some work to do. The good news? The biggest part is behind us! :-)

What we'll do now is set up a simple directory structure for Cyrus to store emails:

::

    sudo mkdir -p /var/imap /var/spool/imap  
    sudo chown cyrus:mail /var/imap /var/spool/imap  
    sudo chmod 750 /var/imap /var/spool/imap  
    
Note how we are making changing the owner (via chown) to **cyrus:mail**, which is the user you created earlier. This allows Cyrus to access email files (still without accessing your awesome cat photos in your home directory).

Let's add some basic configuration for the Cyrus IMAP server. Two files have to be added: ``/etc/imapd.conf`` and ``/etc/cyrus.conf``.

For ``/etc/imapd.conf``, a good starting point would be this:

::

    configdirectory: /var/imap  
    partition-default: /var/spool/imap  
    admins: imapuser 
    sasl_pwcheck_method: saslauthd  
    allowplaintext: yes  
    virtdomains: yes  
    defaultdomain: localhost  
    
Note how we are setting the **configdirectory** and **partition-default** to the folders we created just before.

The admin user is the ``imapuser`` created in step 4, for authentication against sasl. Change this value if you named your user something different.

For ``/etc/cyrus.conf``, I recommend starting with this:

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

8. Installing Cyrus (finally)
-----------------------------
Now, we can download the Cyrus source code and compile it:

::

    git clone https://git.cyrus.foundation/diffusion/I/cyrus-imapd.git && cd cyrus-imapd  
    autoreconf -s -i  
    ./configure CFLAGS="-Wno-unused-parameter -g -O0 -Wall -Wextra -Werror" --enable-coverage --enable-http --enable-unit-tests --enable-replication --with-openssl=yes --enable-nntp --enable-murder --enable-idled --enable-sieve --prefix=`pwd`
    make lex-fix && make && make install  
    
This will install the Cyrus binaries in the same directory where the source code is. You can change the ``--prefix`` option value to change this behaviour.

Before you launch Cyrus for the first time, you'll need to create the Cyrus directory structure, this is done easily with the ``mkimap`` tool:

::

    sudo -u cyrus ./tools/mkimap  

Finally, launch Cyrus:

::

    sudo ./master/master -d  

I recommend you check ``/var/log/syslog`` for errors so you can quickly understand potential problems.

Time to cheer!
 
Troubleshooting
---------------
Some common issues are explained below. You are welcome to join us in the :ref:`#cyrus IRC channel on Freenode <feedback>` if you need help or just want to chat about Cyrus, IMAP, donuts, etc :-)

I have all kinds of weird Perl errors when running cyradm
#########################################################

The solution is quite simple: we need to set the Perl library path right. To be honest, I was too lazy to figure out exactly which path was right, so I added this snippet to my ``~/.bashrc`` file:

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

setting up SSL certificates
---------------------------

setting up lmtp daemon delivery
-------------------------------

Sending a test email
--------------------

Checking carddav
----------------

Checking caldav
---------------
