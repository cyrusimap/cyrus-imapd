.. _imapinstallguide:
==================================
Developer Environment Installation
==================================

You've decided to help add to the Cyrus project, excellent!

These instructions by Ellie Timony(@elliefm) from FastMail_, are based on Debian 8.0, cause that's what she was setting up as she wrote it. Other Linux distros will probably be similar in the broad ideas but perhaps different in the specifics. If you already have a preferred distro, use that (we assume you know how to use its package management system). If you don't already have a preferred distro, maybe consider using Debian.

Cyrus
=====

Fetching Cyrus
---------------

You'll need access to the cyrus-imapd git repository.

1. You'll need a public key. If you don't already have a `~/.ssh/id_rsa.pub`, then create one with `ssh-keygen(1)`.
    * Use the GitHub guide, following `steps 1-3`_
    
2. Login to Phabricator_
    * Go to the `SSH Keys settings panel`_.
    * Click **Upload public key**
    * Paste the contents of your ``~/.ssh/id_rsa.pub`` (n.b. NOT ``~/.ssh/id_rsa``!) into the public key box.
    * Give it a descriptive name and click **Upload**
    
3. Install git if you don't already have it:
    * ``sudo apt-get install git``    
    
4. Clone the cyrus-imapd repository (you can get this URL from the Diffusion app within Phabricator):
    * If you are a member of `IMAP Committers`_, use ``git clone ssh://git@git.cyrus.foundation/diffusion/I/cyrus-imapd.git``
    * If you aren't (yet), use ``git clone https://git.cyrus.foundation/diffusion/I/cyrus-imapd.git``

Setting up dependencies
-----------------------

1. Install tools for building
    * ``sudo apt-get install build-essential autoconf automake libtool pkg-config bison flex valgrind``
    
2. Install dependencies for master branch
    * ``sudo apt-get install libjansson-dev libxml2-dev libsqlite3-dev libical-dev libsasl2-dev libssl-dev libopendkim-dev libcunit1-dev libpcre3-dev uuid-dev``

3. Additional dependencies for cyrus-imapd-2.5: you'll need the ``-dev`` package to match whichever version of libdb you already have installed (assuming it's probably already installed). I needed ``libdb5.3-dev`` on debian 8.0, but ``libdb5.1-dev`` on 7.8.

.. _steps 1-3: https://help.github.com/articles/generating-ssh-keys/
.. _Phabricator: https://git.cyrus.foundation/
.. _SSH Keys settings panel: https://git.cyrus.foundation/settings/panel/ssh/
.. _IMAP Committers: https://git.cyrus.foundation/tag/imap_committers/


Compile Cyrus
---------------

.. code-block:: bash

    cd /path/to/cyrus-imapd
    
    autoreconf -i -s   # generates a configure script, and its various dependencies
    
    ./configure CFLAGS="-Wno-unused-parameter -g -O0 -Wall -Wextra -Werror" --enable-coverage \
    --enable-http --enable-unit-tests --enable-replication --with-openssl=yes --enable-nntp \
    --enable-murder --enable-idled --enable-event-notification --enable-sieve --prefix=/usr/cyrus

    make lex-fix   # you need this if compile fails with errors from sieve/sieve.c

    make

    make check
    
    make install  # optional if you're just developing on this machine

The ``--prefix`` option sets where Cyrus is installed to. Adjust to suit.
    
You may see warnings regarding libical v2.0 being recommended to support certain functionality. Currently libical v1.0.1 is sufficient, unless you need/want RSCALE (non-gregorian recurrences), VPOLL (consensus scheduling), or VAVAILABILITY (specifying availability over time) functionality. If v2 is required, it will need to be installed from `github <https://github.com/libical/libical>`_.  
    
.. _imapinstallguide_cassandane:

Cassandane
==========

Cassandane is a Perl-based integration test suite for Cyrus.

Why "Cassandane"? Wikipedia indicates that Cassandane_ was the name of
the consort of King Cyrus the Great of Persia, founder of the Achaemenid
Persian Empire.  So that's kinda cool.

.. _Cassandane: http://en.wikipedia.org/wiki/Cassandane

Install and configure Cassandane
--------------------------------

1. Clone the Cassandane repository (you can get the URL from the Diffusion app within Phabricator)
    * If you are a member of `IMAP Committers`_, use: ``git clone ssh://git@git.cyrus.foundation/diffusion/C/cassandane.git``
    * If you aren't (yet), use ``git clone https://git.cyrus.foundation/diffusion/C/cassandane.git``

2. Install dependencies

.. code-block:: bash

    sudo apt-get install libtest-unit-perl libconfig-inifiles-perl \
        libdatetime-perl libbsd-resource-perl libxml-generator-perl \
        libencode-imaputf7-perl libio-stringy-perl libnews-nntpclient-perl \
        libfile-chdir-perl libnet-server-perl libunix-syslog-perl \
        libdata-uuid-perl libjson-xs-perl libdata-ical-perl libjson-perl \
        libdatetime-format-ical-perl libtext-levenshteinxs-perl \
        libmime-types-perl libdatetime-format-iso8601-perl libcal-dav-perl \
        libclone-perl

There are a number of Perl modules required that aren't already packages in the standard repository. A few aren't in CPAN yet and should be installed from github.

.. code-block:: bash

    git clone https://github.com/brong/Net-DAVTalk/
    cd Net-DAVTalk
    perl Makefile.PL
    make
    sudo make install
    cd ..

    git clone https://github.com/brong/Net-CardDAVTalk/
    cd Net-CardDAVTalk
    perl Makefile.PL
    make
    sudo make install
    cd ..

    git clone https://github.com/brong/Net-CalDAVTalk/
    cd Net-CalDAVTalk
    perl Makefile.PL
    make
    sudo make install
    cd ..

    git clone https://github.com/brong/Mail-JMAPTalk/
    cd Mail-JMAPTalk
    perl Makefile.PL
    make
    sudo make install
    cd ..

The quickest option for the rest is installing via CPAN, but you could build packages using dh-make-perl if that is preferred.

.. code-block:: bash

    sudo cpan -i Tie::DataUUID
    sudo cpan -i XML::Spice
    sudo cpan -i XML::Fast
    sudo cpan -i Data::ICal::TimeZone
    sudo cpan -i Text::VCardFast

3. Install Cassandane

.. code-block:: bash

    cd /path/to/cassandane
    make

4. Copy ``cassandane.ini.example`` to ``cassandane.ini``

5. Edit ``cassandane.ini`` to set up your cassandane environment.
    * Assuming you configure cyrus with ``--prefix=/usr/cyrus`` (as above), then the defaults are mostly fine
    * Set ``destdir`` to ``/var/tmp/cyrus``
    
6. Create a ``cyrus`` user and matching group and also add ``cyrus`` to group ``mail``

.. code-block:: bash

    sudo adduser --system --group cyrus
    sudo adduser cyrus mail
    
7. Give your user account access to sudo as ``cyrus``

    * ``sudo visudo``
    * add a line like:``username ALL = (cyrus) NOPASSWD: ALL``, where "username" is your own username

8. Make the ``destdir`` directory, as the ``cyrus`` user

    * ``sudo -u cyrus mkdir /var/tmp/cass``

Building cyrus-imapd for Cassandane
-----------------------------------

    * ``cd /path/to/cyrus-imapd``
    * `Compile Cyrus`_ (as above)
    * ``make -e DESTDIR=/var/tmp/cyrus install``

Running cassandane tests:
-------------------------
    
    * As user ``cyrus``, run the tests.
    
.. code-block:: bash

    cd /path/to/cassandane
    sudo -u cyrus ./testrunner.pl -f pretty -j 8

Read the script to see other options. If you're having problems, add more ``-v`` options to the testrunner to get more info out.

Arcanist
=========

Installing Arcanist
--------------------

Arcanist is a tool for managing workflow (code review, etc), which sits between git and Phabricator.

.. note::

    Conrad says: "Installing arcanist on Ubuntu was apparently as easy as ``sudo apt-get install arcanist``. But, the folks over at arcanist say: "clone the code from GitHub."

1. `Install Arcanist`_
2. Set up Arcanist
    * cd in to any of the GIT repositories (so that the ./.arcconfig file included in those has the upper hand for the next step)
    * Link your local arc to Phabricator: ``arc install-certificate``
    
3. Get familiar with the :ref:`Arcanist workflow <devprocess>`

.. _Install Arcanist: https://secure.phabricator.com/book/phabricator/article/arcanist/#installing-arcanist

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

    /etc/logrotate.d/cyrus.conf
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

----

Ready to get a :ref:`basic server <basicserver>` up and running now you're all installed?
    
.. _FastMail : https://www.fastmail.com
