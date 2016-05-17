.. _imapinstallguide:

==================================
Developer Environment Installation
==================================

You've decided to help add to the Cyrus project, excellent!

These instructions are based on Debian 8.0 because it has to be based on something. Other Linux distributions will be similar in the broad ideas but may differ in the specifics. If you already have a preferred distro, use that (we assume you know how to use its package management system). If you don't already have a preferred distro, maybe consider using Debian.

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

3. Additional dependencies for cyrus-imapd-2.5: you'll need the ``-dev`` package to match whichever version of libdb you already have installed (assuming it's probably already installed). On Debian 8.0, ``libdb5.3-dev`` is needed, but ``libdb5.1-dev`` on 7.8.

4. Install dependencies for :ref:`building the docs <contribute-docs>`.
    * ``sudo pip install python-sphinx``
    * ``sudo cpan install Pod::POM::View::Restructured``

.. _steps 1-3: https://help.github.com/articles/generating-ssh-keys/
.. _Phabricator: https://git.cyrus.foundation/
.. _SSH Keys settings panel: https://git.cyrus.foundation/settings/panel/ssh/
.. _IMAP Committers: https://git.cyrus.foundation/tag/imap_committers/


Compile Cyrus
---------------

There are additional :ref:`compile and installation steps<imapinstall-xapian>` if you are using Xapian for searching.  

.. code-block:: bash

    cd /path/to/cyrus-imapd
    
    autoreconf -i -s   # generates a configure script, and its various dependencies
    
    ./configure CFLAGS="-W -Wno-unused-parameter -g -O0 -Wall -Wextra -Werror -fPIC" \
    --enable-coverage --enable-calalarmd --enable-apple-push-service --enable-autocreate \
    --enable-nntp --enable-http --enable-unit-tests \
    --enable-replication --with-openssl=yes --enable-nntp --enable-murder \
    --enable-idled --enable-event-notification --enable-sieve --prefix=/usr/cyrus

    make lex-fix   # you need this if compile fails with errors from sieve/sieve.c

    make

    make check
    
    make install  # optional if you're just developing on this machine
    
    make install-binsymlinks    # Useful if you're testing older Cyrus versions

The ``--prefix`` option sets where Cyrus is installed to. Adjust to suit.

It may be of use to also add ``--std=gnu99`` to the ``CFLAGS``.  That generates TONS of warnings.
    
You may see warnings regarding libical v2.0 being recommended to support certain functionality. Currently libical v1.0.1 is sufficient, unless you need/want RSCALE (non-gregorian recurrences), VPOLL (consensus scheduling), or VAVAILABILITY (specifying availability over time) functionality. If v2 is required, it will need to be installed from `github <https://github.com/libical/libical>`_.  

Arcanist
=========

Installing Arcanist
--------------------

Arcanist is a tool for managing workflow (code review, etc), which sits between git and Phabricator.

.. note::

    Conrad (@conradk) says: "Installing arcanist on Ubuntu was apparently as easy as ``sudo apt-get install arcanist``. But, the folks over at arcanist say: "clone the code from GitHub."

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
