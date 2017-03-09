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

Follow our :ref:`Guide to GitHub <github-guide>` for details on how to access the repository, fork it, clone it, and branch it.

Setting up dependencies
-----------------------

1. Install tools for building
    * ``sudo apt-get install build-essential autoconf automake libtool pkg-config bison flex valgrind``

2. Install dependencies for master branch
    * ``sudo apt-get install libjansson-dev libxml2-dev libsqlite3-dev libical-dev libsasl2-dev \
      libssl-dev libopendkim-dev libcunit1-dev libpcre3-dev uuid-dev``

3. Additional dependencies for cyrus-imapd-3: you'll need the ``-dev`` package to match whichever version of libdb you already have installed (assuming it's probably already installed). On Debian 8.0, ``libdb5.3-dev`` is needed, but ``libdb5.1-dev`` on 7.8.

4. Install dependencies for :ref:`building the docs <contribute-docs>`.
    * ``sudo pip install python-sphinx``
    * ``sudo cpan install Pod::POM::View::Restructured``


Compile Cyrus
---------------

There are additional :ref:`compile and installation steps<imapinstall-xapian>` if you are using Xapian for searching,
or if you are :ref:`using jmap <developer-jmap>`.

.. tip::
    Passing environment variables as an argument to configure,
    rather than setting them in the environment before running configure,
    allows their values to be logged in config.log.  This is useful for diagnosing
    problems.

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

If you're running on Debian, and you install to ``/usr/local``, you may need to update your library loader. Edit ``/etc/ld.so.conf.d/x86_64-linux-gnu.conf`` so it includes the following additional line::

    /usr/local/lib/x86_64-linux-gnu

Without this, when you attempt to start Cyrus, it reports ``error while loading shared libraries: libcyrus_imap.so.0: cannot open shared object file: No such file or directory`` because it can't find the Cyrus library in /usr/local/lib.

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
