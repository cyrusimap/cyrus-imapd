.. _developer-testing:

==========================
Developer Test Environment
==========================

This assumes you have your :ref:`basic server running <installing>` and you've made some changes and you want to test them to work out what's going right... or wrong.

.. _install_cassandane:

Installing Cassandane
=====================

Cassandane is a Perl-based integration test suite for Cyrus.
`Cassandane documentation <https://github.com/cyrusimap/cyrus-imapd/tree/master/cassandane/doc>`_
includes information on setting up tests and writing new tests.

Why "Cassandane"? Wikipedia indicates that Cassandane_ was the name of
the consort of King Cyrus the Great of Persia, founder of the Achaemenid
Persian Empire.  So that's kinda cool.

.. _Cassandane: https://en.wikipedia.org/wiki/Cassandane

Install and configure Cassandane
--------------------------------

1. You already have it -- it's in the "cassandane" subdirectory of the cyrus-imapd
   sources.

2. Install dependencies

   .. code-block:: bash

        sudo apt-get install libanyevent-perl libtest-unit-perl libconfig-inifiles-perl \
            libdatetime-perl libbsd-resource-perl libxml-generator-perl \
            libencode-imaputf7-perl libio-stringy-perl libnews-nntpclient-perl \
            libfile-chdir-perl libfile-libmagic-perl libnet-server-perl libunix-syslog-perl \
            libdata-uuid-perl libjson-xs-perl libdata-ical-perl libjson-perl \
            libdatetime-format-ical-perl libtext-levenshteinxs-perl \
            libmime-types-perl libdatetime-format-iso8601-perl libcal-dav-perl \
            libclone-perl libstring-crc32-perl libnet-ldap-server-perl

   The quickest option for the rest is installing via CPAN, but you could build
   packages using dh-make-perl if that is preferred.

   .. code-block:: bash

        sudo cpan -i Tie::DataUUID
        sudo cpan -i XML::Spice
        sudo cpan -i XML::Fast
        sudo cpan -i Data::ICal::TimeZone
        sudo cpan -i Text::VCardFast
        sudo cpan -i Mail::IMAPTalk
        sudo cpan -i List::Pairwise
        sudo cpan -i Convert::Base64
        sudo cpan -i Net::DAVTalk
        sudo cpan -i Net::CardDAVTalk
        sudo cpan -i Net::CalDAVTalk
        sudo cpan -i Mail::JMAPTalk
        sudo cpan -i Math::Int64

3. Install Cassandane

   .. code-block:: bash

    cd /path/to/cyrus-imapd/cassandane
    make

4. Copy ``cassandane.ini.example`` to ``cassandane.ini`` in your home directory

5. Edit ``cassandane.ini`` to set up your cassandane environment.

    * Assuming you configure cyrus with ``--prefix=/usr/cyrus`` (as above), then the defaults are mostly fine
    * Set ``destdir`` to ``/var/tmp/cyrus``
    * Add ``[valgrind]`` if you're using it.
    * Add an ``[imaptest]`` section.  For the moment, it may be necessary to
      suppress the binary tests as they are buggy upstream still.

      .. code-block:: ini

            [imaptest]
            basedir=/path/to/imaptest/imaptest
            suppress=append-binary urlauth-binary fetch-binary-mime fetch-binary-mime-qp

6. Create a ``cyrus`` user and matching group and also add ``cyrus`` to group ``mail``

   .. code-block:: bash

        sudo adduser --system --group cyrus
        sudo adduser cyrus mail

7. Give your user account access to sudo as ``cyrus``

    * ``sudo visudo``
    * add a line like:``username ALL = (cyrus) NOPASSWD: ALL``, where "username" is your own username

8. Make the ``destdir`` directory, as the ``cyrus`` user

    * ``sudo -u cyrus mkdir /var/tmp/cass``

Install IMAPTest
----------------

IMAPTest_ is a testing suite which uses libraries from the Dovecot installation.

1. Fetch and compile Dovecot.

    * Get the latest nightly snapshot from http://dovecot.org/nightly/dovecot-latest.tar.gz
    * ``./configure && make`` (No need for make install)

2. Fetch and compile IMAPTest

    * Download http://dovecot.org/nightly/imaptest/imaptest-latest.tar.gz
    * ``./configure --with-dovecot=../dovecot-2.2 && make`` (No need for make install)
    * The ``--with-dovecot=<path>`` parameter is used to specify path to Dovecot v2.2 sources' root directory.

.. _IMAPTest: http://www.imapwiki.org/ImapTest

Rebuild Cyrus for Testing
=========================

Prepare to rebuild by making the source tree shiny and clean as if you've done a brand new checkout. Leave no old artifacts lying around!

.. code-block:: bash

    cd /path/to/cyrus-imapd
    make clean
    git clean -f -x -d
    autoreconf -v -i

.. warning::
    Apply caution! The ``git clean`` removes anything that's a build product, but also anything it doesn't know about: which may include your new source files you haven't added yet.

Set the compile flags for testing and debugging. It may be of use to also add ``--std=gnu99`` here.  That does TONS of warnings, and ``-g`` enables debug mode.

.. code-block:: bash

    CFLAGS="-g -fPIC -W -Wall -Wextra -Werror"

Configure the environment.

.. code-block:: bash

    ./configure --prefix=/usr/cyrus --with-cyrus-prefix=/usr/cyrus \
    --enable-autocreate --enable-http --enable-unit-tests \
    --enable-replication --enable-nntp --enable-murder \
    --enable-idled --enable-xapian --enable-calalarmd \
    --enable-backup

    make lex-fix   # you need this if compile fails with errors from sieve/sieve.c

And finally, make it.

If you're testing across versions, the binsymlinks is necessary as older Cyrus doesn't have the binaries in the new locations. This uses the default install path of ``/usr/cyrus/``. It can be useful to also have ``/usr/cyrus25``, ``/usr/cyrus24``, etc, if you're testing with older versions as well.

.. code-block:: bash

    make -j16 && make -j16 check
    sudo make install
    sudo make install-binsymlinks
    sudo cp tools/mkimap /usr/cyrus/bin/mkimap


Running the tests
=================

As user ``cyrus``, run the tests.

.. code-block:: bash

    cd /path/to/cyrus-imapd/cassandane
    sudo -u cyrus ./testrunner.pl -f pretty -j 8

Debugging and stacktraces
=========================

Check out the guide to :ref:`running Cyrus components under gdb <faqs-o-gdb>`.

In the event of a crash, here's how to :ref:`generate a stacktrace <faqs-o-coredump>`.

Tips and Tricks
===============

Read the script to see other options. If you're having problems, add more ``-v`` options to the testrunner to get more info out.

**Looking for memory leaks?** Run with --valgrind to use valgrind (if it's installed). It is slower, which is why it doesn't need to be always used.

Running with -v -v is very noisy, but gives a lot more data.  For example: all IMAP telemetry.

Also helpful to run ``sudo tail -f /var/log/syslog``, and examine  /var/tmp/cass as root to examine log files and disk structures for failed tests.
