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

        sudo cpan -i AnyEvent Config::IniFiles Data::GUID Digest::CRC File::Slurp IO::File::fcntl IO::Socket::INET6 Net::Server::PreForkSimple News::NNTPClient Plack::Loader Types::Standard Unix::Syslog XML::Generator XML::Simple
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
        sudo cpan -i Test::Unit

3. Build Cassandane's binary components

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
    * add lines like:

      .. code-block::

        Defaults:username rlimit_core=default
        username ALL = (cyrus) NOPASSWD: ALL

      where "username" is your own username

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

This is not quite the same IMAPTest that CI uses.  The CI system uses
a docker image, which among other things has Dovecot and IMAPTest already
built in so that they don't need to be rebuilt every time CI runs.

The docker image is built from Dockerfile_ in the cyrus-docker repo.  If you
want to locally reproduce the same testing that CI runs, you can search it
for "dovecot.git" and "imaptest.git" to see how these two components
are fetched and built, and do the same yourself.  Briefly, Dovecot is built
from a known commit id on the upstream repository, whereas IMAPTest is built
from the "cyrus" branch of our own fork.

.. _IMAPTest: http://www.imapwiki.org/ImapTest
.. _Dockerfile: https://github.com/cyrusimap/cyrus-docker/blob/master/Debian/Dockerfile

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

Cassandane internals need to run as the ``cyrus`` user, but if you gave
yourself passwordless sudo access as instructed above, then Cassandane will
take care of switching to the ``cyrus`` user for you.  In which case, just run
it as yourself.

If you didn't give yourself this access, you will first need to become the
``cyrus`` user by some other means, and then run it from there.

.. code-block:: bash

    cd /path/to/cyrus-imapd/cassandane
    ./testrunner.pl

Do not run it as root.

Debugging and stacktraces
=========================

Check out the guide to :ref:`running Cyrus components under gdb <faqs-o-gdb>`.

In the event of a crash, here's how to :ref:`generate a stacktrace <faqs-o-coredump>`.

Core dumps will be owned by the ``cyrus`` user, but your source tree will
probably be owned by yourself.  Copy the core dump somewhere convenient,
change the ownership to yourself, and then you can open the core file in
gdb for examination.

Tips and Tricks
===============

Read the script to see other options. If you're having problems, add more
``-v`` options to the testrunner to get more info out.

**Looking for memory leaks?** Run with --valgrind to use valgrind (if it's
installed). It is slower, which is why it doesn't need to be always used.

Running with -v -v is very noisy, but gives a lot more data.  For example: all
IMAP telemetry.

Also helpful to run ``sudo tail -f /var/log/syslog``, and examine
/var/tmp/cass as ``cyrus`` to examine log files and disk structures for
failed tests.
