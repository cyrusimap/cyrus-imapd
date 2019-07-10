.. _compiling:

=========
Compiling
=========

These instructions are based on Debian 8.0 because it has to be based on something. Other Linux distributions will be similar in the broad ideas but may differ in the specifics. If you already have a preferred distro, use that (we assume you know how to use its package management system). If you don't already have a preferred distro, maybe consider using Debian.

First make sure you have a :ref:`copy of the source <getcyrus>`. You can either fetch the latest source from git, or using one of our release tarballs.

Setting up dependencies
=======================

Required Build Dependencies
---------------------------

Building a basic Cyrus that can send and receive email: the minimum libraries required to build a functional Cyrus.

.. csv-table:: Build Dependencies
    :header: "Package", "Debian", "RedHat"

    `autoconf`_, "autoconf", "autoconf"
    `automake`_, "automake", "automake"
    `bison`_, "bison", "bison"
    `Cyrus SASL`_, "libsasl2-dev", "cyrus-sasl-devel"
    `flex`_, flex, flex
    `gcc`_, gcc, gcc
    `gperf`_, gperf, gperf
    `jansson`_, libjansson-dev, jansson-devel
    `libbsd`_ ,libbsd-dev, libbsd-devel
    `libtool`_, libtool, libtool
    `ICU`_, libicu-dev, libicu-devel
    `uuid`_, uuid-dev, libuuid-devel
    `openssl`_ :ref:`(Note about versions) <openssl-versions>`, libssl-dev, openssl-devel
    `pkgconfig`_, pkg-config, pkgconfig
    `sqlite`_, libsqlite3-dev, sqlite-devel

.. _autoconf: http://www.gnu.org/software/autoconf/
.. _automake: http://www.gnu.org/software/automake/
.. _bison: http://www.gnu.org/software/bison/
.. _Cyrus SASL: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _flex: http://flex.sourceforge.net/
.. _gcc: http://gcc.gnu.org
.. _gperf: http://www.gnu.org/software/gperf/
.. _jansson: http://www.digip.org/jansson/
.. _libbsd: https://libbsd.freedesktop.org/wiki/
.. _libtool: http://www.gnu.org/software/libtool/
.. _ICU: http://www.icu-project.org/
.. _uuid: https://www.kernel.org/pub/linux/utils/util-linux/
.. _openssl: http://www.openssl.org/
.. _pkgconfig: http://pkgconfig.freedesktop.org
.. _sqlite: https://www.sqlite.org/

To install all dependencies from packages on Debian Jessie, use this:

.. include:: /assets/cyrus-build-reqpkg.rst

Optional Build Dependencies
---------------------------

The following build dependencies are optional, and enable functionality,
code maintenance tasks or building the documentation.

Developers only
###############

.. csv-table::
    :header: "Package", "Debian", "RedHat",  "Required for ``make check``?", "Notes"
    :widths: 20,15,15,5,45

    `CUnit`_, libcunit1-dev, cunit-devel, "yes", "Development headers for compiling Cyrus IMAP's unit tests."
    `perl(ExtUtils::MakeMaker)`_, ??, ??, "no", "Perl library to assist in building extensions to Perl.

    Configure option: ``--with-perl``"
    `libdb-dev`, libdb-dev, libdb-devel, "no", "The -dev package must match the version of libdb you already have installed (assuming it's probably already installed). On Debian 8.0, ``libdb5.3-dev`` is needed, but ``libdb5.1-dev`` on 7.8."
    `perl-devel`_, perl-dev, perl-devel, "no", "Perl development headers to allow building binary perl libraries. Needs version 5+.

    Configure option: ``--with-perl``"
    `perl(Pod::POM::View::Restructured)`_,,,, "Perl library to generate man pages.  This has to be available to the system-wide perl interpreter, found by ``which``:  ``./configure --with-perl`` is not honoured."
    `python(GitPython)`_,,,, "Python library needed for building the documentation"
    `python(Sphinx)`_,,,, "Python library needed for building the documentation"
    `valgrind`_, valgrind, valgrind, "no", "Performance and memory testing."
    `xxd`_,,,, "For rebuilding the _js.h files, for CalDAV and CardDAV support."

SASL Authentication
###################

.. csv-table::
    :header: "Package", "Debian", "RedHat",  "Required for ``make check``?", "Notes"
    :widths: 20,15,15,5,45

    `Cyrus SASL Plain`_, libsasl2-modules, cyrus-sasl-plain,  "yes", "Cyrus SASL package that ships the \
    library required to pass Cyrus IMAP's PLAIN authentication unit tests."
    `Cyrus SASL MD5`_, libsasl2-modules, cyrus-sasl-md5, "yes", "Cyrus SASL library required to pass Cyrus IMAP's DIGEST-MD5
    authentication unit tests"
    `sasl binaries`_, sasl2-bin, sasl2-bin, "no", "Administration tools for managing SASL"
    `Kerberos`_, libsasl2-modules-gssapi-mit, krb5-devel, "no", "Development headers required to enable Kerberos v5 authentication
    capabilities. Otherwise also known as the authentication mechanism *GSSAPI*.

    Configure option: ``--with-krbimpl=mit`` "

Alternate database formats
##########################

.. csv-table::
    :header: "Package", "Debian", "RedHat",  "Required for ``make check``?", "Notes"
    :widths: 20,15,15,5,45

    `mysql`_ or `mariadb`_, libmysqlclient-dev or libmariadb-dev, mysql-devel or mariadb-devel, "no", "MariaDB or MySQL development headers, to allow Cyrus IMAP to use
    it as the backend for its databases.

    Configure option: ``--with-mysql``, ``--with-mysql-incdir``, ``--with-mysql-libdir``"
    `postgresql`_, postgresql-dev, postgresql-devel, "no"

CalDAV and/or CardDAV
#####################

.. csv-table::
    :header: "Package", "Debian", "RedHat",  "Required for ``make check``?", "Notes"
    :widths: 20,15,15,5,45

    `libical`_, libical-dev, libical-devel, "no", "libical >= 0.48 required for scheduling support.
    **Note:** Linux distributions Enterprise Linux 6 and Debian Squeeze are
    known to ship outdated **libical** packages versions 0.43 and
    0.44 respectively. The platforms will not support scheduling."
    `libxml`_, libxml2-dev, libxml2-devel, "", "no"

Other
#####

.. csv-table::
    :header: "Package", "Debian", "RedHat",  "Required for ``make check``?", "Notes"
    :widths: 20,15,15,5,45

     SSL certificates, ssl-cert-dev, mod_ssl, "no", "Used if you're installing SSL certificates"
    `ClamAV`_,,,, Used by **cyr_virusscan**.
    `net-snmp`_, libsnmp-dev, net-snmp-devel, "no", "version 4.2 or higher"
    `openldap`_, libldap2-dev, openldap-devel, "no", "Development headers to enable **ptloader** to interface with LDAP
    directly, for canonification of login usernames to mailbox names,
    and verification of login usernames, ACL subjects and group
    membership.

    Configure option: ``--with-ldap``"
    `tcp_wrappers`_, tcp_wrappers, xx, "no"
    `transfig`_, transfig, xx, "no", "also known as fig2dev"
    `pcre`_,,,, "PCRE 1 (or 8) - for regular expression matching"
    `perl(Term::ReadLine)`_,,,, "Perl library needed by cyradm"
    `libsrs2`_,,,, "Sender Rewriting Scheme for lmtp, used on Sieve redirect "
    `zlib`_, zlib1g-dev, zlib-devel, "no", "Compression support for httpd"
    `libbrotli`_,,,, "Brotli compression support for httpd"
    `wslay`_,,,, "WebSockets support in httpd"
    `nghttp2`_, libnghttp2-dev, libnghttp2-devel, "no", "HTTP/2 support for httpd"

.. _ClamAV: https://www.clamav.net/
.. _CUnit: http://cunit.sourceforge.net/
.. _Cyrus SASL Plain: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _Cyrus SASL MD5: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _sasl binaries: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _Kerberos: http://web.mit.edu/kerberos/www/
.. _libbrotli: https://github.com/google/brotli
.. _libical: https://github.com/libical/libical/
.. _libxml: http://xmlsoft.org/
.. _mysql: http://www.mysql.com
.. _mariadb: http://mariadb.org
.. _net-snmp:  http://net-snmp.sourceforge.net/
.. _nghttp2: https://nghttp2.org/
.. _openldap: http://www.openldap.org/
.. _pcre: http://www.pcre.org/
.. _perl(Term::ReadLine): https://metacpan.org/pod/Term::ReadLine
.. _perl(ExtUtils::MakeMaker): http://search.cpan.org/dist/ExtUtils-MakeMaker/
.. _perl(Pod::POM::View::Restructured): https://metacpan.org/pod/Pod::POM::View::Restructured
.. _perl-devel: http://www.perl.org/
.. _postgresql: http://www.postgresql.org/
.. _python(GitPython): https://github.com/gitpython-developers/GitPython
.. _python(Sphinx): https://www.sphinx-doc.org/
.. _libsrs2: https://www.libsrs2.org/
.. _tcp_wrappers: ftp://ftp.porcupine.org/pub/security/index.html
.. _transfig: http://www.xfig.org/
.. _valgrind: http://www.valgrind.org/
.. _wslay: https://tatsuhiro-t.github.io/wslay/
.. _zlib: http://zlib.net/
.. _xxd: https://github.com/ConorOG/xxd/


Install tools for building
    * ``sudo apt-get install build-essential``


Optionally install dependencies for :ref:`building the docs <contribute-docs>`.
    * ``sudo pip install python-sphinx``
    * ``sudo cpan install Pod::POM::View::Restructured``


Compile Cyrus
=============

There are additional :ref:`compile and installation steps<imapinstall-xapian>` if you are using Xapian for searching,
or if you are :ref:`using jmap <developer-jmap>`.

Default build: mail only
------------------------

.. parsed-literal::

    $ :command:`autoreconf -i`
    $ :command:`./configure` [options]

Check the summary after ``./configure`` completes to ensure it
matches your expectations.

To view all options, and disable or enable specific features,
please see:

.. parsed-literal::

    # :command:`./configure --help`

.. tip::
    Passing environment variables as an argument to configure,
    rather than setting them in the environment before running configure,
    allows their values to be logged in config.log.  This is useful for diagnosing
    problems.

Optional dependencies
---------------------

Some features are disabled by default and must be explicitly enabled
via configure.

Sieve is enabled by default.

CalDAV and CardDAV
##################

    ``./configure --enable-http --enable-calalarmd``

Murder
######

    ``./configure --enable-murder``

Replication
###########

    ``./configure --enable-replication``

Compile
-------

.. code-block:: bash

    cd /path/to/cyrus-imapd

    autoreconf -i -s   # generates a configure script, and its various dependencies

    ./configure CFLAGS="-W -Wno-unused-parameter -g -O0 -Wall -Wextra -Werror -fPIC" \
    --enable-coverage --enable-calalarmd --enable-autocreate \
    --enable-nntp --enable-http --enable-unit-tests \
    --enable-replication --with-openssl=yes --enable-murder \
    --enable-idled --prefix=/usr/cyrus

    make lex-fix   # you need this if compile fails with errors from sieve/sieve.c

    make

The ``--prefix`` option sets where Cyrus is installed to.

It may be of use to also add ``--std=gnu99`` to the ``CFLAGS``.  That generates TONS of warnings.

Having problems with :ref:`compilation <compilationerrors>` or
:ref:`linking <linker-warnings>`?

If you're running on Debian, and you install to ``/usr/local``, you may need to update your library loader. Edit ``/etc/ld.so.conf.d/x86_64-linux-gnu.conf`` so it includes the following additional line::

    /usr/local/lib/x86_64-linux-gnu

Without this, when you attempt to start Cyrus, it reports ``error while loading shared libraries: libcyrus_imap.so.0: cannot open shared object file: No such file or directory`` because it can't find the Cyrus library in /usr/local/lib.

Check
-----

.. code-block:: bash

    make check    # this runs the cunit tests.

This runs the cunit tests and is used for testing that the libraries support
all the expected behaviour. If this fails, please :ref:`report it to the
cyrus-dev mailing list <feedback-mailing-lists>` with details of your source
version, operating system and affected libraries.


Next: :ref:`installing Cyrus <installing>`.

.. _FastMail : https://www.fastmail.com
