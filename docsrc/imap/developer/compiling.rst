.. _compiling:

=========
Compiling
=========

These instructions are based on Debian 8.0 because it has to be based on
something. Other Linux distributions will be similar in the broad ideas but may
differ in the specifics. If you already have a preferred distro, use that (we
assume you know how to use its package management system). If you don't already
have a preferred distro, maybe consider using Debian.

First make sure you have a :ref:`copy of the source <getcyrus>`. You can either
fetch the latest source from git, or download one of our release tarballs.

Setting up dependencies
=======================

Required Build Dependencies
---------------------------

Building a basic Cyrus that can send and receive email: the minimum libraries
required to build a functional cyrus-imapd.

.. csv-table::
    :header: "Package", "Debian", "RedHat", "Notes"

    `autoconf`_, "autoconf", "autoconf"
    `automake`_, "automake", "automake"
    `bison`_, "bison", "bison"
    `Cyrus SASL`_, "libsasl2-dev", "cyrus-sasl-devel"
    `flex`_, flex, flex
    `gcc`_, gcc, gcc
    `gperf`_, gperf, gperf
    `jansson`_, libjansson-dev, jansson-devel
    `libbsd`_, libbsd-dev, libbsd-devel
    `libtool`_, libtool, libtool
    `ICU`_, libicu-dev, libicu-devel, "version 55 or newer"
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

Build dependencies for additional functionality
-----------------------------------------------

The following dependencies enable additional functionality, help with
code maintenance tasks or are required for building the documentation.

Developers only
###############

The developer dependencies are required if you are building from git sources,
have modified certain source files from the release tarball, or have configured
with ``--enable-maintainer-mode`` in order to build a new package.

If you are building normally from a pure release tarball, then you don't need
these dependencies. The files, these dependencies produce, have been pre-built
and included in the release, and do not normally need to be re-built.

.. csv-table::
    :header: "Package", "Debian", "RedHat", "Required", "Notes"
    :widths: 20,15,15,5,45

    `perl-devel`_, perl-dev, perl-devel, "no", "Needed for building binary perl
    libraries, version 5+."
    `perl(ExtUtils::MakeMaker)`_,,, "no", "Needed for building extensions to
    Perl."
    `perl(Pod::POM::View::Restructured)`_,,, "no", "Needed to generate man
    pages. This has to be available to the system-wide perl interpreter, found
    by ``which``."
    `python(GitPython)`_,,, "no", "Needed for building the documentation."
    `python(Sphinx)`_,,, "no", "Needed for building the documentation."
    `transfig`_, transfig, transfig, "no", "Also known as fig2dev, transfig is
    an artifact from the old days, and is only used for generation of a couple
    of png files in the legacy documentation (doc/legacy/murder.png and
    doc/legacy/netnews.png). One day it should be merged into the current
    documentation, cause then we can get rid of it: `issues/1769`_."
    `valgrind`_, valgrind, valgrind, "no", "Performance and memory testing."
    `xxd`_,vim-common,vim-common, "no", "Needed for the _js.h files, for CalDAV
    and CardDAV support."

SASL Authentication
###################

.. csv-table::
    :header: "Package", "Debian", "RedHat", "Required", "Notes"
    :widths: 20,15,15,5,45

    `Cyrus SASL Plain`_, libsasl2-modules, cyrus-sasl-plain, "yes/no", "Required
    to pass Cyrus IMAP's PLAIN authentication unit tests."
    `Cyrus SASL MD5`_, libsasl2-modules, cyrus-sasl-md5, "yes/no", "Required to
    pass Cyrus IMAP's DIGEST-MD5 authentication unit tests."
    `sasl binaries`_, sasl2-bin, sasl2-bin, "no", "Administration tools for
    managing SASL."
    `Kerberos`_, libsasl2-modules-gssapi-mit, krb5-devel, "yes/no", "Development
    headers required to enable Kerberos v5 authentication capabilities, also
    known as the authentication mechanism *GSSAPI*. Configure option:
    ``--with-krbimpl=mit``."

Alternate database formats
##########################

.. csv-table::
    :header: "Package", "Debian", "RedHat", "Required", "Notes"
    :widths: 20,15,15,5,45

    `mysql`_ or `mariadb`_, "libmysqlclient-dev or libmariadb-dev", "mysql-devel
    or mariadb-devel", "yes/no", "MariaDB or MySQL development headers, required
    to allow Cyrus IMAP to use it as the backend for its databases. Configure
    options: ``--with-mysql``, ``--with-mysql-incdir``,
    ``--with-mysql-libdir``."
    `postgresql`_, postgresql-dev, postgresql-devel, "yes/no", "PostgreSQL
    development headers, required to allow Cyrus IMAP to use it as the backend
    for its databases. Configure option: ``--with-pgsql``."

CalDAV, CardDAV, or JMAP (httpd subsystem)
##########################################

.. csv-table::
    :header: "Package", "Debian", "RedHat", "Required", "Notes"
    :widths: 20,15,15,5,45

    `libbrotli`_, libbrotli-dev, brotli-devel, "no", "It provides Brotli
    compression support for http communications (otherwise only ``deflate`` and
    ``gzip`` (optionally) would be available)."
    `libchardet`_, libchardet-dev, libchardet-devel, "yes/no", "It is used
    by the **JMAP** module of httpd to detect the character set of untagged
    8-bit headers. Without it, cyrus-imapd will not do character-set detection.
    If some piece of data has no character set coming in, it will have no
    character set. Required for JMAP, but otherwise is not needed."
    `libical`_, libical-dev, libical-devel, "yes", "It provides
    calendaring functionality for CalDAV, which can't be used without this lib.
    Version 3.0.0 or higher is required."
    `libxml`_, libxml2-dev, libxml2-devel, "yes", "A fundamental lib for
    all \*DAV functionality."
    `nghttp2`_, libnghttp2-dev, libnghttp2-devel, "no", "HTTP/2 support
    for the entire **httpd** subsystem (\*DAV & JMAP)."
    `shapelib`_, libshp-dev, shapelib, "yes/no", "It is required for
    **tzdist** service to have geolocation support. Otherwise it is not needed.
    Version 1.3.0 or higher is required when using it."
    `wslay`_, libwslay-dev, wslay-devel, "no", "It provides WebSockets support
    in httpd. Only used with **JMAP**, otherwise not needed. Version 1.1.1 or
    higher is required when using it."
    `zlib`_, zlib1g-dev, zlib-devel, "no", "It provides gzip compression
    support for http communications."

Other
#####

.. csv-table::
    :header: "Package", "Debian", "RedHat", "Required", "Notes"
    :widths: 20,15,15,5,45

    `CUnit`_, libcunit1-dev, cunit-devel, "no", "Development headers for
    compiling Cyrus IMAP's unit tests. Required to run ``make check``."
    SSL certificates, ssl-cert-dev, mod_ssl, "no", "Used if you're
    installing SSL certificates."
    `ClamAV`_, libclamav-dev, clamav-devel, "no", "It is used by
    **cyr_virusscan**, otherwise not needed."
    `CLD2`_, libcld2-dev, cld2-devel, "yes/no", "Compact Language Detector 2
    (probabilistically detects over 80 languages in Unicode UTF-8 text, either
    plain text or HTML/XML). Required for **Xapian** (``--enable-xapian``),
    otherwise not needed."
    `openldap`_, libldap2-dev, openldap-devel, "no", "Development headers
    to enable **ptloader** to interface with LDAP directly, for canonification
    of login usernames to mailbox names, and verification of login usernames,
    ACL subjects and group membership. Configure option: ``--with-ldap``."
    `pcre`_, libpcre3-dev, pcre-devel, "yes", "PCRE 1 (8.x) - for utf-8/unicode
    regular expression matching. Could be replaced by something else in the
    future. See `issues/1731`_ for more information."
    `perl(Term::ReadLine)`_,,, "no", "Perl library needed by **cyradm**."
    `libsrs2`_, *no package*, *no package*, "no", "It is used for
    implementing Sender Rewriting Scheme (SRS) functionality for messages
    forwarded by sieve scripts. Without it, messages forwarded by sieve scripts
    will not have this functionality and might have difficulty delivering to
    SMTP servers that insist on it."

.. _ClamAV: https://www.clamav.net/
.. _CUnit: http://cunit.sourceforge.net/
.. _Cyrus SASL Plain: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _Cyrus SASL MD5: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _sasl binaries: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _Kerberos: http://web.mit.edu/kerberos/www/
.. _libbrotli: https://github.com/google/brotli
.. _libchardet: https://github.com/Joungkyun/libchardet
.. _libical: https://github.com/libical/libical/
.. _libxml: http://xmlsoft.org/
.. _mysql: http://www.mysql.com
.. _mariadb: http://mariadb.org
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
.. _shapelib: http://shapelib.maptools.org
.. _libsrs2: https://www.libsrs2.org/
.. _transfig: http://www.xfig.org/
.. _valgrind: http://www.valgrind.org/
.. _wslay: https://tatsuhiro-t.github.io/wslay/
.. _zlib: http://zlib.net/
.. _xxd: https://github.com/ConorOG/xxd/
.. _CLD2: https://github.com/CLD2Owners/cld2
.. _issues/1769: https://github.com/cyrusimap/cyrus-imapd/issues/1769
.. _issues/1731: https://github.com/cyrusimap/cyrus-imapd/issues/1731#issuecomment-273064554


Install tools for building
    * ``sudo apt-get install build-essential``


Optionally install dependencies for :ref:`building the docs <contribute-docs>`.
    * ``sudo pip install python-sphinx``
    * ``sudo cpan install Pod::POM::View::Restructured``


Compile Cyrus
=============

There are additional :ref:`compile and installation steps<imapinstall-xapian>`
if you are using Xapian for searching, or if you are :ref:`using jmap
<developer-jmap>`.

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
    Passing environment variables as an argument to configure, rather than
    setting them in the environment before running configure, allows their
    values to be logged in config.log.  This is useful for diagnosing problems.

Optional dependencies
---------------------

Some features are disabled by default and must be explicitly enabled
via configure.

Sieve is enabled by default.

CalDAV, CardDAV, WebDAV, JMAP
#############################

    ``./configure --enable-http --enable-calalarmd --enable-jmap``

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

It may be of use to also add ``--std=gnu99`` to the ``CFLAGS``. That generates
TONS of warnings.

Having problems with :ref:`compilation <compilationerrors>` or
:ref:`linking <linker-warnings>`?

If you're running on Debian, and you install to ``/usr/local``, you may need to
update your library loader. Edit ``/etc/ld.so.conf.d/x86_64-linux-gnu.conf`` so
it includes the following additional line::

    /usr/local/lib/x86_64-linux-gnu

Without this, when you attempt to start Cyrus, it reports ``error while loading
shared libraries: libcyrus_imap.so.0: cannot open shared object file: No such
file or directory`` because it can't find the Cyrus library in /usr/local/lib.

Check
-----

.. code-block:: bash

    make check    # this runs the cunit tests.

This runs the cunit tests and is used for testing that the libraries support
all the expected behaviour. If this fails, please :ref:`report it to the
cyrus-dev mailing list <feedback-mailing-lists>` with details of your source
version, operating system and affected libraries.


Next: :ref:`installing Cyrus <installing>`.

.. _Fastmail : https://www.fastmail.com
