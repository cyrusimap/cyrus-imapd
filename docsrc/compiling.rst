.. _compiling:

=========
Compiling
=========

These instructions assume a Debian-based system, because they have to assume
something.  Other Linux distributions are similar in the broad strokes but
differ in specifics; if you have a preferred distro, use it and translate the
package names (we assume you know how to drive its package manager).

This page is about building Cyrus from source -- typically from a release
tarball -- in order to *run* it.  If you want to *develop* Cyrus, don't build it
by hand: use the container-based workflow in the :ref:`developer quickstart
<developer-quickstart>`, which installs every dependency and builds and tests
Cyrus for you.

First make sure you have a :ref:`copy of the source <getcyrus>`. You can either
fetch the latest source from git, or download one of our release tarballs.

.. Note::

    Cyrus does not support compiling with `Link Time Optimization
    <https://gcc.gnu.org/onlinedocs/gccint/LTO-Overview.html>`_,
    but some platforms now enable Link Time Optimization by default.
    If your platform does so, you will need to override it, perhaps
    by adding ``-fno-lto`` to ``CFLAGS`` and ``LDFLAGS``.

Setting up dependencies
=======================

Required Build Dependencies
---------------------------

Building a basic Cyrus that can send and receive email: the minimum libraries
required to build a functional cyrus-imapd.

.. csv-table::
    :header: "Package", "Debian", "Notes"

    `autoconf`_, "autoconf"
    `automake`_, "automake"
    `bison`_, "bison"
    `Cyrus SASL`_, "libsasl2-dev"
    `flex`_, flex
    `gcc`_, gcc
    `gperf`_, gperf
    `ICU`_, libicu-dev, "version 55 or newer"
    `jansson`_, libjansson-dev
    `libbsd`_, libbsd-dev
    `libtool`_, libtool
    `openssl`_, libssl-dev
    `perl`_, perl
    `perl App-Cmd`_, libapp-cmd-perl
    `perl Moo`_, libmoo-perl
    `pkgconfig`_, pkg-config
    `sqlite`_, libsqlite3-dev
    `uuid`_, uuid-dev

.. _autoconf: http://www.gnu.org/software/autoconf/
.. _automake: http://www.gnu.org/software/automake/
.. _bison: http://www.gnu.org/software/bison/
.. _Cyrus SASL: :cyrus-sasl:`Cyrus SASL </>`
.. _flex: http://flex.sourceforge.net/
.. _gcc: http://gcc.gnu.org
.. _gperf: http://www.gnu.org/software/gperf/
.. _ICU: http://www.icu-project.org/
.. _jansson: http://www.digip.org/jansson/
.. _libbsd: https://libbsd.freedesktop.org/wiki/
.. _libtool: http://www.gnu.org/software/libtool/
.. _openssl: http://www.openssl.org/
.. _perl: https://www.perl.org/
.. _perl App-Cmd: https://metacpan.org/dist/App-Cmd
.. _perl Moo: https://metacpan.org/dist/Moo
.. _pkgconfig: http://pkgconfig.freedesktop.org
.. _sqlite: https://www.sqlite.org/
.. _uuid: https://www.kernel.org/pub/linux/utils/util-linux/

To install all of these from packages on Debian, use this:

.. include:: /assets/cyrus-build-reqpkg.rst

Build dependencies for additional functionality
-----------------------------------------------

The following dependencies enable additional functionality.  Enable the
matching features with the configure options noted below.

.. note::

    Building from a git checkout (rather than a release tarball), regenerating
    the man pages, or rebuilding this documentation all need extra tooling
    (autotools in maintainer mode, Sphinx, and so on).  Rather than chase those
    by hand, use the container-based :ref:`developer workflow
    <developer-quickstart>`, which has all of it pre-installed.

SASL Authentication
###################

.. csv-table::
    :header: "Package", "Debian", "Required", "Notes"
    :widths: 20,15,5,45

    `Cyrus SASL Plain`_, libsasl2-modules, "yes/no", "Required
    to pass Cyrus IMAP's PLAIN authentication unit tests."
    `sasl binaries`_, sasl2-bin, "no", "Administration tools for
    managing SASL."
    `Kerberos`_, libsasl2-modules-gssapi-mit, "no", "Development
    headers required to enable Kerberos v5 authentication capabilities, also
    known as the authentication mechanism *GSSAPI*. Configure option:
    ``--with-gss_impl=mit``."

Alternate database formats
##########################

.. csv-table::
    :header: "Package", "Debian", "Required", "Notes"
    :widths: 20,15,5,45

    `mysql`_ or `mariadb`_, "libmysqlclient-dev or libmariadb-dev", "yes/no", "MariaDB or MySQL development headers, required
    to allow Cyrus IMAP to use it as the backend for its databases. Configure
    options: ``--with-mysql``, ``--with-mysql-incdir``,
    ``--with-mysql-libdir``."
    `postgresql`_, postgresql-dev, "yes/no", "PostgreSQL
    development headers, required to allow Cyrus IMAP to use it as the backend
    for its databases. Configure option: ``--with-pgsql``."

CalDAV, CardDAV, or JMAP (httpd subsystem)
##########################################

.. csv-table::
    :header: "Package", "Debian", "Required", "Notes"
    :widths: 20,15,5,45

    `libbrotli`_, libbrotli-dev, "no", "It provides Brotli
    compression support for http communications (otherwise only ``deflate`` and
    ``gzip`` (optionally) would be available)."
    `libchardet`_, libchardet-dev, "yes/no", "It is used
    by the **JMAP** module of httpd to detect the character set of untagged
    8-bit headers. Without it, cyrus-imapd will not do character-set detection.
    If some piece of data has no character set coming in, it will have no
    character set. Required for JMAP, but otherwise is not needed."
    `libical`_, libical-dev, "yes", "It provides
    calendaring functionality for CalDAV, which can't be used without this lib.
    Version 4.0.0 or higher is required."
    `libxml`_, libxml2-dev, "yes", "A fundamental lib for
    all \*DAV functionality."
    `nghttp2`_, libnghttp2-dev, "no", "HTTP/2 support
    for the entire **httpd** subsystem (\*DAV & JMAP)."
    `shapelib`_, shapelib, "yes/no", "It is required for
    **tzdist** service to have geolocation support. Otherwise it is not needed.
    Version 1.3.0 or higher is required when using it."
    `wslay`_, libwslay-dev, "no", "It provides WebSockets support
    in httpd. Only used with **JMAP**, otherwise not needed. Version 1.1.1 or
    higher is required when using it."
    `xxd`_, xxd, "yes", "Needed for the _js.h files, for CalDAV
    and CardDAV support."
    `zlib`_, zlib1g-dev, "no", "It provides gzip compression
    support for http communications."

Other
#####

.. csv-table::
    :header: "Package", "Debian", "Required", "Notes"
    :widths: 20,15,5,45

    `CUnit`_, libcunit1-dev, "no", "Development headers for
    compiling Cyrus IMAP's unit tests. Required to run ``make check``."
    SSL certificates, ssl-cert-dev, "no", "Used if you're
    installing SSL certificates."
    `ClamAV`_, libclamav-dev, "no", "It is used by
    **cyr_virusscan**, otherwise not needed."
    `CLD2`_, libcld2-dev, "yes/no", "Compact Language Detector 2
    (probabilistically detects over 80 languages in Unicode UTF-8 text, either
    plain text or HTML/XML). Required for **Xapian** (``--enable-xapian``),
    otherwise not needed."
    `openldap`_, libldap2-dev, "no", "Development headers
    to enable **ptloader** to interface with LDAP directly, for canonification
    of login usernames to mailbox names, and verification of login usernames,
    ACL subjects and group membership. Configure option: ``--with-ldap``."
    `pcre2`_, libpcre2-dev, "yes", "PCRE 2 (10.x) - for utf-8/unicode
    regular expression matching. Could be replaced by something else in the
    future. See `issues/1731`_ for more information."
    `perl(Term::ReadLine)`_,, "no", "Perl library needed by **cyradm**."
    `libsrs2`_, *no package*, "no", "It is used for
    implementing Sender Rewriting Scheme (SRS) functionality for messages
    forwarded by sieve scripts. Without it, messages forwarded by sieve scripts
    will not have this functionality and might have difficulty delivering to
    SMTP servers that insist on it."

.. _ClamAV: https://www.clamav.net/
.. _CUnit: http://cunit.sourceforge.net/
.. _Cyrus SASL Plain: :cyrus-sasl:`Cyrus SASL </>`
.. _sasl binaries: :cyrus-sasl:`Cyrus SASL </>`
.. _Kerberos: http://web.mit.edu/kerberos/www/
.. _libbrotli: https://github.com/google/brotli
.. _libchardet: https://github.com/Joungkyun/libchardet
.. _libical: https://github.com/libical/libical/
.. _libxml: http://xmlsoft.org/
.. _mysql: http://www.mysql.com
.. _mariadb: http://mariadb.org
.. _nghttp2: https://nghttp2.org/
.. _openldap: http://www.openldap.org/
.. _pcre2: http://www.pcre.org/
.. _perl(Term::ReadLine): https://metacpan.org/pod/Term::ReadLine
.. _postgresql: http://www.postgresql.org/
.. _shapelib: http://shapelib.maptools.org
.. _libsrs2: https://www.libsrs2.org/
.. _wslay: https://tatsuhiro-t.github.io/wslay/
.. _zlib: http://zlib.net/
.. _xxd: https://github.com/ConorOG/xxd/
.. _CLD2: https://github.com/CLD2Owners/cld2
.. _issues/1731: https://github.com/cyrusimap/cyrus-imapd/issues/1731#issuecomment-273064554


Compile Cyrus
=============

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

JMAP
####

    ``./configure --enable-jmap``

.. note::

    HTTP, CalDAV, CardDAV, WebDAV and the calendar alarm daemon are
    always built and no longer require configure options.  libical,
    libxml2 and SQLite3 are required build dependencies for every Cyrus
    build (see the table above).  JMAP remains optional because it also
    requires Xapian.

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

    autoreconf -i -s   # generates the configure script and its dependencies

    ./configure --prefix=/usr/cyrus [feature options]

    make

The ``--prefix`` option sets where Cyrus is installed to.

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

This runs the cunit tests (which need CUnit and ``--enable-unit-tests``) and is
used for testing that the libraries support all the expected behaviour. If this
fails, please :ref:`report it to the cyrus-dev mailing list
<feedback-mailing-lists>` with details of your source version, operating system
and affected libraries.


Next: :ref:`installing Cyrus <installing>`.
