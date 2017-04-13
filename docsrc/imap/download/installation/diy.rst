.. _install-diy:

==============
Do It Yourself
==============

The following guides outline building Cyrus IMAP from a fresh clone of
the GIT repository's branches, or a tarball of a released version.

Unless you specifically need unreleased patches, the tarball package is
recommended as it comes with a number of resources pre-built for you,
such as the documentation.

----

.. contents::
    :local:

----

1. Fetch the source
===================

From Tarball
------------

Download the `latest stable tarball`_ : version |imap_current_stable_version|.

Extract the tarball:

.. parsed-literal::

    $ :command:`tar xzvf cyrus-imapd-x.y.z.tar.gz`

.. _latest stable tarball: ftp://ftp.cyrusimap.org/cyrus-imapd/

Continue with :ref:`imap-installation-diy-build-dependencies`.

From GIT
--------

Read our :ref:`Guide to GitHub <github-guide>` for details on how to
access our GitHub repository, and fork/clone the source.

Continue with :ref:`imap-installation-diy-build-dependencies`.

.. _imap-installation-diy-build-dependencies:

2. Build Dependencies
=====================

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
    `libtool`_, libtool, libtool
    `ICU`_, libicu-dev, libicu
    `uuid`_, uuid-dev, libuuid-devel
    `openssl`_, libssl-dev, openssl-devel
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
.. _libtool: http://www.gnu.org/software/libtool/
.. _ICU: http://www.icu-project.org/
.. _uuid: https://www.kernel.org/pub/linux/utils/util-linux/
.. _openssl: http://www.openssl.org/
.. _pkgconfig: http://pkgconfig.freedesktop.org
.. _sqlite: https://www.sqlite.org/

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
    `perl-devel`_, perl-dev, perl-devel, "no", "Perl development headers to allow building binary perl libraries. Needs version 5+.

    Configure option: ``--with-perl``"
    `valgrind`_, valgrind, valgrind, "no", "Performance and memory testing."

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

    `lmdb`_, lmdb-dev, lmdb, "no", "Lightning Memory-Mapped Database Manager (LMDB) backend for Cyrus IMAP
    databases.     LMDB requires database environments to be set to a (user-configurable)
    maximum size. The Cyrus backend uses 512MB as default size. Cyrus
    installations may override this by setting the environment variable
    CYRUSDB_LMDB_MAXSIZE. The value of this variable must be an integer,
    optionally followed (without space) by 'mb' or 'gb' to define the
    maximum size in bytes, megabytes or gigabytes. The size should be a
    multiple of the OS page size. "
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

    `net-snmp`_, libsnmp-dev, net-snmp-devel, "no", "version 4.2 or higher"
    `openldap`_, libldap2-dev, openldap-devel, "no", "Development headers to enable **ptloader** to interface with LDAP
    directly, for canonification of login usernames to mailbox names,
    and verification of login usernames, ACL subjects and group
    membership.

    Configure option: ``--with-ldap``"
    `tcp_wrappers`_, tcp_wrappers, xx, "no"
    `transfig`_, transfig, xx, "no"
    `zlib`_, zlib1g-dev, zlib-devel, "no", "Compression support for httpd"
    `nghttp2`_, libnghttp2-dev, libnghttp2-devel, "no", "HTTP/2 support for httpd"

.. _CUnit: http://cunit.sourceforge.net/
.. _Cyrus SASL Plain: :ref:`Cyrus SASL <cyrussasl:sasl-index>`
.. _Cyrus SASL MD5: :ref:`Cyrus SASL <cyrussasl:sasl-index`
.. _sasl binaries: :ref:`Cyrus SASL <cyrussasl:sasl-index`
.. _lmdb: http://lmdb.tech/
.. _Kerberos: http://web.mit.edu/kerberos/www/
.. _libical: http://freeassociation.sourceforge.net/
.. _libxml: http://xmlsoft.org/
.. _mysql: http://www.mysql.com
.. _mariadb: http://mariadb.org
.. _net-snmp:  http://net-snmp.sourceforge.net/
.. _openldap: http://www.openldap.org/
.. _perl(ExtUtils::MakeMaker): http://search.cpan.org/dist/ExtUtils-MakeMaker/
.. _perl-devel: http://www.perl.org/
.. _postgresql: http://www.postgresql.org/
.. _tcp_wrappers: ftp://ftp.porcupine.org/pub/security/index.html
.. _transfig: http://www.xfig.org/
.. _valgrind: http://www.valgrind.org/
.. _zlib: http://zlib.net/
.. _nghttp2: https://nghttp2.org/

Continue with :ref:`imap-installation-diy-configure`

.. _imap-installation-diy-configure:

3. Configure the Build
======================

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

Some features are disabled by default and must be explicitly enable-idled
via configure.

Sieve is enabled by default.

CalDAV and CardDAV
##################

    ``./configure --enable-http --enable-calalarmd``

Murder
######

    ```./configure --enable-murder``

Replication
###########

    ```./configure --enable-replication``

4. Compile and install
======================

.. code-block:: bash

    cd /path/to/cyrus-imapd

    autoreconf -i
    ./configure [options]

    make

    make check

    make install  # optional if you're just developing on this machine

If this is the first time you've installed Cyrus, read our :ref:`Basic Server Configuration guide <basicserver>`.
It walks through the steps of configuring the server and sending a sample piece of test mail.
