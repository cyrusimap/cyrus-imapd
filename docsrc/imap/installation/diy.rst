==============
Do It Yourself
==============

The following guides outline building Cyrus IMAP from a fresh clone of
the GIT repository's branches, or a tarball of a released version.

.. WARNING::

    The level of technical difficulty involved with home-brew or DIY
    Cyrus IMAP versions is **high**.

    You are specifically requested **not** to build your own unless you
    have an appropriate comprehension of dependencies and building those
    yourself if you have to.

From GIT
========

Clone the GIT repository:

.. parsed-literal::

    $ :command:`git clone git@github.com:cyrusimap/cyrus-imapd.git`

Check out the desired branch or revision:

.. parsed-literal::

    $ :command:`git branch -la`
    * master
      (...snip...)
      remotes/origin/cyrus-imapd-2.3
      remotes/origin/cyrus-imapd-2.4
      remotes/origin/cyrus-imapd-2.5
    $ :command:`git checkout $BRANCH`

Continue with :ref:`imap-installation-diy-build-dependencies`.

From Tarball
============

Download the `latest stable tarball`_ : version |imap_current_stable_version|.

Extract the tarball:

.. parsed-literal::

    $ :command:`tar xzvf cyrus-imapd-x.y.z.tar.gz`

.. _latest stable tarball: https://github.com/cyrusimap/cyrus-imapd/releases

Continue with :ref:`imap-installation-diy-build-dependencies`.

.. _imap-installation-diy-build-dependencies:

Build Dependencies
==================

If you run an operating system or Linux distribution that already
includes packages for Cyrus IMAP, then the build dependencies for
Cyrus IMAP are specified in the packaging specification for that
package.

To install build dependencies on a Fedora, Red Hat Enterprise Linux or
CentOS system for example, you can run the following commands:

.. parsed-literal::

    # :command:`yum install yum-utils`
    # :command:`yum-builddep cyrus-imapd`

Consult the upstream documentation of your platform for further
information on the availability of such commands and their usage.

Required Build Dependencies
---------------------------

The following list includes the names of packages used in RPM-based
distributions:

**autoconf** 2.63 or higher

    from http://www.gnu.org/software/autoconf/

**automake**

    from http://www.gnu.org/software/automake/

**bison**

    from http://www.gnu.org/software/bison/

**cyrus-sasl-devel**

    from http://asg.web.cmu.edu/sasl/sasl-library.html

**flex**

    from http://flex.sourceforge.net/

**gcc**

    from http://gcc.gnu.org

**gperf**

    from http://www.gnu.org/software/gperf/

**libtool** version 2.2.6 or higher

    from http://www.gnu.org/software/libtool/

**libuuid-devel**

    from https://www.kernel.org/pub/linux/utils/util-linux/

**openssl-devel** (see :task:`29`) version 0.9.4 or higher

    from http://www.openssl.org/

**pkgconfig**

    from http://pkgconfig.freedesktop.org

Optional Build Dependencies
---------------------------

The following build dependencies are optional, and enable functionality,
Cyrus IMAP code maintenance tasks or documentation rendering.

**CUnit-devel**

    Development headers for compiling Cyrus IMAP's unit tests, from
    http://cunit.sourceforge.net/.

    Used for ``make check``.

**cyrus-sasl-plain** version 2.1.7 or higher

    Cyrus SASL package that ships the library required to pass Cyrus
    IMAP's PLAIN authentication unit tests, from
    http://asg.web.cmu.edu/sasl/sasl-library.html

    Used with ``make check``.

**cyrus-sasl-md5** version 2.1.7 or higher

    Cyrus SASL library required to pass Cyrus IMAP's DIGEST-MD5
    authentication unit tests, from
    http://asg.web.cmu.edu/sasl/sasl-library.html

    Used with ``make check``.

**db4-devel** or **libdb-devel** version 3.0.55 or higher

    .. NOTE::

        Berkeley DB support has been dropped in versions of Cyrus IMAP
        equal to or higher than Cyrus IMAP 3.0.

    Berkely DB backend for Cyrus IMAP databases, from
    https://www.oracle.com/database/berkeley-db/index.html.

    .. NOTE::

        The use of Berkely DB for Cyrus IMAP databases is discouraged,
        and is likely to be obsoleted.

**db4-utils** or **libdb-utils** version 3.0.55 or higher

    .. NOTE::

        Berkeley DB support has been dropped in versions of Cyrus IMAP
        equal to or higher than Cyrus IMAP 3.0.

    Utilities for Berkeley DB databases, from
    https://www.oracle.com/database/berkeley-db/index.html, needed to pass unit
    tests.

    Used with ``make check``.

**groff**

    from http://www.gnu.org/software/groff/

**jansson-devel**

    Development headers for Jansson, a C-library for JSON, from
    http://www.digip.org/jansson/.

    Version 2.0 or higher is required for the event notifications
    feature.

    Version 2.3 or higher is required for HTTP.

    Configure options: ``--enable-event-notifications`` and
    ``--enable-http``.

    .. NOTE::

        Specifying the configure option ``--enable-event-notifications``
        without having Jansson development headers installed will
        **not** cause ``./configure`` to fail.

**krb5-devel**

    Development headers required to enable Kerberos v5 authentication
    capabilities for Cyrus IMAP, from http://web.mit.edu/kerberos/www/.

    Otherwise also known as the authentication mechanism *GSSAPI*.

    Configure option: ``--with-krbimpl=mit``

**libical-devel**

    .. IMPORTANT::

        **libical >= 0.48** is required for scheduling support.

    from http://freeassociation.sourceforge.net/

    .. NOTE::

        Linux distributions Enterprise Linux 6 and Debian Squeeze are
        known to ship outdated **libical** packages versions 0.43 and
        0.44 respectively. The platforms will not support scheduling.

**libxml2-devel**

    from http://xmlsoft.org/

**mariadb-devel** or **mysql-devel**

    MariaDB or MySQL development headers, to allow Cyrus IMAP to use
    either as the backend for its databases.

    **mariadb-devel** from http://mariadb.org

    **mysql-devel** from http://www.mysql.com

    Configure option: ``--with-mysql``

    .. versionadded:: 2.5.0

    Configure options: ``--with-mysql-incdir``, ``--with-mysql-libdir``

    *Prior to version 2.5*.

**net-snmp-devel** version 4.2 or higher

    from http://net-snmp.sourceforge.net/

**openldap-devel**

    Development headers to enable **ptloader** to interface with LDAP
    directly, for canonification of login usernames to mailbox names,
    and verification of login usernames, ACL subjects and group
    membership, from http://www.openldap.org/.

    Configure option: ``--with-ldap``

**perl(ExtUtils::MakeMaker)**

    Perl library to assist in building extensions to Perl, from http://search.cpan.org/dist/ExtUtils-MakeMaker/.

    Configure option: ``--with-perl``

**perl-devel** version 5 or higher

    Perl development headers to allow building binary perl libraries,
    from http://www.perl.org/.

    Configure option: ``--with-perl``

**postgresql-devel**

    from http://www.postgresql.org/

**sqlite-devel**

    from http://www.sqlite.org/

**tcp_wrappers**

    from ftp://ftp.porcupine.org/pub/security/index.html

**transfig**

    from http://www.xfig.org/

**valgrind**

    from http://www.valgrind.org/

Continue with :ref:`imap-installation-diy-configure`

.. _imap-installation-diy-configure:

Configure the Build
===================

.. parsed-literal::

    $ :command:`autoreconf -vi`
    $ :command:`./configure [options]`

Check the summary after ``./configure`` completes successfully. The
following segment shows the defaults in version 2.5.0, ran on a system
with all mandatory and optional build dependencies installed, so yours
may (read: will) differ:

.. parsed-literal::

    Cyrus Imapd configured components

        event notification: yes
        gssapi:             yes
        autocreate:         no
        idled:              no
        http:               no
        kerberos V4:        no
        murder:             no
        nntpd:              no
        replication:        no
        sieve:              yes

    External dependencies:
        ldap:               no
        openssl:            yes
        pcre:               yes

    Database support:
        bdb:                yes
        mysql:              no
        postgresql:         no
        sqlite:             no

To view additional options, and disable or enable specific features,
please see:

.. parsed-literal::

    # :command:`./configure --help`
