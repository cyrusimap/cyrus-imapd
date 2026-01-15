Supported Platforms and System Requirements
===========================================

Cyrus IMAP supports the following platforms;

* FreeBSD

* All reasonably recent versions of Linux, including but not limited to the
  following distributions, in no particular order other than alphabetic;

    * `CentOS <https://www.centos.org>`__
    * `Debian <https://www.debian.org>`__
    * `Fedora <https://www.fedoraproject.org>`__
    * `Gentoo <https://www.gentoo.org>`__
    * `openSUSE <https://www.opensuse.org>`__
    * `Red Hat Enterprise Linux <https://www.redhat.com/en>`__
    * `SUSE Linux <https://www.suse.com>`__

  Should your Linux distribution not be listed here, please refer to
  :ref:`support` for ways of contacting the Cyrus IMAP team.

* Solaris

By reasonably recent versions of Linux, we intend to indicate the Cyrus project
can keep up with the latest distribution release earmarked stable.

Building Cyrus IMAP
-------------------

In this section, we only list the aspects of building Cyrus IMAP of particular
interest to most common deployment scenarios. For more information on all
``configure`` options with full details, we refer you to ``./configure --help``.

Required Software Components
----------------------------

The following software components are required for Cyrus IMAP to build at all,
with minimal functionality;

* ``autoconf``
* ``automake``
* ``zlib`` (Development Headers)

Obviously, the list is not complete

Recommended Software Components
-------------------------------

We recommend you consider building Cyrus IMAP with the following software
components included;

Idled Support
"""""""""""""

To enable near real-time client updates through IMAP IDLE (as described in
:rfc:`2177`), configure Cyrus IMAP with the ``--enable-idled`` option.

Murder Support
""""""""""""""

To enable horizontal scalability, Cyrus IMAP supports the distribution of
mailboxes across Cyrus IMAP servers in a Murder setup. To enable murder support
in Cyrus IMAP, configure Cyrus IMAP with the ``--enable-murder`` option.

Replication Support
"""""""""""""""""""

To enable replication support in Cyrus IMAP, configure Cyrus IMAP with the
``--enable-replication`` option.

Obviously, the list is not complete

Recommended Software Components Enabled by Default
--------------------------------------------------

Sieve Support
"""""""""""""

Without any additional effort, Sieve support is already enabled by default. To
disable Sieve, use the ``--disable-sieve`` option to ``configure``.

Optional Software Components
""""""""""""""""""""""""""""

When including the following software components during the build process,
and providing the options listed here, additional optional functionality can
be implemented;

**MySQL** (Development headers)

To enable using MySQL as a database server backend, include the MySQL
development headers and make sure to configure Cyrus IMAP with
``--with-mysql``.

Should MySQL - the client libraries or the development headers - be installed
in a non-standard location, please consider using any of the following options;

::

    --with-mysql=DIR          use MySQL (in DIR) [no]
    --with-mysql-libdir=DIR   MySQL lib files are in DIR
    --with-mysql-incdir=DIR   MySQL include files are in DIR

**PostgreSQL** (Development headers)

To enable using PostgreSQL as a database server backend, include the
PostgreSQL development headers and make sure to configure Cyrus IMAP with
``--with-pgsql``.

Should PostgreSQL - the client libraries or the development headers - be
installed in a non-standard location, please consider using any of the
following options;

::

    --with-pgsql=DIR          use PostgreSQL (in DIR) [no]
    --with-pgsql-libdir=DIR   Pgsql lib files are in DIR
    --with-pgsql-incdir=DIR   Pgsql include files are in DIR

Obviously, the list is not complete
