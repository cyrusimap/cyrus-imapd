Supported Platforms and System Requirements
===========================================

Cyrus IMAP supports the following platforms;

* FreeBSD

* All reasonably recent versions of Linux, including but not limited to the following distributions, in no particular order other than alphabetic;

    * `CentOS <https://www.centos.org>`__
    * `Debian <https://www.debian.org>`__
    * `Fedora <https://www.fedoraproject.org>`__
    * `Gentoo <https://www.gentoo.org>`__
    * `openSUSE <https://www.opensuse.org>`__
    * `Red Hat Enterprise Linux <https://www.redhat.com/en>`__
    * `SUSE Linux <https://www.suse.com>`__

    Should your Linux distribution not be listed here, please refer to :ref:`feedback` for ways of contacting the Cyrus IMAP team.

* Solaris

By reasonably recent versions of Linux, we intend to indicate the Cyrus project can keep up with the latest distribution release earmarked stable.

Building Cyrus IMAP
-------------------

In this section, we only list the aspects of building Cyrus IMAP of particular interest to most common deployment scenarios. For more information on all ``configure`` options with full details, we refer you to ``./configure --help``.

Required Software Components
----------------------------

The following software components are required for Cyrus IMAP to build at all, with minimal functionality;

* ``autoconf``
* ``automake``
* ``zlib`` (Development Headers)

Obviously, the list is not complete

Recommended Software Components
-------------------------------

We recommend you consider building Cyrus IMAP with the following software components included;

Idled Support
"""""""""""""

To enable near real-time client updates through IMAP IDLE (as described in `RFC 2177 <http://tools.ietf.org/html/rfc2177>`__), configure Cyrus IMAP with the ``--enable-idled`` option.

Murder Support
""""""""""""""

To enable horizontal scalability, Cyrus IMAP supports the distribution of mailboxes across Cyrus IMAP servers in a Murder setup. To enable murder support in Cyrus IMAP, configure Cyrus IMAP with the ``--enable-murder`` option.

Replication Support
"""""""""""""""""""

To enable replication support in Cyrus IMAP, configure Cyrus IMAP with the ``--enable-replication`` option.

Obviously, the list is not complete

Recommended Software Components Enabled by Default
--------------------------------------------------

Sieve Support
"""""""""""""

Without any additional effort, Sieve support is already enabled by default. To disable Sieve, use the ``--disable-sieve`` option to ``configure``.

Optional Software Components
""""""""""""""""""""""""""""

When including the following software components during the build process, and providing the options listed here, additional optional functionality can be implemented;

**Berkeley DB** (Development headers)

To enable using Berkely DB as a database backend, include the Berkeley DB development headers and make sure to configure Cyrus IMAP with ``--with-bdb``.

Berkeley DB Versions and Conversion

The Cyrus IMAP ``configure`` process attempts to automatically detect and use the latest Berkeley DB technology available on the system. This may, however, not be the same version on your production systems. Since database conversions between versions of the Berkeley DB technology are particularly difficult and therefor NOT considered fully supported, we recommend you do NOT use Berkeley DB.

Should the Berkeley DB development headers be installed in a non-standard location, or should you need a specific version when multiple versions are available on the system, please consider using any of the following options;

::

    --with-bdb=DIR            use Berkeley DB (in DIR) [yes]
    --with-bdb-libdir=DIR     Berkeley DB lib files are in DIR
    --with-bdb-incdir=DIR     Berkeley DB include files are in DIR</screen>

**MySQL** (Development headers)

To enable using MySQL as a database server backend, include the MySQL development headers and make sure to configure Cyrus IMAP with ``--with-mysql``.

Should MySQL - the client libraries or the development headers - be installed in a non-standard location, please consider using any of the following options;

::

    --with-mysql=DIR          use MySQL (in DIR) [no]
    --with-mysql-libdir=DIR   MySQL lib files are in DIR
    --with-mysql-incdir=DIR   MySQL include files are in DIR

**PostgreSQL** (Development headers)

To enable using PostgreSQL as a database server backend, include the PostgreSQL development headers and make sure to configure Cyrus IMAP with ``--with-pgsql``.

Should PostgreSQL - the client libraries or the development headers - be installed in a non-standard location, please consider using any of the following options;

::

    --with-pgsql=DIR          use PostgreSQL (in DIR) [no]
    --with-pgsql-libdir=DIR   Pgsql lib files are in DIR
    --with-pgsql-incdir=DIR   Pgsql include files are in DIR

Obviously, the list is not complete

