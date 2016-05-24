.. _imap-installation-rhel-latest-development:

Installation of Cyrus IMAP |imap_latest_development_version| on Red Hat Enterprise Linux
========================================================================================

.. NOTE::

    Packages for Cyrs IMAP version |imap_latest_development_version| can
    be obtained from the :ref:`imap-installation-obs`.

#.  Clone the GIT repository:

    .. parsed-literal::

        $ :command:`git clone` |git_cyrus_imapd_url|

#.  Install the build dependencies:

    .. parsed-literal::

        # :command:`yum -y install \\
            autoconf \\
            automake \\
            bison \\
            CUnit-devel \\
            cyrus-sasl-devel \\
            cyrus-sasl-md5 \\
            cyrus-sasl-plain \\
            flex \\
            gcc \\
            groff \\
            jansson-devel \\
            krb5-devel \\
            libical-devel \\
            libxml2-devel \\
            libtool \\
            libuuid-devel \\
            mysql-devel \\
            net-snmp-devel \\
            openldap-devel \\
            openssl-devel \\
            "perl(ExtUtils::MakeMaker)" \\
            perl-devel \\
            pkgconfig \\
            postgresql-devel \\
            sqlite-devel \\
            tcp_wrappers \\
            transfig`

#.  Execute the following commands:

    .. parsed-literal::

        $ :command:`autoreconf -vi`
        $ :command:`./configure` [options]

    For a full list of options, see ``./configure --help``.

    .. NOTE::

        We recommend at least specifying ``--prefix=/usr`` and
        ``--libexecdir=/usr/libexec/cyrus-imapd``.

#.  Build Cyrus IMAP:

    .. parsed-literal::

        $ :command:`make`

#.  Install Cyrus IMAP (with sufficient privileges):

    .. parsed-literal::

        # :command:`make install`
