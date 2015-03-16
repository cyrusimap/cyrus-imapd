.. _imap-installation-rhel-current-stable-next:

Installation of Cyrus IMAP |imap_current_stable_next_version| on Red Hat Enterprise Linux
=========================================================================================

.. NOTE::

    Packages for Cyrs IMAP version |imap_current_stable_next_version|
    can be obtained from the :ref:`imap-installation-obs`.

#.  Clone the GIT repository:

    .. parsed-literal::

        $ :command:`git clone` |git_cyrus_imapd_url|

#.  Checkout the branch for the current stable series of Cyrus IMAP:

    .. parsed-literal::

        $ :command:`git checkout` |imap_current_stable_branch|

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

        We recommend at least specifying ``--prefix=/usr``,
        ``--with-cyrus-prefix=/usr/lib/cyrus-imapd`` and
        ``--with-service-path=/usr/lib/cyrus-imapd``.

#.  Build Cyrus IMAP:

    .. parsed-literal::

        $ :command:`make`

#.  Install Cyrus IMAP (with sufficient privileges):

    .. parsed-literal::

        # :command:`make install`
