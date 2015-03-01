CentOS
======

Currently supported versions of CentOS include Cyrus IMAP packages in
the repositories configured on a stock system:

*   Cyrus IMAP |imap_el5_stock_version| for CentOS 5
*   Cyrus IMAP |imap_el6_stock_version| for CentOS 6
*   Cyrus IMAP |imap_el7_stock_version| for CentOS 7

.. NOTE::

    The Cyrus project does not support running any versions of the Cyrus
    IMAP software older than the version of the software shipped
    with the operating system itself.

To install the version of Cyrus IMAP that comes with the operating
system, issue the following command:

.. parsed-literal::

    # :command:`yum install cyrus-imapd`

Next, set a password for the default administrative user ``cyrus``:

.. parsed-literal::

    # :command:`passwd cyrus`
    Changing password for user cyrus.
    New password:
    Retype new password:
    passwd: all authentication tokens updated successfully.

Start the service, and (optionally) ensure the service starts up when the
system boots:

.. parsed-literal::

    # :command:`service cyrus-imapd start`
    # :command:`chkconfig cyrus-imapd on`

Next, continue with :ref:`imap-configuring-the-mta`.

Other Versions of Cyrus IMAP
----------------------------

The following guides walk you through providing you with a version of
the Cyrus IMAP software that is no longer mainstream, and as such the
level of technical detail is advanced.

*   :ref:`installation-centos-cyrus-imapd-latest-stable`
*   :ref:`installation-centos-cyrus-imapd-next-stable`
*   :ref:`installation-centos-cyrus-imapd-latest-development`

.. toctree::
    :glob:
    :hidden:

    centos/*
