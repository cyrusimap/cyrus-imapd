Red Hat Enterprise Linux
========================

Red Hat Enterprise Linux ships Cyrus IMAP packages as part of the base
operating system repositories. If the base operating system has a
subscription activated, then `Red Hat, Inc.`_ supports the package
through the usual support channels.

Currently supported versions of Red Hat Enterprise Linux include
Cyrus IMAP packages in the repositories configured on a stock system:

*   Cyrus IMAP |imap_el5_stock_version| for Red Hat Enterprise Linux 5
*   Cyrus IMAP |imap_el6_stock_version| for Red Hat Enterprise Linux 6
*   Cyrus IMAP |imap_el7_stock_version| for Red Hat Enterprise Linux 7

.. NOTE::

    The Cyrus project does not support running any versions of the Cyrus
    IMAP software older than the version of the software shipped
    with the operating system itself.

To install the version of Cyrus IMAP that comes with the operating
system, issue the following command:

.. parsed-literal::

    # :command:`yum install cyrus-imapd`

Other Versions of Cyrus IMAP
----------------------------

*   :ref:`installation-rhel-cyrus-imapd-latest-stable`
*   :ref:`installation-rhel-cyrus-imapd-next-stable`
*   :ref:`installation-rhel-cyrus-imapd-latest-development`

.. toctree::
    :glob:
    :hidden:

    rhel/*

.. _Red Hat, Inc.: https://redhat.com
