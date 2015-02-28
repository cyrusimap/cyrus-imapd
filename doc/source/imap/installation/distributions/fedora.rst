Fedora
======

Fedora is a Linux distribution that does not generally enforce a policy
of not providing you with upgrades of software during the life-cycle of
any of the distribution's released versions, or what could otherwise be
expected to constitute "stable".

While package maintainers tend to want to prevent unpleasant surprises
from being deployed to your Fedora system, and therefore generally
ship only versions of one series to any one given released distribution
version, the Cyrus project cannot guarantee you will not receive an
upgrade at some point, and cannot guarantee this upgrade will run
smoothly -- even though we do our best.

To inform yourself about the version of Cyrus IMAP available on your
Fedora system, execute the following command:

.. parsed-literal::

    # :command:`yum info cyrus-imapd`

To install Cyrus IMAP using the stock distribution repositories, use:

.. parsed-literal::

    # :command:`yum install cyrus-imapd`

Other Versions of Cyrus IMAP
----------------------------

*   :ref:`installation-fedora-cyrus-imapd-latest-stable`
*   :ref:`installation-fedora-cyrus-imapd-next-stable`
*   :ref:`installation-fedora-cyrus-imapd-latest-development`

.. toctree::
    :glob:
    :hidden:

    fedora/*
