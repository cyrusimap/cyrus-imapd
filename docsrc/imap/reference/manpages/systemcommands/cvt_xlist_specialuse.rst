.. cyrusman:: cvt_xlist_specialuse(8)

.. _imap-reference-manpages-systemcommands-cvt_xlist_specialuse:

========================
**cvt_xlist_specialuse**
========================

Convert legacy xlist-*flag* settings to user special-use annotations.

Synopsis
========

.. parsed-literal::

    **cvt_xlist_specialuse** [OPTIONS] mailbox...

Description
===========

**cvt_xlist_specialuse** is a tool for converting xlist-*flag* settings from
:cyrusman:`imapd.conf(5)` to user special-use annotations.

.. _cvt_xlist_specialuse-options:

Options
=======

.. program:: cvt_xlist_specialuse

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -v, --verbose

    Produce verbose output

Examples
========

.. parsed-literal::

    **cvt_xlist_specialuse** user.*

..

    Set special-use annotations for all users (unixhierarchysep: off)

.. parsed-literal::

    **cvt_xlist_specialuse** user/*

..

    Set special-use annotations for all users (unixhierarchysep: on)

History
=======

The xlist-*flag* settings existed for a while in Cyrus IMAP 2.4, for setting
special-use style flags for particular folder names (on a server-wide basis).
This was deprecated at some point with the introduction of :rfc:`6154`.

The **cvt_xlist_specialuse** tool was introduced in Cyrus IMAP 3.0 to aid
administrators in upgrading from older deployments where xlist-*flag*
settings had been in use.

Files
=====

See Also
========

:cyrusman:`imapd.conf(5)`
