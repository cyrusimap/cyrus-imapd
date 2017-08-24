.. _imap-admin-sockets:

Cyrus Socket Locations
======================

.. _imap-admin-sock:

The Cyrus IMAP server provides service interfaces via either TCP/IP
ports or Unix domain sockets.  For the later, Cyrus requires the parent
directory exist prior to initialization.

The following sockets may be required for any host providing local Unix
domain access for the listed services, where ``<rundir>`` is the base
directory for Cyrus sockets. This defaults to
``{configdirectory}/socket/`` where {configdirectory} is as defined in
:cyrusman:`imapd.conf(5)`, but is often redefined as
``/var/run/cyrus/socket/`` or more recently ``/run/cyrus/socket/``:

::

    lmtp      <rundir>/lmtp   # Lightweight Mail Transport Protocol service
    idle      <rundir>/idle   # idled daemon socket
    notify    <rundir>/notify # Notification daemon socket
    ptloader  <rundir>/ptsock # PT Loader socket (alternative authorization)

.. _imap-admin-sock-end:

Controlling Socket Locations
----------------------------

Locations of sockets may be tailored to the needs of different
sites, via the use of several settings in :cyrusman:`imapd.conf(5)`:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob idlesocket
	:end-before: endblob idlesocket

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob lmtpsocket
	:end-before: endblob lmtpsocket

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob notifysocket
	:end-before: endblob notifysocket

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob ptloader_sock
	:end-before: endblob ptloader_sock
