.. _imap-admin-ports-services:

Cyrus Service Definitions
=========================

.. include:: /assets/services.rst

Controlling Service Ports and Sockets
-------------------------------------

The actual port or socket used by any given service may be controlled
in the service definition line for that service in the
:cyrusman:`cyrus.conf(5)` file, using the ``listen=`` directive.  Please
consult the :cyrusman:`cyrus.conf(5)` man page for details.
