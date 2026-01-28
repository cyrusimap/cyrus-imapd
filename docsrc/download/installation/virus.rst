.. _install-virus:

=============
Virus Scanner
=============

About virus scan support
========================

Cyrus can use an external virus scanner to check for infected mail. Currently,
only `ClamAV`_ is supported.

Infected mail can be reported on, or removed.

It is possible to use Cyrus's virus scanner support **without** a virus scanner,
by passing in an IMAP SEARCH string. Messages matching that string are treated
as infected.

For more information, see :cyrusman:`cyr_virusscan(8)`.

.. _ClamAV: https://www.clamav.net

Virus Scanner Configuration
===========================

General configuration
---------------------

Once the virus scanner has been installed, Cyrus must be recompiled: the
configure step will detect the presence of a supported virus library and
use it.

:cyrusman:`cyr_virusscan(8)` can be run manually, or configured to run
periodically by cron(8) via crontab(5) or your preferred method
(i.e. /etc/cron.hourly), or by :cyrusman:`master(8)` in the EVENTS{} section in
:cyrusman:`cyrus.conf(5)`.

ClamAV
------

Cyrus does not need any special configuration to work with `ClamAV`_:
once ClamAV is installed, compiling Cyrus will automatically detect and use
the ClamAV libraries.
