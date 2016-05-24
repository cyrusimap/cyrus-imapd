.. _imap-installation-obs:

==========================
Open Build System Packages
==========================

`Kolab Systems AG`_ provides `the existing Open Build Service`_ instance
also used for the `Kolab Groupware solution`_ to build packages for
Cyrus IMAP on a regular basis [#]_.

Using these packages is recommended, because they install the necessary
SysVinit or Systemd files.

The following packages are built:

*   `Cyrus IMAP master`_ (from GIT)

    The latest and greatest but also most volatile version of Cyrus
    IMAP.

    .. WARNING::

        Do **NOT** use this version in production. This version is
        provided for development, quality assurance and technology
        preview purposes only.

2.5 Series
==========

*   `Cyrus IMAP 2.5-next`_ (from GIT)

    The latest HEAD for the ``cyrus-imapd-2.5`` GIT branch, most likely
    the version to end up as ``2.5.(x+1)``.

*   `Cyrus IMAP 2.5-current`_ (from released tarballs)

    The latest release of the ``cyrus-imapd-2.5`` series.

2.4 Series
==========

*   `Cyrus IMAP 2.4-next`_ (from GIT)

    The latest HEAD for the ``cyrus-imapd-2.4`` GIT branch, most likely
    the version to end up as ``2.4.(x+1)``.

*   `Cyrus IMAP 2.4-current`_ (from released tarballs)

    The latest release of the ``cyrus-imapd-2.4`` series.

.. _Cyrus IMAP master: https://obs.kolabsys.com/project/show/cyrus-imapd:master
.. _Cyrus IMAP 2.5-next: https://obs.kolabsys.com/project/show/cyrus-imapd:2.5-next
.. _Cyrus IMAP 2.5-current: https://obs.kolabsys.com/project/show/cyrus-imapd:2.5.x
.. _Cyrus IMAP 2.4-next: https://obs.kolabsys.com/project/show/cyrus-imapd:2.4-next
.. _Cyrus IMAP 2.4-current: https://obs.kolabsys.com/project/show/cyrus-imapd:2.4.x
.. _Kolab Groupware solution: https://kolab.org
.. _Kolab Systems AG: https://kolabsystems.com
.. _the existing Open Build Service: https://obs.kolabsys.com/
.. _Why a Private OBS?: https://docs.kolab.org/developer-guide/packaging/obs-for-kolab/why-private-obs.html#dev-packaging-why-private-obs

.. rubric:: Footnotes

.. [#]

    See `Why a Private OBS?`_
