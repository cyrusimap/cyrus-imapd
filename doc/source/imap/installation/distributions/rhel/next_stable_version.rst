.. _installation-rhel-cyrus-imapd-next-stable:

Installation of Cyrus IMAP |imap_next_stable_version| on Red Hat Enterprise Linux
=================================================================================

The completion of this documentation is pending the resolution of
:task:`34`.

.. parsed-literal::

    $ :command:`git checkout` |imap_latest_stable_branch|

View patches, if any, against the latest stable version
|imap_latest_stable_version| using the following command:

.. parsed-literal::

    $ :command:`git format-patch` |imap_latest_stable_version|

Record the number of patches with:

.. parsed-literal::

    $ :command:`patchlevel=$(ls -1 \*.patch | wc -l)`

Create a new tarball:

.. parsed-literal::

    $ :command:`git archive` \\
        --prefix |imap_latest_stable_version|.$patchlevel/ HEAD | \\
        gzip -c > cyrus-imapd-|imap_latest_stable_version|.$patchlevel.tar.gz
