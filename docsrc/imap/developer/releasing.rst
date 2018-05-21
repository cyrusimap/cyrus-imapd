.. _imap-developer-releasing:

====================
Releasing Cyrus IMAP
====================

.. contents::

These instructions are specifically for doing releases from branches that
contain RST-based documentation and infrastructure.  This includes 2.5 and
later versions.

For new releases from ancient branches, see :ref:`imap-developer-ancient-releasing`


Prerequisites
=============

.. startblob releaseprereqs

You will need a GPG key that you can use for signing.  Ellie doesn't remember
off the top of her head how to create one of these, so for now just read the
manual like she did. :)

Once you have a GPG key, it's helpful to upload your public key to
`the MIT key-server <http://pgp.mit.edu>`_

You also need a shell account on www.cyrusimap.org and ftp.cyrusimap.org,
with SSH key authentication.  You need to be in the "admin" group on each,
and also the "cyrupload" group on the latter.

And you need permission to send to the cyrus-announce mailing list.

.. endblob releaseprereqs


Release notes
=============

Write up the release notes, and add them to the appropriate location under
``docsrc/imap/download/release-notes/``.  They will not yet be linked up.

Commit and push your changes, and then wait for cyrusimap.org to rebuild
(happens each hour, and takes a few mins, so check at about 5 past).  The
new release notes will be available at their direct URL -- easiest way to
find it is to browse to some earlier version's release notes, then change
version in the address bar to load up the new one.  Confirm that they are
correct and complete.


Pre-release testing
===================

1. Ensure your git repository is clean, using something like ``git clean -xfd``.
   Note that this command will destroy any uncommitted work you might have,
   so make sure your ducks are in line before proceeding.
2. Generate a configure script: ``autoreconf -i -s``
3. Generate everything else: ``./configure --enable-maintainer-mode`` (you do not
   need any other options at this stage).
4. Run ``make distcheck``.  This will generate a distribution tarball, and
   test it in various ways.  It takes about 10-15 mins to run, depending on
   your hardware.  If this command fails, you are not ready to release --
   fix the problems, get them tested and committed, then restart the
   pre-release testing.
5. ``make distcheck`` can only test so much (it doesn't know about cunit or
   cassandane), so you also need to check the tarball against those.

   i.    The tarball will be called something like ``cyrus-imapd-3.0.0-rc2-23-g0241b22.tar.gz``
         (this corresponds to the ``git describe`` output).
   ii.   Extract it: ``tar xfz cyrus-imapd-*.tar.gz`` (substitute version for ``*``).
   iii.  Change into the directory: ``cd cyrus-imapd-*``
   iv.   Configure it: ``./configure [...]`` (provide the same arguments you would
         when building for Cassandane at any other time).
   v.    Compile it: ``make -j4`` -- it should build correctly.
   vi.   Run the unit tests: ``make -j4 check`` -- they should pass.
   vii.  Install it to your Cassandane prefix: ``make install``
   viii. Then run Cassandane normally -- it should pass.
   ix.   If any of this fails, fix it, commit it, then restart the pre-release
         testing.


Linking up release notes
========================

The linkage of release notes is handled in ``docsrc/conf.py``.  There's a bunch
of places it needs to be updated.  We should iterate these in detail at some
point, but for now the easiest thing to do is look for lines containing the
previous version and, if it makes sense to do so, update them to contain the
new version.

After this change is committed and pushed upstream, the cyrusimap.org website
will start showing the new version as the "current" version at the next hourly
update.  So ellie likes to do this step at about 5-10 past the hour, which then
gives her 50 minutes to finish the rest of the release process without the
website updating before the downloads are available.


Version tagging
===============

Note: it is absolutely critical that your local commits have been pushed
upstream at this point.  If they are not, and if anybody else pushes in the
meantime, you will end up with a mess.

1. Ensure your repository is clean again: ``git clean -xfd``
2. Create a signed, annotated tag for the new version: ``git tag -s cyrus-imapd-<version>``
3. You will be prompted to enter a commit message for the tag.  I use the
   following, just because it's what the old instructions said::

        We are pleased to announce the release of Cyrus IMAP version <version>.

        This release contains features and fixes you can find on the following pages:

        [paste link to the release notes for this version here]

4. You will also be prompted to enter the pass phrase for your GPG key, do it.
5. Generate a configure script: ``autoreconf -i -s``
6. Generate everything else: ``./configure --enable-maintainer-mode``
7. Create the distribution tarball: ``make distcheck`` (yes, again! this time
   will have the correct version, now that you've tagged it.)
8. If anything goes wrong up to here, delete the tag, fix the issue, and start
   again from scratch.
9. Sign the distribution tarball: ``gpg --sign -b cyrus-imapd-<version>.tar.gz``
10. Ellie also likes to copy the tarball and signature file somewhere safe,
    just in case something happens between now and uploading.
11. Push the tag upstream: ``git push ci cyrus-imapd-<version>`` (assuming your
    remote is named "ci").

Releasing
=========

1. Upload the tarball and signature to www: ``scp cyrus-imapd-*.tar.gz cyrus-imapd-*.tar.gz.sig
   www.cyrusimap.org:/var/www/html/releases/``
2. Upload them to ftp too: ``scp cyrus-imapd-*.tar.gz cyrus-imapd-*.tar.gz.sig
   ftp.cyrusimap.org:/srv/ftp/cyrus-imapd/``
3. SSH into both www and ftp, and move older releases to the old versions
   directory.  You want only the two most recent tarball+sig pairs for each
   major series.
4. Update the topic in the #cyrus IRC channel.
5. Send an announcement to the info-cyrus and cyrus-announce lists.
