.. _imap-developer-ancient-releasing:

===================================================
Releasing new builds of ancient Cyrus IMAP versions
===================================================

.. contents::

Introduction
============

These instructions are specifically for doing releases from branches that do
not contain RST-based documentation or infrastructure.  This includes 2.3 and
2.4.  It might work for even older versions as well.

For contemporary releases, see :ref:`imap-developer-releasing`

Prerequisites
=============

.. include:: /imap/developer/releasing.rst
	:start-after: startblob releaseprereqs
	:end-before: endblob releaseprereqs

Release notes and version update
================================

1. Write up the changes, and add them to the top of the ``doc/changes.html``
   file with a suitable new heading.  Stick to very basic HTML here.
2. Update the ``VERSION = ..`` line in ``Makefile.in`` to specify the new
   version number.
3. Commit these changes to git.

Pre-release testing
===================

1. Ensure your git repository is clean, using something like ``git clean -xfd``.
   Note that this command will destroy any uncommitted work you might have,
   so make sure your ducks are in line before proceeding.
2. Generate a configure script: ``autoreconf -i -s -I cmulocal``
3. Generate everything else: ``./configure --enable-maintainer-mode`` (you do not
   need any other options at this stage).
4. Run ``make dist``.  This will generate a distribution tarball.
5. Test the tarball:

   i.    The tarball will be called something like ``cyrus-imapd-2.3.19.tar.gz``
         (this is based on the ``VERSION = ...`` line in ``Makefile.in``)
   ii.   Visually inspect the contents of the tarball, making sure it looks like
         it contains everything it needs to: ``tar tfz cyrus-imapd-*.tar.gz | less``
         (substitute version for ``*``).
   iii.  Extract it: ``tar xfz cyrus-imapd-*.tar.gz``
   iv.   Change into the directory: ``cd cyrus-imapd-*``
   v.    Configure it: ``./configure [...]`` (provide the same arguments you would
         when building for Cassandane at any other time).
   vi.   Compile it: ``make`` -- it should build correctly.
   vii.  Run the unit tests if there are any: ``make check`` -- they should pass.

.. Note::
    We don't bother to run ``make distcheck`` on the old branches, because it
    almost certainly won't work.  We also don't bother to run Cassandane, for
    much the same reason.  If it builds, that's about as much as we can do.

Cross-pollination of release notes
==================================

The ancient versions do not contain ReStructured Text documentation.  To have the
release notes for these versions appear on the cyrusimap.org website, they need to
be added to current branches as well.

1. Change to the current stable branch (at time of writing, this is ``cyrus-imapd-3.0``).
2. Create a new release notes document at the appropriate location under
   ``docsrc/imap/download/release-notes/``.
3. Add the release notes you wrote earlier, this time using RST format rather
   than simple HTML.
4. Test, commit, push, and they will be online at the next hour.
5. Also cherry-pick this commit to the ``master`` branch.

Building the release
====================

1. Ensure your repository is clean again: ``git clean -xfd``
2. Create a signed, annotated tag for the new version: ``git tag -s cyrus-imapd-<version>``
3. You will be prompted to enter a commit message for the tag.  I use the
   following, just because it's what the old instructions said::

        We are pleased to announce the release of Cyrus IMAP version <version>.

        This release contains features and fixes you can find on the following pages:

        [paste link to the release notes for this version here]

4. You will also be prompted to enter the pass phrase for your GPG key, do it.
5. Generate a configure script: ``autoreconf -i -s -I cmulocal``
6. Generate everything else: ``./configure --enable-maintainer-mode``
7. Create the distribution tarball: ``make dist``
8. If anything goes wrong up to here, delete the tag, fix the issue, and start
   again from scratch.
9. Sign the distribution tarball: ``gpg --sign -b cyrus-imapd-<version>.tar.gz``
10. Ellie also likes to copy the tarball and signature file somewhere safe,
    just in case something happens between now and uploading.
11. Push the tag upstream: ``git push ci cyrus-imapd-<version>`` (assuming your
    remote is named "ci").

Finishing up
============

Now follow the remaining steps from :ref:`imap-developer-releasing`
