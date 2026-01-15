.. _imap-developer-releasing:

======================================
Releasing Cyrus IMAP - normal releases
======================================

.. contents::

These instructions are specifically for doing point releases. Those are
releases that change the *z* in ``x.y.z``.

For snapshot releases from the master branch, see
:ref:`imap-developer-snapshot-releasing`

For major (x.y) releases, you will follow this process for publishing the
release tarballs, but there are additional steps before and around that,
detailed at :ref:`imap-developer-major-releasing`.

Prerequisites
=============

.. startblob releaseprereqs

You will need a GPG key that you can use for signing.  Ellie doesn't remember
off the top of her head how to create one of these, so for now just read the
manual like she did. :)

Once you have a GPG key, it's helpful to upload your public key to
`the MIT key-server <http://pgp.mit.edu>`_

And you need permission to send to the cyrus-announce mailing list.

.. endblob releaseprereqs

Release notes
=============

Write up the release notes, and add them to the appropriate location under
``docsrc/download/release-notes/``.  They will not yet be linked up.
Build the documentation locally with ``make doc-html``, then check the new
release notes file in your brower to make sure it's correct and complete.
It will be in ``doc/html/download/release-notes/...``.

Commit the new release notes with a message like ``docs: release notes for
cyrus-imapd <version>``, but don't push it yet.  You might want to keep these
release commits on a separate branch for now, so you can rebase it if the real
branch changes along the way.

Pre-release testing
===================

1. Ensure your git repository is clean, using something like ``git clean -dfx``.
   Note that this command will destroy any uncommitted work you might have,
   so make sure your ducks are in line before proceeding.
2. Generate a configure script: ``autoreconf -i -s``
3. Generate everything else: ``./configure --enable-maintainer-mode`` (you do not
   need any other options at this stage).
4. Run ``make distcheck``.  This will generate a distribution tarball, and
   test it in various ways.  It takes about 10-15 mins to run, depending on
   your hardware.  If this command fails*, you are not ready to release --
   fix the problems, get them tested and committed, then restart the
   pre-release testing.
5. ``make distcheck`` can only test so much (it doesn't know about cunit or
   cassandane), so you also need to check the tarball against those.

   i.    The tarball will be called something like ``cyrus-imapd-3.12.2-rc2-23-g0241b22.tar.gz``
         (this corresponds to the ``git describe`` output).
   ii.   Extract it: ``tar xfz cyrus-imapd-*.tar.gz`` (substitute version for ``*``).
   iii.  Change into the directory: ``cd cyrus-imapd-*``
   iv.   Configure it: ``./configure [...]`` (provide the same arguments you would
         when building for Cassandane at any other time).
   v.    Compile it: ``make -j4`` -- it should build correctly.
   vi.   Run the unit tests: ``make -j4 check`` -- they should pass.
   vii.  Install it to your Cassandane prefix: ``make install``
   viii. Then run Cassandane normally -- it should pass.
   ix.   If any of this fails, fix it, commit it, land it upstream, then
         restart the pre-release testing.

Linking up release notes
========================

The linkage of release notes is handled in ``docsrc/conf.py``.  There's a bunch
of places it needs to be updated.  We should iterate these in detail at some
point, but for now the easiest thing to do is look for lines containing the
previous version and, if it makes sense to do so, update them to contain the
new version.

Commit this on your WIP branch with a message like ``docs: cyrus-imapd
<version> released``.  This is usually the commit you'll end up tagging as the
release.


Version tagging
===============

Note: it is critical that your local copy of the branch you'll be releasing to
is clean and up to date, and that your WIP branch (if any) is a direct
descendant of it, otherwise you may end up with a mess later.

1. Ensure your repository is clean again: ``git clean -dfx``
2. Create a signed, annotated tag for the new version: ``git tag -s cyrus-imapd-<version>``
3. You will be prompted to enter a commit message for the tag.  I use the
   following, just because it's what the old instructions said::

        We are pleased to announce the release of Cyrus IMAP version <version>.

        This release contains features and fixes you can find on the following pages:

        [paste link to the release notes for this version here]

4. You will also be prompted to enter the pass phrase for your GPG key, do it.
5. Generate a configure script: ``autoreconf -i -s``
6. Generate everything else, this time with release checks enabled:
   ``./configure --enable-maintainer-mode --enable-release-checks``
7. Create the distribution tarball: ``make distcheck`` (yes, again! this time
   will have the correct version, now that you've tagged it.)
8. If anything goes wrong up to here, delete the tag, fix the issue, and start
   again from scratch.
9. Sign the distribution tarball: ``gpg --sign -b cyrus-imapd-<version>.tar.gz``
10. Ellie also likes to copy the tarball and signature file somewhere safe,
    just in case something happens between now and uploading.
11. If you've been using a WIP branch for the release notes and docsrc/conf.py
    changes, fast forward your commits onto the real branch and push it
    upstream.
12. Push the tag upstream: ``git push ci cyrus-imapd-<version>`` (assuming your
    remote is named "ci").


Inter-version website consistency
=================================

The website is built from an amalgamation of documentation from:

* The current stable cyrus-imapd branch (top level)
* The current master cyrus-imapd branch (``/dev`` hierarchy)
* The release-numbered cyrus-imapd branches (``/x.y`` hierarchies)
* The current master cyrus-sasl branch (``/sasl`` hierarchy)

When making a cyrus-imapd release, you need to add the new release notes
file to each relevant cyrus-imapd branch, including master and the current
stable branch.  You also need to check and update the contents of
``docsrc/conf.py`` on each branch AND the cyrus-sasl repository.

For the cyrus-imapd branches, you can mostly just cherry-pick the two release
commits around.  The docsrc/conf.py changes may not pick cleanly to the master
branch but it's not hard to figure out how to massage it.

For cyrus-sasl, manually update its docsrc/conf.py with the correct cyrus-imapd
version numbers, commit it with a similar message, and push it.  If in doubt,
have a look at previous commits that modified this file for inspiration.  If
you don't have push access to the cyrus-sasl repository, check with someone who
does.

This step sometimes gets forgotten, so if you actually follow it, and notice
some missing versions, just go ahead and add them while you're there.

Uploading
=========

.. Note::
    This section does NOT apply to releases from the master branch.  We
    do not publish release tarballs for those.  People running master code
    are expected to use a git checkout.

Time to upload the release tarball and signature file!

1. Navigate to https://github.com/cyrusimap/cyrus-imapd/releases
2. The tag you pushed earlier will now be available as a release, but it will
   have very little information about it
3. Click on the tag name
4. Click "Edit tag" on the right
5. *Leave every field on the page as it is (probably blank!), except*:
6. Use the "Attach binaries by dropping them here or selecting them" widget
   to upload the tarball and signature files
7. If this is an alpha/beta/rc release, make sure the "This is a pre-release"
   checkbox is *unchecked*
8. If this *isn't* a pre-release, then if and *only* if this is a release of
   the latest series of Cyrus, ensure the "Set as the latest release" checkbox
   is *checked*.  In other words, if the latest stable release is 3.10.4 and
   you're releasing 3.10.5, choose "Set as the latest release".  If you're
   releasing 3.8.9, don't.
9. Click "Save".  The commit message from the tag annotation will be used
   as the release description.

Tell the world
==============

1. Send an announcement to the info-cyrus and cyrus-announce lists.
