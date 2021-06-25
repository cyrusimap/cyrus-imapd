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

And you need permission to send to the cyrus-announce mailing list.

.. endblob releaseprereqs

Order of operations
===================

Sometimes you're releasing several new versions all at once(ish), for example
maybe there's been a security fix that affected 2.4, 2.5 and 3.0.

Github's release page will put a "Latest Release" graphic on the release with
the newest tag (by timestamp, I think).  This means that, if you're doing new
releases for several different versions, you want to do the oldest one first,
and only do the release for the current-stable branch last.

If you start at the current stable branch and then work your way backwards
through the older ones, you'll get Github saying "2.5.15 is the Latest
Release" even though 3.0.13 was also just released... so, even though
releasing the current-stable fix feels more urgent, suck it up and get the
older-branch ones out first.


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
   your hardware.  If this command fails*, you are not ready to release --
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

.. Note::
    ``make distcheck`` doesn't work on the 2.5 branch.  For 2.5, just use
    ``make dist`` instead.

.. Note::
    Realistically, there's usually some set of expected Cassandane failures
    from each Cyrus branch, especially for 2.5.  If you're doing releases
    regularly, you've probably got a good gut feel for which failures are a
    problem and which ones are just "that old thing".  If you don't do
    releases regularly, try to pull in someone who does for guidance about
    which failures are ignorable, and which should be a source of stress.

    If in doubt, try building and testing the previous release from the same
    series, and compare the test results.


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

Note: it is absolutely critical that your repository is clean and your local
commits have been pushed upstream at this point.  If they are not, and if
anybody else pushes in the meantime, you will end up with a mess.

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


Inter-version website consistency
=================================

The website is built from an amalgamation of documentation from:

* The current stable cyrus-imapd branch (top level)
* The current master cyrus-imapd branch (``/dev`` hierarchy)
* Each of the following cyrus-imapd branches (``/x.y`` hierarchies)

    - cyrus-imapd-2.5
    - cyrus-imapd-3.0
    - cyrus-imapd-3.2

* The current master cyrus-sasl branch (``/sasl`` hierarchy)

When making a cyrus-imapd release, you need to add the new release notes
file to each relevant cyrus-imapd branch.  You also need to check and
update the contents of ``docsrc/conf.py`` on each branch AND the cyrus-sasl
repository.

Sometimes you can just cherry-pick the commits around, but note that the
2.5 website stores release notes files in a different path, so if you
bother to copy release notes back to this branch, a naive cherry-pick will
not put them in the right place!

This step often gets forgotten, so if you actually follow it, and notice
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
7. If this is an alpha/beta/rc release, click the "This is a pre-release"
   checkbox
8. Click "Save".  The commit message from the tag annotation will be used
   as the release description.

Tell the world
==============

1. Send an announcement to the info-cyrus and cyrus-announce lists.
