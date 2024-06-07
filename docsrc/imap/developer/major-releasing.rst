.. _imap-developer-major-releasing:

=====================================
Releasing Cyrus IMAP - major releases
=====================================

.. contents::

These instructions describe the process of turning what was the master
branch into a new release series, and making the first release from it.

For normal point releases, see :ref:`imap-developer-releasing`

Prerequisites
=============

Same as for normal releases.

Feature freeze
==============

This is the period where new features are not being merged to the master
branch.  It usually starts at the start of December, and continues until
the new series has its own cyrus-imapd-x.y branch, which is usually forked
in early January.

Once the new series has its own branch, any bug fixes will need to be
developed against master and then backported to the new branch.  In
contrast, bug fixes that happen during the feature freeze only need to land
once, so take advantage of this window to focus on those.

The feature freeze also reduces races between the release manager doing the
various tasks of a release and other developers merging changes.

Once the new series has its own branch, normal feature development can resume
on master -- developing features for the *next* major release.

Make sure master is good
========================

With the master branch checked out and up to date:

1. Ensure your git repository is clean, using something like
   ``git clean -xfd``.  Note that this command will destroy any uncommitted
   work you might have, so make sure your ducks are in line before proceeding.
2. Generate a configure script: ``autoreconf -i -s``
3. Generate everything else: ``./configure --enable-maintainer-mode`` (you do
   not need any other options at this stage).
4. Run ``make distcheck``.  This will generate a distribution tarball, and
   test it in various ways.  It takes about 10-15 mins to run, depending on
   your hardware.  If you usually build Cyrus with a script that sets PATH etc,
   you will need to provide the same environment at this step.  For example,
   ellie uses an alias like this for this step:

   ``alias distcheck="PATH=/usr/local/cyruslibs/bin:$PATH make distcheck"``.

   If ``make distcheck`` fails, you are not ready to proceed -- fix the
   problems, get them tested and committed, then restart this testing.
5. ``make distcheck`` can only test so much (it doesn't know about cunit or
   cassandane), so you also need to check the tarball against those.

   i.    The tarball will be called something like
         ``cyrus-imapd-3.0.0-rc2-23-g0241b22.tar.gz``
         (this corresponds to the ``git describe`` output).
   ii.   Extract it: ``tar xfz cyrus-imapd-*.tar.gz``
         (substitute version for ``*``).
   iii.  Change into the directory: ``cd cyrus-imapd-*``
   iv.   Configure it: ``./configure [...]`` (provide the same arguments and
         environment that you would when building for Cassandane at any other
         time).
   v.    Compile it: ``make -j4`` -- it should build correctly.
   vi.   Run the unit tests: ``make -j4 check`` -- they should pass.
   vii.  Install it to your Cassandane prefix: ``make install``
   viii. Change into the `cassandane` directory within the extracted source
         (not the git source!): ``cd cassandane``
   ix.   Build Cassandane's binary components: ``make -j4``
   x.    Run Cassandane: ``./testrunner.pl``
   xi.   If any of this fails, get it fixed and merged, then redo this testing


Forking the new series branch
=============================

You will find (e.g. with ``git describe`` when viewing the master branch) that
the master branch has a version with an odd number in the second field, e.g.
3.\ **7**\ .  The new series branch should be named one number higher than
this, making it an even number.  Thus, if master is currently 3.7, then the new
series will be 3.8 (and then master will become 3.9).

1. Make sure your repository and master branch are up to date
2. Checkout the master branch: ``git checkout master``
3. Create and check out the new series branch:
   ``git checkout -b cyrus-imapd-<series>``
4. Edit `docsrc/conf.py`.  Update all the versioning information to say that:

   - this is version `<series>.0-alpha0`
   - the current stable version is `<series>.0-alpha0` (i.e. this one)
   - the previous stable version is whatever the current stable version
     used to be
   - the latest development version is the next odd number up from what it used
     to be, as a `.0-alpha0` -- that is, if it used to be `3.7.something`,
     it is now `3.9.0-alpha0`.
   - (these are all lies right now, but they will become true as we go)
   - find `html_theme_options` and update the option that configures which
     branch to show for the build status badge to be this branch, not "master"
   - Also add a suitable entry to the `extlinks` table near the bottom of the
     file.

5. Update `docsrc/index.rst` to state that this is the stable version, not
   the development one.  It's easiest to just copy and update the text from the
   previous stable version of this file.
6. Add release notes infrastructure:

   a. Make the directories for the new series:
      ``mkdir -p docsrc/imap/download/release-notes/<series>/x``
      (note the `x`, it's important for some historical reason)
   b. Make the directories for the new dev version:
      ``mkdir -p docsrc/imap/download/release-notes/<dev>/x``
   c. Create `docsrc/imap/download/release-notes/<version>/index.rst`
      for each of these, with stub contents.  It's easiest to just
      copy and update from an older one.
   d. Add stub release notes for alpha0.  This will be a file called
      `docsrc/imap/download/release-notes/<series>/x/<series>.0-alpha0.rst`.
      If we've been doing dev snapshots from master, start by copying the
      release notes from the most recent one of those.  If we haven't, then
      you will be starting with a blank document, in which case it's easiest
      to copy the release notes file from the previous major release, delete
      all the bullet points (leaving just the headings), and fix all the
      numbers.

7. Update `README.md`:

   - It will be claiming to be the development version, but this is now (or
     will be) the stable version, so update that.  If in doubt, mimic what
     the old stable branch's copy says.  This is another set of lies that will
     become true as we go.
   - Search through the whole document for version numbers, and update them
     sensibly for the future reality.  Do this mindfully, not with a batch
     find-replace.
   - The stable "build status" badge at the very top should reference the real
     stable version for now.  This gets shown on GitHub rather than our own
     site, so it can't lie.
   - This is also a good time for a careful review of the contents of this
     file.  Fix anything that's out of date, missing, etc.

8. Make sure your RST changes are good:  ``make doc-html``.  Pay attention
   to any errors or warnings (they will be coloured).  There will be some
   you can clearly ignore, such as glob patterns for future release notes
   that don't exist yet, but do your best to deal with everything else.
   The generated documentation will be under the `doc/html/` directory --
   examine it in your browser to make sure all your formatting and such makes
   sense.
9. XXX maybe missing some stuff here still?

You can double check your work by looking at what changed last time a new
stable series was forked:
``git show --format=fuller cyrus-imapd-<oldstable>.0-alpha0``.
Also look a few commits forward, in case the previous releaser
missed steps before tagging, and had to catch them up later.

Once you're satisfied that you've done everything that needed doing here:

1. Commit all these changes.  A single commit is good, we would like this to
   be the very first commit after the fork point.
2. Create a signed, annotated tag declaring that this is now alpha0 of the .0
   release of the new series:
   ``git tag -s cyrus-imapd-<series>.0-alpha0``
3. You will be prompted to enter a commit message for the tag (this is
   what makes it an "annotated" tag).  Ellie uses something like "not a real
   release, but need a tag for versioning".
4. You will also be prompted to enter the pass phrase for your GPG key, do it.
5. Push the new branch: ``git push ci cyrus-imapd-<series>`` (assuming your
   remote is named "ci")
6. Push the new tag: ``git push ci cyrus-imapd-<series>.0-alpha0``

Fastmail specific: also push the new branch and tag to the Fastmail repo.

Updating the master branch
==========================

You now need to make similar, but not identical, changes to the master branch,
too.

1. Check out the master branch: ``git checkout master``
2. Edit `docsrc/conf.py`: Make all the same changes as you did before, except
   that:

   - version and release should reflect that this is the development version,
     not the new stable version
   - XXX anything else?

3. Create the release notes directories and populate their stub index files.
   Note that in this case you're doing both the new series stubs, and the new
   dev series stubs.  You need to do both, because someday this will be a
   stable version, and the website will need all the historical release notes.
4. Remove all files except the template from `changes/next/`. These will be
   new features in the new release, which means they're no longer new on the
   master branch.  An exception is if there are changes currently on master
   that will be reverted from the new branch after forking -- in that case,
   don't delete those changes files from master.  More on this later.
5. Update `README.md`.
6. XXX probably steps missing here too
7. Make sure the RST changes are good: ``make doc-html``, pay attention
   to errors and warnings.

You may think you can do this by cherry-picking your commit from the new
release branch and then amending it with the dev version differences... and you
can, but do so very cautiously, because the differences between these branches
are important.

You can double check your work by looking at what changed *on master* last time
a new series forked.  As before, look a few commits ahead too, in case the
previous releaser missed steps before tagging.

Once you're satisfied that you've done everything that needed doing here:

1. Commit all these changes.  A single commit is good, we would like this to
   be the very first commit after the fork point.
2. Create a signed, annotated tag declaring that this is now alpha0 of the .0
   "release" of the new development version:
   ``git tag -s cyrus-imapd-<dev>.0-alpha0``
3. You will be prompted to enter a commit message for the tag (this is
   what makes it an "annotated" tag).  Ellie uses something like "not a real
   release, but need a tag for versioning".
4. You will also be prompted to enter the pass phrase for your GPG key, do it.
5. Push the new commit
6. Push the new tag: ``git push ci cyrus-imapd-<dev>.0-alpha0``

**Once this step is done, the feature freeze can end.**

Fastmail specific: also push the updated master branch and new tag to the
Fastmail repo.  This ensures our builds will also start using the new version
number once they update past the fork point.

Github updates
==============

On Github, have a look at the branch protection settings that apply to the
current stable branch.  Apply the same protections to the new branch.

Create labels for the new series and new dev series.  Give them pleasant
colours and sensible descriptions.

- <series>
- backport-to-<series>
- <dev>

Also update the description of the label for the old master version number.

Revert anything that's not yet ready
====================================

If there are commits on master that need to remain on master, but are not
yet ready for release for some reason, this is a good point to revert those
commits on the new branch only.  Any `changes/next` files from these commits
should remain on master, or be copied back to master if they were accidentally
deleted earlier.

This doesn't and shouldn't happen often.

Tell the website builder about the new branch
=============================================

The website is automatically rebuilt by a script, which needs to be updated
to know about the new series.

1. Clone ``git@github.com:cyrusimap/cyrusimap.org.git``, or ensure the clone
   you already have is up to date
2. Update `run-gp.sh` to know about the new version.  You'll need to add code
   in several places, but it's pretty self-explanatory once you look at it.
   For the time being, do NOT change which version `$target` and
   `$target/stable` are rsync'd from.  We'll change these later, once the real
   release has been published.  In the meantime, we want the top level and
   stable sections to continue to be built from the existing stable branch.
3. You can check your work by comparing your changes to previous commits
4. Commit and push your changes.  The system that runs this script fetches
   changes automatically before running it, so the next run to start will
   use the updated version.  It starts approximately on the hour, and can
   take ~15 minutes if there are large changes, such as adding a whole new
   branch...
5. You should now be able to access a version of the website built from the
   new branch at `https://www.cyrusimap.org/<version>/`.  Check that in your
   browser, make sure it reports the correct new versions.
6. You should also see a new "automatic commit" from "cyrusdocgen" on
   https://github.com/cyrusimap/cyrusimap.github.io -- that's the result of
   the run-gp.sh script having run.

First beta
==========

This work mostly happens on the new branch.

1. Check through `lib/imapoptions` for options with `"UNRELEASED"` in any of
   their version fields.

   - Replace these with the version number of the eventual actual (non-beta)
     release.  For example, if we're starting the 3.8 series, this will be
     "3.8.0".  That is to say, the first real release that these changes will
     appear in.
   - If any have been missed, there will be warnings (in yellow) when trying
     to (re)generate `lib/imapopts.c`.  You can run
     ``touch lib/imapoptions && make lib/imapopts.c`` to check
   - Commit this change, and also cherry-pick it onto `master`.

2. Copy the stub release notes that you made for `<series>.0-alpha0` into a new
   document for `<series>.0-beta1`.
3. Review the contents of all the `changes/next/*` files.  Flesh out the new
   release notes document accordingly.  (Compare previous `...-beta1` release
   notes to get a sense of the tone and level of detail.)
4. Review `docsrc/imap/download/upgrade.rst`, also with reference to the
   `changes/next/*` files.  Make any necessary updates.  We expect people
   upgrading to the new version to follow these instructions, so they'd better
   be as complete and correct as we can get them.
5. Review `docsrc/imap/rfc-support.rst`, also with reference to the
   `changes/next/*` files, and make any necessary updates.  Also compare this
   file with the version of it on the stable branch.  Check for any changes
   that don't have an accompanying `changes/next` file, and if there are any,
   also add suitable release notes and/or upgrade documentation for those.
6. Check your RST changes: ``make doc-html``
7. Once the documentation updates have been finalised, the `changes/next/*`
   files (except for the template) should be removed -- they are no longer
   changes.  The history is a bit easier to read later if you commit the
   doc updates and the removal of the changes files in the same commit.
8. Follow the :ref:`imap-developer-releasing` instructions to get
   `cyrus-imapd-<series>.0-beta1` released.

Subsequent betas
================

Monitor Github and the mailing lists for bug reports against the previous beta.
Make fixes against master, then backport them to the new series branch.

Periodically make new beta releases, as bugs are found and fixed.

Remember that until the real release is really released, the release notes
contain the changes since the previous *stable* version.  This means each of
the betas will start with copying the previous beta's release notes and
adding any new details, without removing what was already there.

Release candidates
==================

After a while, the flow of bug reports and fixes will dry up, and so we start
cutting "release candidates" instead.  These are effectively identical to
betas, except we call them -rc1, -rc2, etc instead.  The change in name
reflects our increased confidence in the software and documentation.

Release
=======

Oh boy, we've come a long way, haven't we!

For this one, we've got a little more housekeeping to do.

1. Follow the :ref:`imap-developer-releasing` normal release process as
   previous, again copy-and-updating the release notes from the last release
   candidate, except this time you're actually doing `<series>.0`, with no
   alpha, beta, or rc qualifiers.  Don't send the announcement email just
   yet though.
2. Remember how we lied about the new version being the stable release?
   We only did that on the new branch and master, though.  `docsrc/conf.py`
   on each of the existing branches will still be announcing old version
   numbers in the "rst_prolog" section.  Go through the old branches and
   update each's `docsrc/conf.py` to contain the same lie.  Commit and push
   these as you go.
3. Remember the `run-gp.sh` script from the cyrusimap.org repository?  Go and
   move the ``rsync ... $target`` and ``rsync ... $target/stable`` lines from
   the block for what is now the previous stable release, into the block for
   the new version (don't forget to update the numbers embedded in these lines
   too).  Once this is pushed, the next website rebuild will make it all true.
4. Once the website is fully updated, send that announcement email.

Post-release
============

From now on, just follow the normal release process to make point releases.
Release notes for point releases describe the difference between this point
release and the previous, and are much more specific than those of major
releases.

