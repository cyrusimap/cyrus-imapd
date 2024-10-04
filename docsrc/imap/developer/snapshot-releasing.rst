.. _imap-developer-snapshot-releasing:

==========================================
Releasing Cyrus IMAP - developer snapshots
==========================================

.. contents::

These instructions describe the process of producing "developer snapshots"
from the master branch.  These are tag-only releases: no release tarball
is published.

For normal point releases, see :ref:`imap-developer-releasing`

We haven't been doing this much, or very consistently.  Consider this
document and process a work in progress, which we'll refine as we go.

You can look at the tag cyrus-imapd-3.3.1 and a few commits before it to
get a sense of the kind of things this process involves.

Prerequisites
=============

Same as for normal releases

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

Mixed-version Cassandane testing
================================

This is a good point to make sure that replication and murder setups can talk
to each other between versions.

1. Add `[cyrus murder]` and `[cyrus replica]` sections to your cassandane.ini
   and configure each with their own prefix, different from your
   `[cyrus default]` one. Check `cassandane/cassandane.ini.example` in the
   repository for examples with comments. Do the same for `[cyrus backup]` if
   you like -- it's not documented like the others, but it works the same way.
2. For each prefix you've configured, check out the Cyrus version you want to
   run there, do a from-scratch complete build with
   ``./configure --prefix=/the/prefix ...`` and install it
3. Do the same for your usual `[cyrus default]` prefix
4. Check out the version whose Cassandane you want to run. Rebuild Cassandane's
   binary components with ``make -C cassandane/utils``
5. Run Cassandane -- the Replication, MurderIMAP, and MurderJMAP suites are
   significant here, and the Backups suite if you configured `[cyrus backup]`.
6. Rinse and repeat for other combinations

You should do this in four combinations:

1. `[cyrus default]` built from master branch, others built from the current
   stable branch, and running Cassandane from the master branch
2. Same as 1, but running Cassandane from the current stable branch
3. `[cyrus default]` built from the current stable branch, others built from
   the master branch, and running Cassandane from the current stable branch
4. Same as 3, but running Cassandane from the master branch

lib/imapoptions
===============

I'm not sure about whether we want to do this step at each snapshot, or
save it for a big batch at the next major release.  The difference is
whether we conceptually treat these tags as releases of the feature or
not.

If we do do this:

Check through `lib/imapoptions` for options with `"UNRELEASED"` in any of
their version fields.

1. Replace these with the version number that this snapshot will be tagged
   as.
2. If any have been missed, there will be warnings (in yellow) when trying
   to (re)generate `lib/imapopts.c`.  You can run
   ``touch lib/imapoptions && make lib/imapopts.c`` to check

Release notes
=============

Snapshot release notes are like major x.y.0 release notes, in that they
contain a high-level overview of the new features/etc, but not a blow-by-blow
of every commit.  They describe the changes since the *last stable series*,
which means the release notes for each subsequent snapshot start as a copy
of the previous, and reset only when a new stable series forks.  The release
notes for the developer snapshots will form the starting point for the release
notes of the next major release.

Release notes live under ``docsrc/imap/download/release-notes/``.

1. Copy the release notes from the previous snapshot of this series into
   a new file for this snapshot.  If this is the first snapshot of the series,
   then copy the `<series>.0-alpha0` release notes instead.
2. Review the contents of all the `changes/next/*` files.  Flesh out the new
   release notes document accordingly.  (Compare previous `...-beta*` and
   `x.y.0` release notes to get a sense of the tone and level of detail.)
3. Review `docsrc/imap/download/upgrade.rst`, also with reference to the
   `changes/next/*` files.  Make any necessary updates.  We expect people
   upgrading to the new version to follow these instructions, so they'd better
   be as complete and correct as we can get them.
4. Review `docsrc/imap/rfc-support.rst`, also with reference to the
   `changes/next/*` files, and make any necessary updates.  Also compare this
   file with the version of it on the stable branch.  Check for any changes
   that don't have an accompanying `changes/next` file, and if there are any,
   also add suitable release notes and/or upgrade documentation for those.

Should the `changes/next` files be removed at this point? I'm not sure, we
have not done any snapshot releases since we started tracking changes like
that.  The major releasing process assumes that this all happens as a big
bang before the x.y.0, but if we return to doing regular snapshots, we can
distribute that load over the year.  If the `changes/next` files are removed
as they're integrated into a snapshot, that will be less confusing, but it
will be harder to do a holistic review later.  Maybe they can be moved
aside somewhere instead of removed, to `changes/<snapshot-version>` or
something...

docsrc/conf.py
==============

1. Update all the relevant version strings in `docsrc/conf.py`

check documentation
===================

1. Make sure your RST changes are good:  ``make doc-html``.  Pay attention
   to any errors or warnings (they will be coloured).  There will be some
   you can clearly ignore, such as glob patterns for future release notes
   that don't exist yet, but do your best to deal with everything else.
   The generated documentation will be under the `doc/html/` directory --
   examine it in your browser to make sure all your formatting and such makes
   sense.

PR and/or commit
================

Once you're satisfied that you've done everything that needed doing here,
commit the changes to a branch and submit a PR.  Historically we've usually
just made these changes directly on master, but since our workflow uses
PRs these days, let's try that.

Once the PR has been approved, rebase your branch on top of current master,
force-push it, and then "Merge" it through the GitHub UI.

Tag
===

You'll want to apply the tag to the merge commit where the PR landed.  Usually
this will be the head of master, but if there's been hang time between merging
the PR and starting this step, other merges might have snuck in on top of it.
That's fine, just be careful about which commit you're tagging.

1. Make sure your master branch is checked out, clean, and up to date
2. Create a signed, annotated tag declaring that this is now whatever version
   it is:
   ``git tag -s cyrus-imapd-<snapshot-version>``
3. You will be prompted to enter a commit message for the tag (this is
   what makes it an "annotated" tag).  Ellie uses something like
   "Developer release <version>".
4. You will also be prompted to enter the pass phrase for your GPG key, do it.
5. It's a good idea to do a full build-and-test of a release tarball at this
   point, just to make sure things are sane.  Throw the tarball away when
   you're done though, we don't publish it.
6. Push the new tag: ``git push ci cyrus-imapd-<snapshot-version>``

Fastmail specific: also push the new tag to the Fastmail repo.

Tell the world
==============

1. Send an announcement to the cyrus-devel list.

Update this document
====================

The process probably changed a little in practice.  Update this document to
match reality!
