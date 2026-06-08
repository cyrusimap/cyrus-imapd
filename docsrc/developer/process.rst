.. _devprocess:

===================
Development process
===================

Our goal is to, while we work, always increase the maintainability of Cyrus's
code.  That means clear code, useful tests, consistent style, and
well-specified intents.  Our processes should push us toward those goals.  As
an open source project, we have most of our process visible to the world.  This
should let you see more or less what we're doing, but it should also make it
easy for newcomers to participate with clear expectations.

Before you begin
================

The great majority of contribution to Cyrus IMAP comes from dedicated, paid
programmers who work mostly on Cyrus.  Their focus is supporting their
employer's needs.  That's the lens through which your contribution is likely to
be read:  will it make the overall system easier or harder to keep working as
they need.

Before embarking on any major changes, contact the team via the :ref:`mailing
lists <feedback-mailing-lists>` to talk about what you have in mind.  For
smaller things, especially bug fixes, a pull request on GitHub might be the
best way to propose the change.

The team holds a mostly-weekly team meeting :ref:`online via Zoom
<feedback-meetings>`.

The :ref:`mailing lists <support>` are used to discuss or announce upcoming or
ongoing changes and releases.

From a PR to a merge
====================

Most changes to Cyrus begin as GitHub pull requests, filed either by members of
the Cyrus team or by outside contributors.  Everything gets reviewed before
merge by at least one member of the core team.  They review looking for
correctness, but they also look at whether the change is going to complicate
future maintenance.  Review assignments are made by the core team: if you're
part of the team, assign your own PR for review.  Otherwise, wait for the team
to pick it up.

The Cyrus core team reviews new pull requests regularly, but sometimes there's
a bit of a backlog, or things slip through the cracks.  If you haven't heard
back in two weeks, consider contacting us on the ``cyrus-devel`` :ref:`mailing
list <support>`.

Pull requests are automatically tested against the test suites, address
sanitizer, and other checks.  PRs with failing tests won't be merged.  PR that
make changes without matching test changes will face close scrutiny.

The release cycle
=================

We release a new major version about once a year.  We release these when we
believe that all the new features work correctly and there are no known
regressions, other than those we've documented as intentional.  These versions
are numbered vX.Y.0, where Y is even.

We release new minor version for major releases once in a while, when we've
built up enough backported bugfixes, or when we've been waiting long enough to
ship the ones we've already applied.  There are numbered vX.Y.Z, where Y is
even and Z is nonzero.

We release a new development snapshot of Cyrus about once a month. While we
won't make a release that doesn't compile, all other bets are off.  If we
discover a critical security problem in a development snapshot, we'll just
merge the fix when it's ready.  Running these in production is your liability
to worry about.  These versions are numbered vX.Y.Z, where Y is odd.

The *macro* part of the version number -- the X in vX.Y.Z -- is updated to
signify larger changes than the major version, but otherwise carries no
particular meaning.  We make these at our discretion.  You should think of them
as major versions that might includer larger new features or a more complex
upgrade than usual.

We stop releasing minor versions for major versions after two years.  While we
*might* push bugfixes for significant problems to the git branch for an old
major release, we won't undertake a new release.  If you're running an old
version of Cyrus, it's up to you (or your package manager) to track and package
new patches.

If we discover a security vulnerability in a non-development-snapshot version
of Cyrus, we practice responsible disclosure.  We produce a fix, then inform
downstream package mangers of that fix.  The fix comes with an embargo date so
it can be released publicly at the same time that updated packages become
available.  In general, we do not pursue security fixes for major versions of
Cyrus over three years old. There may be exceptions to this, but generally you
should try to run a recent release.
