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

Content linters
---------------

Two of those checks are about what the source *contains* rather than what it
does, so they can fail a PR that builds and tests perfectly well.  They live in
``tools/``, run on every push and pull request, and you can easily run them
locally.

``tools/hard-tab-tool``
    Fails if a file contains a hard tab.  Run it with no arguments to check the
    whole tree, or pass paths to check part of it.  With ``--really`` it fixes
    the files instead of listing them, expanding each tab to the next
    eight-column stop.

``tools/find-fixme-markers``
    Fails if a file contains a FIXME marker.  A "FIXME" that lives in the tree
    forever isn't a reminder, it's noise.  If you want to flag unfinished
    business, file an issue.  A file that genuinely has to contain the word can
    be listed in ``.fixme_ignore``.

Describing your change for the release notes
--------------------------------------------

Changes significant enough to appear in the release notes for the next version
need an entry in ``changes/next/``.  That means a new feature, a removed
feature, changes to configuration options, things requiring pre-upgrade action,
and so on.  The release manager will assemble the release notes from those
entries, so missing these can put future upgraders in a bad situation.

Add a file, named after your branch, using ``changes/next/0000-TEMPLATE`` as
the template -- it lists the fields and explains what each is for.  In short: a
one-line description for the release notes, where the full documentation lives,
any ``lib/imapoptions`` changes, what an admin has to *do* when upgrading, and
the GitHub issue if there is one.

Pure refactoring, test-only changes, and internal cleanups don't need an entry.
If you're unsure, write one: a needless entry costs the release manager a
moment's deletion, and a missing one costs an operator a surprise.

Commit messages
---------------

Write for whoever arrives from ``git blame`` in a year asking what the point of
the change was.  They have the commit message and nothing else: the reviewer
had the PR description, the branch and the diff, but this reader has none of
them.

* Use an imperative subject line that names the outcome, prefixed with the
  primary file or component edited: ``jmap_tasklist.c: implement priority
  sort``, ``README.md: add cross-reference to security policy``.
* Explain *why*, not *what*.  The diff already shows what changed; don't
  enumerate it file by file.
* Most commits want a subject and one to three sentences.
* Earn any extra length.  A longer message is justified by things the reader
  can't get from the diff: a trap they'd fall into again, a constraint that
  forced an odd shape, a deliberate limitation, or an alternative you rejected
  and they'd otherwise wonder about.
* "Currently X, however that's a problem because Y, so we've chosen to do Z" is
  a good shape when you're not sure how to begin.
* A relaxed, concise, first-person voice is right.  It's fine to say "let's",
  and fine to admit that something is a bit hacky.
* Back a performance or behavioral claim with concrete evidence when you have
  it: before-and-after timings, an strace excerpt, sample output.
* Cite a commit by hash only once it's on upstream master, where it stays put.
  A hash from the branch under development won't survive the rebase that lands
  it.

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

We generally don't release minor versions for major versions other than the
current stable one.  That is, once 3.14.0 is released, there may not be further
3.12.x releases.  In practice, we *sometimes* push bugfixes for significant
problems to the git branch for an old major release, and *might* make a minor
version to ship security updates.  Really, though, if you're running an old
version of Cyrus, it's up to you (or your package manager) to track and package
new patches.

If we discover a security vulnerability in a non-development-snapshot version
of Cyrus, we practice responsible disclosure.  We produce a fix, then inform
downstream package mangers of that fix.  The fix comes with an embargo date so
it can be released publicly at the same time that updated packages become
available.  In general, we do not pursue security fixes for major versions of
Cyrus over one year old.  There may be exceptions to this, but generally you
should try to run a recent release.
