# Contributing to Cyrus

So, you want to contribute to Cyrus?  Great!

You'll probably want to join the [cyrus-devel mailing
list](https://www.cyrusimap.org/imap/support/feedback-mailing-lists.html#feedback-mailing-lists)
where development issues get discussed.  You don't need to, but if you're
considering doing a substantial amount of work, it's a good idea to ask about
it first.

This document is meant to be a quick overview of the most important things you
need to know to get your work reviewed, approved, and into Cyrus.

## Your Code

Cyrus doesn't have a hard and fast style guide, *but it will*.  For now,
consult the [Cyrus hacking
docs](https://www.cyrusimap.org/imap/developer/guidance/hacking.html), which
spell out some of the standards of formatting and construction.  This document
is, at present, quite out of date.  You are probably best served by just
copying the style of the surrounding code.

The repostitory contains a `.clang-format` file that reflects our preferred
style.  This isn't applied automatically, and existing files are not already in
that style -- so it's not a silver bullet for styling.  But it might help.

## The Tests

You should run the tests.  Submitting a change that breaks existing tests isn't
good for anybody!  If your pull request changes the code but doesn't add a
test, you should explain why.  "Code changes add tests" is the default
assumption.

There are two kinds of tests:

* The [Cassandane test
  suite](https://www.cyrusimap.org/imap/developer/developer-testing.html) is an
  integration test suite.  It can and should be run against your build of
  Cyrus, and it's right there in the repo under `./cassandane`.
* The [cunit tests](https://www.cyrusimap.org/imap/developer/unit-tests.html)
  are located in the Cyrus IMAP repository, in `./cunit` and run by `make
  check`.  You should run these, too.

The simplest way to run these is by using the `dar` tool along with
`cyrus-docker`.  You can read more about those in the [Cyrus IMAP Developer
Guide](https://www.cyrusimap.org/dev/imap/developer/overview.html).

## Submitting Your Work

We use GitHub, including pull requests.  Submit a pull request.  One of the
committers should review it soon.  If they don't, the best place to ask for
a review is the cyrus-devel mailing list, mentioned above.

Remember to sign your commits.  This just means that they should be made with
`git commit --signoff`.  More importantly, it is how you certify the [Developer
Certificate of Origin](https://developercertificate.org/), which states your
assertion that you have the legal right to submit your code to Cyrus for
redistribution as part of Cyrus.

**All code is reviewed before merge.**  This includes code submitted by
committers.  This means that if you want to know what awaits you in code
review, you can look at some recently merged or closed pull requests.

## Cyrus Versioning and Bugfix Policy

Cyrus is free software that comes with no guarantees, but we try to fix bugs
when they're found.  The policy on that is something like this:

* We release a new **development snapshot** of Cyrus about once a month.  While
  we won't make a release that doesn't *compile*, all other bets are off.  If
  we discover a critical security problem in a development snapshot, we'll just
  merge the fix when it's ready.  Running these in production is *your*
  liability to worry about.  These versions are numbered vX.Y.Z, where Y is
  odd.
* We release a **new minor version** about once a year.  We release these when
  we believe that all the new features work correctly and there are no known
  regressions, other than those we've documented as intentional.  These
  versions are numbered vX.Y.0, where Y is even.
* We release **new micro version** for minor releases once in a while, when
  we've built up enough backported bugfixes, or when we've been waiting long
  enough to ship the ones we've already applied.  There are numbered vX.Y.Z,
  where Y is even and Z is nonzero.

The "macro" part of the version number -- the X in vX.Y.Z -- is updated to
signify larger changes than the minor version, but otherwise carries no
particular meaning.

We stop releasing micro releases for minor releases after two years.  While we
might push bugfixes for significant problems to the git branch for an old minor
release, we won't undertake a new release.  If you're running an old version of
Cyrus, it's up to you (or your package manager) to track and package new
patches.

If we discover a security vulnerability in a non-development-snapshot version
of Cyrus, we practice responsible disclosure.  We produce a fix, then inform
downstream package mangers of that fix, with an embargo date so that the fix
can be released publicly at the same time that updated packages become
available.  In general, we do not pursue security fixes for minor versions of
Cyrus over three years old.  There may be exceptions to this, but generally you
should try to run a recent stable release.
