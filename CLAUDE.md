
These are instructions for Claude for work in the "cyrus-imapd" repository.

# Development environment

The "dar" executable is the tool to manage development environments for code
located in the "cyrus-imapd" repository. All builds and tests must happen
in the Docker container managed by "dar" for the current branch or worktree.
The reference architecture is Linux.  For basic instructions on
development with this system, consult docsrc/developer/overview.rst

Every dar subcommand documents itself.  Run `dar help build`, `dar help test`,
and so on to get the switches.  `dar help build` also names the reference build
configuration, which is the set of ./configure options used both for
development and for CI.

Two combinations are worth knowing up front.  For a first-time build, use `dar
build -b`, which builds under the "bear" command so that clang tools have a
`compile_commands.json` to read.  To rebuild, use `dar build -nr`, and omit the
"b" switch: bear records only what it compiles, so running it over an
incremental build truncates `compile_commands.json` to the few files that were
rebuilt.

# Testing

The project has some unit tests, located in the "cunit" directory, but the
majority of tests are in the "cassandane" directory.

These are documented, respectively, in:

* docsrc/developer/cassandane.rst
* docsrc/developer/cunit.rst

The "dar test" command runs Cassandane tests, and with no arguments runs all of
them, which is rarely what you want.  Name a suite to run just that suite (`dar
test Simple`), or a suite and a test to run one test (`dar test
Simple.append`).  The rest of the grammar -- several suites at once, negation --
is in docsrc/developer/cassandane.rst, and `dar help test` lists the switches
that dar exposes.  "dar test" delegates to `cassandane/testrunner.pl`, whose
own `--help` is the authoritative option list if you need something dar doesn't
pass through.

## How to write Cassandane tests

First, consult docsrc/developer/cassandane.rst.  It covers the shape of a
tiny-test, the test attributes, the object model, the assertions, the
multi-variant convention, and how to compare iCalendar and vCard data.

Beyond what's written there:

- When appropriate, prefer `assert_cmp_deeply` over `assert_deep_equals` or
  multiple simple assertions.
- For JMAP tests, use the Cassandane::JMAPTester and Cassandane::TestEntity
  packages and subpackages.
- Many older Cassandane tests have version-bounding annotations like
  `min_version_3`.  Don't add them, even though you'll copy from nearby tests
  that have them.  The exception is the one cassandane.rst names: a test that
  runs against an older or external Cyrus, such as a replication test, still
  needs its guard.

# Coding style

Two automated lints will reject source that builds and tests perfectly well:
no hard tabs, and no "FIXME" markers.  Both cover C, header, Perl and reST
files; docsrc/developer/process.rst has the exact rules and how to run them.
Say what you would have marked FIXME in an ordinary comment, or leave it out.

C style is defined by the `.clang-format` file at the repository root and
described in docsrc/developer/c-style.md, which covers when to reformat and
when to match the surrounding code, the memory and string conventions, and the
logging requirement.  Read it before writing C.  The rules most easily got
wrong:

- Format new code with clang-format.  For a small edit inside older code,
  match the local style instead -- a three-line fix should be a three-line
  diff.
- Use `bool` for boolean variables, including `<stdbool.h>` where it isn't
  already included.  Don't use C23-only constructs: `configure.ac` doesn't
  request a C standard, so C compiles at the compiler's default, which is C17
  on the reference image.  C++ is C++17.
- Declare a variable in the innermost scope that needs it, e.g. `for (size_t i
  = 0;`.
- Log with `xsyslog_ev`, never `syslog`.  See doc/README.logfmt.md.

When you write Perl code in this project then the following general rules
apply:

- Target Perl v5.28 and use its features freely: postfix dereference,
  subroutine signatures, and lexical subroutines can be especially helpful for
  clarity.

# Landing a change

Changes significant enough to appear in the release notes for the next version
should get an entry in `changes/next/`, in a file named after the branch.
docsrc/developer/process.rst explains the fields and which changes are exempt,
and also covers how a PR gets reviewed and what the automated checks will
reject.

## Commit messages

The conventions are in docsrc/developer/process.rst.  Follow them.  These
additional rules are for you specifically, and are not in that document:

- Your audience is not the human guiding a coding session.  Talk to that person
  via the primary interface, not the commit message.
- Don't provide egregious counting of entities changed.
- Don't defend every decision you made.  If the reviewer would have made the
  same choice, it doesn't need a paragraph -- the code describes the choices.
- Evidence for a claim belongs in the message.  A report of your work -- which
  tests pass, what you verified, what you couldn't check -- does not.  That's
  for the PR, if anywhere.

# Documentation

The project documentation is a Sphinx site built from three sources: the pages
under docsrc, Doxygen comments in C headers, and Pod in Perl programs and
modules.

Work from those source files, not from the built site.  The site is a
convenience for human readers and it isn't checked in, so in a clone you can
only read the source files.  They have all the actual content, though!  One
consequence: cross-references appear as `:ref:` labels rather than links, and
you resolve one by grepping docsrc for the label.

Doxygen coverage is currently an aspiration.  The Doxyfile reads only headers
under imap, lib, and sieve, almost none of them carry Doxygen comments yet.  We
want that to grow, so give new and edited C headers Doxygen comments even
though the neighbouring declarations have none.

Write documentation, which should be very concise.  When writing pages for the
Sphinx site, favor Markdown over reStructuredText.  Your audience is generally
"experts who need a quick refresher or to be reminded of exact semantics".

To build the documentation, you can use dar and run `dar makedocs`.  The build
is nitpicky and treats warnings as errors, so a dangling cross-reference fails
it, and a clean run means CI will be clean too.

docsrc/developer/documentation.rst covers the source formats, the custom roles,
and which pages under docsrc are generated rather than written.

## Where to look things up

docsrc/developer/index.rst is the table of contents for the developer docs, and
names every page in it by path.  Beyond the pages already cited above:

**Getting oriented**

- `docsrc/developer/quickstart.rst` -- the shortest path from a checkout to a
  passing test, and the conventions for writing one
- `docsrc/developer/source-tree.md` -- what's in each top-level directory, and
  what the four installed libraries are for
- `docsrc/developer/c-style.md` -- clang-format, the memory and string
  conventions, and the process startup and shutdown rules
- `docsrc/developer/process.rst` -- how a change gets reviewed and merged, and
  what the version numbers mean
- `docsrc/developer/documentation.rst` -- the Sphinx setup, the custom roles
  like `:rfc:` and `:cyrusman:`, and the man page conventions

**Internals**

- `docsrc/developer/API/` -- the mailbox, index and cyrusdb APIs
- `docsrc/developer/replication-protocol.md` and
  `docsrc/developer/annotator-protocol.md` -- both written as internal
  references for the Cyrus team
- `docsrc/developer/thoughts/` -- often the only description of a subsystem:
  `locking.rst`, `namelocks.rst`, `prot.rst` (the stdio replacement for network
  i/o), `bytecode.rst` (Sieve), `mailbox-format.rst`,
  `var_directory_structure.rst` and `namespaces.rst`
- `doc/README.cyrusdb.md`, `doc/README.twom.md`, `doc/README.zeroskip.md` --
  the key-value store interface, and two of its backends

**Protocols and standards**

- `docsrc/rfc-support.rst` -- what Cyrus implements and how completely.  Update
  it when that changes.
- `docsrc/reference/extensions/` -- Cyrus's own non-standard protocol
  extensions

**Conventions to check before landing a change**

- `lib/imapoptions/README.md` -- the format of an imapd.conf option definition
- `changes/next/0000-TEMPLATE` -- the release-note entry a user-visible change
  needs, and the fields it has to fill in
- `doc/README.logfmt.md` -- the rulebook for structured logging

The pages in docsrc/developer/thoughts and the cyrusdb pages under
docsrc/developer/API are often dated (bordering on abandoned).  Where they and
the code disagree, the code is right.

## Comments

- Keep inline comments in code as tight as possible, ideally 1-2 lines.  Longer
  comments are needed only for explaining complex or counter-intuitive code.
- Only comment what the code can't say itself.  Don't narrate what the code
  obviously does.
- Comments documenting how to use a function or module may be longer, as they
  will explain usage, calling conventions, contract, invariants, and so on.
- In general, comments should only explain the **current** code. Avoid
  explaining changes to prior implementation. That's what git history is for.

## General Style Rules

- Do not anthropomorphize inanimate or abstract entities. Verbs like "speak",
  "answer", "scrutinize" almost always are wrong, unless they actually refer
  to human activity.
