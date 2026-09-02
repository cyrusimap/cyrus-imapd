
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

First, consult docsrc/developer/cassandane.rst

Sometimes, a test is best expressed as a set of variations to be tested, rather
than a single test scenario.  In these cases, build specialized assertion
methods that test a described variant, then install one test method for each
variant.

Conventionally, in multi-variant tests, the assertion method should be named
`assert_{testname}` where "testname" is the name of the file.  This assertion method
then can get called from multiple test methods in that same file, where each
method is named `test_{testname}__{variant}`, where "variant" is some short but
human-readable summary of what this scenario is all about.  Note the *double*
underscores between the test name and the variant name. The "test_" prefix
tells Cassandane that this method is a test.

When appropriate, prefer `assert_cmp_deeply` over `assert_deep_equals` or
multiple simple assertions.  For JMAP tests, use the Cassandane::JMAPTester and
Cassandane::TestEntity packages and subpackages.  In general, when creating
test data, prefer the TestEntity system over explicit JMAP calls.  On the other
hand, do not rely on the specific JMAP default values created by TestEntity methods.  If the
test requires careful control of the JMAP method calls made, make them with
`->request`.

To compare iCalendar data, use `vcard2hash` from Text::VCardFast.  While their
name suggests they are about VCard, they are also adequate for iCalendar data.
That way your tests do not need to use string matching in Perl which could
break if the iCalendar data contains continuation lines.

Lastly, many older Cassandane tests have version-bounding annotations like
`min_version_3`.  Do not use these version annotations, even if you copy from
nearby tests that use them.

# Coding style

Two automated lints will reject source that builds and tests perfectly well:
no hard tabs, and no "FIXME" markers.  Both cover C, header, Perl and reST
files; docsrc/developer/process.rst has the exact rules and how to run them.
Say what you would have marked FIXME in an ordinary comment, or leave it out.

When you write C code in this project then the following general rules apply:

- When you edit existing C code and the code change does not create a new block
  scope (e.g. it's not starting with curly braces), then try to emulate the
  code style of the existing code snippet to reduce git diff noise.

- When you edit C code and the code change does introduce a new block scope or
  a new function or the like, then use clang-format using the ".clang-format"
  file to format that code.

- When you define new variables with boolean semantics, use `bool` instead of
  `int`. Generally prefer to use C23 constructs over older C language
  revisions.  For C++, use revision C++17.

- When you declare new variables, try to keep the variable scope to the most
  inner scope, e.g. a `size_t i` iterator for a for loop should be declared in
  the initializer of the for loop like `for (size_t i = 0;`.

- When you write new logging messages in the code, you must use the
  `xsyslog_ev` function.  Consult doc/README.logfmt.md for more information.

When you write Perl code in this project then the following general rules
apply:

- Target Perl v5.28 and use its features freely: postfix dereference,
  subroutine signatures, and lexical subroutines can be especially helpful for
  clarity.

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

To build the documentation, you can use dar and run `dar makedocs`.

## Where to look things up

docsrc/developer/index.rst is the table of contents for the developer docs, and
names every page in it by path.  Beyond the pages already cited above:

**Getting oriented**

- `docsrc/developer/quickstart.rst` -- the shortest path from a checkout to a
  passing test, and the conventions for writing one
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
  `var_directory_structure.rst`, `namespaces.rst`, and `hacking.rst`, which is
  where the xmalloc family and the strlcpy/memcpy conventions are written down
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

## Commit messages

Write for whoever lands on this from `git blame` in a year, asking what the
point of the change was. They will have the commit message and nothing else;
the reviewer has the PR description, the branch and the diff as well.  Your
audience is not the human guiding a coding session -- talk to that person via
the primary interface.

- Use an imperative subject line that names the outcome or goal. Prefix with
  the primary file edited. "jmap_tasklist.c: implement priority sort",
  "README.md: add cross-reference to security policy".
- Explain *why*, not *what*. The diff already shows what changed. Don't
  enumerate the literal file-by-file changes.  Don't provide egregious counting
  of entities changed.
- Most commits want a subject and one to three sentences.
- Earn any extra length.  Longer messages are justified by things the reader
  can't see from the diff alone, a trap they'd fall into again, a constraint
  that forced an odd shape, a deliberate limitation or a rejected alternative
  they'd otherwise wonder about.
- Walk it through as "Currently X… however that's a problem because Y… so we
  have chosen to do Z".
- Write in a relaxed, concise, first-person voice. It's fine to say "let's"
  or admit something is "a bit hacky".
- Deployment requirements belongs in the PR description, not here.  That will
  matter for about a week, and the reader you're writing for arrives long after
  it stopped being true.
- Don't defend every decision you made. If the reviewer would have made the
  same choice, it doesn't need a paragraph — the code describes the choices.
- Back up performance or behavioural claims with concrete evidence when you
  have it, such as before/after timings, an strace excerpt, sample output.
  That's different from reporting your work — which tests pass, what you
  verified, what you couldn't check. That's for the PR, if anywhere.
- Cite a commit by hash only once it's on upstream master, where it stays put
  and gives the reader a direct pointer. Never cite one from the branch under
  development, as the branch is extremely likely to be rebased during merge, so
  any referenced hash will become invalid.

## General Style Rules

- Do not anthropomorphize inanimate or abstract entities. Verbs like "speak",
  "answer", "scrutinize" almost always are wrong, unless they actually refer
  to human activity.
