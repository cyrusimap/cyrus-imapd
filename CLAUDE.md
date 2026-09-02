
These are instructions for Claude for work in the "cyrus-imapd" repository.

# Development environment

The "dar" executable is the tool to manage development environments for code
located in the "cyrus-imapd" repository. All builds and tests must happen
in the Docker container managed by "dar" for the current branch or worktree.
The reference architecture is Linux, not macOS.  For basic instructions on
development with this system, consult docsrc/developer/overview.rst

When performing a first-time build, use `dar build -b`. The "b" switch tells dar
to build with the "bear" command in the container, to generate the
`compile_commands.json` file to use with clang tools.

To perform an increment rebuild, use `dar build -nr`.  The "r" switch tells dar
to build incrementally, the "n" switch tells it to skip running the cunit
tests.  Of course, if your task involves running a cunit test, you must omit
the "n" switch.  Omit the "b" switch or you will truncate the
`compile_commands.json` file.

# Testing

The project has some unit tests, located in the "cunit" directory, but the
majority of tests are in the "cassandane" directory.

These are documented, respectively, in:

* docsrc/developer/cassandane.rst
* docsrc/developer/cunit.rst

The "dar test" command allows running the full Cassandane test suite, but a
typical workflow will involve only running some tests.  You can run a single
test suite by naming that test suite in the "dar test" command.  To run the
"Simple" test suite call "dar test Simple".  You can run a single test in a
suite by naming that test suite and test name in the "dar test", e.g. to run
the "append" test in the "Simple" suite call
"dar test Simple.append".  For more on arguments you can pass, consult
`cassandane/testrunner.pl`, to which "dar test" delegates.

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

The project documentation is managed by Sphinx, and found mostly in the docsrc
directory.  C files are documented with Doxygen.  Perl programs and modules are
documented with Pod.  Write documentation, which should be very concise.  When
writing pages for the Sphinx site, favor Markdown over reStructuredText.  Your
audience is generally "experts who need a quick refresher or to be reminded of
exact semantics".

To build the documentation, you can use dar and run `dar makedocs`.

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
