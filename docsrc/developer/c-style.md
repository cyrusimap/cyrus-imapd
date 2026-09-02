# C style

Cyrus is thirty years of C by many hands, so the tree is not uniformly styled.
The rules below are what we're converging on.

## clang-format is the arbiter

The repository has a `.clang-format` at its root, and it is the definition of
our C style.  Good practice is:

- **New code gets formatted.** A new function, a new file, or an edit that
  introduces a block scope of its own: run `clang-format` over what you added.
- **Edits inside existing code match their surroundings.** If you're changing a
  line or two inside a function that predates the config, follow the local
  style even where it differs from `.clang-format`. A three-line fix should
  produce a three-line diff.

If you want to reformat a file wholesale, that might be fine, but make it a
commit of its own that changes nothing else, so that reviewers and `git blame`
can skip straight over it.

## Conventions clang-format can't express

`.clang-format` settles layout. These are the habits it can't check:

- **Declare variables in the innermost scope that needs them.** A loop counter
  belongs in the loop: `for (size_t i = 0; ...)`.
- **Use `bool` for things that are boolean**, not `int`. Include
  `<stdbool.h>`; the build does not currently request a C standard that gives
  you `bool` for free.
- **C++ is C++17**, requested by `configure.ac`. C is whatever the compiler
  defaults to, which on our reference image is C17 — so C23-only constructs
  will not build.
- **Allocate through the libcyrus wrappers** — `xmalloc`, `xzmalloc`,
  `xrealloc`, `xstrdup`, `xstrndup` — which call `fatal()` on failure so
  callers don't each have to. `struct buf` and `strarray` exist so that most
  code needn't hand-manage strings at all.
- **`strlcpy` when you know the buffer size, `memcpy` when you're deliberately
  truncating.** Avoid `strncpy`: it's slower than `memcpy` and less safe than
  `strlcpy`, and its behaviour surprises people.
- **Log with `xsyslog_ev()`**, not `syslog()`. Structured logging has its own
  rulebook in `doc/README.logfmt.md`, and the key vocabulary is enforced by a
  lint at build time.

Two automated checks reject source on grounds of what it contains rather than
what it does — no hard tabs, and no fix-me markers. Both are described under
{ref}`the development process <devprocess>`.

Some older conventions worth knowing, because you'll meet them: command-line
tools link `cli_fatal.o` so they all fail the same way; a call to
`cyrus_init()` must be paired with `cyrus_done()`; and services exit through
`shut_down()` and nowhere else. {ref}`The hacking notes
<imap-developer-guidance-hacking>` have more in this vein, though that page is
old enough that you should check it against the code. Where its spacing rules
disagree with `.clang-format` — it predates the config, and calls for mixed
tabs and spaces — `.clang-format` wins.
