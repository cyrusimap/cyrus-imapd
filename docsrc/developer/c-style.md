(developer-c-style)=

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
  code needn't hand-manage strings at all. For a great many small allocations
  that get freed together, the memory pool in `lib/mpool.h` is much faster,
  at the cost of holding everything until the pool goes.
- **`strlcpy` when you know the buffer size, `memcpy` when you're deliberately
  truncating.** Avoid `strncpy`: it's slower than `memcpy` and less safe than
  `strlcpy`, and its behaviour surprises people.
- **Map files with `map_refresh()` and `map_free()`** from `lib/map.h`, rather
  than `read()` and `lseek()`: it's our portable wrapper around `mmap()`, and
  reading a file this way is usually much faster. The maps are read-only, so
  write through ordinary file i/o — but open the descriptor `O_RDWR` anyway,
  because some platforms require that of anything they'll `mmap()`.
- **Log with `xsyslog_ev()`**, not `syslog()`. Structured logging has its own
  rulebook in {ref}`the logfmt page <developer-logfmt>`, and the key
  vocabulary is enforced by a
  lint at build time.

Two automated checks reject source on grounds of what it contains rather than
what it does — no hard tabs, and no fix-me markers. Both are described under
{ref}`the development process <devprocess>`.

## Process conventions

Long-standing rules about how a Cyrus program starts up and shuts down. They're
not enforced by anything, so they're easy to miss and annoying to debug.

- **A service exits through `shut_down()`, and nowhere else.** `fatal()` should
  try to call it too, with a recursion guard in case `shut_down()` is what
  broke. Command-line tools generally don't need one.
- **Command-line tools link `cli_fatal.o`**, so they all fail the same way,
  unless there's a good reason for one to be different.
- **`cyrus_init()` must be paired with `cyrus_done()`** before the process
  exits.
- **Nothing calls the cyrusdb `init()` or `done()` methods** except
  `libcyrus_init()`.
- **A tool that must run as the cyrus user should check that first**, before
  anything else, and `fatal()` if it isn't.
- **Return from `main()`**; don't call `exit()` at the bottom of it.
