This document describes how the zeroskip database backend is integrated into
Cyrus.  The on-disk format, the concurrency and durability protocol, and the
recovery rules are specified upstream in the zeroskip repository's
`doc/specification.md`, which is normative; this document does not restate it.

zeroskip is an append-only ordered key-value store.  Where twom and twoskip are
single mmaped files updated in place, a zeroskip database is a *directory* of
immutable and append-only files.  Nothing is ever written except by appending to
a file or by creating a new one, so readers take no lock at all and never block
the single writer, nor it them.

`lib/zeroskip.c` and `lib/zeroskip.h` are verbatim copies of the upstream
library and must stay that way.  Everything Cyrus-specific lives in
`lib/cyrusdb_zeroskip.c`.

## What being a directory changes

Most of the cyrusdb integration is a direct translation of the twom wrapper.
Four things are not, all because the database is a directory:

* **Detection.**  `cyrusdb_detect()` reads file magic for the other backends.
  For a directory it looks for an entry named `zeroskip*`, which matches both
  the data files (`zeroskip-<uuid>-<generation>` and the active
  `zeroskip-<uuid>.current`) and the `zeroskip.lock` file.  Matching the lock
  file too means a database that has been created but holds no data is still
  recognised.

* **Unlink.**  Removing a database means removing a tree, so the backend uses
  `removedir()` rather than the generic `xunlink()`.

* **Archive.**  `ctl_cyrusdb` archives by copying each named file into a backup
  directory.  The zeroskip archiver creates a subdirectory and copies the
  `zeroskip-*` data files into it.  Everything under the `zeroskip.` metadata
  prefix -- the lock file, repack staging, the pointer table cache -- is left
  behind, since all of it is recreated on demand.

* **Conversion.**  `rename(2)` will not replace a file with a directory or the
  reverse, so the in-place replace at the end of `cyrusdb_convert()` tries a
  plain `cyrus_rename()` first; that succeeds outright for a same-shape convert
  and only fails EISDIR/ENOTDIR when the shape changed.  Only then does it fall
  back to renaming the original aside, moving the new database into place, and
  removing the original.  `struct cyrusdb_backend` carries a
  `CYRUSDB_BACKEND_ISDIR` flag so `cyrusdb_open()` can tell a shape mismatch
  from a genuine I/O error and hand it to the conversion path.

## Reclaim

zeroskip offers two reclaim operations and Cyrus uses both.  `zs_db_compact()`
merges the whole database into a single file and is the only thing that reclaims
tombstones, so it backs the cyrusdb checkpoint slot that `ctl_cyrusdb -c` drives
-- an explicit maintenance pass, where being unbounded is the point.
`zs_db_repack()` merges geometrically and is what the post-commit path wants.

The library will run that cascade itself, from whichever write transaction
starts a new generation and finds work to do.  Cyrus opens with
`ZS_NOAUTOREPACK` and takes the deferral instead: a commit that sees
`zs_db_should_repack()` queues the repack through `libcyrus_delayed_action()`,
so it runs at the next idle point rather than inside the transaction a user is
waiting on.  The two are not interchangeable -- disarming the cascade without
running the repack leaves a database that only accumulates files, and every read
merges across all of them.

A conversion is not deferrable the same way.  Each generation must be converted
to in-order form once, and by default that lands on whichever commit ends the
generation; `zs_db_seal()` would pre-empt it from idle time, but Cyrus has
nowhere to call it from without reopening the database at every idle point,
which costs more than the outlier it removes.

## The pointer table cache

Opening a database that has accumulated unordered files means replaying them.
zeroskip caches the resulting pointer tables so a later open replays only what
has been appended since one was published.

A planted pointer table yields wrong records, so the library never picks a
location itself -- but the database directory is already ours and already
access-controlled, so the wrapper asks for the cache there, in a
`zeroskip.cache` subdirectory, rather than running uncached.  A directory that
serves one database can also sweep tables carrying anyone else's UUID, since
they are garbage by construction.

`zeroskip_index_path` moves the cache to one directory shared by every database,
each getting a `<path>/<uuid>` of its own.  A tmpfs is a good choice, since
losing the cache costs only time; a world-writable path such as `/tmp` is not,
because planting a table there would be trivial.  The library refuses an index
directory that resolves to the database directory itself.
