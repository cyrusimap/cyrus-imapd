1. Ensure your git repository is clean, using something like
   ``git clean -xfd``.  Note that this command will destroy any uncommitted
   work you might have, so make sure your ducks are in line before proceeding.
2. Using :ref:`dar <cyd-and-dar>`, run ``dar distcheck`` -- this will confirm
   that the repository's HEAD is in a good state to ship.  It runs
   ``autoreconf``, enables maintainer mode, and runs ``make distcheck``.  Then
   it extracts the tarball that ``distcheck`` built, configures, builds,
   installs, and runs the tests.  For more information about this process,
   consult the source of ``cyd distcheck``.
3. If any of the above failed, get it fixed and merged, then start over at step
   one.
