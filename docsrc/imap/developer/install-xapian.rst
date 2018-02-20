.. _imapinstall-xapian:

====================
Xapian for searching
====================

Cyrus can be configured to use `Xapian <http://xapian.org>`_ to power its searches.

Compiling Xapian for Cyrus
==========================

.. note::

    If CJK support is not required in your environment, you can use Cyrus with a
    standard upstream Xapian 1.4 release. Skip this section and move straight on to
    :ref:`Configuring Xapian <configuring-xapian>`. If you need CJK support, you will
    still need to use the cyruslibs Xapian fork and compile from source.

The cyrusimap/cyruslibs repository provides a pre-patched copy of 1.5-dev Xapian, ready for use with Cyrus. We are working on having the patches integrated upstream.

Compiling Xapian requires gcc 4.9 or later.

To build Xapian, fetch the cyruslibs package which comes with pre-patched Xapian and some other
dependencies. They are installed in ``/usr/local/cyruslibs`` by default unless overridden on the
command line.

.. code-block:: bash

    export CYRUSLIBS="/usr/local/cyruslibs"
    export PKG_CONFIG_PATH="$CYRUSLIBS/lib/pkgconfig:$PKG_CONFIG_PATH"
    export LDFLAGS="-Wl,-rpath,$CYRUSLIBS/lib -Wl,-rpath,$CYRUSLIBS/lib/x86_64-linux-gnu"
    export XAPIAN_CONFIG="$CYRUSLIBS/bin/xapian-config-1.5"

    git clone git@github.com:cyrusimap/cyruslibs.git
    cd cyruslibs
    sh build.sh $CYRUSLIBS_DIR

Then follow on with the Cyrus :ref:`compilation instructions <compiling>`, adding ``--enable-xapian`` to the flags to ``./configure``.

.. _configuring-xapian:

Configuring Xapian
==================

Xapian requires a running :cyrusman:`squatter(8)` instance:

* In :cyrusman:`cyrus.conf(5)` set up a daemon squatter to run: ::

    START {
      # run a rolling squatter
      squatter cmd="squatter -R"
    }

* Enable sync logging: Set ``sync_log: on`` in :cyrusman:`imapd.conf(5)`.
* Add a squatter sync log channel: ``sync_log_channels: squatter`` in :cyrusman:`imapd.conf(5)`.

You also need (at least one) search tier. Add this to :cyrusman:`imapd.conf(5)`.

::

    search_engine: xapian
    search_index_headers: no
    search_batchsize: 8192
    defaultpartition: base
    defaultsearchtier: t1
    partition-base: /var/cyrus/spool
    t1searchpartition-base: /var/cyrus/search

If you want to do more complex search tiers and repacking, you'll want to read:

http://lists.tartarus.org/pipermail/xapian-discuss/2014-October/009112.html
