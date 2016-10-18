.. _imapinstall-xapian:

====================
Xapian for searching
====================

Cyrus can be configured to use `Xapian <http://xapian.org>`_ to power its searches.

Compiling Xapian for Cyrus
==========================

Before compiling Cyrus with the ``--enable-Xapian`` option, Xapian must first be patched and compiled.

The version of Xapian used to build the search support into Cyrus was
2.2, and the patches in the cyrus-imapd repository are against that version.

To build the library:

.. code-block:: bash

    # choose your own adventures here
    export XAPIAN_DIR=/opt/xapian
    export CYRUS_DIR=/opt/cyrus
    export SRC_DIR=/opt/src

    cd $SRC_DIR
    wget http://oligarchy.co.uk/xapian/1.2.21/xapian-core-1.2.21.tar.xz
    tar -xf xapian-core-1.2.21.tar.xz
    cd xapian-core-1.2.21
    tar -xf $cyrusdir/contrib/xapian_quilt.tar.gz
    QUILT_PATCHES=xapian_quilt quilt push -a
    autoreconf -v -i
    ./configure --prefix=$XAPIAN_DIR
    make
    make install

Then follow on with the Cyrus :ref:`compilation instructions <imapinstallguide>`, adding ``--enable-xapian`` to the flags to ``./configure``    

Configuring Xapian
==================

Configuration-wise, you'll need to set up sync log to a channel called **squatter**, and at least one search tier.

::

    search_engine: xapian
    search_index_headers: no
    search_batchsize: 8192
    defaultpartition: default
    defaultsearchtier: t1
    partition-default: /var/cyrus/spool
    t1searchpartition-default: /var/cyrus/search

And then you'll need to arrange for a rolling squatter to run on startup. In :cyrusman:`cyrus.conf(5)`::

    START {
      # run a rolling squatter
      squatter cmd="squatter -R"
    }

If you want to do more complex search tiers and repacking, you'll  want to read:

http://lists.tartarus.org/pipermail/xapian-discuss/2014-October/009112.html


