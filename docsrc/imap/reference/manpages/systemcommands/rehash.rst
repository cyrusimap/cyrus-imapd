.. cyrusman:: rehash(8)

.. _imap-reference-manpages-systemcommands-rehash:

==========
**rehash**
==========

rehash checks and rehashes Cyrus directories based on the hashing settings
in the imapd.conf.

Use in the event you choose to change your hashing settings. For more information
on directory hashing, see the documentation on :ref:`imap-admin-locations-hashing`.

Synopsis
========

.. parsed-literal::

    **rehash** [**-v**] [**-n**] [**-f**|**-F**] [**-i**|**-I**] imapd.conf

Description
===========

**rehash** fixes the hashing on Cyrus directories.

It should be safe to run rehash on a running system, but it may mess things up
horribly if you have some processes still running with old config, and some with
new - so it is always recommended to fully shut down Cyrus, change the
configuration file, run rehash, and then start Cyrus again.

Options
=======

.. program:: rehash

.. option:: imapd.conf

    imapd.conf must always be provided.  On a normal system this will be
    /etc/imapd.conf.  The correct hashing settings will be read from the
    provided imapd.conf, or can be overridden with options.

.. option:: -v

    In -v verbose mode, each rename command will be printed, as well as
    any creation or deletion of folders.

.. option:: -n

    In -n "no change" mode, it will just print the changes.  Note,
    verbose is always turned on in no-change mode.

.. option:: -f | -F

    | -f forces fulldirhash: no
    | -F forces fulldirhash: yes

.. option:: -i

    |  -i forces hashimapspool: no
    |  -I forces hashimapspool: yes

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
