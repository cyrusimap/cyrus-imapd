Set up a simple directory structure for Cyrus to store emails, owned by
the ``cyrus`` user and group ``mail``:

::

    sudo mkdir -p /var/lib/cyrus /var/spool/cyrus
    sudo chown -R cyrus:mail /var/lib/cyrus /var/spool/cyrus
    sudo chmod 750 /var/lib/cyrus /var/spool/cyrus


The ``/var/spool/cyrus`` directory is the
:ref:`partition <imap-features-mail-spool-partitions>` where Cyrus will store
mail and must be allocated sufficient storage. The exact location can be
configured in :cyrusman:`imapd.conf(5)` in the partitions options.
