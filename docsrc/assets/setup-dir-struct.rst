Set up a simple directory structure for Cyrus to store emails, owned by
the ``cyrus`` user and group ``mail``:

::

    sudo mkdir -p /var/lib/cyrus /var/spool/cyrus
    sudo chown -R cyrus:mail /var/lib/cyrus /var/spool/imap
    sudo chmod 750 /var/lib/cyrus /var/spool/cyrus
