Multiple partitions may be used for various reasons, such as to
distribute load between different storage pools or technologies.  Please
consult :ref:`imap-features-mail-spool-partitions` for more details and
use cases.

To define additional mail spools, add more ``partition-name`` entries
to :cyrusman:`imapd.conf(5)` as needed.  For example, let's imagine we
want to migrate users to new partitions split by first character of the
user's last name, and add a partition for shared mailboxes (see
:ref:`imap-features-namespaces-shared`):

* Sample::

    defaultpartition: main
    partition-main: /var/spool/cyrus
    partition-am: /var/spool/cyrus-am
    partition-nz: /var/spool/cyrus-nz
    partition-shared: /var/spool/cyrus-shared
