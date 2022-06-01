.. _imap-developer-thoughts-improved_mboxlist_sort:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

Enabling improved_mboxlist_sort
=================================

You can't enable and disable ``improved_mboxlist_sort`` on a live
system. You need to dump and load the necessary database after stopping
and before starting the master process.  Rename the original mailboxes.db
out of the way between dumping the old and loading the new.

Dumping the mailboxes.db file

::

    ctl_mboxlist -d > /var/tmp/mailboxes.txt
    mv mailboxes.db mailboxes.db.orig
    ctl_mboxlist -u < /var/tmp/mailboxes.txt

If your subscription databases are not in flat files you need to do
something similar. Each user will have his own subscription file. Do the
following for each subscription file.

::

    cyr_dbtool -C $file skiplist show > $file.TXT
    cyr_dbtool -n $file skiplist set < $file.TXT

The above fragments will overwrite the original file. So you could
redirect to a temporary file and overwrite the database if the import
succeeds.
