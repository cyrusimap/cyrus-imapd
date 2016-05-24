Why does reconstruct -m not work?
---------------------------------

From the :cyrusman:`reconstruct(8)` man page::

    −m     NOTE: CURRENTLY UNAVAILABLE
                 Rebuild  the  mailboxes file.  Use whatever data in the existing
                 mailboxes file it can scavenge, then scans all partitions listed
                 in the imapd.conf(5) file for additional mailboxes.
                 
Reconstruct is currently unable to rebuild the mailboxes db, and 
comments on the mailing list indicate this ability will not be added; at 
least, not any time soon. 

The solution here is to make sure that you back up your mailboxes db, 
preferably including a plain-text copy of it. Please see Backups for 
more information. 

If you do find yourself with a corrupted mailboxes.db, there are a few 
things you can try. The first is to see if ``db_recover`` can recover 
your database. If that doesnt' work, there should be backups in 
``$CONFIGDIRECTORY/db.backup1`` and ``$CONFIGDIRECTORY/db.backup2`` that 
may be OK. 

If you're using Simon Matter's RPMs, plain-text copies of the mailboxes 
database should be being generated and saved in 
``/var/lib/imap/backup``. Try rebuilding the db from one of those using 
:cyrusman:`ctl_mboxlist(8)`. Alternately, try asking the mailing list 
for help. 

