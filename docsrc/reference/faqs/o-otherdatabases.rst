Can I use MySQL (or another SQL database) as the primary mail store?
--------------------------------------------------------------------

Using a database as the main message store for Cyrus is not currently 
supported. According to discussions on the mailing list, there is little 
benefit in adding such support (given typical IMAP access patterns, 
optimizations in the current mail store that make it fast, and the 
amount of effort involved to retrofit a different mailstore into the 
backend), so it's unlikely to ever be written. 

The Cyrus mail store is a normal directory tree, with mailboxes stored 
as directories and messages stored as individual files. Some additional 
information, eg index data, is kept in the "cyrus.*" files in the 
mailboxes. 

Cyrus DOES have the option of using databases of various types for 
storing some other information, such as authentication data, mailbox 
lists, etc. There may be reasons to add a SQL backend to these databases 
in the future (in addition to flat, and skiplist).

