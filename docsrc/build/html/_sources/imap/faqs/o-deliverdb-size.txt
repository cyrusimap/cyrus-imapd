.. _faq-o-deliberdb-size:

Why is deliver.db so large?
---------------------------

Having a large deliver.db (on the order of tens of megabytes) is not 
uncommon, since a record is kept of every message that goes through 
lmtpd (so that duplicate suppression can do its work), so there's a lot 
of data there. 

Note also that it is common for databases to have unused 
space that may not be immediately recovered for performance reasons 
(this is the case with Berkeley DB and Cyrus Skiplist) You can control 
the size by increasing the frequency at which it gets pruned. 


