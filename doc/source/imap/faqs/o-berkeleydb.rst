Why does ctl_cyrusdb -r take so long with Berkeley DB?
------------------------------------------------------

Berkeley DB maintains a log of all the transactions since the last 
checkpoint of the database. In order to ensure the database is in a 
consistent state, you must recover the log after any outage (thus the 
recommendation to run these processes when Cyrus starts). They can take 
a long time for a few reasons. 

The most common one is that you need to checkpoint the cyrusdb more 
often. This can be done with a simple ``ctl_cyrusdb -c``. If you do this 
very often, the amount of log that needs to be recovered will be 
significantly shorter. We recommend doing this at least once every half 
hour, and more often on busy sites. 

The other reason is that your :ref:`deliver.db may be very large <faq-o-deliberdb-size>`. This is 
solvable by increasing the pruning interval (the -E parameter to 
ctl_deliver, which you should run on a regular basis), or (in a pinch) 
by just removing the database (since the effects of losing it do not 
prevent operation, they just cause vacation messages to be resent, and 
duplicate delivery suppression to possibly deliver duplicates). 

* "by increasing the pruning interval": My understanding is that the 
   number after "-E" is the number of days after which entries are 
   discarded. Is there a way to reduce it to a number of hours? Since most 
   of our mail is internal mail should rarely be delayed by more then an 
   hour or two. 

* In case it's useful to anyone we discovered that moving /var/lib/imap 
   from an ext2 to an ext3 journaled filesystem made a vast difference for 
   the worse. While recovering the database Berkeley DB does a vast 
   quantity of small writes and that combined with the updates to the 
   journal absolutely kills disk performance (with journalling it was 
   taking about 40 minutes to start Cyrus on a mail server with about 500 
   users and 200G of mail). On the flip side moving /var/lib/imap to a 
   hardware RAID system with a decent amount of onboard cache reduced this 
   time to under 30 seconds. I think Berkeley DB could probably be 
   optimized to deal with this better, but in the mean time avoid 
   journaling filesystems, or at least be prepared to experiment to find 
   something that works for you. 



