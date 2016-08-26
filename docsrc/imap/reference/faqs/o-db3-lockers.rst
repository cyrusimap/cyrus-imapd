Is the "db3: x Lockers" log message harmful?
--------------------------------------------

This message is generally not harmful unless it is increasing at an 
alarming rate or you are seeing other performance problems. It indicates 
contention within a Berkeley DB database page, and especially on small 
databases will occur quite frequently. 

If there are performance problems, often times the best solution is to 
convert your mailbox list to a skiplist format. 

Paul M Fleming (pfleming@siumed.edu) also notes::

    We found limiting the number of lmtp processes to 10 helped with locker problems. Let sendmail/postfix handle the queuing and lmtp the delivery.. When we tried to blast 10-20 messages/sec at our test server locking became a problem with the duplicate delivery db. Across 3 servers and 600 concurrent logins (lmtpd maxchild=10 on each server) we never see any locking problems and usually have less than 1 second delivery times.
    
Andreas (andreas@conectiva.com.br) writes::

    Take a look at this text: http://www.openldap.org/faq/index.cgi?_highlightWords=locks&file=893
    
    It's written for openldap, but explains several important Berkeley DB configuration parameters. In particular:
    
        On a very busy system you might see error messages talking about running out of locks, lockers, or lock objects. Usually the default values are plenty, and in older versions of the BDB library the errors were more likely due to library bugs than actual system load. However, it is possible that you have actually run out of lock resources due to heavy system usage. If this happens, you should read about the set_lk_max_lockers[1], set_lk_max_locks[2], and set_lk_max_objects[3] keywords.

    http://www.oracle.com/technology/documentation/berkeley-db/db/api_reference/C/envset_lk_max_lockers.html
    http://www.oracle.com/technology/documentation/berkeley-db/db/api_reference/C/envset_lk_max_locks.html
    http://www.oracle.com/technology/documentation/berkeley-db/db/api_reference/C/envset_lk_max_objects.html

    The links above talk about the C api, but don't get alarmed, these paremeters can be set with a DB_CONFIG configuration file located in the DB environment home.

I also suppose the :manpage:`db_stat(8)` utility can be used to diagnose this.

