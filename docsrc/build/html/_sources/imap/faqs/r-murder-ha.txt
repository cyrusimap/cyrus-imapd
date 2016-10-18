Does the Cyrus Murder support High Availability configurations?
---------------------------------------------------------------

The :ref:`Cyrus Murder <murder>` clustering solution drastically 
increases system-wide reliability as compared to a traditional 
standalone IMAP server. However, this configuration is not a true High 
Availability/Redundancy solution (nor is such a beast trivial to 
implement given the constraints on traditional Email systems). 

The frontends of the CyrusMurder are, in every sense, 100% redundant. No 
server-specific data is maintained on them, and one is as good as any 
other from the point of view of a user. 

The mupdate server is indeed a single point of failure, however a 
failure at this point only prohibits message delivery (via the LMTP 
proxies that are querying it for up-to-date mailbox data) and certain 
mailbox operations (create, delete, setacl, and so on). Mail can still 
be accessed by all users of the system, and incoming mail will recieve 
temporary failures, so the sending MTA should continue to queue the 
mail. 

The failure of a backend will result in a partial system wide failure -- 
the mailboxes that were stored on that backend will no longer be 
available for use by any users. Delivery of new mail will again be 
tempfailed, and queued by the sending MTA. 

Some people have suggested shared storage and the use of hot spare 
backends to combat this solution. The Cyrus authors do not generally 
recommend the use of shared storage in the Cyrus environment. However 
people have reported success in various configurations. The shared 
filesystem still needs to support file locking, and it is highly 
recommended that it have an efficient mmap implementation. 


