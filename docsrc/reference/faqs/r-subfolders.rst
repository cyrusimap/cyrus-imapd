Can I have subfolders not appear under INBOX?
---------------------------------------------

The altnamespace setting in ``/etc/imapd.conf`` changes the way the 
mailbox list is presented to users (including fileinto directives in 
Sieve scripts). Instead of appearing as subfolders of INBOX, 
altnamespace makes subfolders appear at the same level as INBOX. It does 
not affect the internal storage nor the way the folders are presented 
through cyradm. See :cyrusman:`imapd.conf(5)` for more information. 



