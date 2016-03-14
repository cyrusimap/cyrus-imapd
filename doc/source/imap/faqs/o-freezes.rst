I have multiple imapd-SERVICES configured and experience occasional freezes when I try to log in!
--------------------------------------------------------------------------------------------------

If you have more than one imapd-service configured in 
:cyrusman:`cyrus.conf(5)` then they must have distinct names (the first 
argument in each line). Otherwise a deadlock can occur because the 
services will try to use the same lockfile, whose filename is derived 
from the name you gave to the service. 

Certain characters, while not strictly forbidden, should not be used in 
these names, because they will cause the name to be truncated. For 
example, "imap" and "imap_remote" will result in the same lockfile 
(``/var/imapd/socket/imap-0.lock``). It is best to only use letters and 
digits. 

