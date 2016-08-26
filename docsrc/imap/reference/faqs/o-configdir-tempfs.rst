Is it safe to put configdir/proc and configdir/lock on a tmpfs filesystem?
--------------------------------------------------------------------------

It's safe to put both of these in tmpfs, and since they're fairly busy 
it's a good idea for performance reasons. Further, nothing ever removes 
files from <configdirectory>/lock/, so it's probably a good idea in 
general to mount that on tmpfs such that a reboot will purge it. The 
Cyrus code will create all the necessary directory structure under 
<configdirectory>/lock on-demand. 

