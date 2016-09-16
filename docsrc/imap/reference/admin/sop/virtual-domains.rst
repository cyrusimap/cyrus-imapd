==========================
Cyrus Virtual Domains
==========================

First of all see the ``install-virtdomains.html`` file in your Cyrus distribution.

Global admins
=============

Pay attention to this in the documentation:

Global administrators are specified with an unqualified userid in the 
admins option and have access to any mailbox on the server. Because 
global admins use unqualified userids, they belong to the defaultdomain. 
As a result, you can **NOT** have a global admin without specifying a 
defaultdomain. Note that when trying to login as a global admin to a 
multi-homed server from remote machine, it might be necessary to fully 
qualify the userid with the defaultdomain. 

In my case (Cyrus was listening not on the hostname but on an alias) I 
had to provide the servername and defaultdomain parameter, and these had 
to be the same. A part of my :cyrusman:`imapd.conf(5)`::

    admins: cyrus cyrus@mail.ugent.be
    defaultdomain: mail1.ugent.be
    servername: mail1.ugent.be
    unixhierarchysep: 1
    virtdomains: userid

See the following thread: http://asg.web.cmu.edu/archive/message.php?mailbox=archive.info-cyrus&msg=39557 Thanks to Baltasar Cevc for helping to debug this.

I added users to ``/etc/sasldb2`` with::

    saslpasswd2 -c cyrus@mail1.ugent.be
    saslpasswd2 -c cyrus@mail.ugent.be

    jura:/mail/mail1/etc# cyradm --user cyrus@mail1.ugent.be mail1.ugent.be
    Password: 
    mail1.ugent.be> lm
    user/fabel@test.ugent.be (\HasNoChildren)         
    user/fiebel@test.ugent.be (\HasNoChildren)        
    user/foo.bar@mail.ugent.be (\HasNoChildren)       
    user/foo.fafa@mail.ugent.be (\HasNoChildren)      
    user/rudy.gevaert@mail.ugent.be (\HasNoChildren)  
    user/testuser2@mail.ugent.be (\HasNoChildren)     
    mail1.ugent.be> quit
    jura:/mail/mail1/etc# cyradm --user cyrus@mail.ugent.be mail1.ugent.be
    Password: 
    mail1.ugent.be> lm
    user/foo.bar (\HasNoChildren)       user/rudy.gevaert (\HasNoChildren)  
    user/foo.fafa (\HasNoChildren)      user/testuser2 (\HasNoChildren)  
    
As you can see the first user is the global admin, while the second user is the admin for the mail.ugent.be domain.

Replication and virtual domains
===============================

In 2.3.3 this doesn't work: http://asg.web.cmu.edu/archive/message.php?mailbox=archive.info-cyrus&msg=39577