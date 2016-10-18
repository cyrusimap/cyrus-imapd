Duplicate Delivery Suppression
------------------------------

Duplicate delivery suppression is a feature of the Cyrus IMAP server 
that allows multiple copies of an identical messages delivered to one 
user to be suppressed, so that the user only receives one copy. This can 
be convenient if, say, one user is on multiple mailing lists that 
commonly receive the same message. 

The way that a message is determined to be a duplicate is a lookup is 
done in the duplicate delivery database for a message-id/mailbox pair. 
If a match is found, the message is suppressed. If a match is not found, 
the pair is added to the database and the message is delivered. 

Duplicate Delivery Suppression can also affect sieve redirects. In this 
case, suppression is done on a message-id/redirect-target basis. 

Duplicate Delivery Suppression can also affect vacation messages. In 
this case, suppression is done based on a hash of the sender's address 
and the vacation message. 


