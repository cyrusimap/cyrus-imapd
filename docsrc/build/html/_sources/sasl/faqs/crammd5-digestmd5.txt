Why do CRAM-MD5 and DIGEST-MD5 not work with CyrusSaslauthd?
------------------------------------------------------------

Saslauthd is only capable of verifying plaintext passwords (it takes a 
plaintext password and a username and responds with "yes" or "no", 
essentially). Therefore, since the plaintext password isn't passed from 
client to server in DIGEST-MD5 and CRAM-MD5, Saslauthd can't verify the 
password. 

Authentication in a CyrusSaslauthd-only environment will not only fail 
with these mechanisms, it doesn't really make a lot of sense. You'll 
want to use an AuxpropPlugin instead (for example, sasldb). 


