Why do POP3 connections take so long, but once the connection is established all is well?
-----------------------------------------------------------------------------------------

In some configurations POP3 needs to generate random data for use by 
APOP authentications. This can lead to delays if ``/dev/random`` does 
not have enough entropy immediately available. 

If you don't need or want support for APOP, you can either compile SASL 
with ``--disable-checkapop``, or you can disable APOP support in 
pop3[proxy]d at runtime by setting ``allowapop:0`` in :cyrusman:`imapd.conf(5)`. 

Otherwise, since there isn't a strong need for high-quality random 
numbers with SASL, there are two options for dealing with this -- link 
/dev/urandom to /dev/random. Alternatively, recompile SASL with 
``--with-devrandom=/dev/urandom``. It's preferred to do the latter, as it 
avoids affecting other applications. 

