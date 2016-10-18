How do I get Cyrus Sieve to play nice with Exim?
------------------------------------------------

This problem results from Cyrus using CRLF sequences to denote line 
breaks in its pipe to the sendmail process, which normal Sendmail 
handles just fine. However, Exim does not handle these sequences ok. 

Exim 4.20 and later has a drop_cr option which you can use, the 
following wrapper script was suggested by Bernhard Erdmann 
(be@berdmann.de):: 


    - /etc/imapd.conf:
    sendmail: /opt/exim/exim_dropcr

    - /opt/exim/exim_dropcr:
    #!/bin/sh
    /opt/exim/exim -dropcr $@ 