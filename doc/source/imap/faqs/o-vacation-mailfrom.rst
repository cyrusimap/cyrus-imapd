Why does Cyrus set the MAIL FROM address of the sender of vacation responses to '<>'?
-------------------------------------------------------------------------------------

Because many of the Sieve features are autoresponders, Cyrus tries to be 
a good network citizen by adhering to the appropriate RFCs: 

From :rfc:`2821`::

    This notification message must be from the SMTP server at the relay host 
    or the host that first determines that delivery cannot be accomplished. 
    Of course, SMTP servers MUST NOT send notification messages about 
    problems transporting notification messages. One way to prevent loops in 
    error reporting is to specify a null reverse-path in the MAIL command of 
    a notification message. When such a message is transmitted the 
    reverse-path MUST be set to null (see section 1.5.5 for additional 
    discussion). 


A MAIL command with a null reverse-path appears as follows:

    ``MAIL FROM:<>``

Also from draft-moore-auto-email-response-02.txt::

    The primary purpose of the MAIL FROM address is to serve as the 
    destination for delivery status messages and other automatic responses. 
    Since in most cases it is not appropriate to respond to an automatic 
    response, and the responder is not interested in delivery status 
    messages, a MAIL FROM address of <> MAY be used for this purpose. 

This is of course slightly more applicable to reject than it is to 
vacation, but there isn't a very strong argument why they should be 
treated differently. 

Note that draft-moore-auto-email-response-02.txt also states:: 

    A MAIL FROM address which is specifically chosen for the purpose of 
    sending automatic responses, and which will not automatically respond to 
    any message sent to it, MAY be used instead of <>. 

Therefore, it may be reasonable to have this be a configurable fixed 
address in the future. 


