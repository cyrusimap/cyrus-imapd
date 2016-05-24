Why does Cyrus reject 8-bit characters in the headers of my messages?
---------------------------------------------------------------------

8-bit characters are not allowed in the headers of an :rfc:`822` 
message. 

We're not about to consider a patch to "fix" the problem of replacing 
8-bit characters with 'X's that doesn't at least supply a default 
character set and properly QP-encode the nonconforming header. 

Another possibility is suggested by Chris Newman:: 

    The correct long term thing to do is to interpret unlabelled 8-bit as 
    UTF-8 if it meets the UTF-8 syntax, and otherwise give it the "unknown" 
    charset label and downconvert to 7-bit using RFC 2047. 
    
    If you want to do 
    something really fancy, you might allow a mapping from the hostname in 
    the envelope from address to a default 8-bit charset (Innosoft's MTA 
    includes an equivalent facility) so the administrator can set up private 
    agreements with specific hosts. 

