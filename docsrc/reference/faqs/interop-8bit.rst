Why does Cyrus reject 8-bit characters in the headers of my messages?
---------------------------------------------------------------------

8-bit characters are not allowed in the headers of an :rfc:`822` 
message.

## Until release 3.0
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

## Release 3.0 and later
All the rationale for pre-3.0 8-bit character support still applies.

However, Cyrus now optionally *does* accept 8-bit characters in MIME header values
for internal processing, if they are valid UTF-8. For example, this allows Cyrus
to index 8-bit message header values for search or emit them on the JMAP or RSS 
interfaces.

Please note that the original message header values are left as-is. That is,
Cyrus does not attempt to repair improperly encoded headers.

To enable this feature one must enable the `rfc2047_utf8` config option. This
causes Cyrus to interpret any high-bit character as UTF-8. Invalid UTF8
characters are internally processed with the UTF-8 replacement character.
