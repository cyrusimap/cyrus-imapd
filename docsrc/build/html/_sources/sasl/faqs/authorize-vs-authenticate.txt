What is the difference between an Authorization ID and a Authentication ID?
---------------------------------------------------------------------------

**Authentication** is the act of proving who you are. "Hello, I'm Dave. To 
prove it, here's my password: Foo." 

**Authorization** is the act of deciding 
whether to grant access to resources. 

:: 

    "I'd like to read Kellie's mail for her." 

In the example, I'm trying to read my wife's mail. I supply my own 
username as the "authentication identifier", my own password (Or 
biometric scan, or whatever else is required to prove I'm really me, 
with whichever mechanism is in use), and my wife's username as the 
"authorization identifier".

At no point need I know my wife's password - instead, either Kellie or 
an administrator needs to explicitly state that I am allowed in "as 
Kellie". Once I've logged in, all the access checks are done against 
Kellie, not against Dave, because I'm acting for her. To all intents and 
purposes, after the authentication exchange itself, the server can 
simply forget about who authenticated - it's not important any more - 
and concentrate on who needs to be authorized. 

Another, more common example of the use of differing authentication 
identifiers and authorization identifiers is in the design of many proxy 
systems. You authenticate perfectly normally to the proxy, authorizing 
as yourself. The proxy then authenticates to the master as itself, but 
supplies you as the authorization identifier, thus getting all the right 
access checks done at source, but not having to have access to your 
authentication credentials. Finally, some mechanisms don't support 
passing a distinct authorization identifier, and for most its optional, 
and defaults to the case that most people are familiar with, where 
authorization and authentication identifiers are the same. 

