#this test should be run after ubertestscript. 
#this depends on ifs and testing to be working properly


if header :contains "subject" "stop"
{stop;}

if header :contains "subject" "keep"
{keep;}

if header :contains "subject" "discard"
{discard;}

#this one is already tested by the ubertest script...
if header :contains "subject" "redirect"
{redirect "me+goodredirect@blah.com";}
