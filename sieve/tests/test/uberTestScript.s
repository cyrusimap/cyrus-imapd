/*using redirect to test if, elsif, and else, along with all of the tests 
  that can be inside

  this is still being added to, there are almost certaintly conditions not 
  being tested 
 

 */


#address all

if address :all :is "from" "zme@true.com"
{redirect "me+aallis@blah.com";}

if address :all :contains "from" "true.com"
{redirect "me+aallcontains@blah.com";}

if address :all :matches "from" "*true.com"
{redirect "me+aallmatches@blah.com";}



#address domain

if address :domain :is "from" "true.com"
{redirect "me+adomainis@blah.com";}

if address :domain :contains "from" "true.com"
{redirect "me+adomaincontains@blah.com";}

if address :domain :matches "from" "*true*"
{redirect "me+adomainmatches@blah.com";}


#address localpart

if address :localpart :is "from" "zme"
{redirect "me+alocalpartis@blah.com";}

if address :localpart :contains "from" "z"
{redirect "me+alocalpartcontains@blah.com";}

if address :localpart :matches "from" "z*"
{redirect "me+alocalpartmatches@blah.com";}






#add tests/messages that differentiate between header/address.
#need to write messages and to tweak tests to make sure everyhting works 
#as expected

if header :contains "Date" "Feb"
{redirect "me+headercontains@blah.com";}

if header :is "Date" "Mon, 25 Feb 2002 08:51:06 -0500"
{redirect "me+headeris@blah.com";}

if header :matches "Date"  "Mon, 25 Feb *"
{redirect "me+headermatches@blah.com";}

##########################################################################
#this stuff will be true for a lot of messages                           #
##########################################################################
#stop 	

if exists "To"
{redirect "me+toexists@blah.com";}
	
if exists "flooglewart"
{redirect "me+badexists@blah.com";}

	if size :over 10K
{redirect "me+over10k@blah.com";}

if size :over 1M
{redirect "me+over1m@blah.com";}

if size :under 1K
{redirect "me+under1k@blah.com";}

#########################################################################
#this stuff will work for any message.                                  #
#########################################################################
#stop


if true
{redirect "me+goodtrue@blah.com";}

if false
{redirect "me+badfalse@blah.com";}

if not false
{redirect "me+goodnot@blah.com";}

if true
{redirect "me+goodif@blah.com";}
else
{redirect "me+badif@blah.com";}

if false
{redirect "me+badelseif@blah.com";}
elsif true
{redirect "me+goodelseif@blah.com";}
else
{redirect "me+badelseif@blah.com";}

if false
{redirect "me+badelse@blah.com";}
elsif false
{redirect "me+badelse@blah.com";}
else
{redirect "me+goodelse@blah.com";}

if false
{}
else
{redirect "me+goodnull@blah.com";}

if true
  {if true
     {if true
        {redirect "me+goodnesting@blah.com";}
     }
  }

#ALLOF(and)
if allof(false, false)
{redirect "me+badallof(ff)@blah.com";}
else
{redirect "me+goodallof@blah.com";}

if allof(false, true)
{redirect "me+badallof(ft)@blah.com";}
else
{redirect "me+goodallof@blah.com";}

if allof(true, false)
{redirect "me+badallof(tf)@blah.com";}
else
{redirect "me+goodallof@blah.com";}

if allof(true, true) 
{redirect "me+goodallof@blah.com";}
else
{redirect "me+badallof(tt)@blah.com";}

#ANYOF(or)
if anyof(false, false)
{redirect "me+badanyof(ff)@blah.com";}
else 
{redirect "me+goodanyof@blah.com";}

if anyof(false,true)
{redirect "me+goodanyof@blah.com";}
else 
{redirect "me+badanyof(ft)@blah.com";}

if anyof(true, false)
{redirect "me+goodanyof@blah.com";}
else 
{redirect "me+badanyof(tf)@blah.com";}

if anyof(true, true)
{redirect "me+goodanyof@blah.com";}
else 
{redirect "me+badanyof(tt)@blah.com";}
