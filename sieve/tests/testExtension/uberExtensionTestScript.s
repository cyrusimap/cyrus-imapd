require ["regex", "relational", "comparator-i;ascii-numeric", "subaddress", "envelope"];

#this is for the extra thigns we have added to sieve
#test extensions
#envelope regex relational comparators subaddress(user and detail)


#need better relational and comparator tests...

if header :value "gt" 
	:comparator "i;ascii-numeric" 
	["number"] ["10"]
{redirect "me+numberover10@blah.com";}
   
  
if header :count "gt" 
	:comparator "i;ascii-numeric" 
	["X"] ["3"]
{redirect "me+X@blah.com";}
       
#header regex

if header :regex "Date" "Tue,(.*)Feb(.*)"
{redirect "me+goodheaderregex@blah.com";}



#address Regex

if address :all :regex "from" "cook(.)Monster(\\+.*)@cookie\\...."
{redirect "me+goodaallregex@blah.com";}

if address :domain :regex "from" "c..kie\\.com"
{redirect "me+goodadomainregex@blah.com";}

if address :localpart :regex "from" "c.{2,4}Monster(\\+.*)"
{redirect "me+goodalocalpartregex@blah.com";}

if address :user :regex "from" "cookyM.....r"
{redirect "me+goodauserregex@blah.com";}

if address :detail :regex "from" "whe*"
{redirect "me+goodadetailregex@blah.com";}


#address user

if address :user :is "from" "mymonster"
{redirect "me+goodauseris@blah.com";}

if address :user :contains "from" "mym"
{redirect "me+goodausercontains@blah.com";}

if address :user :matches "from" "my*r"
{redirect "me+goodausermatches@blah.com";}


#address detail

if address :detail :is "from" "underbed"
{redirect "me+goodadetailis@blah.com";}

if address :detail :contains "from" "bed"
{redirect "me+goodadetailcontains@blah.com";}

if address :detail :matches "from" "under*"
{redirect "me+goodadetailmatches@blah.com";}

######################################################################
#ENVELOPE
######################################################################


#envelope all

if envelope :all :is "from" "WERT+erk@true.com"
{redirect "me+eallis@blah.com";}

if envelope :all :contains "from" "true.com"
{redirect "me+eallcontains@blah.com";}

if envelope :all :matches "from" "WERT*.com"
{redirect "me+eallmatches@blah.com";}


#envelope domain

if envelope :domain :is "from" "true.com"
{redirect "me+edomainis@blah.com";}

if envelope :domain :contains "from" "true"
{redirect "me+edomaincontains@blah.com";}

if envelope :domain :matches "from" "*true.com"
{redirect "me+edomainmatches@blah.com";}


#envelope localpart

if envelope :localpart :is "from" "WERT+erk"
{redirect "me+elocalpartis@blah.com";}

if envelope :localpart :contains "from" "WE"
{redirect "me+elocalpartcontains@blah.com";}

if envelope :localpart :matches "from" "WE?T*"
{redirect "me+elocalpartmatches@blah.com";}

#envelope regex

if envelope :all :regex "from" "true.com"
{redirect "me+goodeallregex@blah.com";}

if envelope :domain :regex "from" "true.com"
{redirect "me+goodedomainregex@blah.com";}

if envelope :localpart :regex "from" "true.com"
{redirect "me+goodelocalpartregex@blah.com";}

if envelope :user :regex "from" "true.com"
{redirect "me+goodeuserregex@blah.com";}

if envelope :detail :regex "from" "true.com"
{redirect "me+goodedetailregex@blah.com";}

#envelope user

if envelope :user :is "from" "WERT"
{redirect "me+goodeuseris@blah.com";}

if envelope :user :contains "from" "WE"
{redirect "me+goodeusercontains@blah.com";}

if envelope :user :matches "from" "*RT"
{redirect "me+goodeusermatches@blah.com";}


#envelope detail

if envelope :detail :is "from" "erk"
{redirect "me+goodedetailis@blah.com";}

if envelope :detail :contains "from" "k"
{redirect "me+goodedetailcontains@blah.com";}

if envelope :detail :matches "from" "e*k"
{redirect "me+goodedetailmatches@blah.com";}
