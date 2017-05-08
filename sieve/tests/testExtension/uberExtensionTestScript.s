require ["regex", "relational", "comparator-i;ascii-numeric", "subaddress",
	"envelope", "date", "index", "imap4flags", "variables"];

#this is for the extra things we have added to sieve
#test extensions
#envelope regex relational comparators subaddress(user and detail)

/*
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

######################################################################
#DATE
######################################################################

if allof(header :is "from" "boss@example.com",
         date :value "ge" :originalzone "date" "hour" "09",
         date :value "lt" :originalzone "date" "hour" "17")
{redirect "me+urgent@blah.com";}

if anyof(date :is "received" "weekday" "0",
         date :is "received" "weekday" "6")
{redirect "me+weekend@blah.com";}

if anyof(date :is :zone "-0800" "received" "weekday" "0",
         date :is :zone "-0800" "received" "weekday" "6")
{redirect "me+weekend(pst)@blah.com";}

if date :is "received" "year" [ "1983", "1993", "2003", "2013" ]
{redirect "me+yearsofthree@blah.com";}

if date :is :index 2 "received" "day" "01"
{redirect "me+firstofthemonth@blah.com";}

if date :is :index 1 :last "received" "day" "01"
{redirect "me+firstofthemonth@blah.com";}

if currentdate :zone "-0800" :is "year" ["2003", "2013", "2023"]
{redirect "me+currentdateis@blah.com";}

if allof(currentdate :value "ge" "date" "2014-01-01",
         currentdate :value "lt" "date" "2015-01-01")
{redirect "me+cd2014@blah.com";}
*/
######################################################################
#HASFLAG
######################################################################

if allof (
header :matches "subject" "*i*?*?s",
header :matches "subject" "*i?*?*s",
header :matches "subject" "*i*??*s",
header :matches "subject" "*i?**?s"
)
{

#
# Positive :count tests
#
setflag "";

if hasflag :count "lt" :comparator "i;ascii-numeric" ["1"]
{redirect "me+good.hasflag.count.lt.1.pos@blah.com";}
else
{redirect "me+bad.hasflag.count.lt.1.pos@blah.com";}

if hasflag :count "le" :comparator "i;ascii-numeric" ["0"]
{redirect "me+good.hasflag.count.le.0.pos@blah.com";}
else
{redirect "me+bad.hasflag.count.le.0.pos@blah.com";}

setflag "flag1 flag2";

if hasflag :count "le" :comparator "i;ascii-numeric" ["2"]
{redirect "me+good.hasflag.count.le.2.pos@blah.com";}
else
{redirect "me+bad.hasflag.count.le.2.pos@blah.com";}

#
# Negative :count tests
#
setflag "";

if hasflag :count "lt" :comparator "i;ascii-numeric" ["0"]
{redirect "me+bad.hasflag.count.lt.0.neg@blah.com";}
else
{redirect "me+good.hasflag.count.lt.0.neg@blah.com";}

if hasflag :count "ge" :comparator "i;ascii-numeric" ["1"]
{redirect "me+bad.hasflag.count.ge.1.neg@blah.com";}
else
{redirect "me+good.hasflag.count.ge.1.neg@blah.com";}

setflag "flag1 flag2";

if hasflag :count "lt" :comparator "i;ascii-numeric" ["2"]
{redirect "me+bad.hasflag.count.lt.2.neg@blah.com";}
else
{redirect "me+good.hasflag.count.lt.2.neg@blah.com";}

#
# Positive tests
#
setflag "there";

if hasflag :matches ["m?*?g", "*h??e*"]
{redirect "me+good.hasflag.contains.pos@blah.com";}
else
{redirect "me+bad.hasflag.contains.pos@blah.com";}

if hasflag :matches "**"
{redirect "me+good.hasflag.contains.null.pos@blah.com";}
else
{redirect "me+bad.hasflag.contains.null.pos@blah.com";}

#
# Negative tests
#
setflag "flag";

if hasflag :matches "?*?*?*?*?*?"
{redirect "me+bad.hasflag.null.neg@blah.com";}
else
{redirect "me+good.hasflag.null.neg@blah.com";}

if hasflag :contains "flags"
{redirect "me+bad.hasflag.contains.neg@blah.com";}
else
{redirect "me+good.hasflag.contains.neg@blah.com";}

if hasflag :matches "?la?g*"
{redirect "me+bad.hasflag.neg@blah.com";}
else
{redirect "me+good.hasflag.neg@blah.com";}


      set "state" "${state} pending";
      if string :matches " ${state} " "* pending *" {
redirect "string.matches.true+good@blah.com";
      } else
{redirect "string.matches.false+bad@blah.com";}
      if string :matches " ${state}" "* pending *" {
redirect "string.matches.true+bad@blah.com";
      } else {
redirect "string.matches.false+good@blah.com";
}

if string " mystring pending" "* pending *"
{redirect "me+bad.string.false@blah.com";}
else
{redirect "me+good.string.false@blah.com";}


if hasflag :matches "state" "?*?*?*?*?*?"
{redirect "me+good.hasflag.match.pos@blah.com";}
else
{redirect "me+bad.hasflag.match.pos@blah.com";}

if hasflag :contains "state" "pend"
{redirect "me+good.hasflag.contains.pos@blah.com";}
else
{redirect "me+bad.hasflag.contains.pos@blah.com";}

if hasflag "state" "pending"
{redirect "me+good.hasflag.is.pos@blah.com";}
else
{redirect "me+bad.hasflag.is.pos@blah.com";}

if hasflag :matches "?la?g*"
{redirect "me+bad.hasflag.neg@blah.com";}
else
{redirect "me+good.hasflag.neg@blah.com";}

}

