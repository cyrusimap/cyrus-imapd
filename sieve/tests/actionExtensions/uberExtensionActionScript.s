require ["reject", "fileinto", "imapflags", "vacation", "notify"];

#this is for the extra thigns we have added to sieve

#action extensions
#reject fileinto imapflags vacation notify 

#REJECT
##############################################
if header :contains "subject" "reject"
{reject "rejected";}

#FILEINTO
##############################################
if header :contains "subject" "fileinto"
{fileinto "INBOX.good";}

#IMAPFLAGS
##############################################
#mark
if header :contains "subject" "zmark"
{mark;}

#unmark
if header :contains "subject" "unmark"
{unmark;}

#addflag
if header :contains "subject" "aflag1"
{addflag "\\seen";}

#addflag
if header :contains "subject" "aflag2"
{addflag ["\\draft", "\\answered", "\\flagged"];}

#setflag
if header :contains "subject" "sflag1"
{setflag "\\deleted";}

#setflag
if header :contains "subject" "sflag2"
{setflag "\\draft";}

#removeflag
if header :contains "subject" "rflag"
{removeflag "\\answered";}

#VACATION
#############################################
if header :contains "subject" "vacation"
{

vacation :days 5 
	 :addresses ["me@blah.com" , "me@somewhereelse.com"]
         :subject "i'm at the beach"
	 "I'll respond in a week or two, when i get back";
}

#NOTIFY and DENOTIFY
#############################################
if header :contains "subject" "notify"
{notify  :high :id "foobar" :message "whee: $subject$";}

if header :contains "subject" "not" 
{denotify :is "foobar" :high;

}

if header :contains "subject" "n2"
{notify   :id "foobar" :message "whee: $subject$";}


if header :contains "subject" "denotify" 
{denotify;}
