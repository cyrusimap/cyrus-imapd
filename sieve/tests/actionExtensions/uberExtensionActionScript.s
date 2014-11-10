require ["reject", "fileinto", "imapflags", "vacation", "notify",
        "vacation-seconds", "copy", "imap4flags", "relational",
        "comparator-i;ascii-numeric", "variables"];

#this is for the extra things we have added to sieve

#action extensions
#reject fileinto imapflags vacation notify

#REJECT
##############################################
if header :matches "subject" "*reject*"
{reject "${0} rejected";}

#FILEINTO
##############################################
if header :matches "subject" "*fileinto*"
{fileinto "INBOX.good.${0}";}

#IMAPFLAGS
##############################################
#mark
if header :contains "subject" "zmark"
{mark;}

#unmark
if header :contains "subject" "unmark"
{unmark;}

#addflag
if header :matches "subject" "*aflag1*"
{addflag "\\seen ${0}";}

#addflag
if header :matches "subject" "*aflag2*"
{addflag ["\\draft", "\\answered", "\\flagged ${0}"];}

#setflag
if header :matches "subject" "*sflag1*"
{setflag "\\deleted ${0}";}

#setflag
if header :matches "subject" "*sflag2*"
{setflag "\\draft ${0}";}

#removeflag
if header :matches "subject" "*rflag*"
{removeflag "\\answered ${0}";}

#IMAP4FLAGS#
##############################################
if header :matches "subject" "*imap4flags*"
{
setflag "existing ${0}";
keep :flags "keepflag ${0}";
fileinto :flags ["fileinto f2"] "INBOX.fileinto.flags ${0}";

addflag ["flag0", "flag1 ${0}"];
addflag ["my flag is here"];
removeflag ["is my ${0}"];

fileinto "INBOX.fileinto.internalflags";
fileinto :flags "" "INBOX.fileinto.nullflags";

}

#VARIABLES
##############################################
if header :matches "subject" "i?ap4f*gs"
{
set :lowerfirst "myvar" "myval";
set :lower :upperfirst :quotewildcard "myvar2" "my*val2";

set "mystring" "string1";
set "mystring2" "00${mystring}00";
set "mystring3" "${0} ${1} ${2} ${mystring2}";

if string :matches "${myvar2}" "my*val2" {
fileinto :copy "INBOX.stringtest.true${1}";
}

}


#VACATION
#############################################
if header :matches "subject" "*vacation*"
{

vacation :days 5
         :addresses ["me@blah.com" , "me@somewhereelse.com"]
         :subject "i'm at the beach"
	 "I'll respond in a week or two, when i get back ${0}";
}

#VACATION-SECONDS
#############################################
if header :contains "subject" "vacation-seconds"
{

vacation :seconds 60
         :addresses ["me@blah.com" , "me@somewhereelse.com"]
         :subject "i'm out of the room"
         "I'll respond in a minute, when i get back";
}

#NOTIFY and DENOTIFY
#############################################
if header :matches "subject" "*notify*"
{notify  :high :id "foobar ${0}" :message "whee: $subject$ ${0}";}

if header :matches "subject" "*not*" 
{denotify :is "foobar ${0}" :high;

}

if header :matches "subject" "*n2*"
{notify   :id "foobar" :message "whee: $subject$ ${0}";}


if header :contains "subject" "denotify"
{denotify;}

