#!/usr/local/bin/perl5 

#
# Created by Alison Greenwald <alison@andrew.cmu.edu> 21 Sep 2000
#

use Time::Local;
use CGI qw(:standard escapeHTML);
use RRDs;
srand(timelocal(localtime));

%periods = (	"daily" => 86400,
		"weekly" => 604800,
		"monthly" => 2419200,
		"yearly" => 31536000,
);


$DDIR="/data/cyrus";
$SERVER=param("server");
$SERVICE=param("service"); 
$FNAME="$SERVER-$SERVICE";
$picdir="/usr/www/tree/current/tainted";
$hpicdir="/current/tainted";

$etime=timelocal((localtime)[0,1,2,3,4,5]);

$RNDNUM = rand()*1024;
$TITLEC="$FNAME in use";
$TITLET="$FNAME connections";


$q= new CGI;
print $q->header();

print("<html><head><title>Graphs</title></head>");
print("<body>");
print("<h1>$SERVICE usage on $SERVER</h1>\n");

foreach $period (sort {$periods{$a} <=> $periods{$b}}keys %periods){
  $sttime = $etime - $periods{$period};
  $DPICNAME="$FNAME-$period-$RNDNUM.gif";

  RRDs::graph("$picdir/cur-$DPICNAME","-t $TITLEC",
              "-s $sttime","-e $etime","-l 0",
              "DEF:a=$DDIR/$SERVER\\\:$SERVICE.rrd:current:MAX",
              "AREA:a#0000FF","COMMENT:Maximum\:","GPRINT:a:MAX:%lf",
              "COMMENT:Minimum\:","GPRINT:a:MIN:%lf");
  $ERROR=RRDs::error;
  print $ERROR if $ERROR;
 $RRDARGD.=" CDEF:throw=b,5000,GT ";
  $RRDARGD.=" CDEF:med=throw,0,b,IF ";
  $RRDARGD.=" CDEF:a=med,300,\*,FLOOR ";

  RRDs::graph("$picdir/tot-$DPICNAME","-t $TITLET", "-s $sttime","-e $etime",
              "DEF:a=$DDIR/$SERVER\\\:$SERVICE.rrd:total:MAX",
              "CDEF:throw=a,5000,GT","CDEF:med=throw,0,a,IF",
              "CDEF:b=med,300,*,FLOOR", "AREA:b#0000FF","COMMENT:Maximum\:",
              "GPRINT:b:MAX:%lf", "COMMENT:Minimum\:","GPRINT:b:MIN:%lf");
  $ERROR=RRDs::error;
  print $ERROR if $ERROR;

  print("<hr><h2>$period</h2>");
  print("<br><h3>Current</h3><img src=\"$hpicdir/cur-$DPICNAME\">");
  print("<br><h3>Total</h3><img src=\"$hpicdir/tot-$DPICNAME\">");

}

print("</body></html>");


