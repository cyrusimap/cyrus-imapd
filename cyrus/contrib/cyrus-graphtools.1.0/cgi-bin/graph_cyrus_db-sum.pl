#!/usr/local/bin/perl5

#
# Created by Alison Greenwald 21 Sep 2000
#
#

#use strict;
use CGI qw(:standard escapeHTML);
use Time::Local;
use RRDs;

$DDIR="/data/cyrus";
$GRAPH="/cgi-bin/graph_cyrus_db.pl";
$picdir="/usr/www/tree/current/tainted";
$hpicdir="/current/tainted";

$q= new CGI;
print $q->header();

print("<html><head><title>Cyrus Stats</title></head>");
print("<body>");

opendir(DH, $DDIR) or die "Could not find data";
@files = readdir(DH);
closedir(DH);

%hash=();
$n=0;
foreach (@files){
  $server = "";
  $ds = "";
  $n++;
  ($server, $end) = split /\:/, $_, 2;
  ($ds,$throwaway) = split /\./,$end,2;
  if($ds ne ""){
    push @{$hash{"$ds"}}, "$server";
  }
}

print("<table>\n");

foreach $service( sort %hash){
  if(!$hash{$service}){
    next;
  }
  print("<h2>$service</h2><ul>\n");
  $cdef.="CDEF:sum=0";
  print("on ");
  foreach $server(@{$hash{$service}}){
    print("<b>$server</b> ");
    ($name, @throwaway)=split /\./, $server;
    push(@args1,"DEF:$name=$DDIR/$server\\\:$service.rrd:current:MAX,");
    push(@args2,"DEF:$name=$DDIR/$server\\\:$service.rrd:total:MAX,");
    $cdef.=",$name,+";
  }
  chomp(@args1, @args2);
  RRDs::graph("$picdir/$service-1.gif",@args1,"$cdef", 
              "AREA:sum#FF0000");
#  RRDs::graph("$picdir/$service-1.gif",
#              "DEF:mail1=$DDIR/mail1.andrew.cmu.edu\\\:$service.rrd:current:MAX",
#              "DEF:mail2=$DDIR/mail2.andrew.cmu.edu\\\:$service.rrd:current:MAX",
#              "CDEF:sum=mail1,mail2,+",
#              "AREA:sum#FF0000");
             
  $error1=RRDs::error;
  RRDs::graph("$picdir/$service-2.gif", @args2, 
               $cdef, "CDEF:throw=sum,10000,GT","CDEF:med=throw,0,sum,IF", 
               "CDEF:msum=med,300,* ", "AREA:msum#FF0000");
  $error2=RRDs::error;
  print("<br><img src=\"$hpicdir/$service-1.gif\">");
  print("<img src=\"$hpicdir/$service-2.gif\">");
  if ($error1) {print $error1}
  if ($error2) {print $error2}
  @args1=(); @args2=(); $cdef=(); $error1=(); $error2=();
  print("</ul>\n");
}

print("</table>\n");

print("</body></html>");

#print head(), start_html("blah"), end-html();
