#!/usr/local/bin/perl5

#
# Created by Alison Greenwald <alison@andrew.cmu.edu> 21 Sep 2000
#
#

#use strict;
use CGI qw(:standard escapeHTML);
use Time::Local;

$DDIR="/data/cyrus";
$GRAPH="/cgi-bin/graph_cyrus_db.pl";

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
#  print("$server $ds $throwaway<br>");
  if($ds ne "" && $ds ne ${$hash{"$server"}}[-1]){
  #this if statement checks to see if $server is the same as the last
  #element in the array specified by this hash
    push @{$hash{"$server"}}, "$ds";
  }
}

print("<table>\n");

foreach $key( sort %hash){
  if($hash{$key}){
    print("<h2>$key</h2><ul>\n");
  }
  foreach $service (@{$hash{$key}}){
    print("<li><a href=\"$GRAPH?server=$key&service=$service\">$service</a>\n");
  }
  print("</ul>\n");
}

print("</table>\n");

print("</body></html>");

#print head(), start_html("blah"), end-html();
