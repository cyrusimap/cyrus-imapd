#!/usr/local/bin/perl5 

################################################################################
## This will read information from the cyrus MIB for all devices specified
## in cyrusrc 
##
##           Copyright 2001 by Carnegie Mellon University
## 
##                       All Rights Reserved
## 
## Permission to use, copy, modify, and distribute this software and its
## documentation for any purpose and without fee is hereby granted,
## provided that the above copyright notice appear in all copies and that
## both that copyright notice and this permission notice appear in
## supporting documentation, and that the name of CMU not be
## used in advertising or publicity pertaining to distribution of the
## software without specific, written prior permission.
## 
## CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
## ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
## CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
## ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
## WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
## ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
## SOFTWARE.
##
## Author: Alison Greenwald <alison@andrew.cmu.edu>
## $Id: cyrus.pl,v 1.1 2001/01/28 22:43:02 wcw Exp $
##
################################################################################
#


use RRDs;
use SNMP 1.8;

do "/data/prog/cyrus/cyrusrc";
get_data();

sub get_data{
  foreach $hname (keys %HOSTS){
    $MAX = 0;
    %walk=snmp_walk($hname, $HOSTS{$hname}, $MASTER);
    foreach $OID (sort keys %walk){
      @O = split /\./, $OID; 
      $RVAL=$walk{$OID};
      chomp $RVAL;
      if($O[-1] > $MAX){
        $MAX = $O[-1];
      }
      $STUFF{"$O[$#O-1]-$O[$#O]"} = $RVAL;
    } #foreach oid 

    for($i=1; $i<=$MAX; $i++){
      $blah[0]=$STUFF{"3-$i"};
      $blah[1]=$STUFF{"2-$i"};
      $blah[2]=$STUFF{"1-$i"};
      print "$hname:$blah[0]: $blah[2], $blah[1]\n";
      populate_dbs();
    } #for
  } #foreach hname
} #sub

sub populate_dbs{
  if(open(DB, "< $DPTH/$hname:$blah[0].rrd")){
    close(DB);
  } else {
    print("Making $DPTH/$hname:$blah[0]:daily.rrd\n");
    RRDs::create("$DPTH/$hname:$blah[0].rrd","-s 1",
                 "DS:current:GAUGE:300:U:U",
                 "DS:total:COUNTER:300:U:U",
                 "RRA:MAX:0.5:300:4320",
                 "RRA:MAX:0.5:1800:336",
                 "RRA:MAX:0.5:14400:168",
                 "RRA:MAX:0.5:86400:364");
    $ERROR=RRDs::error;
    print $ERROR if $ERROR;
  }

  RRDs::update("$DPTH/$hname:$blah[0].rrd", "N:$blah[1]:$blah[2]");

}#find_dbs

sub snmp_walk{
  my ($server, $comm, $rootoid) = @_;
  my %walk=();
  my $sess = new SNMP::Session ( DestHost => $server, 
                                 Community => $comm,
                                 UseNumeric => 1, 
                                 UseLongNames => 1
                               );

  my @orig=split /\./, $rootoid;  # original oid for comparison

  my $var = new SNMP::Varbind(["$rootoid"]); 
  my $val = $sess->getnext($var);
  my $name = $var->[$SNMP::Varbind::tag_f];
  $name .= ".$var->[$SNMP::Varbind::iid_f]" if $var->[$SNMP::Varbind::iid_f];
  my @current=split /\./, $name;

  while (!$sess->{ErrorStr} && $orig[$#orig] eq $current[$#orig]
        && $#current > $#orig){
    my $value=$var->[$SNMP::Varbind::val_f];

    $walk{"$name"} = $value;
    $val = $sess->getnext($var);
    $name=$var->[$SNMP::Varbind::tag_f];
    $name .= ".$var->[$SNMP::Varbind::iid_f]" if $var->[$SNMP::Varbind::iid_f];
    @current=split /\./, $name;
  }  #while

  print("$sess->{ErrorStr}\n") if $sess->{ErrorStr};
  return(%walk);

}
