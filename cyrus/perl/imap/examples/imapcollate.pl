#! /usr/bin/perl -w
# 
# Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: imapcollate.pl,v 1.5.4.1 2003/02/27 18:13:39 rjs3 Exp $

use Getopt::Long;
use Cyrus::IMAP;
use Cyrus::IMAP::Admin;

sub usage {
  print "imapcollate - Summerize messages in folders\n";
  print "  usage:\n";
  print "    imapcollate [-u user] <server> <criteria>\n";
  print "\n";
  print "possible <criteria>: from\n";
  print "\n";
  print "  example: \n";
  print "    imapcollate cyrus.andrew.cmu.edu \"inbox*\" from\n";
  print "\n";
  exit 0;
}

GetOptions("u|user=s" => \$user,
	   "m|min=i" => \$min);

if (@ARGV) {
    $server = shift(@ARGV);
} else {
  usage;
}

if (@ARGV) {
    $where = shift(@ARGV);
} else {
  usage;
}

if (@ARGV) {
    $crit = shift(@ARGV);
} else {
  usage;
}

if ((!defined $server) || (!defined $where)) {
  usage;
}

if (!$crit eq "from") {
  print "Criteria $crit not allowed\n";
  usage;
}

my $cyrus = Cyrus::IMAP->new($server);
$cyrus->authenticate(-user => $user, -maxssf => 0); #xxx hangs when have a security layer

#list mailboxes in inbox.*
my @info = ();
$cyrus->addcallback({-trigger => 'LIST',
		     -callback => sub {
		        my %d = @_;
			next unless $d{-text} =~ s/^\(([^\)]*)\) //;
			my $attrs = $1;
			my $sep = '';
			# NIL or (attrs) "sep" "str"
			if ($d{-text} =~ /^N/) {
			  return if $d{-text} !~ s/^NIL//;
			}
			elsif ($d{-text} =~ s/\"\\?(.)\"//) {
			  $sep = $1;
			}
			return unless $d{-text} =~ s/^ //;
			my $mbox;
			if ($d{-text} =~ /\"(([^\\\"]*\\)*[^\\\"]*)\"/) {
			  ($mbox = $1) =~ s/\\(.)/$1/g;
			} else {
			  $d{-text} =~ /^([]!\#-[^-~]+)/;
			  $mbox = $1;
			}
			push @{$d{-rock}}, $mbox;
		      },
		      -rock => \@info});

my ($rc, $msg) = $cyrus->send('', '', "LIST * $where");
$cyrus->addcallback({-trigger => 'LIST'});
if ($rc eq 'OK') {
} else {
  die "IMAP Error: $msg ";
}

my %fromlis;

foreach $a (@info) {

  my %dat = coll($a);

  foreach $per (sort keys %dat) {
    if (defined $fromlis{$per}) {
      $fromlis{$per} += $dat{$per};
    } else {
      $fromlis{$per} = $dat{$per};
    }
  }
  
}

@sorted = sort {
  $fromlis{$b} <=> $fromlis{$a}
    ||
      length($b) <=> length($a)
    ||
      $a cmp $b
    } keys %fromlis;

foreach $a (@sorted) {
  if ((defined $min) && ($fromlis{$a} < $min)) {
    next;
  }
  printf("%40s %d\n", $a, $fromlis{$a});
}


sub coll {
  my ($mb) = @_;

  my %dat;

  #select something
  my ($rc, $msg) = $cyrus->send('', '', "EXAMINE $mb");
  if ($rc eq 'OK') {
  } else {
    die "Select of $mb failed with $msg";
  }

  #list size of all msgs
  my $totalsize = 0;
  $flags = 1;

  print "fetching in $mb...\n";
  
  $cyrus->addcallback({-trigger => 'FETCH', -flags => $flags,
		       -callback => sub {
			 my %d = @_;
			 my $msgno = 1;
			 $msgno = $d{-msgno};

			 my $size = 0;
			 if ( $d{-text} =~ /.*(From:)(.*)\<(.*\@.*)\>/i)
			   {
			       $addr = $3;
			   } elsif ( $d{-text} =~ /.*(From:)\s*\".*\"\s*(.*\@.*)/i) {
			       $addr = $2;
			   } elsif ( $d{-text} =~ /.*(From:)\s*(\S+\@\S+)\s*/i) {
			       $addr = $2;
			   } else {
			     #print "no From header found in msgno $msgno ($d{-text})\n";
			       $addr = "<none>";
			   }
			   $addr =~ tr/[A-Z]/[a-z]/;
			   if ($addr =~ /(.*)\+.*@(.*)/) {
				   $addr = "$1\@$2";
			   }
               ${$d{-rock}}{$addr}++;
		    }, 
  -rock => \%dat});

  ($rc, $msg) = $cyrus->send('', '', 'UID FETCH 1:* (BODY[HEADER.FIELDS (FROM)])');
  $cyrus->addcallback({-trigger => 'FETCH'});
  if ($rc eq 'OK') {
  } else {
    die "Fetch in $mb failed with $msg";
  }

  (%dat);
} 

