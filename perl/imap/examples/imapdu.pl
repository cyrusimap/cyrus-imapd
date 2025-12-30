#! /usr/bin/perl -w
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use Getopt::Long;
use Cyrus::IMAP;
use Cyrus::IMAP::Admin;
use Pod::Usage;

my $user;
my $verbose = 0;
my $server;
my $where;

GetOptions("u|user=s" => \$user,
           "v|verbose!" => \$verbose) or pod2usage(2);

if (@ARGV) {
    $server = shift(@ARGV);
} else {
    pod2usage("$0: too few arguments\n");
}

if (@ARGV) {
    $where = shift(@ARGV);
} else {
    pod2usage("$0: too few arguments\n");
}

if ((!defined $server) || (!defined $where)) {
    pod2usage("$0: too few arguments\n");
}

my $cyrus = Cyrus::IMAP->new($server);
$cyrus->authenticate(-user => $user); #to debug -maxsff => 0

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

my ($rc, $msg) = $cyrus->send('', '', "LIST \"\" $where*");
$cyrus->addcallback({-trigger => 'LIST'});
if ($rc eq 'OK') {
} else {
  die "IMAP Error: $msg ";
}

my %mb_size;
my %mb_msgs;

foreach my $a (@info) {
    my ($b, $c) = sizeofmailbox($a);

    my @z = split(/\./, $a);

    my $str = "";
    foreach my $y (@z) {
        if ($str ne "") {
            $str=$str.".";
        }
        $str=$str.$y;
        $mb_size{$str} += $b;
        $mb_msgs{$str} += $c;
    }
}

foreach $a (sort keys %mb_size) {
  if (defined $mb_size{$a}) {
    showsize($mb_size{$a}, $mb_msgs{$a}, $a);
  }
}


sub sizeofmailbox {
  my ($mb) = @_;

  #select something
  my @info = ();
  $cyrus->addcallback({-trigger => 'FLAGS',
                       -callback => sub {

                       },
                       -rock => \@info});
  print STDERR "$mb...\n" if $verbose;
  my ($rc, $msg) = $cyrus->send('', '', "EXAMINE \"$mb\"");
  if ($rc eq 'OK') {
  } else {
      print "failed: $mb: $msg\n";
  }

  #list size of all msgs
  my $totalsize = 0;
  my $flags = 1;

  my %info = ();
  $info{'totalsize'} = 0;
  $info{'messages'} = 0;

  $cyrus->addcallback({-trigger => 'FETCH', -flags => $flags,
                       -callback => sub {
                         my %d = @_;
                         my $msgno = 1;
                         $msgno = $d{-msgno};

                         my $size = 0;
                         if ( $d{-text} =~ /\(RFC822.SIZE (\d+)\)/)
                           {
                             $size = $1;
                           }
                         ${$d{-rock}}{'totalsize'} += $size;
                         ${$d{-rock}}{'messages'}++;
                    },
  -rock => \%info});

  ($rc, $msg) = $cyrus->send('', '', 'FETCH 1:* RFC822.SIZE');
  $cyrus->addcallback({-trigger => 'FETCH'});

  ($info{'totalsize'}, $info{'messages'});
}

sub showsize {

  my ($size,$msgs, $name) = @_;

  if ($size < 1024) {
    printf "%9.2f bytes\t", $size;
  } elsif ($size < 1024*1024) {
    $size = $size/1024;
    printf "%9.2f KB\t", $size;
  } else {
    $size = $size/ (1024 *1024);
    printf "%9.2f MB\t", $size;
  }

  printf "%6d msg%s\t", $msgs, $msgs == 1 ? "" : "s";

  print "\t$name\n";
}


__END__

=head1 NAME

imapdu - show mailbox usage stats

=head1 SYNOPSIS

imapdu [B<--user>=I<user>] [B<--verbose>] I<server> I<pattern>

=head1 EXAMPLE

   imapdu cyrus.andrew.cmu.edu inbox
