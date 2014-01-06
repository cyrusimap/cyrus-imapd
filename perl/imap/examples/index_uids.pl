#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Std;

use Cyrus::IndexFile;
use Cyrus::CacheFile;
use Cyrus::HeaderFile;

my %Opts;
getopts('CHcdDu:', \%Opts);

my $file = shift || die "Usage: $0 <indexfile>\n";
unless (-f $file) {
  die "File doesn't exist $file\n";
}

my $cfile = $Opts{C};
my $hfile = $Opts{H};
unless ($cfile) {
  $cfile = $file;
  $cfile =~ s/index$/cache/;
}
unless ($hfile) {
  $hfile = $file;
  $hfile =~ s/index$/header/;
}
my $index = Cyrus::IndexFile->new_file($file);
my $cache;
if ($Opts{c}) {
  $cache = Cyrus::CacheFile->new_file($cfile);
}
my $headerfile = Cyrus::HeaderFile->new_file($hfile);
my $header = $index->header();
unless ($Opts{u}) {
  if ($Opts{d}) {
    print $index->header_dump() . "\n";
  } elsif ($Opts{D}) {
    print $index->header_longdump() . "\n";
  } else {
    $header->{NumRecords} ||= $header->{Exists};
    print "V:$header->{MinorVersion} E:$header->{Exists} N:$header->{NumRecords} U:$header->{LastUid} M:$header->{HighestModseq}\n";
  }
}
while (my $r = $index->next_record) {
  next if ($Opts{u} and $Opts{u} != $r->{Uid});
  if ($Opts{d}) {
    print $index->record_dump() . "\n";
  }
  elsif ($Opts{D}) {
    my $offset = sysseek($index->{handle}, 0, 1);
    print "Offset: $offset\n";
    print $index->record_longdump();
    my @flags = $index->flagslist($headerfile);
    print "FLAGS: @flags\n";
    print "\n";
  }
  elsif ($header->{MinorVersion} == 9) {
    print "$r->{Uid} $r->{MessageUuid} $r->{Size}\n";
  }
  elsif ($header->{MinorVersion} < 13) {
    my @flags = $index->flagslist();
    print "$r->{Uid}\@$r->{Modseq} $r->{MessageGuid} $r->{Size} (@flags)\n";
  }
  else {
    my @flags = $index->flagslist($headerfile);
    printf "$r->{Uid}\@$r->{Modseq} $r->{MessageGuid} $r->{CID} $r->{Size} (@flags)\n";
  }
  if ($Opts{c}) {
    $cache->offset($r->{CacheOffset});
    my $r = $cache->next_record();
    print $cache->print_record($r);
    print "------------------------------------------------\n";
  }
}
