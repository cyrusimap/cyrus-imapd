#!/usr/bin/env perl

use warnings;

use IO::File;
use IO::Dir;

my $name = shift || '.';
cleanup($name);

sub cleanup {
  my $name = shift;
  return cleanup_file($name) if -f $name;
  my $d = IO::Dir->new($name);
  while (defined($_ = $d->read)) {
    next if m/^\./;
    # XXX this should really be file name patterns to process,
    # XXX not ones to ignore...
    next if m/^Makefile/;
    next if m/\.tgz$/;
    next if m/\.tar\.gz$/;
    next if m/\.gif$/;
    cleanup("$name/$_");
  }
}


sub cleanup_file {
  my $filename = shift;
  print "$filename\n";
  my $ih = IO::File->new($filename, "r") || die "can't read $filename";
  my $oh = IO::File->new("$filename.new", "w");

  if (stream_clean($ih, $oh)) {
    system("chmod", "a+x", "$filename.new") if -x $filename;
    rename("$filename.new", "$filename");
  }
  else {
    unlink("$filename.new");
  }
}

sub stream_clean {
  my ($ih, $oh) = @_;
  while (<$ih>) {
    print $oh clean_line($_) . "\n";
  }
  return 1;
}

sub clean_line {
  my $line = shift;
  use bytes;
  $line =~ s/[ \t]+$//;
  $line =~ s/[\r\n]//g;
  my $op = 0;
  my $out = "";
  foreach my $i (0..(length($line)-1)) {
    my $chr = substr($line, $i, 1);
    if ($chr eq "\t") {
      my $inc = 8 - ($op % 8);
      $out .= " " x $inc;
      $op += $inc;
    }
    else {
      $out .= $chr;
      $op++;
    }
  }
  return $out;
}
