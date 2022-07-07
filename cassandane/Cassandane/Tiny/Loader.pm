package Cassandane::Tiny::Loader;
use strict;
use warnings;

use Carp ();

our $RELOADED;

sub import {
  my ($class, $path) = @_;

  my $into = caller;

  unless (-d $path) {
    Carp::confess(qq{can't find path "$path" for loading tests; Cassandane expects to be run from the ./cyrus-imapd/cassandane directory"});
  }

  my @tests = `find $path -type f \! -name "*~" \! -name ".*"`;

  if ($?) {
    Carp::confess("couldn't use find(1) to find tiny test files in $path");
  }

  chomp @tests;

  for my $test (sort @tests) {
    local $RELOADED;

    unless (eval "package $into; do qq{$test}; 1") {
      Carp::confess("tried to load $test but it failed: $@");
    }

    unless ($RELOADED) {
      Carp::confess("tried to load $test but it did not 'use Cassandane::Tiny'");
    }
  }

  return;
}

1;
