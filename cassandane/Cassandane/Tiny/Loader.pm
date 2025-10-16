package Cassandane::Tiny::Loader;
use v5.26.0;
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

    open(my $test_fh, '<', $test) or die "can't read test file $test: $!";
    my $test_code = do { local $/; <$test_fh> };

    $test_code = qq{use v5.28.0;\n}
               . qq{use warnings FATAL => 'redefine';\n}
               . qq{use experimental 'signatures';\n}
               . qq{package $into;\n}
               . qq{# line 1 "$test"\n}
               . $test_code
               . qq{\n1; # <- magic true value\n};

    unless (evalbytes $test_code) {
      Carp::confess("tried to load $test but it failed: $@");
    }

    unless ($RELOADED) {
      Carp::confess("tried to load $test but it did not 'use Cassandane::Tiny'");
    }
  }

  return;
}

1;
