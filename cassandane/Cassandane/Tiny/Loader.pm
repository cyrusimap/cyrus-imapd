package Cassandane::Tiny::Loader;
use v5.28.0;
use warnings;

use Carp ();
use Package::Stash;

our $RELOADED;

sub import {
  my ($class) = @_;

  my $into = caller;

  my ($moniker) = $into =~ /\ACassandane::Cyrus::([_0-9A-Za-z]+)\z/;

  my $path = "tiny-tests/$moniker";

  unless (-d $path) {
    Carp::confess(qq{can't find path "$path" for loading tests; Cassandane expects to be run from the ./cyrus-imapd/cassandane directory"});
  }

  my @tests = `find $path -type f \! -name "*~" \! -name ".*"`;

  if ($?) {
    Carp::confess("couldn't use find(1) to find tiny test files in $path");
  }

  chomp @tests;

  my (@bad_name, @no_tests);

  my $stash = Package::Stash->new($into);

  for my $test (sort @tests) {
    local $RELOADED;

    my ($base) = $test =~ m{(?:.*/)?(.*?)$};
    if ($base =~ /^test_/) {
      push @bad_name, $base;
    }

    open(my $test_fh, '<', $test) or die "can't read test file $test: $!";
    my $test_code = do { local $/; <$test_fh> };

    my $tests = grep {; /^(bogus_)?test_/ } $stash->list_all_symbols("CODE");
    $tests //= 0;

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

    my $now_tests = grep {; /^(bogus_)?test_/ } $stash->list_all_symbols("CODE");
    $now_tests //= 0;

    unless ($now_tests > $tests) {
      push @no_tests, $test;
    }
  }

  my $should_err = 0;

  if (@bad_name) {
    $should_err++;

    # If you have JMAPEmail/test_foo, and you say:
    #
    #    ./testrunner.pl JMAPEmail.test_foo
    #
    # ... no tests will run if you've named the test in test_foo sensibly:
    #
    #   sub test_foo { ... }
    #
    # ...because cassandane matches the *subroutine with the test_ prefix
    # removed* (foo) against the basename of the file (test_foo) which
    # won't match.
    #
    # You'd have to name the subroutine test_test_foo which is silly.
    #
    # Instead, just forbid test files named this way. They are in
    # tiny-tests/*, so the word 'test' is redundant.
    warn("Found files named 'test_...'.\n"
      . "These should be renamed to remove the 'test_' prefix\n"
      . "\t" . join("\n\t", sort @bad_name)
      . "\n"
    );
  }

  if (@no_tests) {
    $should_err++;

    warn("The following files specified no test_* subroutines\n"
       . "\t" . join("\n\t", sort @no_tests)
       . "\n"
    );
  }

  if ($should_err) {
    die "Prior errors detected while collecting tests, bailing out\n";
  }

  return;
}

1;
