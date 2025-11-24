#!/usr/bin/perl
use v5.28.0;
use warnings;

use File::Basename qw(fileparse);

my $file;
my @buffer;

if (!@ARGV or !-e $ARGV[0]) {
  die <<~'EOF';
  Greetings!  You've run the tiny test splitter.  This program exists to split
  big Cassandane test classes into lots of little test files.  The primary
  benefit of this is that you'll avoid conflicts when many peopled add or edit
  tests.  Eventually, this program won't need to exist, so its construction is
  a little shaky, but at least there's this notice!

  Run this program from ./cassandane like this:

    ./utils/tiny-test-splitter Cassandane/Cyrus/SomeClass.pm

  That will edit SomeClass.pl, removing all the test subroutines and adding, at
  the end, a `use` statement to load all the tiny test files.  The tiny test
  files will be present in ./tiny-tests/SomeClass.

  After doing that, run the tests with:

    ./testrunner.pl SomeClass

  Everything should still pass!  If it doesn't, debug things.  The most common
  problem is that the tiny tests use variables (like $foo or @bar) from
  SomeClass.pm -- that won't work, and you'll want to replace them with
  methods.

  It it does pass, `git add tiny-tests/SomeClass` and commit!  Good job!
  EOF
}

my $filename = shift @ARGV;

my $prefix = fileparse($filename, '.pm');

unless (-d "tiny-tests/$prefix") {
  system "mkdir -p tiny-tests/$prefix";
}

open my $infile, '<', $filename
  or die "can't open $filename for reading: $!";

my @lines = <$infile>;

close $infile or die "error reading $infile: $!";

die "$filename appears to use Cassandane::Tiny::Loader already!\n"
  if grep {; /use Cassandane::Tiny::Loader/ } @lines;

LINE: while ($_ = shift @lines) {
  if (/^sub test_(\S+)/) {
    my $file = $1;
    say $file;

    my @test_buffer;

    while (@buffer && $buffer[-1] =~ /^#/) {
      push @test_buffer, pop @buffer;
    }

    @test_buffer = reverse @test_buffer if @test_buffer;

    push @test_buffer, $_;

    my $in_heredoc;

    TESTLINE: while (defined($_ = shift @lines)) {
      push @test_buffer, $_;

      if (/<<\s?(['"])?EOF/) {
        $in_heredoc = 1;
        next TESTLINE;
      }

      if (/^EOF$/m) {
        undef $in_heredoc;
        next TESTLINE;
      }

      if (!$in_heredoc && /^}$/ && (!@lines || $lines[0] =~ /^$/)) {
        open my $fh, '>', "tiny-tests/$prefix/$file"
          or die "can't open $file: $!";
        print {$fh} "#!perl\nuse Cassandane::Tiny;\n\n", @test_buffer;
        close $fh;
        next LINE;
      }
    }
  }

  # Skip double blanks lines.
  next LINE if @buffer && $buffer[-1] =~ /^$/ && /^$/;

  push @buffer, $_;
}

pop @buffer while $buffer[-1] !~ /\S/;

die "output file does not end in magic true value!\n"
  unless $buffer[-1] eq "1;\n";

splice @buffer, -2, 0, (
  "\n",
  "use Cassandane::Tiny::Loader 'tiny-tests/$prefix';\n",
);

open my $outfile, '>', $filename
  or die "can't open $filename for writing: $!";

print {$outfile} @buffer;
close $outfile or die "error writing to $filename and closing: $!";
