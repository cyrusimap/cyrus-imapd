use v5.20.0;
use warnings;

my $file;
my @buffer;

my $prefix = shift @ARGV;

unless (-d "tiny-tests/$prefix") {
  system "mkdir -p tiny-tests/$prefix";
}

my @lines = <<>>;

LINE: while ($_ = shift @lines) {
  if (/^sub test_(\S+)/) {
    $file = $1;
    $file =~ s/_/-/g;
    say $file;
  }

  if (/^}$/ && (!@lines || $lines[0] =~ /^$/)) {
    push @buffer, $_;
    open my $fh, '>', "tiny-tests/$prefix/$file"
      or die "can't open $file: $!";
    print {$fh} "#!perl\nuse Cassandane::Tiny;\n\n", @buffer;
    close $fh;

    undef $file;
    @buffer = ();
    next LINE;
  }

  next if ! $file && /^\s*$/;

  push @buffer, $_;
}
