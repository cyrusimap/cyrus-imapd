# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use SIEVE::Cyrus;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

sub mysub {

  my($name, $isactive) = @_ ;
  
  print "$name : $isactive\n";

}

sub prompt {

  my($prompt) = @_ ;

  print "$prompt: \n";

  "tmartin";
}

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $obj = sieve_get_handle("acap1.andrew.cmu.edu","prompt","prompt","prompt","prompt");

print "connected\n";

$ret = sieve_put_file($obj, "a");

print "sieve_put = $ret\n";

$ret = sieve_list($obj, "mysub");

print "sieve_list = $ret\n";

$ret = sieve_get($obj,"a",$str);

print "sieve_get = $ret\n";

$ret = sieve_delete($obj, "a");

print "sieve_list = $ret\n";

$ret = sieve_list($obj, "mysub");

print "sieve_list = $ret\n";
