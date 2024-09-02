#!/usr/bin/perl -w

use Math::Int64;

my $sha1hex = shift || die usage();
my $cid = Math::Int64::uint64(0);
for (0..7) {
    $cid <<= 8;
    $cid |= hex(substr($sha1hex, $_*2, 2));
}
$cid ^= Math::Int64::string_to_uint64("0x91f3d9e10b690b12", 16); # chosen by fair dice roll
my $res = lc Math::Int64::uint64_to_string($cid, 16);
print sprintf("%016s", $res) . "\n";


sub usage {
  return <<EOF
Usage: $0 <sha1hex>

This can be used to convert from a GUID to a CID, or vice-versa,
though of course it will be just the GUID prefix converting
from a CID.

e.g.
  ./guid2cid.pl 35fdfb3ee0bd4f64320c92bbad4687352966dfb8
  => a40e22dfebd44476
  ./guid2cid.pl a40e22dfebd44476
  => 35fdfb3ee0bd4f64

EOF
}
