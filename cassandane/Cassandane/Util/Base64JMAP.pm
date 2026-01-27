# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Base64JMAP;
use strict;
use warnings;
use base qw(Exporter);
use MIME::Base64 qw(encode_base64url decode_base64url);

use Cassandane::Util::Log;

our @EXPORT = qw(&encode_base64jmap &decode_base64jmap);

sub encode_base64jmap
{
    my ($bytes) = @_;
    my $encoded = encode_base64url($bytes, '');

    $encoded =~ tr{ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-_}
                  {-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz};

    return $encoded;
}

sub decode_base64jmap
{
    my $encoded = shift;

    $encoded =~ tr{-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz}
                  {ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-_};

    return decode_base64url($encoded);
}

1;
