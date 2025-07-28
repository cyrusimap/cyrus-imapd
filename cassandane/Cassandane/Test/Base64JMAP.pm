#!/usr/bin/perl

package Cassandane::Test::Base64JMAP;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Unit::TestCase);

use Cassandane::Util::Base64JMAP;
use MIME::Base64 qw(encode_base64url decode_base64url);

sub test_encode_base64jmap
{
    my ($self) = @_;

    # Pass in a decoded form of the string we expect to get URL encoded as the
    # entire charlist in order, then check that we got its exact replacement
    # form
    my $encoded = encode_base64jmap(
        decode_base64url(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        )
    );

    $self->assert_str_equals(
        '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz',
        $encoded
    );
}

sub test_decode_base64jmap
{
    my ($self) = @_;

    # Pass in the replacement charlist verbatim, it will be transformed then
    # bas64url decoded. Encode that and check that it is our expected
    # incoming charlist
    my $decoded = decode_base64jmap('-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz');

    $self->assert_str_equals(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
        encode_base64url($decoded, '')
    );
}

1;
