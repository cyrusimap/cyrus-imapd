#!/usr/bin/perl

package Cassandane::Test::NewTestUrl;
use strict;
use warnings;

use JSON;
use LWP::UserAgent;

use lib '.';
use base qw(Cassandane::Unit::TestCase);

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_basic
{
    my ($self) = @_;

    my $string_based_url = $self->new_test_url("string based");
    my $code_based_url = $self->new_test_url(sub {
        return [
            201,
            [],
            [ "code based" ],
        ],
    });

    my $lwp = LWP::UserAgent->new;

    {
        my $res = $lwp->get($string_based_url->url);
        $self->assert_str_equals('200', $res->code);
        $self->assert_str_equals('string based', $res->decoded_content);
    }

    {
        my $res = $lwp->get($code_based_url->url);
        $self->assert_str_equals('201', $res->code);
        $self->assert_str_equals('code based', $res->decoded_content);
    }

    $string_based_url->unregister;

    {
        # Unregistering one shouldn't affect the other
        my $res = $lwp->get($code_based_url->url);
        $self->assert_str_equals('201', $res->code);
        $self->assert_str_equals('code based', $res->decoded_content);
    }

    $code_based_url->update("newval");

    {
        my $res = $lwp->get($code_based_url->url);
        $self->assert_str_equals('200', $res->code);
        $self->assert_str_equals('newval', $res->decoded_content);
    }

    {
        eval { $string_based_url->url };
        my $err = $@;
        $self->assert_matches(
            qr/\QCannot call ->url after ->unregister has been called\E/,
            $err,
        );
    }

    {
        eval { $string_based_url->update("foo") };
        my $err = $@;
        $self->assert_matches(
            qr/\QCannot call ->update after ->unregister has been called\E/,
            $err,
        );
    }

    # Plack example
    my $plack_based_url = $self->new_test_url(sub {
        my $env = shift;
        my $req = Plack::Request->new($env);

        my $payload = decode_json($req->raw_body);

        my $res;

        if ($payload->{good}) {
            $res = Plack::Response->new(200);
            $res->content_type('application/json');
            $res->body(encode_json({ good => "job" }));
        } else {
            $res = Plack::Response->new(400);
            $res->content_type('application/json');
            $res->body(encode_json({ tough => "luck" }));
        }

        return $res->finalize;
    });

    {
        my $res = $lwp->post(
            $plack_based_url->url,
            Content => encode_json({ good => 1 }),
        );
        $self->assert_str_equals('200', $res->code);

        my $json = decode_json($res->decoded_content);
        $self->assert_deep_equals(
            { good => "job" },
            $json,
        );
    }

    {
        my $res = $lwp->post(
            $plack_based_url->url,
            Content => encode_json({ good => 0 }),
        );
        $self->assert_str_equals('400', $res->code);

        my $json = decode_json($res->decoded_content);
        $self->assert_deep_equals(
            { tough => "luck" },
            $json,
        );
    }
}

1;
