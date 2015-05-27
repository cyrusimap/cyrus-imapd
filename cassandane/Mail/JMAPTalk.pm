#!/usr/bin/perl -cw

use strict;
use warnings;

package Mail::JMAPTalk;

use JSON::XS qw(decode_json encode_json);
use Convert::Base64;
use Carp qw(confess);

our $VERSION = '0.01';

sub new {
  my ($Proto, %Args) = @_;
  my $Class = ref($Proto) || $Proto;

  my $Self = bless { %Args }, $Class;

  return $Self;
}

sub ua {
  my $Self = shift;
  unless ($Self->{ua}) {
    $Self->{ua} = HTTP::Tiny->new(agent => "Net-JMAPTalk/$VERSION");
  }
}

sub auth_header {
  my $Self = shift;
  return 'Basic ' . encode_base64("$Self->{user}:$Self->{password}", '');
}

sub uri {
  my $Self = shift;
  my $scheme = $Self->{scheme} // 'http';
  my $host = $Self->{host} // 'localhost';
  my $port = $Self->{port} // ($scheme eq 'http' ? 80 : 443);
  my $url = $Self->{url} // '/jmap';

  return "$scheme://$host:$port$url";
}

sub Request {
  my ($Self, $Requests, %Headers) = @_;

  $Headers{'Content-Type'} //= "application/json";

  if ($Self->{user}) {
    $Headers{'Authorization'} = $Self->auth_header();
  }

  my $uri = $Self->uri();

  my $Response = $Self->ua->post($uri, {
    headers => \%Headers,
    content => encode_json($Requests),
  });

  confess "JMAP request for $Self->{user} failed ($uri): $Response->{status} $Response->{reason}: $Response->{content}"
    unless $Response->{success};

  return decode_json($Response->{content});
}


1;
