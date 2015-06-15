#!/usr/bin/perl -cw

use strict;
use warnings;

package Mail::JMAPTalk;

use JSON::XS qw(decode_json encode_json);
use Convert::Base64;
use Carp qw(confess);

our $VERSION = '0.01';
our $CLIENT = "Net-JMAPTalk";
our $AGENT = "$CLIENT/$VERSION";

sub new {
  my ($Proto, %Args) = @_;
  my $Class = ref($Proto) || $Proto;

  my $Self = bless { %Args }, $Class;

  return $Self;
}

sub ua {
  my $Self = shift;
  unless ($Self->{ua}) {
    $Self->{ua} = HTTP::Tiny->new(agent => $AGENT);
  }
  return $Self->{ua};
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

  return $url if $url =~ m/^http/;

  return "$scheme://$host:$port$url";
}

sub Login {
  my ($Self, $Username, $Password) = @_;

  my $data = $Self->AuthRequest({
    username => $Username,
    clientName => $CLIENT,
    clientVersion => $VERSION,
    deviceName => $Self->{deviceName} || 'api',
  });

  while ($data->{continuationToken}) {
    die "Unknown method" unless grep { $_ eq 'password' } @${data->{methods}};
    $data = $Self->Request({
      token => $data->{continuationToken},
      method => 'password',
      password => $Password,
    });
  }

  die "Failed to get a token" unless $data->{accessToken};

  $Self->{token} = $data->{accessToken};
  $Self->{url} = $data->{uri};
  $Self->{upload} = $data->{upload};
  $Self->{eventSource} = $data->{eventSource};

  return 1;
}

sub Request {
  my ($Self, $Requests, %Headers) = @_;

  $Headers{'Content-Type'} //= "application/json";

  if ($Self->{user}) {
    $Headers{'Authorization'} = $Self->auth_header();
  }
  if ($Self->{token}) {
    $Headers{'Authorization'} = "JMAP $Self->{token}";
  }

  my $uri = $Self->uri();

  my $Response = $Self->ua->post($uri, {
    headers => \%Headers,
    content => encode_json($Requests),
  });

  if (wantarray) {
    my $jdata;
    $jdata = decode_json($Response->{content}) if $Response->{success};
    return ($Response, $jdata);
  }
  confess "JMAP request for $Self->{user} failed ($uri): $Response->{status} $Response->{reason}: $Response->{content}"
    unless $Response->{success};

  return decode_json($Response->{content});
}


1;
