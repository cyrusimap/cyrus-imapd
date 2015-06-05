package Net::DAVTalk;

use strict;
use warnings FATAL => 'all';

use Carp;
use HTTP::Tiny;
use JSON;
use Tie::DataUUID qw{$uuid};
use XML::Spice;
use Net::DAVTalk::XMLParser;
use MIME::Base64 qw(encode_base64);
use Encode qw(encode_utf8 decode_utf8);
use URI::Escape qw(uri_unescape);

=head1 NAME

Net::DAVTalk - Interface to talk to DAV servers

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Net::DAVTalk is was originally designed as a service module for Net::CalDAVTalk
and Net::DAVTalk, abstracting the process of connecting to a DAV server and
parsing the XML responses.

Example:

    use Net::DAVTalk;
    use XML::Spice;

    my $davtalk = Net::DAVTalk->new(
        url => "https://dav.example.com/",
        user => "foo\@example.com",
        password => "letmein",
    );

    $davtalk->Request(
        'MKCALENDAR',
        "$calendarId/",
        x('C:mkcalendar', $Self->NS(),
            x('D:set',
                 x('D:prop', @Properties),
            ),
        ),
    );

    $davtalk->Request(
        'DELETE',
        "$calendarId/",
    );

=head1 SUBROUTINES/METHODS

=head2 $class->new(%Options)

Options:

    url: either full https?:// url, or relative base path on the server to the DAV endpoint

    host, scheme and port: alternative to using full URL.  If URL doesn't start with https? then these will be used to construct the endpoint URI.

    expandurl and wellknown: if these are set, then the wellknown name (caldav and carddav are both defined) will be used to resolve /.well-known/$wellknown to find the current-user-principal URI, and then THAT will be resovlved to find the $wellknown-home-set URI, which will be used as the URL for all further actions on this object.

    user and password: if these are set, perform basic authentication.

=cut

# General methods

sub new {
  my ($Class, %Params) = @_;

  unless ($Params{url}) {
    confess "URL not supplied";
  }

  # Assume url points to xyz-home-set, otherwise expand the url
  if (delete $Params{expandurl}) {
    # Locating Services for CalDAV and CardDAV (RFC6764)
    my $PrincipalURL = $Class->GetCurrentUserPrincipal(%Params);

    my $HomeSet = $Class->GetHomeSet(
      %Params,
      url => $PrincipalURL,
    );

    $Params{url} = $HomeSet;
  }

  my $Self = bless \%Params, ref($Class) || $Class;
  $Self->SetURL($Params{url});
  $Self->ns(D => 'DAV:');

  return $Self;
}

=head2 $Self->SetURL($url)

Change the endpoint URL for an existing connection.

=cut

sub SetURL {
  my ($Self, $URL) = @_;

  if ($URL =~ m{^https?://}) {
    my ($HTTPS, $Hostname, $Port, $BasePath)
      = $URL =~ m{^http(s)?://([^/:]+)(?::(\d+))?(.*)?};

    unless ($Hostname) {
      confess "Invalid hostname in '$URL'";
    }

    $Self->{scheme}   = $HTTPS ? 'https' : 'http';
    $Self->{host}     = $Hostname;
    $Self->{port}     = ($Port || ($HTTPS ? 443 : 80));
    $Self->{basepath} = $BasePath;
  }
  else {
    $Self->{basepath} = $URL;
  }

  $Self->{url} = "$Self->{scheme}://$Self->{host}:$Self->{port}$Self->{basepath}";

  return $Self->{url};
}

sub fullpath {
  my $Self = shift;
  my $path = shift;
  my $basepath = $Self->{basepath};
  return $path if $path =~ m{^/};
  return "$basepath/$path";
}

sub shortpath {
  my $Self = shift;
  my $origpath = shift;
  my $basepath = $Self->{basepath};
  my $path = $origpath;
  $path =~ s{^$basepath/?}{};
  return ($path eq '' ? $origpath : $path);
}

=head2 $Self->Request($method, $path, $content, %headers)

The whole point of the module!  Perform a DAV request against the
endpoint, returning the response as a parsed hash.

   method: http method, i.e. GET, PROPFIND, MKCOL, DELETE, etc

   path: relative to base url.  With a leading slash, relative to server root, i.e. "Default/", "/dav/calendars/user/foo/Default".

   content: if the method takes a body, raw bytes to send

   headers: additional headers to add to request, i.e (Depth => 1)

=cut

sub Request {
  my ($Self, $Method, $Path, $Content, %Headers) = @_;

  # setup request {{{

  $Content = '' unless defined $Content;
  my $Bytes = encode_utf8($Content);

  $Self->{ua} ||= HTTP::Tiny->new(
    agent => "Net-DAVTalk/0.01",
  );

  $Headers{'Content-Type'} //= 'application/xml';
  $Headers{Host} //= $Self->{host};

  if ($Self->{user}) {
    $Headers{'Authorization'} = $Self->auth_header();
  }

  # XXX - Accept-Encoding for gzip, etc?

  # }}}

  # send request {{{

  my $URI = $Self->request_url($Path);

  my $Response;

  my $OldAlarm = alarm 60;
  eval {
    local $SIG{ALRM} = sub { die 'timed out' };

    $Response = $Self->{ua}->request($Method, $URI, {
      headers => \%Headers,
      content => $Bytes,
    });
  };
  alarm $OldAlarm;

  if ($@ and $@ =~ /timed out/) {
    confess "Error with $Method for $URI (504, Gateway Timeout)";
  }

  if ($Response->{status} == 301 or $Response->{status} == 302) {
    if ($ENV{DEBUGDAV}) {
      warn "******** REDIRECT $Response->{status} to $Response->{headers}{location}\n";
    }

    $OldAlarm = alarm 60;
    eval {
      local $SIG{ALRM} = sub { die 'timed out' };

      $Response = $Self->{ua}->request($Method, $Response->{headers}{location}, {
        headers => \%Headers,
        content => $Bytes,
      });
    };
    alarm $OldAlarm;

    if ($@ and $@ =~ /timed out/) {
      confess "Error with $Method for $Response->{headers}{location} (504, Gateway Timeout)";
    }
  }

  # one is enough

  if ($ENV{DEBUGDAV}) {
    warn "<<<<<<<< " . Data::Dumper::Dumper({method => $Method, uri => $URI, headers => \%Headers, content => $Bytes }) . "\n\n";
    warn ">>>>>>>> " . Data::Dumper::Dumper($Response) . "\n\n";
    warn Data::Dumper::Dumper($Self->{ua});
  }

  if ($Method eq 'REPORT' && $Response->{status} == 403) {
    # maybe invalid sync token, need to return that fact
    my $Encoded = Encode::decode_utf8($Response->{content});
    my $Xml = xmlToHash($Encoded);
    if (exists $Xml->{"{DAV:}valid-sync-token"}) {
      return {
        error => "valid-sync-token",
      };
    }
  }

  unless ($Response->{success}) {
    confess "Error with $Method for $URI ($Response->{status}, $Response->{reason})\n\n$Bytes\n\n$Response->{content}";
  }

  my $ResponseContent = $Response->{content} || '';

  if ((grep { $Method eq $_ } qw{GET DELETE}) or ($Response->{status} != 207) or (not $ResponseContent)) {
    return { content => $ResponseContent };
  }

  # }}}

  # parse XML response {{{
  my $Encoded = Encode::decode_utf8($ResponseContent);

  my $Xml = xmlToHash($Encoded);

  # Normalise XML

  if (exists($Xml->{"{DAV:}response"})) {
    if (ref($Xml->{"{DAV:}response"}) ne 'ARRAY') {
      $Xml->{"{DAV:}response"} = [ $Xml->{"{DAV:}response"} ];
    }

    foreach my $Response (@{$Xml->{"{DAV:}response"}}) {
      if (exists($Response->{"{DAV:}propstat"})) {
        unless (ref($Response->{"{DAV:}propstat"}) eq 'ARRAY') {
          $Response->{"{DAV:}propstat"} = [$Response->{"{DAV:}propstat"}];
        }
      }
    }
  }

  return $Xml;

  # }}}
}

sub GetCurrentUserPrincipal {
  my ($Class, %Args) = @_;

  if (ref $Class) {
    %Args  = %{$Class};
    $Class = ref $Class;
  }

  my $OriginalURL = $Args{url} || '';
  my $Self        = $Class->new(%Args);
  my $NS_D        = $Self->ns('D');
  my $NS_C        = $Self->ns('C');
  my @BasePath    = split '/', $Self->{basepath};

  @BasePath = ('', ".well-known/$Args{wellknown}") unless @BasePath;

  PRINCIPAL: while(1) {
    $Self->SetURL(join '/', @BasePath);

    my $Response = $Self->Request(
      'PROPFIND',
      '',
      x('D:propfind', $Self->NS(),
        x('D:prop',
          x('D:current-user-principal'),
        ),
      ),
      Depth => 0,
    );

    foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
      foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
        if (my $Principal = $Propstat->{"{$NS_D}prop"}{"{$NS_D}current-user-principal"}{"{$NS_D}href"}{content}) {
          $Self->SetURL(uri_unescape($Principal));
          return $Self->{url};
        }
      }
    }

    pop @BasePath;
    last unless @BasePath;
  }

  croak "Error finding current user principal at '$OriginalURL'";
}

sub GetHomeSet {
  my ($Class, %Args) = @_;

  if (ref $Class) {
    %Args  = %{$Class};
    $Class = ref $Class;
  }

  my $OriginalURL = $Args{url} || '';
  my $Self        = $Class->new(%Args);
  my $NS_D        = $Self->ns('D');
  my $NS_HS       = $Self->ns($Args{homesetns});
  my $HomeSet     = $Args{homeset};

  my $Response = $Self->Request(
    'PROPFIND',
    '',
    x('D:propfind', $Self->NS(),
      x('D:prop',
        x("$Args{homesetns}:$HomeSet"),
      ),
    ),
    Depth => 0,
  );

  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      if (my $Homeset = $Propstat->{"{$NS_D}prop"}{"{$NS_HS}$HomeSet"}{"{$NS_D}href"}{content}) {
        $Self->SetURL($Homeset);
        return $Self->{url};
      }
    }
  }

  croak "Error finding $HomeSet home set at '$OriginalURL'";
}

sub genuuid {
  my $Self = shift;
  return "$uuid";
}

sub auth_header {
  my $Self = shift;
  return 'Basic ' . encode_base64("$Self->{user}:$Self->{password}", '');
}

sub request_url {
  my $Self = shift;
  my $Path = shift;

  my $URL = $Self->{url};

  if ($Path) {
    if ($Path =~ m{^/}) {
      $URL =~ s{(^https?://[^/]+)(.*)}{$1$Path};
    }
    else {
      $URL =~ s{/$}{};
      $URL .= "/$Path";
    }
  }

  return $URL;
}

sub NS {
  my $Self = shift;

  return {
    map { ( "xmlns:$_" => $Self->ns($_) ) }
      $Self->ns(),
  };
}

sub ns {
  my $Self = shift;

  # case: keys
  return keys %{$Self->{ns}} unless @_;

  my $key = shift;
  # case read one
  return $Self->{ns}{$key} unless @_;

  # case write
  my $prev = $Self->{ns}{$key};
  $Self->{ns}{$key} = shift;
  return $prev;
}



# merge existing and new shareWith params and commit to DAV
#
# UpdateShareACL($DAV, $Path, $NewObj, $OldObj);
#
# $DAV    - Net::DAVTalk or subclass object
# $Path   - path to resource (under user principal)
# $NewObj - object with wanted state
# $OldObj - object with existing state
#
# objects have this structure:
#
# {
#   mayRead         => [true|false],
#   mayWrite        => [true|false],
#   mayAdmin        => [true|false],
#   mayReadFreeBusy => [true|false], (calendar only)
#   shareWith => [
#     {
#       email  => 'user@example.com',
#       mayXXX => [true|false],
#       ...
#     }, {
#       ...
#     },
#   ]
# }
#
# see the AJAX API docs for more info

sub UpdateShareACL {
  my ($Self, $Path, $NewObj, $OldObj) = @_;
  $OldObj ||= {};

  # We only ever update ACLs if explicity set
  return unless exists $NewObj->{shareWith};

  my $Old = $OldObj->{shareWith} || [];
  my $New = $NewObj->{shareWith} || [];

  # ACL -> DAV properties
  my @allprops = qw(
    D:write-properties
    D:write-content
    D:read
    D:unbind
    CY:remove-resource
    CY:admin
  );
  my %acls = (
    mayRead => [qw(D:write-properties D:read)],
    mayWrite => [qw(D:write-content D:write-properties CY:remove-resource)],
    mayAdmin => [qw(CY:admin D:unbind)],
  );

  # extras for calendar
  if ($Self->isa("Net::CalDAVTalk")) {
    push @allprops, "C:read-free-busy";
    $acls{mayReadFreeBusy} = [qw(C:read-free-busy D:write-properties)];
  }

  my %set;
  my $dirty = 0;

  my %NewMap = map { $_->{email} => $_ } @$New;
  my %OldMap = map { $_->{email} => $_ } @$Old;

  # Merge these two, figure what's changed, write the appropriate DAV ACL command,
  my %keys = (%OldMap, %NewMap);
  foreach my $email (sort keys %keys) {
    my %newe = map { $_ => 1 } map { @{$acls{$_}||[]} }
               grep { $NewMap{$email}{$_} } keys %acls;
    my %olde = map { $_ => 1 } map { @{$acls{$_}||[]} }
               grep { $OldMap{$email}{$_} } keys %acls;
    foreach my $prop (@allprops) {
      $dirty = 1 if !!$newe{$prop} != !!$olde{$prop}; # bang bang
      if ($newe{$prop}) {
        push @{$set{"/dav/principals/user/$email"}}, $prop;
      }
    }
  }

  # own privileges as well
  my %newe = map { $_ => 1 } map { @{$acls{$_}||[]} }
             grep { exists $NewObj->{$_} ? $NewObj->{$_} : $OldObj->{$_} } keys %acls;
  my %olde = map { $_ => 1 } map { @{$acls{$_}||[]} }
             grep { $OldObj->{$_} } keys %acls;
  foreach my $prop (@allprops) {
    $dirty = 1 if !!$newe{$prop} != !!$olde{$prop}; # bang bang
    if ($newe{$prop}) {
      push @{$set{""}}, $prop;
    }
  }

  return unless $dirty;

  my @aces;
  foreach my $uri (sort keys %set) {
    my $Prin = $uri eq '' ? x('D:self') : x('D:href', $uri);
    push @aces,
       x('D:ace',
         x('D:principal', $Prin),
         x('D:grant', map { x('D:privilege', x($_)) } @{$set{$uri}}),
       );
  }

  $Self->Request(
    'ACL',
    "$Path/",
     x('D:acl', $DAV->NS(), @aces),
  );
}

1;

1;

=head2 function2

=cut

=head1 AUTHOR

Bron Gondwana, C<< <brong at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-davtalk at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-DAVTalk>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::DAVTalk


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-DAVTalk>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-DAVTalk>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-DAVTalk>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-DAVTalk/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2015 FastMail Pty. Ltd.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Net::DAVTalk
