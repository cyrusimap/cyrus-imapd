package Net::CardDAVTalk;

use 5.006;
use strict;
use warnings FATAL => 'all';


use Net::DAVTalk;
use base qw(Net::DAVTalk);

use Carp;
use Text::VCardFast qw(vcard2hash);
use XML::Spice;
use Net::CardDAVTalk::VCard;
use Data::Dumper;


=head1 NAME

Net::CardDAVTalk - The great new Net::CardDAVTalk!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Net::CardDAVTalk;

    my $foo = Net::CardDAVTalk->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 function1

=cut

# General methods

sub new {
  my ($Class, %Params) = @_;

  $Params{homesetns} = 'C';
  $Params{homeset} = 'addressbook-home-set';
  $Params{wellknown} = 'carddav';

  my $Self = $Class->SUPER::new(%Params);

  $Self->ns(C => 'urn:ietf:params:xml:ns:carddav');
  $Self->ns(M => 'http://messagingengine.com/ns/cardsync');

  return $Self;
}

# Address book methods {{{

sub NewAddressBook {
  my ($Self, $Path, %Args) = @_;

  $Path || confess 'New address book path not specified';

  $Self->Request(
    'MKCOL',
    "$Path/",
    x('D:mkcol', $Self->NS(),
      x('D:set',
        x('D:prop',
          x('D:resourcetype',
            x('D:collection'),
            x('C:addressbook'),
          ),
          x('D:displayname', $Args{name}),
        ),
      ),
    ),
  );

  return $Path;
}

sub DeleteAddressBook {
  my ($Self, $Path) = @_;

  $Path || confess 'Delete address book path not specified';

  $Self->Request(
    'DELETE',
    "$Path/"
  );

  return 1;
}

sub UpdateAddressBook {
  my ($Self, $Path, %Args) = @_;

  $Path || confess 'Update address book path not specified';

  my @Params;

  if (defined $Args{name}) {
    push @Params, x('D:displayname', $Args{name});
  }

  return undef unless @Params;

  $Self->Request(
    'PROPPATCH',
    "$Path/",
    x('D:propertyupdate', $Self->NS(),
      x('D:set',
        x('D:prop',
          @Params,
        ),
      ),
    ),
  );

  return 1;
}

sub GetAddressBooks {
  my ($Self, %Args) = @_;

  my @props;
  if ($Args{Sync}) {
    push @props, x('D:sync-token');
  }

  my $Response = $Self->Request(
    'PROPFIND',
    '',
    x('D:propfind', $Self->NS(),
      x('D:prop',
        x('D:displayname'),
        x('D:resourcetype'),
        x('D:current-user-privilege-set'),
        @props,
      ),
    ),
    Depth => 1,
  );

  my @AddressBooks;

  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    my $HRef = $Response->{"{$NS_D}href"}{content}
      || next;
    my $Path = $Self->unrequest_url($HRef);

    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      next unless $Propstat->{"{$NS_D}prop"}{"{$NS_D}resourcetype"}{"{$NS_C}addressbook"};

      # XXX - this is really quite specific and probably wrong-namespaced...
      my $Perms = $Propstat->{"{$NS_D}prop"}{"{$NS_D}current-user-privilege-set"}{"{$NS_D}privilege"};
      my $isReadOnly = (grep { exists $_->{"{$NS_D}write-content"} } @{$Perms || []}) ? 0 : 1;

      my %AddressBook = (
        path       => $Path,
        name       => ($Propstat->{"{$NS_D}prop"}{"{$NS_D}displayname"}{content} || ''),
        isReadOnly => $isReadOnly,
      );
      if ($Args{Sync}) {
        $AddressBook{syncToken} = $Propstat->{"{$NS_D}prop"}{"{$NS_D}sync-token"}{content} || '';
      }
      push @AddressBooks, \%AddressBook;
    }
  }

  return \@AddressBooks;
}

# }}}

# Contact methods {{{

sub NewContact {
  my ($Self, $Path, $VCard) = @_;

  $Path || confess "New contact path not specified";
  $VCard->isa("Net::CardDAVTalk::VCard") || confess "Invalid contact";

  my $Uid = $VCard->uid() // $VCard->uid($Self->genuuid());

  $Self->Request(
    'PUT',
    "$Path/$Uid.vcf",
    $VCard->as_string(),
    'Content-Type'  => 'text/vcard',
    'If-None-Match' => '*',
  );

  return $VCard->{CPath} = "$Path/$Uid.vcf";
}

sub DeleteContact {
  my ($Self, $CPath) = @_;

  $CPath || confess "Delete contact path not specified";

  $Self->Request(
    'DELETE',
    $CPath,
  );

  return $CPath;
}

sub UpdateContact {
  my ($Self, $CPath, $VCard) = @_;

  $CPath || confess "Update contact path not specified";
  $VCard->isa("Net::CardDAVTalk::VCard") || confess "Invalid contact";

  $Self->Request(
    'PUT',
    $CPath,
    $VCard->as_string(),
    'Content-Type' => 'text/vcard',
    'If-Match'     => '*',
  );

  return $VCard->{CPath} = $CPath;
}

sub GetContact {
  my ($Self, $CPath) = @_;

  $CPath || confess "Get contact path not specified";

  my $Response = $Self->Request(
    'GET',
    $CPath,
  );

  my $Data = $Response && $Response->{content}
    // return undef;

  my $VCard = eval { Net::CardDAVTalk::VCard->new_fromstring($Data) }
    // return undef;

  $VCard->{CPath} = $CPath;

  return $VCard;
}

sub GetContactAndProps {
  my ($Self, $CPath, $Props) = @_;
  $Props //= [];

  $CPath || confess "Get contact path not specified";

  my $Response = $Self->Request(
    'REPORT',
    $CPath,
    x('C:addressbook-query', $Self->NS(),
      x('D:prop',
        x('D:getetag'),
        x('C:address-data'),
        map { x(join ":", @$_) } @$Props,
      ),
    ),
    Depth => '0',
  );

  my ($Contact, @Errors);

  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $VCard = eval { $Self->ParseReportData($Response, $Propstat, $Props) } || do {
        push @Errors, $@ if $@;
        next;
      };

      $Contact = $VCard;
    }
  }

  return wantarray ? ($Contact, \@Errors) : $Contact;
}

sub GetContacts {
  my ($Self, $Path, $Props, %Args) = @_;
  $Props //= [];

  my $Response = $Self->Request(
    'REPORT',
    "$Path/",
    x('C:addressbook-query', $Self->NS(),
      x('D:prop',
        x('D:getetag'),
        x('C:address-data'),
        map { x(join ":", @$_) } @$Props,
      ),
    ),
    Depth => 'infinity',
  );

  my (@Contacts, @Errors);

  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $VCard = eval { $Self->ParseReportData($Response, $Propstat, $Props) } || do {
        push @Errors, $@ if $@;
        next;
      };

      push @Contacts, $VCard;
    }
  }

  return wantarray ? (\@Contacts, \@Errors) : \@Contacts;
}

sub SyncContacts {
  my ($Self, $Path, $Props, %Args) = @_;
  $Props //= [];

  $Path || confess "Sync contacts path required";

  # WebDAV Collection Synchronization (RFC6578)
  my $Response = $Self->Request(
    'REPORT',
    "$Path/",
    x('D:sync-collection', $Self->NS(),
      x('D:sync-token', ($Args{syncToken} ? ($Args{syncToken}) : ())),
      x('D:sync-level', 1),
      x('D:prop',
        x('D:getetag'),
        x('C:address-data'),
        map { x(join ":", @$_) } @$Props,
      ),
    ),
  );

  if (($Response->{error} // "") eq 'valid-sync-token') {
    delete $Args{syncToken};
    return $Self->SyncContacts($Path, $Props, %Args);
  }

  my (@Contacts, @Removed, @Errors);

  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');
  foreach my $Response (@{$Response->{"{$NS_D}response"} || []}) {
    my $HRef = $Response->{"{$NS_D}href"}{content}
      || next;
    my $CPath = $Self->unrequest_url($HRef);

    # For members that have been removed, the DAV:response MUST
    # contain one DAV:status with a value set to '404 Not Found' and
    # MUST NOT contain any DAV:propstat element
    if (!$Response->{"{$NS_D}propstat"}) {
      my $Status = $Response->{"{$NS_D}status"}{content};
      if ($Status =~ m/ 404 /) {
        push @Removed, $CPath;
      } else {
        warn "ODD STATUS";
        push @Errors, "Odd status in non-propstat response: $Status";
      }
      next;
    }

    # For members that have changed (i.e., are new or have had their
    # mapped resource modified), the DAV:response MUST contain at
    # least one DAV:propstat element and MUST NOT contain any
    # DAV:status element.
    foreach my $Propstat (@{$Response->{"{$NS_D}propstat"} || []}) {
      my $Status = $Propstat->{"{$NS_D}status"}{content};

      if ($Status =~ m/ 200 /) {
        my $VCard = eval { $Self->ParseReportData($Response, $Propstat, $Props) } || do {
          push @Errors, $@ if $@;
          next;
        };

        push @Contacts, $VCard;
      }
      elsif ($Status =~ m/ 404 /) {
        # Missing properties return 404 status response, ignore

      }
      else {
        warn "ODD STATUS";
        push @Errors, "Odd status in propstat response: $Status";
      }
    }
  }

  my $SyncToken = $Response->{"{$NS_D}sync-token"}{content};

  return wantarray ? (\@Contacts, \@Removed, \@Errors, $SyncToken) : \@Contacts;
}

sub MoveContact {
  my ($Self, $CPath, $NewPath) = @_;

  $CPath || confess "Move contact path not specified";
  $NewPath || confess "Move contact destination path not specified";

  $Self->Request(
    'MOVE',
    $CPath,
    undef,
    'Destination'  => $Self->request_url($NewPath),
  );

  return $NewPath;
}

# }}}

sub ParseReportData {
  my ($Self, $Response, $Propstat, $Props) = @_;

  my $NS_C = $Self->ns('C');
  my $NS_D = $Self->ns('D');

  my $HRef = $Response->{"{$NS_D}href"}{content}
    // return;
  my $CPath = $Self->unrequest_url($HRef);

  my $Data = $Propstat->{"{$NS_D}prop"}{"{$NS_C}address-data"}{content}
    // return;

  my $VCard = Net::CardDAVTalk::VCard->new_fromstring($Data);
  return unless $VCard;

  $VCard->{CPath} = $CPath;

  my %Props;
  for (@$Props) {
    my ($NS, $PropName) = @$_;
    my $NS_P = $Self->ns($NS);
    my $PropValue = $Propstat->{"{$NS_D}prop"}{"{$NS_P}$PropName"}{content}
      // next;
    $Props{"${NS}:${PropName}"} = $PropValue;
  }

  $VCard->{meta} = \%Props;

  return $VCard;
}

sub unrequest_url {
  my $Self = shift;
  my $Path = shift;

  if ($Path =~ m{^/}) {
    $Path =~ s#^\Q$Self->{basepath}\E/?##;
  } else {
    $Path =~ s#^\Q$Self->{url}\E/?##;
  }
  $Path =~ s#/$##;

  return $Path;
}

=head1 AUTHOR

Bron Gondwana, C<< <brong at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-carddavtalk at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-CardDAVTalk>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::CardDAVTalk


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-CardDAVTalk>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-CardDAVTalk>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-CardDAVTalk>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-CardDAVTalk/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2015 Bron Gondwana.

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

1; # End of Net::CardDAVTalk
