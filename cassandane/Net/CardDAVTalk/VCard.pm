package Net::CardDAVTalk::VCard;

use 5.014;
use strict;
use warnings;
use Text::VCardFast qw(vcard2hash hash2vcard);
use Encode qw(decode_utf8 encode_utf8);
use MIME::Base64 qw(decode_base64);
use List::Pairwise qw(mapp);
use List::MoreUtils qw(all pairwise);
use Data::Dumper;

# Core {{{

sub new {
  my $Proto = shift;
  my $Class = ref($Proto) || $Proto;

  my $Self = {
    type => 'VCARD',
    properties => {
      version => [
        {
          name => "version",
          value => "3.0"
        },
      ],
    }
  };

  return bless $Self, $Class;
}

sub new_fromstring {
  my $Proto = shift;
  my $Class = ref($Proto) || $Proto;

  my $Parsed = eval { vcard2hash(shift, multival => [ qw(n adr org) ]) };

  my $Self = $Parsed->{objects}->[0];
  if ($Self->{type} ne 'vcard') {
    warn "Found non-vcard '$Self->{type}' for in $_";
    return undef;
  }

  bless $Self, $Class;

  $Self->Normalise();

  return $Self;
}

sub new_fromfile {
  my $Proto = shift;
  my $Class = ref($Proto) || $Proto;

  my $FileR = shift;

  my $Fh;
  if (ref $FileR) {
    $Fh = $FileR;
  } else {
    open($Fh, $FileR)
      || die "Could not read '$FileR': $!";
  }

  my $Input = do { local $/; <$Fh>; };

  my $Self = $Class->new_fromstring($Input);
  $Self->{file} = $FileR if !ref $FileR;

  return $Self;
}

sub as_string {
  my $Self = shift;

  return eval { hash2vcard({ objects => [ $Self ] }) };
}

sub uid {
  my $Self = shift;
  $Self->V('uid', 'value', @_);
}

# }}}

# ME VCard manipulation {{{

my @VParamTypes = qw(work home text voice fax cell cell video pager textphone internet);
push @VParamTypes, map { uc } @VParamTypes;

my @VItemN = qw(surnames givennames additionalnames honorificprefixs honorificsuffixes);
my @VItemADR = qw(postofficebox extendedaddress streetaddress locality region postalcode countryname);
my @VItemORG = qw(company department);
my %VExpand = (n => \@VItemN, adr => \@VItemADR, org => \@VItemORG);

my @ProtoPrefixes = (
  [ 'tel', qr/tel:/ ],
  [ 'impp', qr/skype:/ ],
  [ 'impp', qr/xmpp:/ ],
  [ 'x-skype', qr/skype:/ ],
  [ 'x-socialprofile', qr/twitter:/ ],
);

my %ABLabelTypeMap = (Home => 'home', Mobile => 'cell', Twitter => 'twitter');

my %VCardEmailTypeMap = (
  home => 'personal',
  work => 'work',
);
my %RevVCardEmailTypeMap = reverse %VCardEmailTypeMap;

my %VCardAdrTypeMap = (
  home => 'home',
  work => 'work',
);
my %RevVCardAdrTypeMap = reverse %VCardAdrTypeMap;

my %VCardTelTypeMap = (
  home => 'home',
  work => 'work',
  cell => 'mobile',
  fax => 'fax',
  pager => 'pager',
);
my %RevVCardTelTypeMap = reverse %VCardTelTypeMap;

my %VCardTypeMap = (
  email => [ \%VCardEmailTypeMap, \%RevVCardEmailTypeMap ],
  adr => [ \%VCardAdrTypeMap, \%RevVCardAdrTypeMap ],
  tel => [ \%VCardTelTypeMap, \%RevVCardTelTypeMap ],
);

my %IMPPServiceTypeMap = qw(
  skype       skype
);

my %IMPPProtoPrefixes = (
  'skype' =>      ['skype'],
  'msn' =>        ['msn','msnim'],
  'googletalk' => ['xmpp'],
  'facebook' =>   ['xmpp'],
  'aim' =>        ['aim'],
  'yahoo' =>      ['ymsgr'],
  'icq' =>        ['icq','aim'],
  'jabber' =>     ['xmpp'],
);

my %XSocialProfileTypeMap = qw(
  twitter     twitter
);

my %XServiceTypeMap = qw(
  twitter         twitter
  skype           skype
  skype-username  skype
  aim             chat
  icq             chat
  google-talk     chat
  jabber          chat
  msn             chat
  yahoo           chat
  ms-imaddress    chat
);

my %VCardNewOnlineMap = (
  'web' => [
    [ 'url' ]
  ],
  'chat' => sub { [
    [ 'impp', { 'x-service-type' => 'jabber', 'x-user' => $_[0] } ],
  ] },
  'twitter' => sub { [
    [ 'x-socialprofile', { 'type' => 'twitter', 'x-user' => $_[0] }, "http://twitter.com/$_[0]" ],
    [ 'x-twitter' ],
  ] },
  'skype' => sub { [
    [ 'impp', { 'x-service-type' => 'skype', 'x-user' => $_[0] } ],
    [ 'x-skype' ],
  ] },
  'other' => sub { [
    [ 'impp', { 'x-user' => $_[0] } ],
  ] },
);

my $NoteParamName = 'x-menote';

sub Normalise {
  my $Self = shift;

  $Self->{meta} = {};

  my $Props = $Self->{properties};

  # Expand/decode/normalise all values
  for (values %$Props) {

    # All properties are array ref of items
    for (@$_) {

      # Scalar or array ref (e.g. 'n', 'adr', etc compound fields)
      my $Value = $_->{value} // $_->{values};

      # If non-ascii value, it's utf-8
      for (ref($Value) ? @$Value : $Value) {
        if (/[\x80-\xff]/) {
          $_ = eval { decode_utf8($_) } // $_;
        }
      }

      # Expand out 'n' and 'adr' fields into components.
      #  Put scalars into expanded fields and scalar refs in values arrayref
      if (my $VFields = $VExpand{$_->{name}}) {
        @$_{@$VFields} = map { $_ // '' } @$Value[0 .. scalar(@$VFields)-1];
        $_->{values} = [ \@$_{@$VFields} ];
        delete $_->{value};
      }

      # Handle base64 encoded value
      my $Encoding = $_->{params}->{encoding};
      if (ref($Encoding) && lc $Encoding->[0] eq 'b') {
        $Value = decode_base64($Value);
        $_->{binary} = 1;
      }

      # Expand and lowercase comma separated type= parameters
      if (my $Type = $_->{params}->{type}) {
        $_->{params}->{type} = $Type = [ $Type ] if !ref $Type;
        @$Type = map { split /,/, lc $_ } @$Type;
      }
      if (my $ServiceType = $_->{params}->{'x-service-type'}) {
        $_->{params}->{'x-service-type'} = $ServiceType = [ $ServiceType ] if !ref $ServiceType;
      }

      $_->{value} = $Value;

      # Create 'groups' item that tracks items in each group
      push @{$Self->{groups}->{$_->{group}}}, $_ if $_->{group};
    }
  }

  # Add any X-ABLabel group items as 'label' attribute
  if (my $Labels = $Props->{'x-ablabel'}) {
    my %LabelMap = map { $_->{group} ? ($_->{group} => $_) : () } @$Labels;
    for (keys %$Props) {
      next if $_ eq 'x-ablabel';
      for (@{$Props->{$_}}) {
        if (my $Label = $LabelMap{$_->{group} // ''}) {
          my $LabelV = $_->{label} = $Label->{value};
          $_->{labelref} = $Label;

          # Attach type= param if appropriate
          $LabelV = $1 if $LabelV =~ m{^_\$\!<([^>]*)};
          if (my $TypeP = $ABLabelTypeMap{$LabelV}) {
            my $TypeList = ($_->{params}->{type} //= []);
            push @$TypeList, $TypeP if !grep { $_ eq $TypeP } @$TypeList;
          }
        }
      }
    }
  }

  # Handle v4 value=uri telephone numbers
  my $Version = $Props->{version};
  if ($Version && $Version->[0] >= 4.0) {
    for (@ProtoPrefixes) {
      my ($Prop, $ProtoRE) = @$_;
      if (my $Items = $Props->{$Prop}) {
        for (@$Items) {
          if ($_->{value} =~ s/^($ProtoRE)//) {
            $_->{proto_strip} = $1;
            # If we found a uri prefix, better have value=uri param
            if (!$_->{params}->{value} && $Prop eq 'tel') {
              $_->{params}->{value} = [ 'uri' ];
            }
          }
        }
      }
    }
  }

  # Create synthetic "online" list. Generate "online_type" and "online_value"
  # based on all the different types for twitter and skype contact info
  my $Online = $Props->{online} = [];

  # URL:foo.com
  for (@{$Props->{url}}) {
    $_->{online_type}  = 'web';
    $_->{online_value} = $_->{value};

    push @$Online, $_;
  }

  # IMPP;X-SERVICE-TYPE=Skype;type=pref:skype:someskype
  for (@{$Props->{impp}}) {
    my $Type  = lc(($_->{params}->{'x-service-type'} // [])->[0] // '');
    my $Value = $_->{value};
    my $ProtoPrefixes = $IMPPProtoPrefixes{$Type} // ['x-apple'];
    $Value =~ s/^$_:// for @$ProtoPrefixes;
    $_->{online_type}  = $IMPPServiceTypeMap{$Type} // 'chat';
    $_->{online_value} = $Value;

    push @$Online, $_;
  }

  # X-SOCIALPROFILE;type=twitter;x-user=sometwitter:http://twitter.com/sometwitter
  for (@{$Props->{'x-socialprofile'}}) {
    my $Type  = lc(($_->{params}->{type} // [])->[0] // '');
    my $Value = $_->{params}->{'x-user'}->[0] // $_->{value};
    $_->{online_type}  = $XSocialProfileTypeMap{$Type} // 'other';
    $_->{online_value} = $Value;

    push @$Online, $_;
  }

  # X-YAHOO:someyahoo
  for my $Type (keys %XServiceTypeMap) {
    for (@{$Props->{"x-$Type"}}) {
      $_->{online_type}  = $XServiceTypeMap{$Type};
      $_->{online_value} = $_->{value};

      push @$Online, $_;
    }
  }

  # Set contact_type to match API
  for ([ 'email', \%VCardEmailTypeMap ],
       [ 'tel', \%VCardTelTypeMap ],
       [ 'adr', \%VCardAdrTypeMap ]) {
    my ($Prop, $Map) = @$_;

    my $Props = $Props->{$Prop} || next;
    for (@$Props) {
      # Prefer calculated online_type, otherwise case on property name or type params
      my ($ContactType) =
        map { ($_ && $Map->{$_}) or () }
          (($_->{online_type} or ()), $_->{name}, @{$_->{params}->{type} // []});

      $_->{contact_type} = $ContactType // 'other';
    }
  }
}

sub DeleteUnusedLabels {
  my ($Self) = @_;
  my $Props = $Self->{properties};

  for (@{$Props->{'x-ablabel'}}) {
    my $Group = $Self->{groups}->{$_->{group}};
    my $NumItems = grep { !$_->{deleted} } @$Group;
    $_->{deleted} = 1 if $NumItems <= 1;
  }
}

sub ReadOnly {
  $_[0]->{ReadOnly} = $_[1] if @_ > 1; return $_[0]->{ReadOnly};
}

sub V {
  my ($Self, $Prop, $Item) = splice @_, 0, 3;
  $Item //= 'value';
  my $Props = $Self->{properties};

  die "Tried to modify read-only contact, fetch directly, not from cache"
    if @_ && $Self->{ReadOnly};

  # Always get/set first item of given type
  my $V = $Props->{$Prop} && $Props->{$Prop}->[0];

  # If setting value, and no existing value, create new
  if (!$V && @_) {
    $V = $Props->{$Prop}->[0] = { name => $Prop, params => {} };

    # Create parts if an multipart field
    if (my $VFields = $VExpand{$Prop}) {
      @$V{@$VFields} = ("") x scalar @$VFields;
      $V->{values} = [ \@$V{@$VFields} ];
    }
  }

  # Get value
  if (!@_) {
    return $V ? $V->{$Item} : undef;

  # Set value
  } else {
    $Self->{vchanged}->{$Prop} = 1;

    local $_ = shift;

    if (defined $_) {
      # Trim whitespace and garbage from values
      s/^\s+//;
      s/\s+$//;
      # Ugg, saw U+200B (ZERO WIDTH SPACE) in some data, http://www.perlmonks.org/?node_id=1020973
      s/\p{FORMAT}//g;
    }

    # Delete item if not a compound value and setting to empty string or undef
    if ((!defined $_ || $_ eq '') && !$V->{values}) {
      my $E = shift @{$Props->{$Prop}};
      $E->{deleted} = 1;
    }

    # Otherwise store the new value
    else {
      $V->{$Item} = $_ // '';

      # Uggg, for compound value, delete if all values empty
      if ($V->{values} && all { $$_ eq '' } @{$V->{values}} ) {
        my $E = shift @{$Props->{$Prop}};
        $E->{deleted} = 1;
      }
    }

    $Self->DeleteUnusedLabels;

    $Self->VRebuildFN if $Prop eq 'n' || $Prop eq 'org';
    return $_;
  }
}

sub VDate {
  my $Self = shift;
  local $_ = shift;

  # Convert VCard -> Our format
  if (!@_) {
    return undef if !$_;

    if (/^(\d{4})-(\d{2})-(\d{2})(?:T|$)/) {
      my ($Y, $M, $D) = ($1, $2, $3);
      $Y = '0000' if $Y eq '1604'; # iOS magic "no year" value
      return "$Y-$M-$D";
    }

    # V4 format
    if (/^(\d{4}|--)(\d{2})(\d{2})(?:T|$)/) {
      my ($Y, $M, $D) = ($1, $2, $3);
      $Y = '0000' if $Y eq '--';
      $Y = '0000' if $Y eq '1604'; # iOS magic "no year" value
      return "$Y-$M-$D";
    }

  # Convert Our format -> VCard
  } else {
    # Delete value if special "empty" value
    return undef if $_ eq '0000-00-00';

    # Our format is V3 format

    # Convert to V4 format if V4 card
    if ($Self->V('version') >= 4.0) {
      my ($Y, $M, $D) = /^(\d{4})-(\d{2})-(\d{2})/;
      $Y = '--' if $Y eq '0000';
      $_ = $Y . $M . $D;
    }

    return $_;
  }

  return undef;
}
sub VRebuildFN {
  my $Self = shift;

  my $NewFN = join " ", map {
    $Self->V('n', $_) or ()
  } qw(honorificprefixs givennames additionalnames surnames);

  my $Suffixes = $Self->V('n', 'honorificsuffixes');
  $NewFN .= ', ' . $Suffixes if $Suffixes;

  # FN is a required field, so we have to set it to something
  unless ($NewFN) {
    $NewFN = $Self->VCompany();
  }
  unless ($NewFN) {
    my ($Email) = $Self->VEmails();
    $NewFN = $Email->{value};
  }
  unless ($NewFN) {
    $NewFN = "No Name";
  }

  $Self->V('fn', 'value', $NewFN);
}

sub VTitle {
  my $Self = shift;
  $Self->V('n', 'honorificprefixs', @_) // '';
}
sub VFirstName {
  my $Self = shift;
  if (!@_) {
    return join " ", map { $_ or () } $Self->V('n', 'givennames'), $Self->V('n', 'additionalnames');
  } else {
    my ($GivenNames, $AdditionalNames) = split / +/, $_[0], 2;
    $Self->V('n', 'givennames', $GivenNames);
    $Self->V('n', 'additionalnames', $AdditionalNames);
  }
}
sub VLastName {
  my $Self = shift;
  $Self->V('n', 'surnames', @_) // '';
}

sub VFN {
  my $Self = shift;
  $Self->V('fn', 'value', @_) // '';
}

sub VNickname {
  shift->V('nickname', 'value', @_) // '';
}
sub VBirthday {
  my $Self = shift;
  if (!@_) {
    return $Self->VDate($Self->V('bday')) // '0000-00-00';
  } else {
    $Self->V('bday', 'value', $Self->VDate($_[0], 1));
  }
}

sub VCompany {
  shift->V('org', 'company', @_) // '';
}
sub VDepartment {
  shift->V('org', 'department', @_) // '';
}
sub VPosition {
  shift->V('title', 'value', @_) // '';
}

sub VNotes {
  shift->V('note', 'value', @_) // '';
}

my %VBasicTypeMap = (type => 'contact_type', value => 'value');
my %VOnlineTypeMap = (type => 'online_type', value => 'online_value');
my %VAdrTypeMap = (type => 'contact_type', street => 'streetaddress', city => 'locality', state => 'region', postcode => 'postalcode', country => 'countryname');
my %RevVAdrTypeMap = reverse %VAdrTypeMap;

sub VKN {
  my $I = shift;
  join "/", map { $I->{$_} } @_;
}

sub VIsSame {
  my ($Self, $Prop, $E, $N) = @_;

  if ($Prop eq 'email' || $Prop eq 'tel') {
    # If type or value is same, consider it the same item
    return 1 if $N->{contact_type} eq $E->{contact_type}
      || $N->{value} eq $E->{value};

  } elsif ($Prop eq 'adr') {
    # If type or value is same, consider it the same item
    return 1 if $N->{contact_type} eq $E->{contact_type}
      || all { ($N->{$_} // '') eq $E->{$_} } @VItemADR;

  } elsif ($Prop eq 'online') {
    # If synthetic online type AND value is same, consider it the same item
    return 1 if $N->{contact_type} eq ($E->{online_type} // $E->{contact_type})
        && $N->{value} eq ($E->{online_value} // $E->{value});

  } else {
    die "Unknown prop: $Prop";
  }
}

sub VUpdateExisting {
  my ($Self, $Prop, $E, $N, $TypeMap) = @_;

  # Need to update vcard specific properties
  if (my $Maps = $VCardTypeMap{$Prop}) {
    if (my $ParamType = $Maps->[1]->{$N->{contact_type}}) {
      # Make sure only the single right type is present in the vcard type param
      my $Types = ($E->{params}->{type} //= []);
      @$Types = grep { !$Maps->[0]->{$_} } @$Types;
      push @$Types, $ParamType;

      # Lets try and be smart and update any label
      $Self->VUpdateLabel($E, $N) if $Prop eq 'adr';
    }
    elsif ($N->{contact_type} eq 'other') {
      delete $E->{params}->{type};
    }

  } else {
    die "Unknown prop: $Prop";
  }

  # Now copy over value(s)
  $E->{$_} = $N->{$_} for values %$TypeMap;
}

sub VUpdateLabel {
  my ($Self, $E, $N) = @_;

  my @Labels;
  # In v4, it's a parameter
  push @Labels, map { \$_ } @{$E->{params}->{label}};

  # In v3, it's a separate property. Either in same group...
  if (my $Group = $E->{group}) {
    for (@{$E->{groups}->{$Group}}) {
      push @Labels, \$_->{value} if $_->{name} eq 'label';
    }
  }
  # ... or check for label with same type (e.g. 'work', 'home', etc)
  if (!@Labels) {
    my ($EType) = grep { $VCardAdrTypeMap{$_} } @{$E->{params}->{type} // []};
    my $Labels = $Self->{properties}->{label};
    if ($EType && $Labels) {
      for (@$Labels) {
        my ($Type) = grep { $VCardAdrTypeMap{$_} } @{$_->{params}->{type} // []};
        push @Labels, \$_->{value} if $Type && $Type eq $EType;
      }
    }
  }

  my @EI = @$E{@VItemADR};
  my @NI = @$N{@VItemADR};

  for my $Label (@Labels) {
    pairwise {
      $$Label =~ s/\b\Q$a\E\b/$b/ if length $a >= 3;
    } @EI, @NI;
  }
}

sub _MakeItem {
  my ($Name, $Type, $Value, $Params, @Extra) = @_;
  +{
    name                              => $Name,
    contact_type                      => $Type,
    (ref $Value ? 'values' : 'value') => $Value,
    params                            => $Params // {},
    @Extra,
  };
}

sub VNewItem {
  my ($Self, $Prop, $N) = @_;
  my $Type = $N->{online_type} // $N->{contact_type};
  my $Value = $N->{online_value} // $N->{value};

  my @New;

  if (my $Maps = $VCardTypeMap{$Prop}) {
    my $Params = {};
    my %Extra;

    # Set vcard type parameter
    if (my $ParamType = $Maps->[1]->{$Type}) {
      $Params->{type} = [ $ParamType ];
    }

    # Expand address value into array ref components
    if ($Prop eq 'adr') {
      @Extra{@VItemADR} = @$N{@VItemADR};
      $Value = [ \@Extra{@VItemADR} ];
    }

    $Params->{$NoteParamName} = $N->{note} if $N->{note};
    if ($N->{pref}) {
      $Params->{type} //= [];
      push @{$Params->{type}}, 'pref';
    }

    push @New, _MakeItem($Prop, $Type, $Value, $Params, %Extra);
  }

  elsif ($Prop eq 'online') {

    my $NewMap = $VCardNewOnlineMap{$Type} // $VCardNewOnlineMap{other};
    push @New, _MakeItem($_->[0], $Type, $Value, $_->[1])
      for @{ref $NewMap eq 'CODE' ? $NewMap->($N->{online_value}) : $NewMap};
  }

  else {
    die "Unknown prop: $Prop";
  }

  if ($N->{note}) {
    $_->{$NoteParamName} = $N->{note} for @New;
  }
  if ($N->{pref}) {
    $_->{pref} = 1 for @New;
  }

  return @New;
}

sub VL {
  my ($Self, $Prop, $TypeMap) = splice @_, 0, 3;
  my $Props = $Self->{properties};

  die "Tried to modify read-only contact, fetch directly, not from cache"
    if @_ && $Self->{ReadOnly};

  my @E = grep { !$_->{deleted} } @{$Props->{$Prop} // []};

  # Easy part, return items
  if (!@_) {
    my %Seen;
    return map {
      my $I = $_;
      # dedup. this might be wrong if the second has pref or note
      my $VKN = VKN($I, values %$TypeMap);
      if ($Seen{$VKN}) {
        ();
      }
      else {
        $Seen{$VKN} = 1;
        my %Props = mapp { ($a => $I->{$b}) } %$TypeMap;
        $Props{pref} = 1 if grep { $_ eq 'pref' } @{$_->{params}->{type} // []};
        $Props{note} = $_->{params}->{$NoteParamName}->[0] if $_->{params}->{$NoteParamName};
        \%Props;
      }
    } @E;

  # Harder part, set items. Try and preserve existing items
  } else {
    $Self->{vchanged}->{$Prop} = 1;

    # Find exact existing matches moved to different spot
    my %EMap = map { VKN($_, values %$TypeMap) => $_ } @E;

    my $Pos = 0;

    my @R;
    for my $New (@_) {
      my $N = { mapp { $b => ($New->{$a} // '') } %$TypeMap };

      my @NewItems;

      # Exact existing item exists (maybe different position)
      if (my $E = delete $EMap{VKN($N, values %$TypeMap)}) {
        push @NewItems, $E;

      } else {
        my $E = $E[$Pos];

        # Same item in same position, update value(s)
        # Not for online though, we always replace those
        if ($Prop ne 'online' && $E && $Self->VIsSame($Prop, $E, $N)) {
          # Don't re-use this item
          delete $EMap{VKN($E, values %$TypeMap)};

          $Self->VUpdateExisting($Prop, $E, $N, $TypeMap);

          push @NewItems, $E;
        }

        # Add new item!
        else {
          push @NewItems, $Self->VNewItem($Prop, $N);

        }
      }

      if (my $Note = $New->{note}) {
        $_->{params}->{$NoteParamName} = [ $Note ] for @NewItems;
      } else {
        delete $_->{params}->{$NoteParamName} for @NewItems;
      }

      if ($New->{pref}) {
        for (@NewItems) {
          $_->{params}->{type} //= [];
          push @{$_->{params}->{type}}, 'pref';
        }
      } else {
        for (@NewItems) {
          $_->{params}->{type} //= [];
          @{$_->{params}->{type}} = grep { $_ ne 'pref' } @{$_->{params}->{type}};
        }
      }

      # Always add to result list
      push @R, @NewItems;
      $Pos += @NewItems;
    }

    # For tel, email, adr, just replace list
    if ($Prop eq 'email' || $Prop eq 'tel' || $Prop eq 'adr') {
      @{$Props->{$Prop}} = @R;

    } elsif ($Prop eq 'online') {
      # Maps to multiple props. Delete the old ones of types we're replacing
      my %ReplaceTypes = map { $_->{contact_type} => 1 } @R;
      $_->{deleted} = 1 for grep { $ReplaceTypes{$_->{online_type}} } @E;

      push @{$Props->{$Prop}}, @R;

    } else {
      die "Unknown prop: $Prop";
    }

    $Self->DeleteUnusedLabels;

    $Self->VRebuildFN if $Prop eq 'email';
  }
}

sub VEmails {
  shift->VL('email', \%VBasicTypeMap, @_);
}
sub VPhones {
  shift->VL('tel', \%VBasicTypeMap, @_);
}
sub VOnline {
  shift->VL('online', \%VOnlineTypeMap, @_);
}
sub VAddresses {
  shift->VL('adr', \%VAdrTypeMap, @_);
}

sub VKind {
  shift->V('x-addressbookserver-kind', 'value', @_) // 'contact';
}

sub VGroupContactUIDs {
  my $Self = shift;
  my $Props = $Self->{properties};

  die "Tried to modify read-only contact, fetch directly, not from cache"
    if @_ && $Self->{ReadOnly};

  if (!@_) {
    return 
      map { s/^urn://; s/^uuid://; $_ }
      map { $_->{value} }
      @{$Props->{'x-addressbookserver-member'} ||[]};

  } else {
    @{$Props->{'x-addressbookserver-member'}} = map {
      {
        name => 'x-addressbookserver-member',
        params => {},
        value => 'urn:uuid:' . $_,
      }
    } @{$_[0]};

    $Self->{vchanged}->{'x-addressbookserver-member'} = 1;

    return @{$_[0]};
  }

}

sub VGroupIds {
  my $Self = shift;
  !@_ || die "You can't set GroupIds on a contact, use ME::CalDAV::UpdateGroups";
  return sort keys %{$Self->{ABGroups} || {}};
}

sub VChanged {
  my $Self = shift;
  return keys %{$Self->{vchanged} // {}};
}
sub VClearChanged {
  my $Self = shift;
  delete $Self->{vchanged};
}

sub MFlagged {
  return shift->MMeta('SF:flagged', @_) || 0;
}
sub MImportance {
  # Defaults to empty string, make it a number
  return shift->MMeta('CY:importance', @_) || 0;
}
sub MMeta {
  my ($Self, $Prop) = (shift, shift);
  if (@_) {
    $Self->{meta}->{$Prop} = shift;
    $Self->{metachanged}->{$Prop} = 1;
  }
  return $Self->{meta}->{$Prop};
}

sub MChanged {
  my $Self = shift;
  return map { [ $_, $Self->{meta}->{$_} ] } keys %{$Self->{metachanged} // {}};
}
sub MClearChanged {
  my $Self = shift;
  delete $Self->{metachanged};
}

# }}}

1;
