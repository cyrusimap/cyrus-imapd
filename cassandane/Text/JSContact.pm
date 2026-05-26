#!/usr/bin/perl -cw

use strict;
use warnings;

package Text::JSContact;

our $VERSION = '0.01';

# vCard <=> JSContact (RFC 9553) conversion
# Follows RFC 9555 for vCard mapping and RFC 9554 for extensions

use Text::VCardFast qw(vcard2hash hash2vcard);
use Encode qw(decode_utf8 encode_utf8);
use MIME::Base64 qw(decode_base64 encode_base64);
use JSON;
use Scalar::Util qw(looks_like_number);

use Exporter 'import';
our @EXPORT_OK = qw(vcard_to_jscontact jscontact_to_vcard patch_vcard);

###############################################################################
# HELPERS
###############################################################################

sub _first_prop {
  my ($props, $name) = @_;
  my $items = $props->{$name};
  return undef unless $items && @$items;
  return $items->[0];
}

sub _first_value {
  my ($props, $name) = @_;
  my $prop = _first_prop($props, $name);
  return undef unless $prop;
  return $prop->{value};
}

sub _param {
  my ($prop, $name) = @_;
  my $val = $prop->{params}{$name};
  return undef unless defined $val;
  return ref $val eq 'ARRAY' ? $val->[0] : $val;
}

sub _params_list {
  my ($prop, $name) = @_;
  my $val = $prop->{params}{$name};
  return () unless defined $val;
  # Split comma-separated values (e.g. TYPE=work,voice)
  return map { split /,/ } (ref $val eq 'ARRAY' ? @$val : ($val));
}

sub _prop_id {
  my ($prop, $new_id) = @_;
  my $pid = _param($prop, 'prop-id');
  return $pid if defined $pid && $pid ne '';
  return $new_id->();
}

sub _decode_value {
  my $val = shift;
  return undef unless defined $val;
  if ($val =~ /[\x80-\xff]/) {
    $val = eval { decode_utf8($val) } // $val;
  }
  return $val;
}

sub _make_contexts {
  my @types = @_;
  my %ctx;
  for my $t (@types) {
    my $lt = lc $t;
    if ($lt eq 'home') { $ctx{private} = JSON::true }
    elsif ($lt eq 'work') { $ctx{work} = JSON::true }
  }
  return %ctx ? \%ctx : undef;
}

sub _make_pref {
  my $prop = shift;
  # vCard 4: PREF parameter
  my $pref = _param($prop, 'pref');
  if (defined $pref && looks_like_number($pref)) {
    return $pref + 0;
  }
  # vCard 3: TYPE=pref
  for my $t (_params_list($prop, 'type')) {
    return 1 if lc $t eq 'pref';
  }
  return undef;
}

sub _to_utc_datetime {
  my $val = shift;
  return undef unless defined $val;
  # Normalize compact timestamps (e.g. 19940930T143510Z -> 1994-09-30T14:35:10Z)
  if ($val =~ /^(\d{4})-?(\d{2})-?(\d{2})T(\d{2}):?(\d{2}):?(\d{2})/) {
    return "$1-$2-$3T$4:$5:$6Z";
  }
  return $val;
}

sub _generate_uid {
  my @hex = ('0'..'9', 'a'..'f');
  my $uuid = '';
  for my $i (1..32) {
    $uuid .= $hex[int(rand(16))];
    $uuid .= '-' if $i == 8 || $i == 12 || $i == 16 || $i == 20;
  }
  substr($uuid, 14, 1) = '4';
  substr($uuid, 19, 1) = $hex[8 + int(rand(4))];
  return "urn:uuid:$uuid";
}

sub _set_if {
  my ($hash, $key, $val, $transform) = @_;
  return unless defined $val && $val ne '';
  $val = $transform->($val) if $transform;
  $hash->{$key} = $val if defined $val;
}

# Collect X-ABLabel associations (Apple extension)
sub _collect_labels {
  my $props = shift;
  my %labels;
  for my $lp (@{$props->{'x-ablabel'} // []}) {
    my $group = $lp->{group} or next;
    my $val = $lp->{value} // '';
    $val = $1 if $val =~ m{^_\$\!<([^>]*)>\!\$_$};
    $labels{$group} = $val;
  }
  return \%labels;
}

sub _apply_label {
  my ($obj, $prop, $labels) = @_;
  if (my $group = $prop->{group}) {
    if (my $label = $labels->{$group}) {
      $obj->{label} = $label;
    }
  }
}

sub _convert_vcard_date {
  my $val = shift;
  return undef unless defined $val;

  # vCard 4 compact: YYYYMMDD or --MMDD
  if ($val =~ /^(\d{4}|--)-?(\d{2})-?(\d{2})(?:T|$)/) {
    my ($y, $m, $d) = ($1, $2, $3);
    $y = '0000' if $y eq '--';
    $y = '0000' if $y eq '1604'; # iOS "no year" magic
    return "$y-$m-$d";
  }

  # Already ISO format
  return $val if $val =~ /^\d{4}-\d{2}-\d{2}/;

  return $val;
}

sub _adr_values {
  my ($values, $idx) = @_;
  my $val = $values->[$idx];
  return () unless defined $val;
  if (ref $val eq 'ARRAY') {
    return grep { defined $_ && $_ ne '' } @$val;
  }
  return ($val) if $val ne '';
  return ();
}

###############################################################################
# VCARD -> JSCONTACT
###############################################################################

sub vcard_to_jscontact {
  my ($vcard_string) = @_;

  my $parsed = eval { vcard2hash($vcard_string, multival => [qw(n adr org)]) };
  return undef unless $parsed && $parsed->{objects} && @{$parsed->{objects}};

  my $vcard = $parsed->{objects}[0];
  return undef unless $vcard && $vcard->{type} eq 'vcard';

  my $props = $vcard->{properties};
  my $id_counter = 0;
  my $new_id = sub { return '' . ++$id_counter };

  my $card = {
    '@type' => 'Card',
    version => '1.0',
  };

  # UID (required)
  $card->{uid} = _first_value($props, 'uid') // _generate_uid();

  # Simple scalar properties
  _set_if($card, 'kind',     _first_value($props, 'kind')
                              // _first_value($props, 'x-addressbookserver-kind'),
                              sub { lc $_[0] });
  _set_if($card, 'prodId',   _first_value($props, 'prodid'));
  _set_if($card, 'updated',  _first_value($props, 'rev'), \&_to_utc_datetime);
  _set_if($card, 'created',  _first_value($props, 'created'), \&_to_utc_datetime);
  _set_if($card, 'language', _first_value($props, 'language'));

  # Complex properties
  _convert_name($card, $props);
  _convert_nicknames($card, $props, $new_id);
  _convert_emails($card, $props, $new_id);
  _convert_phones($card, $props, $new_id);
  _convert_addresses($card, $props, $new_id);
  _convert_organizations($card, $props, $new_id);
  _convert_titles($card, $props, $new_id);
  _convert_anniversaries($card, $props, $new_id);
  _convert_notes($card, $props, $new_id);
  _convert_online_services($card, $props, $new_id);
  _convert_media($card, $props, $new_id);
  _convert_links($card, $props, $new_id);
  _convert_calendars($card, $props, $new_id);
  _convert_scheduling_addresses($card, $props, $new_id);
  _convert_crypto_keys($card, $props, $new_id);
  _convert_directories($card, $props, $new_id);
  _convert_preferred_languages($card, $props, $new_id);
  _convert_personal_info($card, $props, $new_id);
  _convert_keywords($card, $props);
  _convert_members($card, $props);
  _convert_related($card, $props);
  _convert_speak_to_as($card, $props, $new_id);

  return $card;
}

###############################################################################
# INDIVIDUAL VCARD -> JSCONTACT CONVERTERS
###############################################################################

# FN + N -> name
sub _convert_name {
  my ($card, $props) = @_;
  my $name = {};

  my $fn = _first_value($props, 'fn');
  $name->{full} = _decode_value($fn) if defined $fn;

  my $n_prop = _first_prop($props, 'n');
  if ($n_prop) {
    my $values = $n_prop->{values} || [];
    # N component order: surname, given, given2, title(prefix), credential(suffix), surname2, generation
    my @kind_map = qw(surname given given2 title credential surname2 generation);

    my @components;
    for my $idx (0..$#kind_map) {
      my $raw = $values->[$idx];
      next unless defined $raw;
      # Handle both arrayref and string; split comma-separated values
      my @vals;
      for my $v (ref $raw eq 'ARRAY' ? @$raw : ($raw)) {
        push @vals, split /,/, $v;
      }
      for my $v (@vals) {
        next unless defined $v && $v ne '';
        push @components, {
          '@type' => 'NameComponent',
          kind  => $kind_map[$idx],
          value => _decode_value($v),
        };
      }
    }

    $name->{components} = \@components if @components;

    # SORT-AS parameter
    my $sort_as_param = _param($n_prop, 'sort-as');
    if ($sort_as_param) {
      my @sa = split /,/, $sort_as_param;
      my %sort_map;
      for my $i (0..$#sa) {
        $sort_map{$kind_map[$i]} = $sa[$i]
          if $i <= $#kind_map && defined $sa[$i] && $sa[$i] ne '';
      }
      $name->{sortAs} = \%sort_map if %sort_map;
    }
  }

  # Apple X-PHONETIC-*-NAME -> phonetic name components
  my $phonFirst = _first_value($props, 'x-phonetic-first-name');
  my $phonLast  = _first_value($props, 'x-phonetic-last-name');
  my $phonMid   = _first_value($props, 'x-phonetic-middle-name');
  if ($phonFirst || $phonLast || $phonMid) {
    my @phon;
    push @phon, { '@type' => 'NameComponent', kind => 'given',   value => _decode_value($phonFirst), phonetic => 'ipa' } if $phonFirst;
    push @phon, { '@type' => 'NameComponent', kind => 'given2',  value => _decode_value($phonMid),   phonetic => 'ipa' } if $phonMid;
    push @phon, { '@type' => 'NameComponent', kind => 'surname', value => _decode_value($phonLast),  phonetic => 'ipa' } if $phonLast;
    $name->{phoneticComponents} = \@phon;
  }

  $card->{name} = $name if %$name;
}

# NICKNAME -> nicknames
sub _convert_nicknames {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{nickname} || return;

  my %map;
  for my $item (@$items) {
    my $val = _decode_value($item->{value});
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => 'Nickname', name => $val };
    if (my $ctx = _make_contexts(_params_list($item, 'type'))) {
      $obj->{contexts} = $ctx;
    }
    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    $map{$id} = $obj;
  }

  $card->{nicknames} = \%map if %map;
}

# EMAIL -> emails
sub _convert_emails {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{email} || return;
  my $labels = _collect_labels($props);

  my %map;
  for my $item (@$items) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => 'EmailAddress', address => $val };
    if (my $ctx = _make_contexts(_params_list($item, 'type'))) {
      $obj->{contexts} = $ctx;
    }
    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    _apply_label($obj, $item, $labels);
    $map{$id} = $obj;
  }

  $card->{emails} = \%map if %map;
}

# TEL -> phones
sub _convert_phones {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{tel} || return;
  my $labels = _collect_labels($props);

  my %tel_feature_map = (
    cell => 'mobile', voice => 'voice', fax => 'fax',
    video => 'video', pager => 'pager', text => 'text',
    textphone => 'textphone',
  );

  my %map;
  for my $item (@$items) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => 'Phone', number => $val };

    my @types = _params_list($item, 'type');
    if (my $ctx = _make_contexts(@types)) {
      $obj->{contexts} = $ctx;
    }

    my %features;
    for my $t (@types) {
      my $feat = $tel_feature_map{lc $t};
      $features{$feat} = JSON::true if $feat;
    }
    $obj->{features} = \%features if %features;

    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    _apply_label($obj, $item, $labels);
    $map{$id} = $obj;
  }

  $card->{phones} = \%map if %map;
}

# ADR -> addresses (+ GEO, TZ by group association)
sub _convert_addresses {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{adr} || return;
  my $labels = _collect_labels($props);

  # Collect grouped GEO/TZ for association with ADR
  my %geo_by_group;
  my %tz_by_group;
  for my $geo (@{$props->{geo} // []}) {
    $geo_by_group{$geo->{group}} = $geo->{value} if $geo->{group};
  }
  for my $tz (@{$props->{tz} // []}) {
    $tz_by_group{$tz->{group}} = $tz->{value} if $tz->{group};
  }

  my %map;
  for my $item (@$items) {
    my $id = _prop_id($item, $new_id);
    my $values = $item->{values} || [];
    my $obj = { '@type' => 'Address' };

    # Build components from ADR structured value
    # Indices: 0=POBox 1=Extended 2=Street 3=Locality 4=Region 5=PostCode 6=Country
    my @components;
    for my $v (_adr_values($values, 2)) {
      push @components, { '@type' => 'AddressComponent', kind => 'name', value => _decode_value($v) };
    }
    for my $v (_adr_values($values, 1)) {
      push @components, { '@type' => 'AddressComponent', kind => 'apartment', value => _decode_value($v) };
    }
    for my $v (_adr_values($values, 3)) {
      push @components, { '@type' => 'AddressComponent', kind => 'locality', value => _decode_value($v) };
    }
    for my $v (_adr_values($values, 4)) {
      push @components, { '@type' => 'AddressComponent', kind => 'region', value => _decode_value($v) };
    }
    for my $v (_adr_values($values, 5)) {
      push @components, { '@type' => 'AddressComponent', kind => 'postcode', value => _decode_value($v) };
    }
    for my $v (_adr_values($values, 6)) {
      push @components, { '@type' => 'AddressComponent', kind => 'country', value => _decode_value($v) };
    }
    $obj->{components} = \@components if @components;

    # Parameters
    my $label_param = _param($item, 'label');
    $obj->{full} = $label_param if defined $label_param;

    my $geo = _param($item, 'geo');
    $geo //= $geo_by_group{$item->{group}} if $item->{group};
    $obj->{coordinates} = $geo if defined $geo;

    my $tz = _param($item, 'tz');
    $tz //= $tz_by_group{$item->{group}} if $item->{group};
    $obj->{timeZone} = $tz if defined $tz;

    my $cc = _param($item, 'cc');
    # Apple X-ABADR grouped with ADR
    if (!$cc && $item->{group}) {
      for my $xabadr (@{$props->{'x-abadr'} // []}) {
        if (($xabadr->{group} // '') eq $item->{group}) {
          $cc = $xabadr->{value};
          last;
        }
      }
    }
    $obj->{countryCode} = $cc if defined $cc;

    my @types = _params_list($item, 'type');
    if (my $ctx = _make_contexts(@types)) {
      $obj->{contexts} = $ctx;
    }
    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    _apply_label($obj, $item, $labels);

    $map{$id} = $obj;
  }

  $card->{addresses} = \%map if %map;
}

# ORG -> organizations
sub _convert_organizations {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{org} || return;

  my %map;
  for my $item (@$items) {
    my $id = _prop_id($item, $new_id);
    my $values = $item->{values} || [];
    my $obj = { '@type' => 'Organization' };

    # First component -> name
    my @name_vals = ref $values->[0] eq 'ARRAY' ? @{$values->[0]} : ($values->[0] // ());
    my $org_name = join(' ', grep { defined $_ && $_ ne '' } @name_vals);
    $obj->{name} = $org_name if $org_name ne '';

    # Subsequent components -> units
    my @units;
    for my $i (1..$#$values) {
      my @vals = ref $values->[$i] eq 'ARRAY' ? @{$values->[$i]} : ($values->[$i]);
      for my $v (@vals) {
        next unless defined $v && $v ne '';
        push @units, { '@type' => 'OrgUnit', name => _decode_value($v) };
      }
    }
    $obj->{units} = \@units if @units;

    # SORT-AS
    my $sort_as = _param($item, 'sort-as');
    if (defined $sort_as) {
      my @sa = split /,/, $sort_as;
      $obj->{sortAs} = $sa[0] if defined $sa[0] && $sa[0] ne '';
      for my $i (0..$#units) {
        $units[$i]{sortAs} = $sa[$i+1] if defined $sa[$i+1] && $sa[$i+1] ne '';
      }
    }

    my @types = _params_list($item, 'type');
    if (my $ctx = _make_contexts(@types)) {
      $obj->{contexts} = $ctx;
    }

    $map{$id} = $obj;
  }

  $card->{organizations} = \%map if %map;
}

# TITLE + ROLE -> titles
sub _convert_titles {
  my ($card, $props, $new_id) = @_;

  my %map;
  for my $spec (['title', 'title'], ['role', 'role']) {
    my ($propname, $kind) = @$spec;
    for my $item (@{$props->{$propname} // []}) {
      my $val = _decode_value($item->{value});
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      $map{$id} = { '@type' => 'Title', kind => $kind, name => $val };
    }
  }

  $card->{titles} = \%map if %map;
}

# BDAY, ANNIVERSARY, DEATHDATE, X-ABDATE -> anniversaries
sub _convert_anniversaries {
  my ($card, $props, $new_id) = @_;
  my $labels = _collect_labels($props);

  my %map;
  for my $spec (['bday', 'birth'], ['anniversary', 'wedding'], ['deathdate', 'death']) {
    my ($propname, $kind) = @$spec;
    for my $item (@{$props->{$propname} // []}) {
      my $val = $item->{value};
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      $map{$id} = {
        '@type' => 'Anniversary',
        kind  => $kind,
        date  => _convert_vcard_date($val),
      };
    }
  }

  # Apple X-ABDATE + X-ABLabel -> anniversaries
  for my $item (@{$props->{'x-abdate'} // []}) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);

    my $kind = 'other';
    if (my $group = $item->{group}) {
      my $label = $labels->{$group};
      if ($label) {
        my $lt = lc $label;
        if ($lt eq 'anniversary') { $kind = 'wedding' }
        elsif ($lt eq 'other') { $kind = 'other' }
        else { $kind = $lt }
      }
    }

    $map{$id} = {
      '@type' => 'Anniversary',
      kind  => $kind,
      date  => _convert_vcard_date($val),
    };
  }

  $card->{anniversaries} = \%map if %map;
}

# NOTE -> notes
sub _convert_notes {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{note} || return;

  my %map;
  for my $item (@$items) {
    my $val = _decode_value($item->{value});
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => 'Note', note => $val };

    my $created = _param($item, 'created');
    $obj->{created} = _to_utc_datetime($created) if defined $created;

    my $author_name = _param($item, 'author-name');
    my $author_uri  = _param($item, 'author');
    if ($author_name || $author_uri) {
      my $author = {};
      $author->{name} = $author_name if $author_name;
      $author->{uri}  = $author_uri  if $author_uri;
      $obj->{author} = $author;
    }

    $map{$id} = $obj;
  }

  $card->{notes} = \%map if %map;
}

# IMPP, SOCIALPROFILE, X-SOCIALPROFILE -> onlineServices
sub _convert_online_services {
  my ($card, $props, $new_id) = @_;
  my $labels = _collect_labels($props);

  my %map;

  for my $item (@{$props->{impp} // []}) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => 'OnlineService', uri => $val };
    my $service = _param($item, 'x-service-type');
    $obj->{service} = $service if defined $service;
    my $user = _param($item, 'x-user');
    $obj->{user} = $user if defined $user;
    my @types = _params_list($item, 'type');
    if (my $ctx = _make_contexts(@types)) { $obj->{contexts} = $ctx }
    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    _apply_label($obj, $item, $labels);
    $map{$id} = $obj;
  }

  for my $propname (qw(socialprofile x-socialprofile)) {
    for my $item (@{$props->{$propname} // []}) {
      my $val = $item->{value};
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      my $obj = { '@type' => 'OnlineService' };

      if ($val =~ m{://}) { $obj->{uri} = $val }
      else                { $obj->{user} = $val }

      my $service = _param($item, 'service-type') // _param($item, 'x-service-type');
      unless ($service) {
        for my $t (_params_list($item, 'type')) {
          my $lt = lc $t;
          if ($lt ne 'home' && $lt ne 'work' && $lt ne 'pref') {
            $service = $lt;
            last;
          }
        }
      }
      $obj->{service} = $service if defined $service;

      my $user = _param($item, 'x-user') // _param($item, 'username');
      $obj->{user} = $user if defined $user && !$obj->{user};

      my @types = _params_list($item, 'type');
      if (my $ctx = _make_contexts(@types)) { $obj->{contexts} = $ctx }
      if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
      _apply_label($obj, $item, $labels);
      $map{$id} = $obj;
    }
  }

  # Legacy X-service IM properties (Apple/others)
  my %xservice_map = (
    'x-aim'     => 'AIM',
    'x-icq'     => 'ICQ',
    'x-msn'     => 'MSN',
    'x-yahoo'   => 'Yahoo',
    'x-jabber'  => 'Jabber',
    'x-skype'   => 'Skype',
    'x-skype-username' => 'Skype',
    'x-twitter' => 'Twitter',
    'x-google-talk' => 'GoogleTalk',
  );
  for my $propname (sort keys %xservice_map) {
    for my $item (@{$props->{$propname} // []}) {
      my $val = $item->{value};
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      my $obj = { '@type' => 'OnlineService', user => $val, service => $xservice_map{$propname} };
      my @types = _params_list($item, 'type');
      if (my $ctx = _make_contexts(@types)) { $obj->{contexts} = $ctx }
      if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
      _apply_label($obj, $item, $labels);
      $map{$id} = $obj;
    }
  }

  $card->{onlineServices} = \%map if %map;
}

# PHOTO, LOGO, SOUND -> media
sub _convert_media {
  my ($card, $props, $new_id) = @_;
  my $labels = _collect_labels($props);

  my %map;
  for my $spec (['photo', 'photo'], ['logo', 'logo'], ['sound', 'sound']) {
    my ($propname, $kind) = @$spec;
    for my $item (@{$props->{$propname} // []}) {
      my $val = $item->{value};
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      my $obj = { '@type' => 'Media', kind => $kind };

      my $encoding = _param($item, 'encoding');
      if ($encoding && lc($encoding) eq 'b') {
        my $mediatype = _param($item, 'mediatype') // _param($item, 'type');
        $mediatype = "image/$mediatype" if $mediatype && $mediatype !~ m{/};
        $mediatype //= 'application/octet-stream';
        $obj->{uri}       = "data:$mediatype;base64," . encode_base64($val, '');
        $obj->{mediaType} = $mediatype;
      } else {
        $obj->{uri} = $val;
        my $mt = _param($item, 'mediatype');
        $obj->{mediaType} = $mt if defined $mt;
      }

      if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
      _apply_label($obj, $item, $labels);
      $map{$id} = $obj;
    }
  }

  $card->{media} = \%map if %map;
}

# Generic resource converter for URI-based properties
sub _convert_resource_to {
  my ($card, $key, $props, $propname, $kind, $new_id, $type) = @_;
  my $labels = _collect_labels($props);

  my %map;
  for my $item (@{$props->{$propname} // []}) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => $type, uri => $val };
    $obj->{kind} = $kind if defined $kind;
    my $mt = _param($item, 'mediatype');
    $obj->{mediaType} = $mt if defined $mt;
    my @types = _params_list($item, 'type');
    if (my $ctx = _make_contexts(@types)) { $obj->{contexts} = $ctx }
    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    _apply_label($obj, $item, $labels);
    $map{$id} = $obj;
  }

  if (%map) {
    $card->{$key} = { %{$card->{$key} // {}}, %map };
  }
}

# URL, FBURL, CONTACT-URI -> links
sub _convert_links {
  my ($card, $props, $new_id) = @_;
  _convert_resource_to($card, 'links', $props, 'url',         undef,     $new_id, 'Link');
  _convert_resource_to($card, 'links', $props, 'fburl',       'freeBusy', $new_id, 'Link');
  _convert_resource_to($card, 'links', $props, 'contact-uri', 'contact', $new_id, 'Link');
}

# CALURI -> calendars
sub _convert_calendars {
  my ($card, $props, $new_id) = @_;
  _convert_resource_to($card, 'calendars', $props, 'caluri', undef, $new_id, 'Calendar');
}

# CALADRURI -> schedulingAddresses
sub _convert_scheduling_addresses {
  my ($card, $props, $new_id) = @_;
  _convert_resource_to($card, 'schedulingAddresses', $props, 'caladruri', undef, $new_id, 'SchedulingAddress');
}

# KEY -> cryptoKeys
sub _convert_crypto_keys {
  my ($card, $props, $new_id) = @_;
  _convert_resource_to($card, 'cryptoKeys', $props, 'key', undef, $new_id, 'CryptoKey');
}

# SOURCE, ORG-DIRECTORY -> directories
sub _convert_directories {
  my ($card, $props, $new_id) = @_;
  _convert_resource_to($card, 'directories', $props, 'source',        'entry',     $new_id, 'Directory');
  _convert_resource_to($card, 'directories', $props, 'org-directory', 'directory', $new_id, 'Directory');
}

# LANG -> preferredLanguages
sub _convert_preferred_languages {
  my ($card, $props, $new_id) = @_;
  my $items = $props->{lang} || return;

  my %map;
  for my $item (@$items) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';
    my $id = _prop_id($item, $new_id);
    my $obj = { '@type' => 'LanguagePref', language => $val };
    my @types = _params_list($item, 'type');
    if (my $ctx = _make_contexts(@types)) { $obj->{contexts} = $ctx }
    if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
    $map{$id} = $obj;
  }

  $card->{preferredLanguages} = \%map if %map;
}

# EXPERTISE, HOBBY, INTEREST -> personalInfo
sub _convert_personal_info {
  my ($card, $props, $new_id) = @_;

  my %level_map = (beginner => 'low', average => 'medium', expert => 'high');
  my %map;

  for my $spec (['expertise', 'expertise'], ['hobby', 'hobby'], ['interest', 'interest']) {
    my ($propname, $kind) = @$spec;
    for my $item (@{$props->{$propname} // []}) {
      my $val = _decode_value($item->{value});
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      my $obj = { '@type' => 'PersonalInfo', kind => $kind, value => $val };

      my $level = _param($item, 'level');
      if ($level) {
        $obj->{level} = $level_map{lc $level} // lc $level;
      }

      my $index = _param($item, 'index');
      $obj->{listAs} = $index + 0 if defined $index;

      $map{$id} = $obj;
    }
  }

  $card->{personalInfo} = \%map if %map;
}

# CATEGORIES -> keywords
sub _convert_keywords {
  my ($card, $props) = @_;
  my $items = $props->{categories} || return;

  my %keywords;
  for my $item (@$items) {
    my $val = $item->{value};
    next unless defined $val;
    for my $cat (split /,/, $val) {
      $cat =~ s/^\s+//;
      $cat =~ s/\s+$//;
      $keywords{$cat} = JSON::true if $cat ne '';
    }
  }

  $card->{keywords} = \%keywords if %keywords;
}

# MEMBER / X-ADDRESSBOOKSERVER-MEMBER -> members
sub _convert_members {
  my ($card, $props) = @_;

  my %members;
  for my $propname (qw(member x-addressbookserver-member)) {
    for my $item (@{$props->{$propname} // []}) {
      my $val = $item->{value};
      next unless defined $val && $val ne '';
      $members{$val} = JSON::true;
    }
  }

  $card->{members} = \%members if %members;
}

# RELATED / X-ABRELATEDNAMES -> relatedTo
sub _convert_related {
  my ($card, $props) = @_;
  my $labels = _collect_labels($props);

  my %related;

  # Standard RELATED property
  for my $item (@{$props->{related} // []}) {
    my $val = $item->{value};
    next unless defined $val && $val ne '';

    my $rel = { '@type' => 'Relation' };
    my %relation;
    for my $t (_params_list($item, 'type')) {
      my $lt = lc $t;
      $relation{$lt} = JSON::true
        if $lt =~ /^(acquaintance|agent|child|co-resident|co-worker|colleague|contact|crush|date|emergency|friend|kin|me|met|muse|neighbor|parent|sibling|spouse|sweetheart)$/;
    }
    $rel->{relation} = \%relation if %relation;
    $related{$val} = $rel;
  }

  # Apple X-ABRELATEDNAMES + X-ABLabel -> relatedTo
  my %ablabel_relation = (
    'mother' => 'parent', 'father' => 'parent', 'parent' => 'parent',
    'brother' => 'sibling', 'sister' => 'sibling',
    'child' => 'child',
    'friend' => 'friend',
    'spouse' => 'spouse', 'partner' => 'spouse',
    'assistant' => 'colleague', 'manager' => 'colleague',
  );
  for my $item (@{$props->{'x-abrelatednames'} // []}) {
    my $val = _decode_value($item->{value});
    next unless defined $val && $val ne '';

    my $rel = { '@type' => 'Relation' };
    my %relation;

    # Get relation type from X-ABLabel
    my $label;
    if (my $group = $item->{group}) {
      $label = $labels->{$group};
    }
    if ($label) {
      my $lt = lc $label;
      if (my $mapped = $ablabel_relation{$lt}) {
        $relation{$mapped} = JSON::true;
      }
    }
    $rel->{relation} = \%relation if %relation;
    $related{$val} = $rel;
  }

  $card->{relatedTo} = \%related if %related;
}

# GRAMGENDER, PRONOUNS (RFC 9554) -> speakToAs
sub _convert_speak_to_as {
  my ($card, $props, $new_id) = @_;

  my $speak = {};

  if (my $gg = _first_value($props, 'gramgender')) {
    $speak->{grammaticalGender} = lc $gg;
  }

  if (my $items = $props->{pronouns}) {
    my %pronouns;
    for my $item (@$items) {
      my $val = _decode_value($item->{value});
      next unless defined $val && $val ne '';
      my $id = _prop_id($item, $new_id);
      my $obj = { '@type' => 'Pronouns', pronouns => $val };
      if (my $ctx = _make_contexts(_params_list($item, 'type'))) {
        $obj->{contexts} = $ctx;
      }
      if (my $pref = _make_pref($item)) { $obj->{pref} = $pref }
      $pronouns{$id} = $obj;
    }
    $speak->{pronouns} = \%pronouns if %pronouns;
  }

  $card->{speakToAs} = $speak if %$speak;
}

###############################################################################
# JSCONTACT -> VCARD
###############################################################################

sub jscontact_to_vcard {
  my ($card) = @_;

  _reset_groups();
  my @props;

  # VERSION (always 4.0)
  push @props, { name => 'version', value => '4.0' };

  # UID
  push @props, { name => 'uid', value => $card->{uid} } if $card->{uid};

  # KIND
  push @props, { name => 'kind', value => $card->{kind} }
    if $card->{kind} && $card->{kind} ne 'individual';

  # PRODID
  push @props, { name => 'prodid', value => $card->{prodId} } if $card->{prodId};

  # REV
  push @props, { name => 'rev', value => $card->{updated} } if $card->{updated};

  # CREATED (RFC 9554)
  push @props, { name => 'created', value => $card->{created} } if $card->{created};

  # LANGUAGE (RFC 9554)
  push @props, { name => 'language', value => $card->{language} } if $card->{language};

  # Name -> N + FN
  _unconvert_name(\@props, $card);

  # All map-based properties
  _unconvert_nicknames(\@props, $card);
  _unconvert_emails(\@props, $card);
  _unconvert_phones(\@props, $card);
  _unconvert_addresses(\@props, $card);
  _unconvert_organizations(\@props, $card);
  _unconvert_titles(\@props, $card);
  _unconvert_anniversaries(\@props, $card);
  _unconvert_notes(\@props, $card);
  _unconvert_online_services(\@props, $card);
  _unconvert_media(\@props, $card);
  _unconvert_links(\@props, $card);
  _unconvert_calendars(\@props, $card);
  _unconvert_scheduling_addresses(\@props, $card);
  _unconvert_crypto_keys(\@props, $card);
  _unconvert_directories(\@props, $card);
  _unconvert_preferred_languages(\@props, $card);
  _unconvert_personal_info(\@props, $card);
  _unconvert_keywords(\@props, $card);
  _unconvert_members(\@props, $card);
  _unconvert_related(\@props, $card);
  _unconvert_speak_to_as(\@props, $card);

  # Build vcard hash structure
  my %by_name;
  for my $prop (@props) {
    $prop->{params} //= {};
    push @{$by_name{$prop->{name}}}, $prop;
  }

  my $vcard = {
    type       => 'vcard',
    properties => \%by_name,
  };

  return hash2vcard({ objects => [$vcard] });
}

###############################################################################
# INDIVIDUAL JSCONTACT -> VCARD CONVERTERS
###############################################################################

sub _contexts_to_types {
  my $contexts = shift;
  return () unless $contexts && ref $contexts eq 'HASH';
  my @types;
  push @types, 'home'  if $contexts->{private};
  push @types, 'work' if $contexts->{work};
  return @types;
}

sub _add_pref_params {
  my ($params, $pref) = @_;
  $params->{pref} = [$pref] if defined $pref;
}

{
  my $group_counter = 0;
  sub _reset_groups { $group_counter = 0 }

  sub _add_label {
    my ($out, $prop, $obj) = @_;
    my $label = $obj->{label};
    return unless defined $label && $label ne '';

    $group_counter++;
    my $group = "item$group_counter";
    $prop->{group} = $group;
    push @$out, {
      name   => 'x-ablabel',
      value  => $label,
      params => {},
      group  => $group,
    };
  }
}

sub _add_context_params {
  my ($params, $obj) = @_;
  if ($obj->{contexts}) {
    my @types = _contexts_to_types($obj->{contexts});
    push @{$params->{type}}, @types if @types;
  }
}

sub _unconvert_name {
  my ($out, $card) = @_;
  my $name = $card->{name} || return;

  # FN
  if (my $full = $name->{full}) {
    push @$out, { name => 'fn', value => $full, params => {} };
  }

  # N from components
  if (my $components = $name->{components}) {
    my %by_kind;
    for my $c (@$components) {
      push @{$by_kind{$c->{kind}}}, $c->{value};
    }

    # N order: surname, given, given2(additional), title(prefix), credential(suffix), surname2, generation
    my @n_values;
    for my $kind (qw(surname given given2 title credential surname2 generation)) {
      my $vals = $by_kind{$kind};
      push @n_values, $vals ? join(',', grep { defined $_ } @$vals) : '';
    }

    # Trim trailing empty components
    pop @n_values while @n_values && $n_values[-1] eq '';

    my $params = {};
    if ($name->{sortAs} && ref $name->{sortAs} eq 'HASH') {
      my @sa;
      for my $kind (qw(surname given given2 title credential surname2 generation)) {
        push @sa, $name->{sortAs}{$kind} // '';
      }
      pop @sa while @sa && $sa[-1] eq '';
      $params->{'sort-as'} = [join(',', @sa)] if @sa;
    }

    push @$out, { name => 'n', values => \@n_values, params => $params };
  }

  # Generate FN from components if no full name given
  if (!$name->{full} && $name->{components}) {
    my @parts;
    for my $c (@{$name->{components}}) {
      next if ($c->{kind} // '') eq 'separator';
      push @parts, $c->{value};
    }
    push @$out, { name => 'fn', value => join(' ', @parts), params => {} } if @parts;
  }
}

sub _unconvert_nicknames {
  my ($out, $card) = @_;
  my $nicknames = $card->{nicknames} || return;

  for my $id (sort keys %$nicknames) {
    my $nn = $nicknames->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $nn);
    _add_pref_params($params, $nn->{pref});
    push @$out, { name => 'nickname', value => $nn->{name}, params => $params };
  }
}

sub _unconvert_emails {
  my ($out, $card) = @_;
  my $emails = $card->{emails} || return;

  for my $id (sort keys %$emails) {
    my $em = $emails->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $em);
    _add_pref_params($params, $em->{pref});
    my $prop = { name => 'email', value => $em->{address}, params => $params };
    _add_label($out, $prop, $em);
    push @$out, $prop;
  }
}

sub _unconvert_phones {
  my ($out, $card) = @_;
  my $phones = $card->{phones} || return;

  my %feature_to_type = (
    mobile => 'cell', voice => 'voice', fax => 'fax',
    video => 'video', pager => 'pager', text => 'text',
    textphone => 'textphone',
  );

  for my $id (sort keys %$phones) {
    my $ph = $phones->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $ph);
    _add_pref_params($params, $ph->{pref});

    if ($ph->{features}) {
      for my $feat (sort keys %{$ph->{features}}) {
        my $type = $feature_to_type{$feat};
        push @{$params->{type}}, $type if $type;
      }
    }

    my $prop = { name => 'tel', value => $ph->{number}, params => $params };
    _add_label($out, $prop, $ph);
    push @$out, $prop;
  }
}

sub _unconvert_addresses {
  my ($out, $card) = @_;
  my $addresses = $card->{addresses} || return;

  my %kind_to_idx = (
    name => 2, apartment => 1,
    locality => 3, region => 4, postcode => 5, country => 6,
  );

  for my $id (sort keys %$addresses) {
    my $adr = $addresses->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $adr);
    _add_pref_params($params, $adr->{pref});

    $params->{label} = [$adr->{full}]        if $adr->{full};
    $params->{geo}   = [$adr->{coordinates}] if $adr->{coordinates};
    $params->{tz}    = [$adr->{timeZone}]    if $adr->{timeZone};
    $params->{cc}    = [$adr->{countryCode}] if $adr->{countryCode};

    # Build ADR values (7 standard components)
    my @values = ('') x 7;

    if (my $components = $adr->{components}) {
      my %by_idx;
      for my $c (@$components) {
        next if ($c->{kind} // '') eq 'separator';
        my $idx = $kind_to_idx{$c->{kind}};
        push @{$by_idx{$idx}}, $c->{value} if defined $idx;
      }
      for my $idx (keys %by_idx) {
        $values[$idx] = join(',', @{$by_idx{$idx}});
      }
    }

    push @$out, { name => 'adr', values => \@values, params => $params };
  }
}

sub _unconvert_organizations {
  my ($out, $card) = @_;
  my $orgs = $card->{organizations} || return;

  for my $id (sort keys %$orgs) {
    my $org = $orgs->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $org);

    my @values = ($org->{name} // '');
    if ($org->{units}) {
      for my $unit (@{$org->{units}}) {
        push @values, $unit->{name};
      }
    }

    if (defined $org->{sortAs}) {
      my @sa = ($org->{sortAs});
      if ($org->{units}) {
        for my $unit (@{$org->{units}}) {
          push @sa, $unit->{sortAs} // '';
        }
      }
      pop @sa while @sa && $sa[-1] eq '';
      $params->{'sort-as'} = [join(',', @sa)] if @sa;
    }

    push @$out, { name => 'org', values => \@values, params => $params };
  }
}

sub _unconvert_titles {
  my ($out, $card) = @_;
  my $titles = $card->{titles} || return;

  for my $id (sort keys %$titles) {
    my $t = $titles->{$id};
    my $propname = ($t->{kind} // 'title') eq 'role' ? 'role' : 'title';
    my $params = { 'prop-id' => [$id] };
    push @$out, { name => $propname, value => $t->{name}, params => $params };
  }
}

sub _unconvert_anniversaries {
  my ($out, $card) = @_;
  my $anns = $card->{anniversaries} || return;

  my %kind_to_prop = (birth => 'bday', wedding => 'anniversary', death => 'deathdate');

  for my $id (sort keys %$anns) {
    my $ann = $anns->{$id};
    my $kind = $ann->{kind} // '';
    my $propname = $kind_to_prop{$kind} // 'anniversary';
    my $params = { 'prop-id' => [$id] };

    my $date = $ann->{date} // '';
    # Convert unknown-year dates to vCard 4 format
    $date = "--$1$2" if $date =~ /^0000-(\d{2})-(\d{2})/;

    push @$out, { name => $propname, value => $date, params => $params };
  }
}

sub _unconvert_notes {
  my ($out, $card) = @_;
  my $notes = $card->{notes} || return;

  for my $id (sort keys %$notes) {
    my $note = $notes->{$id};
    my $params = { 'prop-id' => [$id] };

    if ($note->{created}) {
      $params->{created} = [$note->{created}];
    }
    if ($note->{author}) {
      $params->{'author-name'} = [$note->{author}{name}] if $note->{author}{name};
      $params->{author}        = [$note->{author}{uri}]   if $note->{author}{uri};
    }

    push @$out, { name => 'note', value => $note->{note}, params => $params };
  }
}

sub _unconvert_online_services {
  my ($out, $card) = @_;
  my $services = $card->{onlineServices} || return;

  for my $id (sort keys %$services) {
    my $svc = $services->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $svc);
    _add_pref_params($params, $svc->{pref});

    $params->{'service-type'} = [$svc->{service}] if $svc->{service};
    $params->{username}       = [$svc->{user}]    if $svc->{user};

    my $uri = $svc->{uri} // $svc->{user} // '';
    push @$out, { name => 'impp', value => $uri, params => $params };
  }
}

sub _unconvert_media {
  my ($out, $card) = @_;
  my $media = $card->{media} || return;

  my %kind_to_prop = (photo => 'photo', logo => 'logo', sound => 'sound');

  for my $id (sort keys %$media) {
    my $m = $media->{$id};
    my $propname = $kind_to_prop{$m->{kind} // 'photo'} // 'photo';
    my $params = { 'prop-id' => [$id] };
    _add_pref_params($params, $m->{pref});
    $params->{mediatype} = [$m->{mediaType}] if $m->{mediaType};
    push @$out, { name => $propname, value => $m->{uri}, params => $params };
  }
}

sub _unconvert_links {
  my ($out, $card) = @_;
  my $links = $card->{links} || return;

  for my $id (sort keys %$links) {
    my $link = $links->{$id};
    my $kind = $link->{kind} // '';
    my $propname = $kind eq 'freeBusy' ? 'fburl'
                 : $kind eq 'contact'  ? 'contact-uri'
                 : 'url';
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $link);
    _add_pref_params($params, $link->{pref});
    $params->{mediatype} = [$link->{mediaType}] if $link->{mediaType};
    push @$out, { name => $propname, value => $link->{uri}, params => $params };
  }
}

sub _unconvert_resource {
  my ($out, $card, $key, $propname) = @_;
  my $resources = $card->{$key} || return;

  for my $id (sort keys %$resources) {
    my $r = $resources->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $r);
    _add_pref_params($params, $r->{pref});
    $params->{mediatype} = [$r->{mediaType}] if $r->{mediaType};
    push @$out, { name => $propname, value => $r->{uri}, params => $params };
  }
}

sub _unconvert_calendars {
  _unconvert_resource($_[0], $_[1], 'calendars', 'caluri');
}

sub _unconvert_scheduling_addresses {
  _unconvert_resource($_[0], $_[1], 'schedulingAddresses', 'caladruri');
}

sub _unconvert_crypto_keys {
  _unconvert_resource($_[0], $_[1], 'cryptoKeys', 'key');
}

sub _unconvert_directories {
  my ($out, $card) = @_;
  my $dirs = $card->{directories} || return;

  for my $id (sort keys %$dirs) {
    my $dir = $dirs->{$id};
    my $kind = $dir->{kind} // '';
    my $propname = $kind eq 'entry' ? 'source' : 'org-directory';
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $dir);
    _add_pref_params($params, $dir->{pref});
    $params->{mediatype} = [$dir->{mediaType}] if $dir->{mediaType};
    push @$out, { name => $propname, value => $dir->{uri}, params => $params };
  }
}

sub _unconvert_preferred_languages {
  my ($out, $card) = @_;
  my $langs = $card->{preferredLanguages} || return;

  for my $id (sort keys %$langs) {
    my $lp = $langs->{$id};
    my $params = { 'prop-id' => [$id] };
    _add_context_params($params, $lp);
    _add_pref_params($params, $lp->{pref});
    push @$out, { name => 'lang', value => $lp->{language}, params => $params };
  }
}

sub _unconvert_personal_info {
  my ($out, $card) = @_;
  my $info = $card->{personalInfo} || return;

  my %level_map = (low => 'beginner', medium => 'average', high => 'expert');

  for my $id (sort keys %$info) {
    my $pi = $info->{$id};
    my $propname = $pi->{kind} // 'expertise';
    my $params = { 'prop-id' => [$id] };
    if ($pi->{level}) {
      $params->{level} = [$level_map{$pi->{level}} // $pi->{level}];
    }
    if (defined $pi->{listAs}) {
      $params->{index} = [$pi->{listAs}];
    }
    push @$out, { name => $propname, value => $pi->{value}, params => $params };
  }
}

sub _unconvert_keywords {
  my ($out, $card) = @_;
  my $keywords = $card->{keywords} || return;
  return unless ref $keywords eq 'HASH' && %$keywords;
  push @$out, { name => 'categories', value => join(',', sort keys %$keywords), params => {} };
}

sub _unconvert_members {
  my ($out, $card) = @_;
  my $members = $card->{members} || return;
  for my $uid (sort keys %$members) {
    push @$out, { name => 'member', value => $uid, params => {} };
  }
}

sub _unconvert_members_apple {
  my ($out, $card) = @_;
  my $members = $card->{members} || return;
  for my $uid (sort keys %$members) {
    # Apple uses urn:uuid: prefix for member UIDs
    my $val = $uid;
    $val = "urn:uuid:$val" unless $val =~ /^urn:uuid:/;
    push @$out, { name => 'x-addressbookserver-member', value => $val, params => {} };
  }
}

sub _unconvert_related {
  my ($out, $card) = @_;
  my $related = $card->{relatedTo} || return;

  for my $uid (sort keys %$related) {
    my $rel = $related->{$uid};
    my $params = {};
    if ($rel->{relation} && ref $rel->{relation} eq 'HASH') {
      my @types = sort keys %{$rel->{relation}};
      $params->{type} = \@types if @types;
    }
    push @$out, { name => 'related', value => $uid, params => $params };
  }
}

sub _unconvert_speak_to_as {
  my ($out, $card) = @_;
  my $sta = $card->{speakToAs} || return;

  if ($sta->{grammaticalGender}) {
    push @$out, { name => 'gramgender', value => $sta->{grammaticalGender}, params => {} };
  }

  if ($sta->{pronouns}) {
    for my $id (sort keys %{$sta->{pronouns}}) {
      my $p = $sta->{pronouns}{$id};
      my $params = { 'prop-id' => [$id] };
      _add_context_params($params, $p);
      _add_pref_params($params, $p->{pref});
      push @$out, { name => 'pronouns', value => $p->{pronouns}, params => $params };
    }
  }
}

###############################################################################
# PATCH: Apply JSContact changes to an existing vCard with minimal disruption
###############################################################################

sub patch_vcard {
  my ($original_vcard, $old_card, $new_card) = @_;

  # Determine which top-level JSContact properties changed
  my %changed = _diff_cards($old_card, $new_card);

  # If nothing changed, return original
  return $original_vcard unless %changed;

  # Parse the original vCard into its raw structure
  my $parsed = eval { vcard2hash($original_vcard, multival => [qw(n adr org)]) };
  return jscontact_to_vcard($new_card) unless $parsed;

  my $vcard = $parsed->{objects}[0];
  return jscontact_to_vcard($new_card) unless $vcard && $vcard->{type} eq 'vcard';

  my $props = $vcard->{properties};

  # Detect which property names the original vCard actually uses, so we
  # generate matching ones (e.g. X-ADDRESSBOOKSERVER-MEMBER vs MEMBER)
  my %original_has;
  for my $name (keys %$props) {
    $original_has{lc $name} = 1 if $props->{$name} && @{$props->{$name}};
  }

  # For each changed property, regenerate just that part
  # Map JSContact property names to the vCard properties they affect
  my %jscontact_to_vcard_props = (
    name          => [qw(fn n x-phonetic-first-name x-phonetic-middle-name x-phonetic-last-name)],
    nicknames     => [qw(nickname)],
    emails        => [qw(email)],
    phones        => [qw(tel)],
    addresses     => [qw(adr x-abadr)],
    organizations => [qw(org)],
    titles        => [qw(title role)],
    anniversaries => [qw(bday anniversary deathdate x-abdate)],
    notes         => [qw(note)],
    onlineServices => [qw(impp socialprofile x-socialprofile x-aim x-icq x-msn x-yahoo x-jabber x-skype x-twitter x-google-talk x-skype-username)],
    media         => [qw(photo logo sound)],
    links         => [qw(url fburl contact-uri)],
    calendars     => [qw(caluri)],
    schedulingAddresses => [qw(caladruri)],
    cryptoKeys    => [qw(key)],
    directories   => [qw(source org-directory)],
    keywords      => [qw(categories)],
    members       => [qw(member x-addressbookserver-member)],
    relatedTo     => [qw(related x-abrelatednames)],
    speakToAs     => [qw(gramgender pronouns)],
    preferredLanguages => [qw(lang)],
    personalInfo  => [qw(expertise hobby interest)],
    # Simple scalar properties
    uid           => [qw(uid)],
    kind          => [qw(kind x-addressbookserver-kind)],
    prodId        => [qw(prodid)],
    updated       => [qw(rev)],
    created       => [qw(created)],
    language      => [qw(language)],
  );

  for my $js_prop (keys %changed) {
    my $vcard_names = $jscontact_to_vcard_props{$js_prop};
    next unless $vcard_names;

    # Remove old vCard properties for this JSContact property
    # Also remove any associated X-ABLabel grouped properties
    my %groups_to_remove;
    for my $vname (@$vcard_names) {
      for my $item (@{$props->{$vname} // []}) {
        $groups_to_remove{$item->{group}} = 1 if $item->{group};
      }
      delete $props->{$vname};
    }

    # Remove orphaned X-ABLabel entries for removed groups
    if (%groups_to_remove && $props->{'x-ablabel'}) {
      $props->{'x-ablabel'} = [
        grep { !$groups_to_remove{$_->{group} // ''} }
          @{$props->{'x-ablabel'}}
      ];
      delete $props->{'x-ablabel'} unless @{$props->{'x-ablabel'}};
    }
  }

  # Generate the new properties from the new card
  _reset_groups();
  my @new_props;

  # Generate only the changed properties
  if ($changed{name})          { _unconvert_name(\@new_props, $new_card) }
  if ($changed{nicknames})     { _unconvert_nicknames(\@new_props, $new_card) }
  if ($changed{emails})        { _unconvert_emails(\@new_props, $new_card) }
  if ($changed{phones})        { _unconvert_phones(\@new_props, $new_card) }
  if ($changed{addresses})     { _unconvert_addresses(\@new_props, $new_card) }
  if ($changed{organizations}) { _unconvert_organizations(\@new_props, $new_card) }
  if ($changed{titles})        { _unconvert_titles(\@new_props, $new_card) }
  if ($changed{anniversaries}) { _unconvert_anniversaries(\@new_props, $new_card) }
  if ($changed{notes})         { _unconvert_notes(\@new_props, $new_card) }
  if ($changed{onlineServices}){ _unconvert_online_services(\@new_props, $new_card) }
  if ($changed{media})         { _unconvert_media(\@new_props, $new_card) }
  if ($changed{links})         { _unconvert_links(\@new_props, $new_card) }
  if ($changed{calendars})     { _unconvert_calendars(\@new_props, $new_card) }
  if ($changed{schedulingAddresses}) { _unconvert_scheduling_addresses(\@new_props, $new_card) }
  if ($changed{cryptoKeys})    { _unconvert_crypto_keys(\@new_props, $new_card) }
  if ($changed{directories})   { _unconvert_directories(\@new_props, $new_card) }
  if ($changed{keywords})      { _unconvert_keywords(\@new_props, $new_card) }
  if ($changed{members}) {
    if ($original_has{'x-addressbookserver-member'}) {
      _unconvert_members_apple(\@new_props, $new_card);
    } else {
      _unconvert_members(\@new_props, $new_card);
    }
  }
  if ($changed{relatedTo})     { _unconvert_related(\@new_props, $new_card) }
  if ($changed{speakToAs})     { _unconvert_speak_to_as(\@new_props, $new_card) }
  if ($changed{preferredLanguages}) { _unconvert_preferred_languages(\@new_props, $new_card) }
  if ($changed{personalInfo})  { _unconvert_personal_info(\@new_props, $new_card) }

  # Simple scalar properties — use Apple property names when original has them
  for my $spec (['uid', 'uid'], ['prodId', 'prodid'],
                 ['updated', 'rev'], ['created', 'created'], ['language', 'language']) {
    my ($js, $vc) = @$spec;
    if ($changed{$js}) {
      if (defined $new_card->{$js} && $new_card->{$js} ne '') {
        push @new_props, { name => $vc, value => $new_card->{$js}, params => {} };
      }
    }
  }
  if ($changed{kind}) {
    if (defined $new_card->{kind} && $new_card->{kind} ne '') {
      my $propname = $original_has{'x-addressbookserver-kind'} ? 'x-addressbookserver-kind' : 'kind';
      push @new_props, { name => $propname, value => $new_card->{kind}, params => {} };
    }
  }

  # Merge new properties into the existing vCard
  for my $prop (@new_props) {
    $prop->{params} //= {};
    push @{$props->{$prop->{name}}}, $prop;
  }

  return hash2vcard({ objects => [$vcard] });
}

# Compare two JSContact cards and return hash of changed property names
sub _diff_cards {
  my ($old, $new) = @_;
  my $json = JSON->new->canonical->utf8;

  my %changed;

  # Check all keys in both old and new
  my %all_keys;
  $all_keys{$_} = 1 for keys %$old, keys %$new;

  # Skip internal/metadata keys
  delete $all_keys{$_} for qw(@type version CPath href _raw meta);

  for my $key (keys %all_keys) {
    my $old_val = $old->{$key};
    my $new_val = $new->{$key};

    # Both undef/missing -> no change
    next if !defined $old_val && !defined $new_val;

    # One exists, other doesn't -> changed
    if (!defined $old_val || !defined $new_val) {
      $changed{$key} = 1;
      next;
    }

    # Compare via canonical JSON encoding
    my $old_json = $json->encode([$old_val]);
    my $new_json = $json->encode([$new_val]);
    $changed{$key} = 1 if $old_json ne $new_json;
  }

  return %changed;
}

1;
