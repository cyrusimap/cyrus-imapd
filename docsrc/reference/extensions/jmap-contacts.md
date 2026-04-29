# JMAP for Contacts extensions

**Capability URI**: `https://cyrusimap.org/ns/jmap/contacts`

Requires `jmap_nonstandard_extensions` to be enabled in the Cyrus
configuration.

## Changes to AddressBook

### New Properties

- **mailboxUniqueId**: `String` (server-set)  The Cyrus internal unique id of
  the mailbox used for storing the AddressBook.

- **cyrusimap.org:href**: `String` (server-set)  The CardDAV URL of the address
  book collection on the server.

## Changes to ContactCard

### New Properties

- **cyrusimap.org:importance**: `Number`  A client-defined sort priority for
  the contact.  Lower values sort earlier.  Defaults to `0`.

- **cyrusimap.org:blobId**: `Id` (server-set)  The blob ID of the raw vCard
  data for this contact.

- **cyrusimap.org:size**: `UnsignedInt` (server-set)  The size in bytes of the
  stored vCard data.

- **cyrusimap.org:href**: `String` (server-set, immutable)  The CardDAV URL of
  this contact resource on the server.

## New Method: ContactCard/parse

This parses one or more vCard blobs and returns the resulting ContactCard
objects without storing them.

Method call arguments:

- **blobIds**: `Id[]`  An array of blob IDs to be parsed
- **properties**: `String[]`  The properties of each parsed card to be returned

Method response arguments:

- **parsed**: `id[Object]|null`  A map of blob id to parsed ContactCard
  representation for each successfully parsed blob, or null if none.

- **notParsable**: `Id[]|null`  A list of ids given that corresponded to blobs
  that could not be parsed as Emails, or null if none.

- **notFound**: `Id[]|null`  A list of blob ids given that could not be found,
  or null if none.
