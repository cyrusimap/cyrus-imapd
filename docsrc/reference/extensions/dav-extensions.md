# CalDAV and CardDAV Extensions

Cyrus implements several proprietary extensions to WebDAV, CalDAV, and CardDAV.
These extensions use Cyrus-specific XML namespaces, distinct from the standard
namespace URIs defined by the relevant RFCs.

## XML Namespaces

The `http://cyrusimap.org/ns/` namespace is used for Cyrus extensions,
conventionally using the prefix `CY`.

## Properties

### `CY:schedule-user-address`

This property can be found on **CalDAV resources**.

This stores the scheduling addresses associated with the authenticated user for
a particular calendar resource.  This is populated from the
`X-Schedule-User-Address` header stored with the calendar object in the IMAP
message store.  The property is presented as `DAV:href` children containing
`mailto:` URIs.

### `CY:scheduling-enabled`

This property can be found on **CalDAV collections**.

A boolean-like flag that controls whether CalDAV Auto-Schedule ({rfc}`6638`) is
advertised and active for a given calendar collection.  When absent or set to
any value other than `F` or `no`, scheduling is enabled (the default).  Setting
it to `F` or `no` suppresses the `calendar-auto-schedule` token from the `DAV:`
response header for that collection and prevents automatic iTIP processing for
events stored in it.

This property is read/write via `PROPPATCH`.  The `Scheduling-Enabled: F` HTTP
request header has the same suppression effect for individual calendar resource
PUT requests.

### `CY:address-groups`

This property can be found on **CardDAV resources**.

Lists the vCard groups (vCards with `KIND:group`) that contain this contact.
The property element has zero or more `CY:address-group` child elements, each
containing the UID of a group that includes this contact's UID in its member
list.

This property is read-only and is only meaningful on vCard resources.

## Privileges

Cyrus defines several sub-privileges in the `CY` namespace that refine the
standard WebDAV ACL privilege tree.  These appear in the
`DAV:supported-privilege-set` response for calendar and address book
collections.  They map to underlying Cyrus IMAP ACL bits as noted.

### Under `DAV:write-properties`

| Privilege                        | Description                      | IMAP ACL bit    |
|----------------------------------|----------------------------------|-----------------|
| `CY:write-properties-collection` | Write properties on a collection | w               |
| `CY:write-properties-resource`   | Write properties on a resource   | n               |

These are just the standard `DAV:write-properties` privilege, split into two
because Cyrus stores collection-level properties and resource-level properties
in different IMAP constructs with different ACL bits.

### Under `DAV:bind`

| Privilege            | Description                        | IMAP ACL bit |
|----------------------|------------------------------------|--------------|
| `CY:make-collection` | Create a new sub-collection        | k            |
| `CY:add-resource`    | Add a new resource to a collection | p            |

### Under `DAV:unbind`

| Privilege              | Description         | IMAP ACL bits  |
|------------------------|---------------------|----------------|
| `CY:remove-collection` | Delete a collection | x              |
| `CY:remove-resource`   | Delete a resource   | te             |

