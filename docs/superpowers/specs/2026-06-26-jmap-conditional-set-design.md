# JMAP Conditional Set (`urn:ietf:params:jmap:conditional`) — Cyrus Proof of Concept

## Goal

Implement `draft-gondwana-jmap-conditional-00` in Cyrus IMAPd as a proof of
concept, with broad coverage across the datatypes that support `Foo/set`.

The draft adds a per-object precondition argument, `ifUnchangedBy`, to every
`Foo/set` method. It provides narrow, `If-Match`-style concurrency control: a
change to a specific object is applied only if the properties the client read
still hold their expected values — avoiding the spurious whole-method
rejections that `ifInState` causes in busy accounts.

## Draft semantics (the contract we implement)

- **`ifUnchangedBy`**: an `Id[PatchObject]` map — object id → PatchObject. The
  precondition for an id is satisfied **iff applying that PatchObject to the
  current server-side object would leave the object unchanged**. Equivalently,
  every pointer in the patch already matches the object's current value at that
  location, with JSON `null` matching an absent property.
- **Scope**: applies only to existing ids that also appear in `update` or
  `destroy`. Creation ids (`#`-prefixed) are out of scope.
- **Timing**: preconditions evaluate against object state **before** any
  create/update/destroy in the same method.
- **Composition with `ifInState`**: `ifInState` is checked first; if it fails
  the whole method is rejected with `stateMismatch` (existing behavior).
  `ifUnchangedBy` is then evaluated per object.
- **Per-object independence**: a failed precondition on one id does not block
  other ids from succeeding.
- **Failure → `stateMismatch`**: a valid pointer whose value differs puts a
  `stateMismatch` SetError into `notUpdated` / `notDestroyed`. The SetError
  carries only the common `type` (and optional `description`); it discloses no
  object data — the client must re-`get` to learn current state.
- **Invalid pointer → `invalidPatch`**: a pointer not valid for the object type
  puts an `invalidPatch` SetError into `notUpdated` / `notDestroyed`.
- **Read-only / server-set properties are allowed** in preconditions (unlike
  update patches): e.g. `blobId`, `size`, timestamps, `threadId`.
- **Comparison representation**: comparison uses the representation the server
  would return for that property from `Foo/get`.
- **Activation**: server advertises `"urn:ietf:params:jmap:conditional": {}`;
  the client must list the URI in the request `using` array for the argument to
  be honored.

## Architecture

Three layers: capability registration/gating, a shared parse + compare helper,
and per-method integration. Comparison logic lives in one place; each `/set`
method supplies the current object representation it already has (or can build).

### 1. Capability registration & gating

- Add `#define JMAP_URN_CONDITIONAL "urn:ietf:params:jmap:conditional"` in
  `imap/jmap_api.h` (alongside the other `JMAP_URN_*` defines, ~line 27).
- Advertise it as an empty object `{}` in the server / per-account capabilities,
  mirroring how `JMAP_URN_BLOB` is added (`imap/jmap_api.c` ~line 989 and the
  `account_capabilities` construction in the per-datatype files as appropriate).
- Honor `ifUnchangedBy` only when `jmap_is_using(req, JMAP_URN_CONDITIONAL)` is
  true (`imap/jmap_api.c:3299`). When the capability is not in use, the argument
  is not parsed specially and falls through to existing unknown-argument
  handling — preserving current behavior exactly.

### 2. Shared parsing + compare helper

- Extend `struct jmap_set` (`imap/jmap_api.h:436`) with:
  ```c
  json_t *if_unchanged_by;   /* Id[PatchObject], NULL when capability not in use */
  ```
- In `jmap_set_parse` (`imap/jmap_api.c:1841`): when the capability is in use,
  parse the `ifUnchangedBy` argument into `set->if_unchanged_by` (a JSON object
  map of id → PatchObject). Validate it is an object; defer per-id PatchObject
  validation to evaluation time (so `invalidPatch` is reported per-id, as the
  draft requires). When the capability is not in use, leave it NULL.
- New shared helper in `imap/jmap_util.c` / `imap/jmap_util.h`:
  ```c
  enum jmap_precondition {
      JMAP_PRECOND_MATCH = 0,    /* applying patch is a no-op: precondition holds */
      JMAP_PRECOND_MISMATCH,     /* valid pointer(s), value differs -> stateMismatch */
      JMAP_PRECOND_INVALID       /* pointer invalid for object type -> invalidPatch */
  };

  /* Compare `patch` (a PatchObject precondition) against `current`
   * (the object's Foo/get representation). `invalid`, if non-NULL, receives
   * the offending pointers on JMAP_PRECOND_INVALID. */
  enum jmap_precondition jmap_precondition_check(json_t *current,
                                                 json_t *patch,
                                                 json_t **invalid);
  ```
  Implementation reuses `jmap_patchobject_apply(current, patch, invalid, flags)`
  (`imap/jmap_util.c:127`):
  - if `jmap_patchobject_apply` reports invalid pointers → `JMAP_PRECOND_INVALID`;
  - else deep-compare the patched result against `current` with `json_equal`:
    equal → `JMAP_PRECOND_MATCH`; differ → `JMAP_PRECOND_MISMATCH`.
  - "null matches absent" falls out naturally: a `null` in the patch deletes an
    already-absent key, leaving the object unchanged.

### 3. Per-method integration

For each id appearing in `update` and in `destroy`, **after** the method's
existing `ifInState` check and **before** any modification:

1. If `set.if_unchanged_by` has no entry for this id, proceed unchanged.
2. Otherwise obtain the current `Foo/get` representation of the object and call
   `jmap_precondition_check`.
3. On `JMAP_PRECOND_MISMATCH`: add `{"type":"stateMismatch"}` to
   `not_updated`/`not_destroyed` for that id and skip it.
   On `JMAP_PRECOND_INVALID`: add `{"type":"invalidPatch"}` (optionally with the
   offending pointer in `description`) and skip it.
4. On `JMAP_PRECOND_MATCH`: proceed with the update/destroy as normal.

Per-object independence is satisfied because each id is handled in its own
iteration of the method's existing per-id loop.

**Source of the current representation, per datatype:**

Concretely specified now (already load a clean json_t during update):

- **ContactCard** (`imap/jmap_contact.c` ~9188-9222): reuse the `old_obj`
  JSContact card already built via `jmap_card_from_vcard()`.
- **CalendarEvent** (`imap/jmap_calendar.c` ~5091-5124): reuse the `old_event`
  json_t already built via `jmapical_tojmap()`.
- **Email** (`imap/jmap_mail.c`): Email has custom patch handling and no single
  json_t. For the PoC, build a **scoped** current representation containing the
  properties that are practically conditionable — `keywords` (and
  `keywords/<flag>`), `mailboxIds` (and `mailboxIds/<id>`), and immutable
  server-set ids (`blobId`, `threadId`, `id`, `size`, timestamps where readily
  available) — rather than a full `Email/get` object. This is sufficient for the
  draft's examples (e.g. `keywords/$seen`, `blobId`) and is documented as a
  PoC scoping decision.

To be detailed during planning ("via existing get path"): **Mailbox, Note,
AddressBook, Calendar, Vacation, SieveScript, EmailSubmission**, and the
calendar-adjacent types (Principal, ShareNotification, ParticipantIdentity,
CalendarEventNotification). Each produces its current json_t by reusing the
representation-building code its own `Foo/get` already uses, factored to operate
on a single object. The planning step will pin down the exact function/entry
point for each.

## Error handling

- All precondition failures are per-object SetErrors, never whole-method errors
  (the whole-method `stateMismatch` remains reserved for `ifInState`).
- `invalidPatch` vs `stateMismatch` is decided entirely by
  `jmap_precondition_check` so the distinction is consistent across datatypes.
- No object values are leaked: SetErrors carry only `type` and optional
  `description` (and `description` must not echo current property values).
- Access control: a precondition referencing a property the caller cannot read
  is handled by the existing read path for that datatype (it would not appear in
  the `Foo/get` representation), consistent with the draft's intent that
  preconditions respect existing access controls.

## Testing (representative subset, Cassandane)

New/extended Cassandane tests (Perl) exercising the contract on **Email** and
**ContactCard** (CalendarEvent if convenient), plus a direct transcription of a
draft example:

1. **Match → proceeds**: precondition matches current value; update applies and
   appears in `updated`.
2. **Mismatch → `stateMismatch`**: precondition value differs; id appears in
   `notUpdated`/`notDestroyed` with `stateMismatch` and the object is unchanged.
3. **Invalid pointer → `invalidPatch`**: pointer not valid for the type yields
   `invalidPatch`.
4. **Per-object independence**: in one call, one id fails its precondition while
   another id (no precondition, or a matching one) succeeds.
5. **Composition with `ifInState`**: a failing `ifInState` rejects the whole
   method (no per-object evaluation); a passing `ifInState` then lets
   per-object preconditions run.
6. **Draft example**: conditional destroy with
   `ifUnchangedBy: { "M7": { "keywords/$seen": null } }` — destroys only when
   unread; yields `stateMismatch` once `$seen` is set.
7. **Capability gating**: without `urn:ietf:params:jmap:conditional` in `using`,
   `ifUnchangedBy` is not honored (existing unknown-argument behavior).

## Out of scope (YAGNI for the PoC)

- A full single-object `Email/get` representation for precondition comparison
  (scoped representation only).
- Optimizing comparison cost; correctness over performance for the PoC.
- Any new client-facing tooling beyond the protocol behavior and tests.

## Key file references

- `imap/jmap_api.h:436` — `struct jmap_set`; `:259` — `jmap_is_using`;
  `:27` — `JMAP_URN_*` defines.
- `imap/jmap_api.c:1841` — `jmap_set_parse`; `:3299` — `jmap_is_using`;
  `:989` — capability advertisement.
- `imap/jmap_util.c:127` — `jmap_patchobject_apply` (pointer resolution reused).
- `imap/jmap_mail.c` — `jmap_email_set` (`ifInState` at ~13606).
- `imap/jmap_contact.c` ~9188 — ContactCard update loads `old_obj`.
- `imap/jmap_calendar.c` ~5091 — CalendarEvent update loads `old_event`.
