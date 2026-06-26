# JMAP Conditional Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `draft-gondwana-jmap-conditional-00`
(`urn:ietf:params:jmap:conditional`) in Cyrus — a per-object `ifUnchangedBy`
precondition argument on `Foo/set` methods — across the datatypes Cyrus
supports.

**Architecture:** One shared comparison helper decides whether a precondition
PatchObject is a no-op against an object's current `Foo/get` representation,
returning match / mismatch / invalid. A thin convenience wrapper turns that into
the `stateMismatch` / `invalidPatch` SetError. Each `Foo/set` method, after its
existing `ifInState` check and before mutating an object, feeds the wrapper the
current representation it loads (or builds via its `Foo/get` code path) and skips
the object on a returned error. The capability is advertised always and the
argument is only parsed when the client lists the URI in `using`.

**Tech Stack:** C (Cyrus IMAPd, jansson for JSON), CUnit (`cunit/*.testc`) for
the helper, Cassandane (Perl) for end-to-end tests. Build/test via the `dar`
docker tool.

## Global Constraints

- Honor `ifUnchangedBy` only when `jmap_is_using(req, JMAP_URN_CONDITIONAL)` is
  true; otherwise behavior is byte-for-byte unchanged from today.
- SetErrors are **bare**: `{"type":"stateMismatch"}` or `{"type":"invalidPatch"}`
  only — never a `description`, never any object value (no data disclosure).
- Preconditions evaluate against pre-modification state, after `ifInState`,
  per object; one object's failure never blocks another.
- Comparison uses the representation `Foo/get` would return for the object.
- `null` in a precondition matches an absent property (falls out of patch-apply).
- Borrowed JSON references in `struct jmap_set` follow the existing pattern
  (`set->if_in_state` etc. are borrowed from the request args, not ref-counted).
- Build after C changes (`dar build`) before running Cassandane (`dar test`).

---

## File Structure

- `imap/jmap_util.h` / `imap/jmap_util.c` — new `enum jmap_precondition` and
  `jmap_precondition_check()` (pure compare; no JMAP-set knowledge).
- `cunit/jmap_util.testc` — unit tests for `jmap_precondition_check()`.
- `imap/jmap_api.h` — `JMAP_URN_CONDITIONAL` define; `if_unchanged_by` field on
  `struct jmap_set`; `jmap_set_precondition()` declaration.
- `imap/jmap_api.c` — parse `ifUnchangedBy` in `jmap_set_parse()`;
  `jmap_set_precondition()` convenience wrapper.
- `imap/jmap_core.c` — advertise the capability in `jmap_core_capabilities()`.
- Per-datatype `imap/jmap_*.c` — call `jmap_set_precondition()` at each update
  and destroy site.
- `cassandane/tiny-tests/JMAPContacts/`, `JMAPEmail/`, `JMAPCalendars/` — tests.

---

### Task 1: Shared precondition compare helper

**Files:**
- Modify: `imap/jmap_util.h` (add enum + prototype near `jmap_patchobject_apply` at `:36`)
- Modify: `imap/jmap_util.c` (add function near `jmap_patchobject_apply` at `:127`)
- Test: `cunit/jmap_util.testc` (add a `test_precondition` function + register it)

**Interfaces:**
- Produces:
  ```c
  enum jmap_precondition {
      JMAP_PRECOND_MATCH = 0,   /* applying patch is a no-op: precondition holds */
      JMAP_PRECOND_MISMATCH,    /* valid pointers, value differs */
      JMAP_PRECOND_INVALID      /* pointer not valid for object type */
  };
  enum jmap_precondition jmap_precondition_check(json_t *current, json_t *patch);
  ```

- [ ] **Step 1: Write the failing unit test**

In `cunit/jmap_util.testc`, after `test_patchobject_invalid` (line 294), add:

```c
static void test_precondition(void)
{
#define TESTCASE(_cur, _patch, _want) \
    { \
        json_t *jcur = json_loads((_cur), JSON_DECODE_ANY, NULL); \
        json_t *jpatch = json_loads((_patch), JSON_DECODE_ANY, NULL); \
        CU_ASSERT_EQUAL((_want), jmap_precondition_check(jcur, jpatch)); \
        json_decref(jpatch); \
        json_decref(jcur); \
    }

    /* exact scalar match -> no-op -> precondition holds */
    TESTCASE("{\"a\":1,\"b\":2}", "{\"a\":1}", JMAP_PRECOND_MATCH);

    /* scalar differs -> mismatch */
    TESTCASE("{\"a\":1}", "{\"a\":2}", JMAP_PRECOND_MISMATCH);

    /* null matches absent property -> no-op -> holds */
    TESTCASE("{\"a\":1}", "{\"b\":null}", JMAP_PRECOND_MATCH);

    /* null does NOT match present property -> mismatch */
    TESTCASE("{\"a\":1}", "{\"a\":null}", JMAP_PRECOND_MISMATCH);

    /* nested pointer match (keywords/$seen present) -> holds */
    TESTCASE("{\"keywords\":{\"$seen\":true}}",
             "{\"keywords/$seen\":true}", JMAP_PRECOND_MATCH);

    /* nested pointer: condition requires absent ($seen null) but present -> mismatch */
    TESTCASE("{\"keywords\":{\"$seen\":true}}",
             "{\"keywords/$seen\":null}", JMAP_PRECOND_MISMATCH);

    /* nested pointer: condition requires absent and it IS absent -> holds */
    TESTCASE("{\"keywords\":{\"$flagged\":true}}",
             "{\"keywords/$seen\":null}", JMAP_PRECOND_MATCH);

    /* pointer into non-existent parent -> invalid */
    TESTCASE("{\"a\":1}", "{\"x/y\":1}", JMAP_PRECOND_INVALID);

    /* whole-object array equality -> holds */
    TESTCASE("{\"a\":[1,2,3]}", "{\"a\":[1,2,3]}", JMAP_PRECOND_MATCH);

    /* whole-object array differs -> mismatch */
    TESTCASE("{\"a\":[1,2,3]}", "{\"a\":[1,2]}", JMAP_PRECOND_MISMATCH);

#undef TESTCASE
}
```

- [ ] **Step 2: Register the test and run it to verify it fails to build/link**

CUnit `.testc` files auto-register functions named `test_*` via the build's
generator, so no manual registration list edit is needed (confirm by grepping
`grep -n "test_patchobject" cunit/jmap_util.testc` shows no manual table). Build
the unit tests:

Run: `dar run make -C cunit` (or `dar build` if the unit-test target is part of
the normal build)
Expected: FAIL — `jmap_precondition_check` / `JMAP_PRECOND_MATCH` undefined.

- [ ] **Step 3: Add the enum and prototype to the header**

In `imap/jmap_util.h`, immediately after the `jmap_patchobject_apply`
declaration (line 36-37), add:

```c
enum jmap_precondition {
    JMAP_PRECOND_MATCH = 0,   /* applying patch is a no-op: precondition holds */
    JMAP_PRECOND_MISMATCH,    /* valid pointer(s), value differs */
    JMAP_PRECOND_INVALID      /* pointer not valid for the object type */
};

/* Evaluate a precondition PatchObject against an object's current Foo/get
 * representation. Returns JMAP_PRECOND_MATCH iff applying `patch` to `current`
 * would leave it unchanged (every pointer already matches, null matching
 * absent). */
extern enum jmap_precondition jmap_precondition_check(json_t *current,
                                                      json_t *patch);
```

- [ ] **Step 4: Implement the helper**

In `imap/jmap_util.c`, after `jmap_patchobject_apply` (ends ~line 189), add:

```c
EXPORTED enum jmap_precondition jmap_precondition_check(json_t *current,
                                                        json_t *patch)
{
    if (!json_is_object(patch))
        return JMAP_PRECOND_INVALID;

    /* An empty precondition is vacuously satisfied. */
    if (!json_object_size(patch))
        return JMAP_PRECOND_MATCH;

    json_t *invalid = json_array();
    json_t *patched = jmap_patchobject_apply(current, patch, invalid, 0);
    enum jmap_precondition res;

    if (!patched || json_array_size(invalid)) {
        /* pointer not valid for this object type */
        res = JMAP_PRECOND_INVALID;
    }
    else if (json_equal(current, patched)) {
        /* applying the patch changed nothing: precondition holds */
        res = JMAP_PRECOND_MATCH;
    }
    else {
        res = JMAP_PRECOND_MISMATCH;
    }

    if (patched) json_decref(patched);
    json_decref(invalid);
    return res;
}
```

- [ ] **Step 5: Run the unit test to verify it passes**

Run: `dar run ./cunit/unit -t jmap_util` (or the repo's unit-test invocation;
discover with `dar run ./cunit/unit -l | grep jmap_util` if unsure)
Expected: PASS — `test_precondition` and existing `jmap_util` tests green.

- [ ] **Step 6: Commit**

```bash
git add imap/jmap_util.h imap/jmap_util.c cunit/jmap_util.testc
git commit -m "jmap: add jmap_precondition_check no-op patch comparison helper

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Register and advertise the capability

**Files:**
- Modify: `imap/jmap_api.h:38` (add define after `JMAP_URN_CALENDAR_PREFERENCES`)
- Modify: `imap/jmap_core.c:147` (`jmap_core_capabilities`)

**Interfaces:**
- Produces: `#define JMAP_URN_CONDITIONAL "urn:ietf:params:jmap:conditional"`,
  advertised as `{}` in every account's capabilities (and thus
  `server_capabilities`, which is built from the same function at
  `jmap_api.c:520,545`).

- [ ] **Step 1: Add the URN define**

In `imap/jmap_api.h` after line 38 (`JMAP_URN_CALENDAR_PREFERENCES`):

```c
#define JMAP_URN_CONDITIONAL "urn:ietf:params:jmap:conditional"
```

- [ ] **Step 2: Advertise it in core capabilities**

In `imap/jmap_core.c`, inside `jmap_core_capabilities` (after the `JMAP_URN_CORE`
set at lines 149-150):

```c
    json_object_set_new(account_capabilities,
            JMAP_URN_CONDITIONAL, json_object());
```

- [ ] **Step 3: Build**

Run: `dar build`
Expected: compiles cleanly.

- [ ] **Step 4: Write a Cassandane test asserting the capability is advertised**

Create `cassandane/tiny-tests/JMAPCore/conditional_capability`:

```perl
#!perl
use Cassandane::Tiny;

sub test_conditional_capability
    :min_version_3_13
    ($self)
{
    my $jmap = $self->{jmap};
    my $res = $jmap->ua->get($jmap->uri, { headers => $jmap->auth_header });
    my $session = decode_json($res->{content});
    my $accountId = $session->{primaryAccounts}{'urn:ietf:params:jmap:core'};
    $self->assert_not_null(
        $session->{accountCapabilities}{$accountId}
                 {'urn:ietf:params:jmap:conditional'},
        "conditional capability advertised");
}
```

If the existing `JMAPCore` suite has a simpler idiom for reading the session
object, mirror it (grep `cassandane/tiny-tests/JMAPCore` for `accountCapabilities`).

- [ ] **Step 5: Run the test**

Run: `dar test JMAPCore.conditional_capability`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add imap/jmap_api.h imap/jmap_core.c cassandane/tiny-tests/JMAPCore/conditional_capability
git commit -m "jmap: advertise urn:ietf:params:jmap:conditional capability

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Parse `ifUnchangedBy` and add the SetError wrapper

**Files:**
- Modify: `imap/jmap_api.h:436-456` (struct field) and add prototype
- Modify: `imap/jmap_api.c:1841` (`jmap_set_parse` arg loop) and add
  `jmap_set_precondition()`

**Interfaces:**
- Consumes: `jmap_precondition_check()` (Task 1), `JMAP_URN_CONDITIONAL`,
  `jmap_is_using()` (`jmap_api.c:3299`).
- Produces:
  ```c
  /* in struct jmap_set */
  json_t *if_unchanged_by;   /* borrowed Id[PatchObject]; NULL if cap not in use */

  /* Returns a bare SetError (caller owns; put in not_updated/not_destroyed),
   * or NULL if there is no precondition for `id` or it is satisfied. */
  extern json_t *jmap_set_precondition(struct jmap_set *set,
                                       const char *id, json_t *current);
  ```

- [ ] **Step 1: Add the struct field**

In `imap/jmap_api.h`, inside `struct jmap_set` request-arguments block (after
`bool apply_empty_updates;` ~line 440):

```c
    json_t *if_unchanged_by;   /* Id[PatchObject], NULL when cap not in use */
```

- [ ] **Step 2: Add the prototype**

In `imap/jmap_api.h`, after the `jmap_set_parse` prototype (~line 463):

```c
extern json_t *jmap_set_precondition(struct jmap_set *set,
                                     const char *id, json_t *current);
```

- [ ] **Step 3: Parse the argument (gated by capability)**

In `imap/jmap_api.c`, in the `json_object_foreach(jargs, ...)` loop of
`jmap_set_parse`, after the `applyEmptyUpdates` branch (the branch ending ~line
1891), add a new branch:

```c
        /* ifUnchangedBy (urn:ietf:params:jmap:conditional) */
        else if (jmap_is_using(req, JMAP_URN_CONDITIONAL) &&
                 !strcmp(key, "ifUnchangedBy")) {
            if (json_is_object(arg)) {
                set->if_unchanged_by = arg;   /* borrowed, like create/update */
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "ifUnchangedBy");
            }
        }
```

Note: placing the `jmap_is_using` guard in the branch condition means that when
the capability is not in use, `ifUnchangedBy` falls through to the existing
unknown-argument handling (`invalidArguments`) — preserving current behavior.

- [ ] **Step 4: Implement the wrapper**

In `imap/jmap_api.c`, after `jmap_set_parse` (ends ~line 2025), add:

```c
EXPORTED json_t *jmap_set_precondition(struct jmap_set *set,
                                       const char *id, json_t *current)
{
    if (!set->if_unchanged_by) return NULL;

    json_t *patch = json_object_get(set->if_unchanged_by, id);
    if (!patch) return NULL;

    switch (jmap_precondition_check(current, patch)) {
    case JMAP_PRECOND_MATCH:
        return NULL;
    case JMAP_PRECOND_INVALID:
        return json_pack("{s:s}", "type", "invalidPatch");
    case JMAP_PRECOND_MISMATCH:
    default:
        return json_pack("{s:s}", "type", "stateMismatch");
    }
}
```

Confirm `jmap_util.h` is included by `jmap_api.c` (grep
`grep -n "jmap_util.h" imap/jmap_api.c`); add the include if missing.

- [ ] **Step 5: Build**

Run: `dar build`
Expected: compiles cleanly. (No behavior wired into any method yet; this task
adds plumbing only.)

- [ ] **Step 6: Commit**

```bash
git add imap/jmap_api.h imap/jmap_api.c
git commit -m "jmap: parse ifUnchangedBy and add jmap_set_precondition wrapper

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: ContactCard/set integration + full test suite

This is the representative end-to-end datatype. ContactCard update already builds
a clean current `old_obj` json_t before applying the patch.

**Files:**
- Modify: `imap/jmap_contact.c` — `_card_set_update` (~`:9204` where `old_obj`
  exists, before patch at `:9222`) and the destroy loop (~`:663-725`)
- Test: `cassandane/tiny-tests/JMAPContacts/card_set_ifunchangedby`

**Interfaces:**
- Consumes: `jmap_set_precondition()` (Task 3). The ContactCard set struct is the
  shared `struct jmap_set` reachable as `set` in `jmap_card_set`; in
  `_card_set_update` it is passed/visible as the surrounding set — confirm the
  exact reference name in scope (grep the function for `not_updated`).

- [ ] **Step 1: Write the failing Cassandane test**

Create `cassandane/tiny-tests/JMAPContacts/card_set_ifunchangedby`:

```perl
#!perl
use Cassandane::Tiny;

sub test_card_set_ifunchangedby
    :min_version_3_13
    ($self)
{
    my $jmap = $self->{jmap};
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'urn:ietf:params:jmap:conditional';

    # Create a card
    my $res = $jmap->CallMethods([
        ['ContactCard/set', {
            create => { "1" => {
                '@type' => 'Card', version => '1.0',
                uid => 'ae2640cc-234a-4dd9-95cc-3106258445b9',
                name => { full => 'John Doe' },
                nicknames => { k391 => { '@type' => 'Nickname', name => 'Johnny' } },
            }},
        }, 'R1'],
    ], \@using);
    my $id = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($id);

    # Precondition MATCHES current value -> update proceeds
    $res = $jmap->CallMethods([
        ['ContactCard/set', {
            ifUnchangedBy => { $id => { 'nicknames/k391/name' => 'Johnny' } },
            update => { $id => { 'nicknames/k391/name' => 'Johnny Boy' } },
        }, 'R2'],
    ], \@using);
    $self->assert_not_null($res->[0][1]{updated}{$id});

    # Precondition MISMATCH (stale expected value) -> stateMismatch, no change
    $res = $jmap->CallMethods([
        ['ContactCard/set', {
            ifUnchangedBy => { $id => { 'nicknames/k391/name' => 'Johnny' } },
            update => { $id => { 'nicknames/k391/name' => 'Nope' } },
        }, 'R3'],
    ], \@using);
    $self->assert_null($res->[0][1]{updated}{$id});
    $self->assert_str_equals('stateMismatch',
                             $res->[0][1]{notUpdated}{$id}{type});

    # Invalid pointer -> invalidPatch
    $res = $jmap->CallMethods([
        ['ContactCard/set', {
            ifUnchangedBy => { $id => { 'bogus/pointer' => 1 } },
            update => { $id => { 'nicknames/k391/name' => 'X' } },
        }, 'R4'],
    ], \@using);
    $self->assert_str_equals('invalidPatch',
                             $res->[0][1]{notUpdated}{$id}{type});

    # Capability NOT in using -> ifUnchangedBy is an unknown argument
    $res = $jmap->CallMethods([
        ['ContactCard/set', {
            ifUnchangedBy => { $id => { 'nicknames/k391/name' => 'stale' } },
            update => { $id => { 'nicknames/k391/name' => 'Whatever' } },
        }, 'R5'],
    ]);  # default using, no conditional
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dar build && dar test JMAPContacts.card_set_ifunchangedby`
Expected: FAIL — `ifUnchangedBy` is rejected as `invalidArguments` even with the
capability (no integration yet), so the MATCH update never lands.

- [ ] **Step 3: Add the precondition check at the update site**

In `imap/jmap_contact.c`, in `_card_set_update`, immediately after `old_obj` is
built (line 9204) and before the patch is applied (line 9222), insert:

```c
    json_t *precond_err = jmap_set_precondition(set, uid, old_obj);
    if (precond_err) {
        json_object_set_new(set->not_updated, uid, precond_err);
        r = 0;
        goto done;   /* match the function's existing cleanup label */
    }
```

Confirm the in-scope names: the object id (`uid`), the set pointer (`set`), the
cleanup label (`done`), and the `not_updated` accessor. Grep the function header
and its existing `json_object_set_new(... not_updated ...)` use (~line 835) to
match exact names; adapt the snippet to them.

- [ ] **Step 4: Add the precondition check at the destroy site**

In the destroy loop (~lines 663-725), after the existing object is confirmed to
exist (so its current representation can be built), build the current card and
check. The destroy path does not already build `old_obj`; construct it the same
way the update path does (`jmap_card_from_vcard(...)` at line 4639) for the
located record, then:

```c
    json_t *precond_err = jmap_set_precondition(&set, uid, cur_obj);
    if (precond_err) {
        json_object_set_new(set.not_destroyed, uid, precond_err);
        json_decref(cur_obj);
        continue;
    }
    json_decref(cur_obj);
```

If wiring a full card build into the destroy path is disproportionate for the
PoC, guard it: only build `cur_obj` when `set.if_unchanged_by &&
json_object_get(set.if_unchanged_by, uid)` is non-NULL, so the common (no
precondition) destroy path is untouched. Add a `card_set_ifunchangedby_destroy`
sub-case to the test exercising destroy with a matching and a mismatching
precondition.

- [ ] **Step 5: Run the test to verify it passes**

Run: `dar build && dar test JMAPContacts.card_set_ifunchangedby`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add imap/jmap_contact.c cassandane/tiny-tests/JMAPContacts/card_set_ifunchangedby
git commit -m "jmap: honor ifUnchangedBy in ContactCard/set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Email/set integration + draft examples

Email has custom patch handling and no single current json_t. Build a **scoped**
current representation (per the spec): `keywords`, `mailboxIds`, and immutable
`id`/`blobId`/`threadId`/`size`. This covers the draft's `keywords/$seen` and
`blobId` examples.

**Files:**
- Modify: `imap/jmap_mail.c` — update path in `_email_update_bulk`
  (current mailboxIds available ~`:13446` via `_email_mailboxes`; current
  keywords via `_email_get_keywords` ~`:6720`) and destroy path in
  `_email_destroy_bulk` (after `_email_mboxrecs_read` ~`:13530`)
- Test: `cassandane/tiny-tests/JMAPEmail/email_set_ifunchangedby`

**Interfaces:**
- Consumes: `jmap_set_precondition()`; `_email_mailboxes(req, NULL, guidrep)`
  → mailboxIds json_t; `_email_get_keywords(req, &getctx, guidrep, &jkw)`
  → keywords json_t; `_guid_from_id(req->cstate, email_id)` → guidrep;
  `jmap_set_blobid`/`jmap_set_threadid`/`jmap_set_emailid` for immutable ids.
- Produces: a local helper `_email_current_repr(req, email_id)` returning a
  scoped json_t (see Step 3).

- [ ] **Step 1: Write the failing Cassandane test**

Create `cassandane/tiny-tests/JMAPEmail/email_set_ifunchangedby`:

```perl
#!perl
use Cassandane::Tiny;

sub test_email_set_ifunchangedby
    :min_version_3_13 :needs_component_sieve
    ($self)
{
    my $jmap = $self->{jmap};
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'urn:ietf:params:jmap:conditional';

    my $res = $jmap->CallMethods([
        ['Mailbox/get', { properties => ['id'] }, 'R0'],
    ], \@using);
    my $inbox = $res->[0][1]{list}[0]{id};

    # Create an email (unread: no $seen)
    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => {
            mailboxIds => { $inbox => JSON::true },
            from => [{ name => "S", email => "s\@local" }],
            subject => "hi",
            bodyStructure => { type => 'text/plain', partId => 'p' },
            bodyValues => { p => { value => "body" } },
            keywords => { '$flagged' => JSON::true },
        }}}, 'R1'],
    ], \@using);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    # Precondition: $flagged is set -> matches -> update proceeds
    $res = $jmap->CallMethods([
        ['Email/set', {
            ifUnchangedBy => { $id => { 'keywords/$flagged' => JSON::true } },
            update => { $id => { 'keywords/$answered' => JSON::true } },
        }, 'R2'],
    ], \@using);
    $self->assert_not_null($res->[0][1]{updated}{$id});

    # Precondition: expect $seen present, but it's absent -> mismatch
    $res = $jmap->CallMethods([
        ['Email/set', {
            ifUnchangedBy => { $id => { 'keywords/$seen' => JSON::true } },
            update => { $id => { 'keywords/$draft' => JSON::true } },
        }, 'R3'],
    ], \@using);
    $self->assert_str_equals('stateMismatch',
                             $res->[0][1]{notUpdated}{$id}{type});

    # Draft example 4.2: destroy only if unread (keywords/$seen null).
    # Currently unread -> precondition holds -> destroy succeeds.
    $res = $jmap->CallMethods([
        ['Email/set', {
            ifUnchangedBy => { $id => { 'keywords/$seen' => undef } },
            destroy => [ $id ],
        }, 'R4'],
    ], \@using);
    $self->assert_deep_equals([ $id ], $res->[0][1]{destroyed});
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dar build && dar test JMAPEmail.email_set_ifunchangedby`
Expected: FAIL — `invalidArguments` / no integration.

- [ ] **Step 3: Add a scoped current-representation helper**

In `imap/jmap_mail.c`, near the other `_email_*` helpers, add:

```c
/* Build the scoped current Foo/get representation used for ifUnchangedBy:
 * keywords, mailboxIds, and immutable ids. Returns NULL if the email is
 * unknown. Caller owns the result. */
static json_t *_email_current_repr(jmap_req_t *req, const char *email_id)
{
    const char *guidrep = _guid_from_id(req->cstate, email_id);
    if (!guidrep) return NULL;

    json_t *mailboxids = _email_mailboxes(req, NULL, guidrep);
    if (!mailboxids) return NULL;

    /* _email_mailboxes returns id -> metadata; reduce to id -> true to match
     * the mailboxIds shape used in set patches. */
    json_t *mids = json_object();
    const char *mid; json_t *jv;
    json_object_foreach(mailboxids, mid, jv) {
        json_object_set_new(mids, mid, json_true());
    }
    json_decref(mailboxids);

    struct email_getcontext getctx = { 0 };
    json_t *keywords = NULL;
    _email_get_keywords(req, &getctx, guidrep, &keywords);
    /* free any getctx-owned state the same way _email_get cleans it up;
     * follow the cleanup pattern used after _email_get_keywords elsewhere. */

    json_t *repr = json_pack("{s:o s:o s:s}",
                             "mailboxIds", mids,
                             "keywords", keywords ? keywords : json_object(),
                             "id", email_id);
    return repr;
}
```

Note on immutable ids: `keywords` and `mailboxIds` are sufficient for the draft
examples and the test above, so this PoC helper builds only those plus `id`. To
also support `blobId`/`threadId`/`size` preconditions later, derive them from
`guidrep` and `req->cstate` (the same way `Email/get` does, via `jmap_set_blobid`
/ `jmap_set_threadid`) and `json_object_set_new` them onto `repr` — out of scope
for the PoC. Verify the exact signature and return-ownership of
`_email_get_keywords` (line 6720) and its cleanup idiom before finalizing.

- [ ] **Step 4: Check preconditions in the update path**

In `_email_update_bulk`, during the per-id parse loop (after the email id is
known and before the update is queued — around lines 13441-13460 where `cur`
mailboxes are already fetched), insert:

```c
    if (set.if_unchanged_by && json_object_get(set.if_unchanged_by, email_id)) {
        json_t *cur_repr = _email_current_repr(req, email_id);
        json_t *precond_err = jmap_set_precondition(&set, email_id, cur_repr);
        if (cur_repr) json_decref(cur_repr);
        if (precond_err) {
            json_object_set_new(not_updated, email_id, precond_err);
            continue;   /* skip queuing this update */
        }
    }
```

Match the exact loop variable names (`email_id`, `not_updated`, the `set`
reference) and the `continue`/skip mechanism used by the surrounding loop
(~lines 13435-13477).

- [ ] **Step 5: Check preconditions in the destroy path**

In `_email_destroy_bulk`, after `_email_mboxrecs_read(...)` populates `mboxrecs`
(~line 13530) and before deletion, iterate the mboxrecs and for each
`uidrec->email_id` that has a precondition, build the current repr and check:

```c
    for (i = 0; i < ptrarray_size(mboxrecs); i++) {
        struct email_mboxrec *mbrec = ptrarray_nth(mboxrecs, i);
        int j;
        for (j = 0; j < ptrarray_size(&mbrec->uidrecs); j++) {
            struct email_uidrec *ur = ptrarray_nth(&mbrec->uidrecs, j);
            if (!set.if_unchanged_by ||
                !json_object_get(set.if_unchanged_by, ur->email_id)) continue;
            json_t *cur_repr = _email_current_repr(req, ur->email_id);
            json_t *precond_err = jmap_set_precondition(&set, ur->email_id, cur_repr);
            if (cur_repr) json_decref(cur_repr);
            if (precond_err) {
                json_object_set_new(not_destroyed, ur->email_id, precond_err);
                /* mark this email_id to be skipped by the deletion below,
                 * following the same skip mechanism used for forbidden/notFound
                 * at lines 13545/13584 */
            }
        }
    }
```

Match the skip mechanism the destroy path already uses for `forbidden`/
`notFound` so a precondition failure removes the id from the deletion set without
disturbing other ids.

- [ ] **Step 6: Run the test to verify it passes**

Run: `dar build && dar test JMAPEmail.email_set_ifunchangedby`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add imap/jmap_mail.c cassandane/tiny-tests/JMAPEmail/email_set_ifunchangedby
git commit -m "jmap: honor ifUnchangedBy in Email/set (scoped current repr)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: CalendarEvent/set integration + test

Third representative datatype. Update already builds `old_event` json_t
(`jmap_calendar.c:5093`) before applying the patch.

**Files:**
- Modify: `imap/jmap_calendar.c` — `setcalendarevents_update` (after `old_event`
  at `:5093`, before patch at `:5121`); destroy loop (~`:6057-6088`)
- Test: `cassandane/tiny-tests/JMAPCalendars/calendarevent_set_ifunchangedby`

**Interfaces:**
- Consumes: `jmap_set_precondition()`; the in-scope set pointer and id in
  `setcalendarevents_update`; `jmapical_tojmap()` for building the current event
  on the destroy path.

- [ ] **Step 1: Write the failing Cassandane test**

Create `cassandane/tiny-tests/JMAPCalendars/calendarevent_set_ifunchangedby`:

```perl
#!perl
use Cassandane::Tiny;

sub test_calendarevent_set_ifunchangedby
    :min_version_3_13
    ($self)
{
    my $jmap = $self->{jmap};
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'urn:ietf:params:jmap:conditional';

    my $res = $jmap->CallMethods([
        ['Calendar/get', { properties => ['id'] }, 'R0'],
    ], \@using);
    my $calId = $res->[0][1]{list}[0]{id};

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', { create => { "1" => {
            calendarIds => { $calId => JSON::true },
            '@type' => 'Event', uid => 'event-ifu-1',
            title => 'Original',
            start => '2026-07-01T09:00:00',
            duration => 'PT1H', timeZone => 'Etc/UTC',
        }}}, 'R1'],
    ], \@using);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    # MATCH -> proceeds
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            ifUnchangedBy => { $id => { title => 'Original' } },
            update => { $id => { title => 'Updated' } },
        }, 'R2'],
    ], \@using);
    $self->assert_not_null($res->[0][1]{updated}{$id});

    # MISMATCH -> stateMismatch
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            ifUnchangedBy => { $id => { title => 'Original' } },
            update => { $id => { title => 'Again' } },
        }, 'R3'],
    ], \@using);
    $self->assert_str_equals('stateMismatch',
                             $res->[0][1]{notUpdated}{$id}{type});
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dar build && dar test JMAPCalendars.calendarevent_set_ifunchangedby`
Expected: FAIL.

- [ ] **Step 3: Add the check at the update site**

In `setcalendarevents_update`, after `old_event` is built (line 5093) — using the
pre-patch copy `update->old_event` (line 5098) — and before
`updateevent_apply_patch_event` (line 5121):

```c
    json_t *precond_err = jmap_set_precondition(set, id, update->old_event);
    if (precond_err) {
        json_object_set_new(set->not_updated, id, precond_err);
        r = 0;
        goto done;   /* match the function's cleanup label */
    }
```

Confirm the in-scope set reference and id names (grep the function for
`not_updated`, ~line 6148) and adapt.

- [ ] **Step 4: Add the check at the destroy site (guarded)**

In the destroy loop (~lines 6057-6088), only when a precondition exists for the
id, build the current event via `jmapical_tojmap()` (as the update path does at
line 5093) and check; on error add `stateMismatch`/`invalidPatch` to
`not_destroyed` and skip. Keep the no-precondition path untouched.

- [ ] **Step 5: Run the test to verify it passes**

Run: `dar build && dar test JMAPCalendars.calendarevent_set_ifunchangedby`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add imap/jmap_calendar.c cassandane/tiny-tests/JMAPCalendars/calendarevent_set_ifunchangedby
git commit -m "jmap: honor ifUnchangedBy in CalendarEvent/set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Mailbox/set integration

**Files:**
- Modify: `imap/jmap_mailbox.c` — `_mboxset_run`: update site before
  `_mbox_update` (~`:3158`), destroy site before `_mbox_destroy` (~`:3174`),
  using `_mbox_get` (`:516`) to build the current representation.

**Interfaces:**
- Consumes: `jmap_set_precondition()`; `_mbox_get(req, mbentry, roles, props,
  share_type, sublist)` (`:516`); `jmap_mbentry_by_mboxid()` to resolve the id.

- [ ] **Step 1: Add a guarded helper to build the current mailbox repr**

In `imap/jmap_mailbox.c`, near `_mbox_get`, add:

```c
static json_t *_mbox_current_repr(jmap_req_t *req, const char *mbox_id)
{
    const mbentry_t *mbentry = jmap_mbentry_by_mboxid(req, mbox_id);
    if (!mbentry) return NULL;
    /* roles/props/sublist NULL => full representation, matching Mailbox/get */
    return _mbox_get(req, mbentry, NULL, NULL, _shared_mbox_type(req, mbentry), NULL);
}
```

Verify `_mbox_get`'s exact parameter list and the `share_type` argument it
expects (line 516); supply the same values `getMailboxes` uses for a normal
fetch. If a `roles` hash is required (non-NULL), allocate and free a temporary
one as the get path does.

- [ ] **Step 2: Check preconditions at update and destroy sites (guarded)**

Update (before `_mbox_update`, ~line 3158):

```c
    if (set->super.if_unchanged_by &&
        json_object_get(set->super.if_unchanged_by, args->mbox_id)) {
        json_t *cur = _mbox_current_repr(req, args->mbox_id);
        json_t *err = jmap_set_precondition(&set->super, args->mbox_id, cur);
        if (cur) json_decref(cur);
        if (err) {
            /* route through the same path result.err uses at lines 3154-3156:
               set not_updated and skip the _mbox_update call for this id */
            json_object_set_new(set->super.not_updated, args->mbox_id, err);
            continue;   /* or the loop's existing skip-to-next-id mechanism */
        }
    }
```

Destroy (before `_mbox_destroy`, ~line 3174): same pattern keyed on `mbox_id`,
writing to `set->super.not_destroyed`. Confirm the exact struct nesting
(`set->super` vs `set`) by grepping `_mboxset_run` for `not_updated`.

- [ ] **Step 3: Build and run the Mailbox suite for regressions**

Run: `dar build && dar test JMAPMailbox`
Expected: PASS (no regressions; new behavior is exercised by the shared cunit
test and manual check below).

- [ ] **Step 4: Manual smoke check**

Using a JMAP client or the existing test harness, issue a `Mailbox/set` update
with a matching and a mismatching `ifUnchangedBy` on `name`, confirming
`updated` vs `stateMismatch`. (Optional: add a small tiny-test mirroring Task 4.)

- [ ] **Step 5: Commit**

```bash
git add imap/jmap_mailbox.c
git commit -m "jmap: honor ifUnchangedBy in Mailbox/set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Note/set integration

Note's update callback already builds the note json and applies a patch.

**Files:**
- Modify: `imap/jmap_notes.c` — `_notes_update_cb` (current note built at `:696`
  via `_note_get`, patch applied at `:703`); `_notes_destroy_cb` (before record
  rewrite at `:768`), using `_note_get` (`:216`).

**Interfaces:**
- Consumes: `jmap_set_precondition()`; `_note_get(msg, note, props, want_created,
  buf)` (`:216`).

- [ ] **Step 1: Check at the update site**

In `_notes_update_cb`, after `_note_get(msg, note, NULL, 1, srock->buf)`
(line 696) builds the current `note`, and before `jmap_patchobject_apply`
(line 703):

```c
    json_t *precond_err = jmap_set_precondition(srock->set, id, note);
    if (precond_err) {
        json_object_set_new(srock->set->not_updated, id, precond_err);
        r = 0;
        goto done;
    }
```

Confirm the set pointer reachable from the callback rock (`srock`) and the id and
cleanup label by reading the function (lines 678-741).

- [ ] **Step 2: Check at the destroy site (guarded)**

In `_notes_destroy_cb` (lines 748-776), when a precondition exists for the id,
build the current note via `_note_get` and check; on failure add the SetError to
`not_destroyed` (line 776 site) and skip the rewrite.

- [ ] **Step 3: Build and run the Notes suite**

Run: `dar build && dar test JMAPNotes`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add imap/jmap_notes.c
git commit -m "jmap: honor ifUnchangedBy in Note/set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: SieveScript/set and VacationResponse/set integration

**Files:**
- Modify: `imap/jmap_sieve.c` — `set_update` (after `sievedb_lookup_id` `:532`),
  `set_destroy` (after lookup `:607`), using `getscript` (`:202`) to build the
  current representation.
- Modify: `imap/jmap_vacation.c` — `vacation_update` (after `vacation_read`
  `:319`), using `vacation_read` (`:125`) for the current singleton.

**Interfaces:**
- Consumes: `jmap_set_precondition()`; `getscript`/`vacation_read` outputs.

- [ ] **Step 1: SieveScript update/destroy checks**

In `set_update` (jmap_sieve.c), after `sievedb_lookup_id(db, id, &sdata, 0)`
(line 532), build the current script json the way `getscript` (line 202) does
(id, name, isActive, blobId) into a local `json_t *cur`, then:

```c
    json_t *precond_err = jmap_set_precondition(set, id, cur);
    json_decref(cur);
    if (precond_err) {
        json_object_set_new(set->not_updated, id, precond_err);
        goto done;
    }
```

`getscript` appends to a get list rather than returning one object; refactor a
small `static json_t *sievescript_torepr(struct sieve_data *sdata)` that both
`getscript` and this call use, to avoid duplicating the field extraction (DRY).
Apply the analogous guarded check in `set_destroy` (after lookup at line 607)
writing to `not_destroyed` (line 626 site).

- [ ] **Step 2: VacationResponse update check (singleton)**

In `vacation_update` (jmap_vacation.c), after `vacation_read(...)` (line 319)
yields the current `vacation` json, and before property validation (line 321):

```c
    json_t *precond_err = jmap_set_precondition(set, "singleton", vacation);
    if (precond_err) {
        json_object_set_new(set->not_updated, "singleton", precond_err);
        goto done;
    }
```

Destroy is always rejected with `singleton` for vacation (line 552) — no
precondition needed there.

- [ ] **Step 3: Build and run both suites**

Run: `dar build && dar test JMAPSieve && dar test JMAPVacation`
(Confirm exact suite names with `dar test -l 2>/dev/null | grep -i 'sieve\|vacation'`
or by listing `cassandane/Cassandane/Cyrus/JMAP*.pm`.)
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add imap/jmap_sieve.c imap/jmap_vacation.c
git commit -m "jmap: honor ifUnchangedBy in SieveScript/set and VacationResponse/set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: EmailSubmission, AddressBook, Calendar integration

These three load no current object during update/destroy today, so each builds
the current repr from its `Foo/get` code path, guarded so the no-precondition
path is untouched.

**Files:**
- Modify: `imap/jmap_mail_submission.c` — `_emailsubmission_update` (after
  `fetch_submission` `:1020`), `_emailsubmission_destroy` (after
  `fetch_submission` `:1134`); `fetch_submission` (`:923`) builds the current
  object.
- Modify: `imap/jmap_contact.c` — `setaddressbooks_update`/`_destroy`
  (delegated from loops `:2696`/`:2646`); current repr via `getaddressbooks_cb`
  (`:1735`).
- Modify: `imap/jmap_calendar.c` — `setcalendars_update`/`_destroy` (delegated
  from loops `:2187`/`:2218`); current repr via `getcalendars_cb` (`:581`).

**Interfaces:**
- Consumes: `jmap_set_precondition()`; the three get-builder functions.

- [ ] **Step 1: EmailSubmission checks**

In `_emailsubmission_update`, after `sub = fetch_submission(req, msg)`
(line 1020) and before the update validation loop (line 1033):

```c
    json_t *precond_err = jmap_set_precondition(set, id, sub);
    if (precond_err) {
        json_object_set_new(set->not_updated, id, precond_err);
        goto done;
    }
```

Apply the analogous check in `_emailsubmission_destroy` after `fetch_submission`
(line 1134), writing to `not_destroyed` (line 1507 site). Confirm the in-scope
set reference names.

- [ ] **Step 2: AddressBook and Calendar checks**

`getaddressbooks_cb` (line 1735) and `getcalendars_cb` (line 581) are mbentry
callbacks that build a single object's json. Factor each into a small
`static json_t *addressbook_torepr(...)` / `calendar_torepr(...)` that the
callback and the new precondition path both call (DRY). In
`setaddressbooks_update`/`setcalendars_update`, before performing the annotation
write, when a precondition exists for the id, resolve the mbentry
(`jmap_mbentry_by_mboxid`), build the repr, call `jmap_set_precondition`, and on
error add the SetError to `not_updated` and return without writing. Mirror for
the destroy delegates writing to `not_destroyed`.

- [ ] **Step 3: Build and run the suites**

Run: `dar build && dar test JMAPSubmission && dar test JMAPContacts && dar test JMAPCalendars`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add imap/jmap_mail_submission.c imap/jmap_contact.c imap/jmap_calendar.c
git commit -m "jmap: honor ifUnchangedBy in EmailSubmission/AddressBook/Calendar set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: Calendar notification destroys and Principal update

Lower-value, partial-mutability types. ShareNotification and
CalendarEventNotification support **destroy** only; Principal supports updating
`timeZone` only; ParticipantIdentity is fully immutable and is **excluded** (no
mutable operation to condition).

**Files:**
- Modify: `imap/jmap_calendar.c` — `notif_set` destroy loop (`:9950-9983`),
  using `sharenotif_tojmap` (`:10089`) / `eventnotif_tojmap` (`:10664`) for the
  current repr; `jmap_setcalendarprincipals` update loop (`:8955-9017`), using
  `buildprincipal` (`:8158`).

**Interfaces:**
- Consumes: `jmap_set_precondition()`; the three get-builder functions above.

- [ ] **Step 1: Notification destroy checks (guarded)**

In `notif_set`'s destroy loop (lines 9950-9983), when a precondition exists for
the id, build the current notification json via the appropriate
`*_tojmap` (the loop already locates the message), call `jmap_set_precondition`,
and on error add the SetError to `not_destroyed` and skip. `notif_set` is shared
by both notification types, so this covers both.

- [ ] **Step 2: Principal update check (guarded)**

In `jmap_setcalendarprincipals`' update loop (lines 8955-9017), before writing
the `timeZone` annotation, when a precondition exists for the id build the
current principal via `buildprincipal` (line 8158), check, and on error add to
`not_updated` and skip.

- [ ] **Step 3: Document the ParticipantIdentity exclusion**

Add a one-line comment at `jmap_participantidentity`'s set entry noting it is
immutable, so `ifUnchangedBy` is not applicable (all operations already
rejected).

- [ ] **Step 4: Build and run the Calendars suite**

Run: `dar build && dar test JMAPCalendars`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add imap/jmap_calendar.c
git commit -m "jmap: honor ifUnchangedBy for calendar notification destroy and Principal update

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 12: Documentation and full regression

**Files:**
- Create: `docs/source/imap/developer/...` note or a `changes/next/*` entry
  following the repo's convention (grep `ls changes/` for the format).

- [ ] **Step 1: Add a changelog/news entry**

Inspect the repo's change-note convention:

Run: `ls changes/ 2>/dev/null && head -20 changes/*/* 2>/dev/null | head -40`
Then add an entry describing the new `urn:ietf:params:jmap:conditional` support
and the datatypes covered, matching that format exactly.

- [ ] **Step 2: Full JMAP regression**

Run: `dar build && dar test JMAPEmail JMAPContacts JMAPCalendars JMAPMailbox JMAPNotes JMAPSieve JMAPVacation JMAPSubmission JMAPCore`
Expected: PASS across all suites.

- [ ] **Step 3: Commit**

```bash
git add changes/
git commit -m "docs: note JMAP conditional set support

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review Notes

- **Spec coverage:** capability gating (Task 2/3), shared compare (Task 1),
  bare SetErrors (Task 3 wrapper), per-object independence (per-id loops in every
  integration task), ifInState composition (checks inserted after existing
  ifInState in each method), broad datatype coverage (Tasks 4-11), representative
  Cassandane tests on ContactCard/Email/CalendarEvent + capability test (Tasks
  2,4,5,6), draft `keywords/$seen` destroy example (Task 5). ParticipantIdentity
  intentionally excluded (immutable) and documented (Task 11).
- **Verification reality:** line numbers are from exploration at plan time and
  may drift; every integration step says to confirm in-scope names by grepping
  the function before editing. Treat the snippets as the shape to match, not
  literal patches.
- **DRY:** Tasks 9-11 factor shared `*_torepr` helpers where a get builder is a
  callback, rather than duplicating field extraction.
