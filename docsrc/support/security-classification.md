(security-classification)=

# How we classify security issues

When we receive a report of a security-related bug, our goal is to get the fix
to Cyrus users quickly and responsibly.  There's a tension in this:  publishing
quickly means that the bug may be well-known before it's well-patched in
downstream distributions.  On the other hand, coordinated disclosure via an
embargo is a time-consuming process, especially as CNAs are struggling to cope
with a flood of LLM-discovered security issues.

Preparing an embargoed release is expensive: it takes coordinated disclosure,
CVE assignment, private backporting, and a synchronized publication across
several branches and downstream vendors. A routine minor release costs a small
fraction of that. If every reported defect were embargoed, the project would
spend all of its effort republishing the last release and none of it improving
the next one.

Because of that, we don't embargo every security defect. This page describes
which ones we do, and why we draw the line where we do. It is written for two
readers: an administrator or downstream packager who wants to know what to
expect from us, and a Cyrus developer deciding how to handle a report in hand.

For how to report a suspected vulnerability, and for which versions still
receive security updates, see
[SECURITY.md](https://github.com/cyrusimap/cyrus-imapd/blob/master/SECURITY.md)
in the root of the source distribution. In short: email
<security@cyrus.topicbox.com>.

## The three outcomes

Every accepted security report is handled in one of three ways.

**Embargoed release.** The fix is developed in private, assigned a CVE
identifier, backported to every supported branch, and published in a
coordinated release with advance notice to downstream vendors. The details of
the defect stay private until that release ships.

**Backport.** The fix lands on `master` immediately, in public, without
obfuscation or minced words.  After that, it's backported to supported
maintenance branches and ships in the next scheduled maintenance release. There
is no embargo and no coordinated disclosure, but the fix goes into a release in
a reasonable time frame.

**Master only.** The fix lands on `master` and is not backported. This is for
defects whose impact does not justify the risk of changing a stable branch.

An issue that exists only on a development branch (a release with an odd
middle version number, such as 3.13.x) is *always* fixed directly on `master`
with no embargo, whatever its severity. Development snapshots are not for
production use.

## What we embargo

An issue is embargoed only if it gives an attacker a **self-contained** means
to cause **lasting** harm on a server that is **reasonably configured**, using
only **non-experimental** features.

This boils down to four checks:  three vetoes and one affirmative test.  First,
we consider whether a veto tells us not to embargo.  Only if no veto applies do
we consider the lasting harm test.  If that tests positive, we will issue an
embargo.

### Veto 1: Self-contained

The report must be exploitable on its own.  It does not qualify just because it
might *become* exploitable when combined with a second, theoretical defect.
Defects often become much more dangerous because they can be strung together.
The Cyrus approach to this problem is to fix each problem quickly as it is
found, rather than to treat each one as a dangerous secret.

### Veto 2: Reasonable configuration

The vulnerable path must be reachable in a configuration that a reasonable
administrator would actually run.  This doesn't mean "the default
configuration" or "what Fastmail does".  It means that if the server
administrator has set things up contrary to common best practice, the expected
mitigation to the problem will be reconfiguration, not an embargoed bugfix.

A service that performs no authentication and is documented as reachable only
from trusted hosts is protected by that boundary. An attack that requires
crossing the boundary is an attack on the deployment, not on Cyrus.

### Veto 3: Non-experimental

New features often take a long time to figure out, and sometimes features still
under development ship in stable releases before they're fully designed and
tested.  These experimental features are not reliable in their behavior.  When
opting in to these nonstandard features, an admin is opting into weaker
security.

A feature is not embargo-eligible if both:

* it must be enabled by the server administrator
* it is behind `jmap_nonstandard_extensions`, in a `vnd.` namespace, or
  described by documentation as a draft or experimental feature

Don't enable experimental features in critical deployments.

### Final test: Lasting harm

We only embargo a fix if the vulnerability creates the possibility of *lasting
harm*.  That has two parts: "lasting" and "harm".

To be lasting, the effect must outlive the attacker's connection and the
server's next restart.

Data written, destroyed, or read by someone who should not have had it is
lasting: a message that has been read cannot be unread. A crashed worker
process, a hung connection, exhausted memory, and burnt CPU are not lasting,
however easily triggered and however little authentication they require.

To be considered "harm", the effect must be at least one of the following:

*   **Writes to memory under the attacker's control.**  Random corruption of
    the heap doesn't pass the test.  It probably doesn't pass the
    self-containedness test, anyway, and it's probably a crasher, which won't
    pass the "lasting" test.

*   **Writes to a filesystem path of the attacker's choosing.**  Typically
    because a string taken from a request reaches a pathname without
    validation.

*   **Injects a server-sent payload into a trusted channel.**  The test is
    whether the injected bytes arrive somewhere the attacker could not have
    sent them directly: into a connection Cyrus makes to another service as
    itself, or into a response that another user receives.  Smuggling a second
    request onto your own connection to Cyrus is not an attack, because you
    could have sent that request yourself.

*   **Exfiltrates, deletes, or corrupts sensitive data.**  While "bypass access
    control" sounds alarming, it can vary quite a bit in impact.  Reading
    another user's mail without read permission is worthy of embargo.  Reading
    the rate of change of their mailbox state is not.  Deleting or rewriting
    another user's content is.

*   **Corrupts persistent state in a way the site cannot undo.**  For example,
    causing Cyrus to corrupt `mailboxes.db` in such a way that it can't be
    recovered without losing data is embargo-worthy.  Intentionally
    corrupting your own data does not qualify.

## What we do not embargo

Some categories are worth clarifying, so that our handling of them is not
mistaken for neglect.

**Availability.**  Cyrus treats availability-only defects as ordinary bugs. A
remote, unauthenticated way to crash a process or exhaust a resource is a real
defect, and we fix it and backport it — but we do not embargo it. This is a
deliberate departure from severity scoring systems, which rate an
unauthenticated remote crash highly and can't distinguish "the daemon restarts"
from "the mail is gone."

**Faults that are only dangerous in combination.**  A single out-of-bounds
byte, an unchecked return, a narrow read of adjacent memory: these are often
treated as security issues on the grounds that a sufficiently determined
attacker could chain several of them into something serious.  We fix such
defects, test them, backport them, and make regular maintenance releases.  We
just avoid the costs involved in maintaining secret branches while waiting out
embargoes.  This policy does not claim they are unimportant; it claims they are
not *emergencies*.

**Existence oracles and leaked activity.**  Learning that a mailbox exists, or
that a user's unread count changed, is a defect worth fixing. It does not
change what an attacker can do.

## Applying these rules

This section is for Cyrus developers triaging a report.

**Work the vetoes in order and stop at the first failure.**  The vetoes are
cheap to evaluate and the lasting harm test less so.

**Write down the standing configuration assumptions.**  The question of
"reasonable configuration" turns on what a competent administrator would run,
and that question is re-arguable every single time it comes up.  Do not
re-derive over and over.  Keep a short list of standing assumptions — which
services are expected to be reachable only from trusted hosts, which limits are
expected to be configured, what is expected to sit in front of the HTTP service
— and amend the list by proposal.

**Any triager may override the outcome by one bucket, in either direction, by
recording one sentence of justification on the issue.**  If we don't allow for
some flexibility, eventually we'll do something patently absurd.  We hope that
the existing tests will always end up on a defensible answer, but when they
don't, you should put your thumb on the scale and write down why.  The logs of
these overrides will be input for the next revision of this policy: if the same
override keeps being written, the rule is wrong in that place.

**An embargo expires.**  If an embargoed issue hasn't been publicly fixed
within thirty days, it is reclassified as a backport unless there is an
explicit, recorded decision to continue the embargo.  Without this, "embargoed"
becomes the name of the backlog where unfinished work piles up, which is the
failure this policy exists to prevent.

**Document feature stability.**  The "non-experimental" veto is built on the
idea that we can point at which features are or are not experimental.  When
this isn't clear, it should be made clear, as soon as possible, by updating the
documentation.  The best time to document this is when merging the feature.
The next best time is today.

## What this policy does not promise

This policy optimizes for fixing more defects, in more releases, sooner.  It
does not optimize for defending against a well-resourced attacker chaining
several minor faults into a novel exploit before we publish.  We do not believe
the alternative — embargoing everything — actually buys that defense, and we
are confident it costs us the throughput to fix the ordinary defects that make
chains possible in the first place.

We would rather say this plainly than let it be inferred from our behavior.
