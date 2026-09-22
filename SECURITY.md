# Security

There are two security documents in this repository, and they answer different
questions.

**This one** is how to tell us that something is broken, and what you can expect
back.

**[docs/SECURITY.md](docs/SECURITY.md)** is the design document: the life of the
root secret, the key derivation, what sealing does on each platform, and what is
trusted. Read that one first if you are trying to understand the exposure rather
than report it. **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** walks the ten
attacks, what each one costs, and what is left over.

## What is, and is not, a security problem here

A provenance tool attracts a particular kind of report, and it helps to say out
loud which half is a bug.

**Not a vulnerability — this is the designed behaviour, and it is documented:**

* **The watermark can be removed by somebody who has the source.** `swp inspect
  fragments` can list every site in a project you control. The watermark is
  unobtrusive, not secret, and SWP-1 does not claim otherwise.
* **A rewrite that changes every protected literal leaves nothing to key on.** A
  reimplementation from memory produces the same report as an original, and
  `NO_PROVENANCE_DETECTED` is not a finding of originality.
* **A `WEAK` or `POSSIBLE` verdict on a tree that is not yours.** The report prints
  the coincidence bound precisely because chance is expected at low site counts.
* **Detection being defeated by picking literal spellings outside the dialect
  table.** That narrows the channels; it does not break the signature scheme, and
  the fingerprint and structure channels exist for this case.

**A vulnerability — please report these:**

* **The root secret reaching an artifact it should never reach:** source, generated
  source, a public manifest, CLI output, a log, a saved report, or the sealed
  store's permissions. The `secret_leak` suite is the only reason we can say that
  is covered; if it happens anyway, we want to know immediately.
* **A manifest or release record that verifies when it should not** — a signature
  that accepts, a public/private classification that lets a keyed site identifier
  into a public artifact, or a release record that agrees with a manifest it was
  not derived from.
* **Evidence appearing for a tree that shares no code with a protected project**
  beyond what chance and the documented false-positive rate allow. A reproducible
  false positive is a serious defect: this tool's output is meant to be usable in a
  dispute.
* **Escaping the scan sandbox.** `swp scan` extracts archives into a private
  temporary directory and refuses path traversal and symlink entries. An archive or
  directory tree that gets it to read, write, or delete outside that boundary — or
  to execute anything — is the most severe class of bug this project can have.
* **A crash, hang, or unbounded resource use on input the limits are supposed to
  contain.** `LIMIT_REACHED` and the `[limits]` ceilings are a security boundary
  against hostile input, not a performance tuning knob. A candidate that exhausts
  memory or CPU past a configured ceiling is a bug. (A `INTERNAL_ERROR`, exit `70`,
  is an invariant this build holds having broken; report it too.)
* **Anything that makes a report say something stronger than the measurement
  behind it**, including in the documentation.

## How to report

Use a **private security advisory**: GitHub → Security → *Report a vulnerability*
on the repository, https://github.com/theaaqibjavaid/SWP-1/security/advisories/new. That keeps
the details out of a public issue while the fix is written.

If you would rather not use GitHub, write to **aaqib100javaid@gmail.com**, the
security contact named in [MAINTAINERS.md](MAINTAINERS.md). No OpenPGP key is
published for that address, so treat ordinary email as unencrypted: ask for a key
before sending anything you would not put in a public issue, and a private security
advisory is the better route for exactly that reason.

Please include: the output of `swp --version`, the operating system, a reproducing
input (a tree, an archive, or the smallest file that still does it), and the exit
code. Redact any root secret and anything you do not have permission to share — a
report that contains your own secret is a second incident, and the analysis almost
never needs it.

## What happens next

| step | commitment |
| --- | --- |
| acknowledgement | within **5 business days**, by whoever sees the advisory first |
| assessment | we tell you whether we agree it is a vulnerability, and what class |
| fix | developed privately where disclosure would create a window; the released build is the disclosure |
| publication | a GitHub security advisory with a CVE where one is warranted, a `CHANGELOG.md` entry, and a release note that says which versions are affected |
| credit | your name, if you want it, in the advisory |

The acknowledgement window is a target we can meet as volunteers, not a contract.
Where a paying arrangement exists, response commitments for that arrangement are
in [SPONSORS.md](SPONSORS.md#what-sponsors-get) — and they are commitments about
*attention and engineering time*, never about withholding a fix from anybody who
runs this software.

## Patch and backport policy

**Every supported public version receives a security fix in the same release
cycle.** There is no paid advance on the patch itself, and there never will be,
for a reason worth stating plainly: SWP-1's value is that a report can be trusted.
A scheme in which free users run a known-broken detector for a billing interval —
or in which an adversary could buy a tier in order to learn that a fix exists
before it is public — trades the property the product exists for against revenue.

What a sponsor buys is speed and hands: an acknowledgement within hours rather
than days, an engineer reproducing the problem in their own tree, help patching a
custom fork or a branch of theirs that is not the current release, and a private
advisory channel that tells them an issue is coming so they can prepare a
mitigation. Those are all things a maintainer can sell without anyone's detector
being worse off.

**Supported versions.** A release line is supported for security fixes until a
later minor line supersedes it by two releases, or until the protocol it writes is
no longer readable — whichever comes first. At the time of writing:

| version | supported |
| --- | --- |
| 1.0.x | yes |
| < 1.0 | no releases precede 1.0.0 |

## A note on scope

SWP-1's security properties belong to the tool and the key. Your project's
protected source is a tree you have edited; keeping a release's root secret
confident, backed up, and out of a public repository is your half, and
[docs/SECURITY.md](docs/SECURITY.md) has the details of what happens if you lose
it — which is not a catastrophe, but is not nothing either.
