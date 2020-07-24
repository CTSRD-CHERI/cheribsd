# Updating Information for CheriBSD users.

This file contains information about updating CheriBSD.  It supplements
the information in the [UPDATING] file with CheriBSD specific
information.  In particular it explains ABI flag days, our branching structure,
and our strategy from merging from upstream FreeBSD.

## Flag days and major changes

Generally speaking, flag days require a complete rebuild of CheriBSD.
When building with [cheribuild] this is usually handled automatically,
but if necessary the `--clean` flag can be used.  When building
directly, avoid the `-DNO_CLEAN` make option.

### Flag days on [master]

| Date       | Commit      | Description | Required action |
| ---------- | ----------- | --- | --- |
| 2020-06-04 | [cc876df74] | MIPS with CHERI support now builds hybrid | Clean rebuild |
| 2020-05-11 | [7e76d8f71] | C/C++ ABI changes | Update to [LLVM b7f5c847dc] and a clean rebuild.|
| 2020-03-06 | [6ce214d1e] | ELF auxargs flags altered | Clean rebuild |

### Flag days on [dev]

| Date       | Commit      | Description | Required action |
| ---------- | ----------- | --- | --- |
| 2020-05-26 | [cc876df74] | MIPS with CHERI support now builds hybrid | Clean rebuild |
| 2020-04-21 | [7e76d8f71] | C/C++ ABI changes | Update to [LLVM b7f5c847dc] and a clean rebuild.|
| 2020-03-06 | [6ce214d1e] | ELF auxargs flags altered | Clean rebuild |

Note: The dates listed are the date the change hit the public tree which
may not correspond to the commit log.

## Branches

The CheriBSD repository contains a number of branches.  The two main branches
are:

* [dev] - The primary development branch.  Pull requests should generally be
  targeted here.  When using this branch, you should also track the [LLVM dev]
  branch.

* [master] - The default branch, synced periodically with [dev] and kept in
  sync with the [LLVM master] branch.  Outside consumers likely wish to follow
  this branch.

To aid comparison with upstream FreeBSD we maintain a couple of branches of stock
FreeBSD:

* [freebsd-head] - FreeBSD HEAD (from [freebsd/freebsd]) as merged to
  [dev].  We update it using fast-forward so commit hashes match upstream.

* [freebsd-crossbuild] - FreeBSD HEAD with a roll up of not-yet-merged
  cross-building changes required to build on a macOS or Linux system.
  We currently merge on top of the existing changes.  This branch
  will eventually go away.

Numerous other branches exist ranging from pull-request branches to long-term
feature development and checkpoints of abandoned work.  We generally delete
pull-request branches after merge.

## Merging strategy

### Updating [dev]

We typically merge from upstream FreeBSD to [dev] in batches of one week
of changes from the end of Friday UTC.  These are merged one upstream
commit at a time using [mergify] to aid bisection.  Sometimes we either
merge at other times because we need an upstream commit.  In a steady
state we merge weekly, but delay and batch updates if we need extra
platform stability and the [master] branch isn't appropriate.

Each merge from upstream FreeBSD to [dev] is accompanied by a tag of the form
`freebsd-head-YYYYMMDD`, and updates to [freebsd-head] and
[freebsd-crossbuild].

### Updating [master]

We typically merge to [master] from [dev] at stable points at least a week
apart.

[cheribuild]: https://github.com/CTSRD-CHERI/cheribuild
[dev]: https://github.com/CTSRD-CHERI/cheribsd/tree/dev
[freebsd-head]: https://github.com/CTSRD-CHERI/cheribsd/tree/freebsd-head
[freebsd-crossbuild]: https://github.com/CTSRD-CHERI/cheribsd/tree/freebsd-crossbuild
[freebsd/freebsd]: https://github.com/freebsd/freebsd
[LLVM dev]: https://github.com/CTSRD-CHERI/llvm-project/tree/dev
[LLVM master]: https://github.com/CTSRD-CHERI/llvm-project/tree/master
[master]: https://github.com/CTSRD-CHERI/cheribsd/tree/master
[mergify]: https://github.com/brooksdavis/mergify
[UPDATING]: UPDATING

[6ce214d1e]: https://github.com/CTSRD-CHERI/cheribsd/6ce214d1e
[7e76d8f71]: https://github.com/CTSRD-CHERI/cheribsd/7e76d8f71
[LLVM b7f5c847dc]: https://github.com/CTSRD-CHERI/llvm-project/commit/b7f5c847dc
