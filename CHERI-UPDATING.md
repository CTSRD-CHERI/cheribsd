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

### Flag days on [main]

| Date       | Commit      | Description | Required action |
| ---------- | ----------- | --- | --- |
| 2022-05-23 | [86d134e9e] | Morello TLS and vararg bounds | Update to [Morello LLVM a7d0053c29] and perform a clean rebuild of all Morello software |
| 2020-11-30 | [3bcdffa1a] | OpenZFS import | Clean rebuild |
| 2020-11-30 | [73173b1f1] | ABI note tag in shared libraries | Clean rebuild |
| 2020-11-30 | [cc876df74] | MIPS with CHERI support now builds hybrid | Clean rebuild |
| 2020-11-30 | [e5c4980cd] | Enable MK_LIB64 on CHERI-RISC-V | delete bin/cheritest*/*.o and usr.bin/kyua/main.o from riscv64 purecap build directores or clean rebuild |
| 2020-05-11 | [7e76d8f71] | C/C++ ABI changes | Update to [LLVM b7f5c847dc] and a clean rebuild.|
| 2020-03-06 | [6ce214d1e] | ELF auxargs flags altered | Clean rebuild |

### Flag days on [dev]

| Date       | Commit      | Description | Required action |
| ---------- | ----------- | --- | --- |
| 2022-05-12 | [86d134e9e] | Morello TLS and vararg bounds | Update to [Morello LLVM a7d0053c29] and perform a clean rebuild of all Morello software |
| 2020-11-17 | [3bcdffa1a] | OpenZFS import | Clean rebuild |
| 2020-11-12 | [73173b1f1] | ABI note tag in shared libraries | Clean rebuild |
| 2020-06-24 | [e5c4980cd] | Enable MK_LIB64 on CHERI-RISC-V | delete bin/cheritest*/*.o and usr.bin/kyua/main.o from riscv64 purecap build directores or clean rebuild |
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

* [main] - The default branch, synced periodically with [dev] and kept in
  sync with the [LLVM master] branch.  Outside consumers likely wish to follow
  this branch.

To aid comparison with upstream FreeBSD we maintain a branch of stock
FreeBSD:

* [freebsd-main] - FreeBSD main (from [freebsd/freebsd-src]) as merged to
  [dev].  We update it using fast-forward so commit hashes match upstream.

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
platform stability and the [main] branch isn't appropriate.

Each merge from upstream FreeBSD to [dev] is accompanied by a tag of the form
`freebsd-main-YYYYMMDD`, and updates to [freebsd-main].

### Updating [main]

We typically merge to [main] from [dev] at stable points at least a week
apart.

### The merge process
CheriBSD is extremely diverged from FreeBSD with nearly two
thousand changed files. As such, there are many opportunities for
a merge to conflict and worse for a merge to not conflict, but
be broken. It is critical that we be able to bisect the merged
changes. To support this we merge changes one commit at a time
from the _first-parent_ history of FreeBSD's `main` using the
[mergify](https://github.com/brooksdavis/mergify) script. This makes it
straightforward to discover which change caused a problem.

This section describes the merge process in detail.

#### Setup
The merger must add an appropriate FreeBSD remote to their setup. This
example uses the official FreeBSD mirror, a mirror on GitHub or the like
will also work fine.
```
$ git remote add upstream https://git.FreeBSD.org/src.git
```
You will also want to enable `git rerere` to simplify handling the same
conflicting merges over again. To do so globally, run:
```
$ git config --global rerere.enabled true
```
Disable rename detection. This sometimes leads to awkward merges but
rename detection takes **forever** on the CheriBSD repo.
```
$ git config merge.renames false
```

#### Identifying the merge point
Update the upstream remote if required:
```
$ git fetch upstream
```
Then identify the head of the set of commits to merge. Because FreeBSD
does not enforce date linearity this is a bit annoying. The default
`Date:` will generally be somewhere in the past relative to the actual
push unless the committer reset the date immediately before with
`git rebase --ignore-date` or `git commit --amend --date=now`. As
such we want to look at the commit date which is a better (but still
sub-optimal) proxy for the time the change was pushed to the FreeBSD
tree. We currently do this by examining the log and looking for the
first `CommitDate: ` line mentioning the day we wish to merge. To see
only eligible commits and to cause the commit date to be displayed we
use:
```
$ git log --first-parent --format=fuller upstream/main
```
We can then use the pager's search function to search for the
appropriate date (e.g.. `Commit.*Fri Feb 12`). It's a good idea to check
a few commits up or down to make sure the commit isn't at an obviously
bad point. Then we create a tag for the commit:
```
$ git tag -m "FreeBSD main DD Month YYYY" freebsd-main-<YYYYMMDD> <hash>
```

#### Performing the merge
First, create a merge branch from an update to date `dev` checkout:
```
$ git checkout -b merge-freebsd-<YYYYMMDD> dev
```
Then start the merge:
```
$ mergify start freebsd-main-<YYYYMMDD>
```
The mergify command will start merging each change one at a time until
it hits a conflict or a pause point (e.g., a path in the merged commit
matches the regex in [.mergify_pause_paths].) After inspecting the
change or resolving the conflict, continue with:
```
mergify continue
```

For ease of conflict resolution, `mergify resolve` opens each file
containing conflict files in `EDITOR` in turn. `mergify autoadd` adds
all conflicted files that no longer contain conflict markers to the
index. It does not add files that were not in the original merge, they
need to be added with `git add`.

Sometimes a change has already been applied to the tree or is a change
requiring porting that is reverted later on. In that case, `mergify
skip` can be used. It restores all modified files to the version in HEAD
and then continues.

#### Rolling back
Over the course of the merge process, it is not uncommon to discover
that a previously merged change requires additional changes. Ideally
we'd make a fixup commit and then rebase, but `git rebase` is useless
with merge commits. Instead, the general process is to stop the merge,
use `git reset` to rewind to the broken commit, fix it up, and restart
the merge. The process usually looks like
```
$ mergify abort
$ git reset --hard <bad merge>
...
$ git commit --amend
$ mergify start freebsd-main-<YYYYMMDD>
```
Sometime the commit itself isn't the problem, but rather that it
enabled a feature than was broken with CHERI. When this happens,
resetting to the commit before the feature was enabled, fixing things,
and restarting can make sense.

Sometimes there are too many awkward changes (e.g. one that required
fixup in files outside the original change) and it's not worth
backtracking to fix things in the ideal location. In that case, make
sure to indicate that the fixup commit fixes an issue introduced in a
particular commit to aid future users of bisect.

#### Finishing up
Once the merge is complete and basic local testing is done, it's time to
update the `freebsd-main` branch and push the tag. (It's good to delay
to this point in hopes of keeping `freebsd-main` relatively in sync with
main.) This can be done in a worktree with:
```
$ git merge --ff-only freebsd-main-<YYYYMMDD>
$ git push
$ git push origin freebsd-main-<YYYYMMDD>
```
Now, push the main tree to create a pull request to kick off a full CI run.
```
$ git push --set-upstream origin merge-freebsd-<YYYYMMDD>
```
Use the GitHub web UI or the `gh` tool to create a pull request against
the `dev` branch. (If the `master` branch isn't sufficiently up to date
the GitHub UI will timeout creating the pull request and display an
angry unicorn. Just keep hitting reload until it succeeds.)
```
$ gh pr create --title "Merge FreeBSD YYYY-MM-DD" --body "PR for CI"  --base dev --head merge-freebsd-<YYYYMMDD>
```
As required, make changes and roll back to make fixes to get CI to pass.

Once CI passes, update the [.last_merge] file to match the tag and commit:
```
$ echo freebsd-head-<YYYYMMMDD> > .last_merge
$ git commit -m "Merged through Month DD, YYYY" .last_merge
```

#### Publishing the changes
Push the branch to `dev`:
```
$ git push origin merge-freebsd-<YYYYMMDD>:dev
```
The PR will automatically close. (You can't use the GitHub UI to merge
because the "Rebase and merge" function always rebases and can't
fast-forward so it fails due to all the merges.)

Delete the `merge-freebsd-<YYYYMMDD>` branch.

[cheribuild]: https://github.com/CTSRD-CHERI/cheribuild
[dev]: https://github.com/CTSRD-CHERI/cheribsd/tree/dev
[freebsd-main]: https://github.com/CTSRD-CHERI/cheribsd/tree/freebsd-main
[freebsd-crossbuild]: https://github.com/CTSRD-CHERI/cheribsd/tree/freebsd-crossbuild
[freebsd/freebsd-src]: https://github.com/freebsd/freebsd-src
[LLVM dev]: https://github.com/CTSRD-CHERI/llvm-project/tree/dev
[LLVM master]: https://github.com/CTSRD-CHERI/llvm-project/tree/master
[main]: https://github.com/CTSRD-CHERI/cheribsd/tree/main
[mergify]: https://github.com/brooksdavis/mergify
[UPDATING]: UPDATING

[e5c4980cd]: https://github.com/CTSRD-CHERI/cheribsd/e5c4980cd
[cc876df74]: https://github.com/CTSRD-CHERI/cheribsd/cc876df74
[6ce214d1e]: https://github.com/CTSRD-CHERI/cheribsd/6ce214d1e
[73173b1f1]: https://github.com/CTSRD-CHERI/cheribsd/73173b1f1
[7e76d8f71]: https://github.com/CTSRD-CHERI/cheribsd/7e76d8f71
[3bcdffa1a]: https://github.com/CTSRD-CHERI/cheribsd/3bcdffa1a
[LLVM b7f5c847dc]: https://github.com/CTSRD-CHERI/llvm-project/commit/b7f5c847dc
[86d134e9e]: https://github.com/CTSRD-CHERI/cheribsd/86d134e9e
[Morello LLVM a7d0053c29]: https://git.morello-project.org/morello/llvm-project/-/commit/a7d0053c29e0275a7d920170fe686ba3b6d61cbf
