CHERI C Tests
=============

This repository contains a set of C tests for the CHERI LLVM / Clang compiler
suite.  These tests are all expect to be run on a pure-capability target (i.e.
where every pointer is represented by a memory capability).

The current version of these tests runs on CHERIBSD using the CHERIABI mode.
Bare metal support is available from the cheritest repository which includes
this one as a subrepository.

Building
--------

The test suite currently requires GNU Make to build (patches to make it work
with bmake are *very* welcome!).  You will need to ensure that you have GNU
Make and the CHERI SDK installed before starting.  Then, run:

	$ gmake install SDK_ROOT=path/to/sdk DESTDIR=path/to/install

This will build all of the tests and install them, along with a `run.sh`
script, in `path/to/install`.  Ideally, the install location is an NFS-mounted
directory accessible from a CHERI system.  You can then run the `run.sh` script
to run the test suite.
