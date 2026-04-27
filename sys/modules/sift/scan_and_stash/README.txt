This repo contains a variant of scan_and_stash suited for CheriBSD.
This variant uses two kernel modules: scan_stash and scan_stash_ace.

Its chief components are:
  (0) Goal
  (1) a working userland program in main.c
  (2) a working kernel module called scan_stash.c
  (3) a working kernel module called scan_stash_ace.c
  (4) a working userland program in ace_control.c

Definitions:
  "normal mode" is when the ACE is disabled.
  "ace mode" is when the ACE is enabled.

-- Description of each component:

(0) The goal of this kernel module is to draw a kernel compartmentalization
    boundary between a process' stack segments and all of its other memory
    segments.  This kernel module, when prompted via an ioctl() of a userland
    process on a device driver created by the module, will iterate across the
    kernel VM data structures for the entire set of memory regions of that user
    process. In the case of physically loaded stack segment pages, the kernel
    module will actually dereference (via the kernel's copyin() function) the
    process' stack page information looking for a cookie.  In the normal mode
    it is intended that ONLY stack pages are actually copied into the kernel
    module memory and checked for the cookie. When the ACE is enabled, the ACE
    mode will dereference user memory in ALL physically/appropriately mapped
    memory segments and extract a secret from the userland program's memory.
    In both cases, the data is written to a file descriptor the userland
    program had passed to the kernel via the ioctl().

    NOTE: It is the case, with this version of the program that the "good
    behavior" of this kernel module is not necessarily useful. This will be
    resolved in a future commit.

(1) The main.c program creates a 'struct secret' instance in global (non-stack)
    memory and populates it with a secret which is the phrase
    "deadbeef-53c237-deadbeef".  It then opens the file "/dev/scan_stash"
    created by the scan_stash module.

    Then a pipe is created whose write end is supplied to an ioctl() invocation
    using the SIFT_SCAN_AND_STASH_IOC_SRCH command. In the case where the ACE
    is disabled, see (3) and (4), this will cause the kernel to take the stack
    pointer of the thread which invoked the ioctl() call, align it to a 64-byte
    value, then search for the page in question which contains that pointer in
    the stack space of the program. When this is found, 24 bytes (at this time
    they are mostly random) are read from the page at that location and
    written, by the kernel, into the write end of the pipe. All of this
    happens during the ioctl(). These 24 bytes are constrained by the
    scan_stash module to be read ONLY from stack pages in the normal case.

    When the ACE is in force, then instead of those 24 bytes at that location
    in the stack, the ACE searches through ALL of the pages in the process' VM
    regions, finds the secret's delimiters, reads the secret from non-stack
    pages into kernel memory, then writes it to the write end of the supplied
    pipe fd.  In the current version, the secret is the string:
    "deadbeef-53c237-deadbeef".

(2) The scan_stash.c program implements the kernel module searching through
    user virtual memory for a cookie. The cookie is the stack pointer of the
    current thread which invoked the ioctl() aligned to 64-bytes. In
    particular, it uses the scan_and_stash function to search the calling
    process's memory segments. It traverses each page of the space in 64-byte
    increments [see NOTE below] (that it copies into the kernel memory from the
    user page) until it finds a chunk in the stack segment which contains the
    64-byte aligned stack pointer.  It then writes 24 bytes of data stored at
    that aligned stack pointer in userspace to pipe, as described in (1).

    This module depends on and expects to be loaded the scan_stash_ace module
    described in (3). We assume, for the purposes of this discussion in (2),
    that the ACE has been disabled. The exported ACE function call is called
    mandatorily in this module.

    NOTE: The module (in normal mode) does not search every page of the user
    address space for the process, for this would possibly cause page faults in
    the kernel module and hence a panic. It skips those pages that: (a) belong
    to virtual memory entries flagged by the kernel as things we don't want to
    read, like a GUARD page or (b) are unable to be mapped (for whatever
    reason) to physical pages, or (c) are not marked as stack pages via the
    stack growing down or up flags for the VM segment.  Pages unable to be
    mapped aren't necessarily actually unable to be mapped, but we didn't write
    any code to map them into physical space.

    Here are useful source files used as references about FreeBSD's
    virtual memory system:
 
    (a) vm/vm_map.h and related in that directory.
    This is by far the most important and informative file. It includes a nice
    description of the memory system and contains the main data structures.
    
    (b) kern/kern_proc.c
    This was useful for examining the traversal of the vm_entry list. To this
    end, see the definition of sysctl_kern_proc_ovmmap().

(3) The scan_stash_ace.c module will load when scan_stash.c does beacuse we
    have added the macro MODULE_DEPEND to the latter to tell the loader that it
    depends on scan_stash_ace. This also acts to export (in Linux terms) the
    global symbols of scan_stash_ace.

    This module defines an exported function called scan_stash_ace() which is
    called (by the scan_stash module) with a struct scan_stash_ace_context
    pointer. This function will either do nothing or perform the ACE depending
    on the dynamic configuration.

    The userspace 'ace_control' program uses an ioctl() on a device file
    created by this module (and different from the one in (2)) to set/clear the
    global bool variable "ace_enabled" in the scan_stash_ace kernel module.
    This variable determines whether scan_stash_ace will execute the ACE or
    just let normal mode occur. 
    
    scan_stash_ace()'s full source code is intended to be hidden from the
    performers. They should assume they can't see what it does.

(4) The ace_control.c program opens the "/dev/scan_stash_ace_ctrl" device
    and will enable or disable the ACE behavior depending upon an ioctl() call
    using that opened fd. Running the program with --ace-enable witll enable
    the ACE behavior, and running the program with --ace-disable will disable
    it. The userland main.c program should work in either case.

TODO: Documentation beyond this point is stale!

-- Running the code


Here is how to run the two modules out-of-source on QEMU from the current
directory.

  1. Ensure you are in a booted into the proper FreeBSD QEMU instance.
     See svn/pacman/notes/FREEBSD-QEMU.txt

  2. Ensure freebsd-staging-area/ is sshfs mounted in it:

    ./mountit

    See Appendix A, you will have to customize that script.

  3. cd to freebsd-staging-area/

    ./doit-scan_and_stash clean
    ./doit-scan_and_stash

    This is a summary of what happens when the second command above is run:

    Make clean for the kernel modules, the user space programs, and then
    recompile everything.

    The tests are currently inspected visually at this time.

    First, the ACE is ensured to be disabled, then:
    The first execution of srch results in garbage being printed out in the
    test-disabled-*.out file. This output is not better characterized at this
    time, sorry. 

    Then, the ACE is ensured to be enabled, then:
    The second execution of srch results in the secret phrase
    "deadbeef-53c237-deadbeef"
    being printed out in the test-enabled*.out file.

    Finally, the ACE is ensured to be disabled, then:
    The third execution of srch is like the first. Garbage is again emitted
    into the out file.

-- Appendix A

  This program is how one mounts an sshfs partition into the FreeBSD instance.
  This program MUST BE MODIFIED for your environment. Specifically the
  username@machine:path must be changed.

# BEGIN ./mountit

#! /bin/sh

kldstat | grep fusefs > /dev/null 2>&1
ret=$?
if [ "$ret" = "1" ]; then
  echo "No fusefs kernel module found, loading a new one."
  kldload -v fusefs
fi

mount | grep freebsd-staging-area > /dev/null 2>&1
ret=$?
if [ "$ret" = "0" ]; then
  echo "Already mounted."
  exit 0
fi

sshfs \
  -o noatime \
  pkeller@orchid:/home/pkeller/svn/pacman/code/cheri/freebsd-staging-area \
  /root/freebsd-staging-area

# END ./mountit
