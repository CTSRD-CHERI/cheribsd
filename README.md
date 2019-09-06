# CheriBSD

CheriBSD extends FreeBSD/BERI to implement memory protection and
software compartmentalization features supported by the CHERI ISA.
FreeBSD/BERI is a port of the open-source FreeBSD operating system that
extends support for the Bluespec Extensible RISC implementation (BERI).
To build and run CheriBSD we recommend using the
[cheribuild](https://github.com/CTSRD-CHERI/cheribuild) script.

The CheriBSD web page can be found here:
http://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheribsd.html

The Qemu-CHERI web page may also be useful:
http://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheri-qemu.html

More information about BERI and CHERI can be found on
http://beri-cpu.org, http://cheri-cpu.org, in the following
Technical Reports:

Capability Hardware Enhanced RISC Instructions: CHERI Instruction-Set
Architecture
https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-927.pdf

Capability Hardware Enhanced RISC Instructions: CHERI Programmer's Guide (outdated, new version coming soon)
http://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-877.pdf


Bluespec Extensible RISC Implementation: BERI Hardware reference
http://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-868.pdf

Bluespec Extensible RISC Implementation: BERI Software reference
http://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-869.pdf

FreeBSD Source:
---------------
This is the top level of the FreeBSD source directory.  This file
was last revised on:
$FreeBSD$

FreeBSD is an operating system used to power modern servers,
desktops, and embedded platforms. A large community has
continually developed it for more than thirty years. Its
advanced networking, security, and storage features have
made FreeBSD the platform of choice for many of the
busiest web sites and most pervasive embedded networking
and storage devices.

For copyright information, please see the file COPYRIGHT in this
directory. Additional copyright information also exists for some
sources in this tree - please see the specific source directories for
more information.

The Makefile in this directory supports a number of targets for
building components (or all) of the FreeBSD source tree.  See build(7), config(8),
https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/makeworld.html, and
https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/kernelconfig.html
for more information, including setting make(1) variables.

Source Roadmap:
---------------
```
bin		System/user commands.

cddl		Various commands and libraries under the Common Development
		and Distribution License.

contrib		Packages contributed by 3rd parties.

crypto		Cryptography stuff (see crypto/README).

etc		Template files for /etc.

gnu		Various commands and libraries under the GNU Public License.
		Please see gnu/COPYING* for more information.

include		System include files.

kerberos5	Kerberos5 (Heimdal) package.

lib		System libraries.

libexec		System daemons.

release		Release building Makefile & associated tools.

rescue		Build system for statically linked /rescue utilities.

sbin		System commands.

secure		Cryptographic libraries and commands.

share		Shared resources.

stand		Boot loader sources.

sys		Kernel sources.

sys/<arch>/conf Kernel configuration files. GENERIC is the configuration
		used in release builds. NOTES contains documentation of
		all possible entries.

tests		Regression tests which can be run by Kyua.  See tests/README
		for additional information.

tools		Utilities for regression testing and miscellaneous tasks.

usr.bin		User commands.

usr.sbin	System administration commands.
```

For information on synchronizing your source tree with one or more of
the FreeBSD Project's development branches, please see:

  https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/current-stable.html
