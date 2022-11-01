# CheriBSD

CheriBSD extends FreeBSD to implement memory protection and
software compartmentalization features supported by the CHERI ISA.
CheriBSD includes support for CHERI extensions to the MIPS and RISC-V
architectures.
To build and run CheriBSD we recommend using the
[cheribuild](https://github.com/CTSRD-CHERI/cheribuild) script.

For information on our branching model, updates, and flag days, please
read [CHERI-UPDATING.md](CHERI-UPDATING.md).

The CheriBSD web page can be found here:
http://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheribsd.html

The Qemu-CHERI web page may also be useful:
http://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheri-qemu.html

More information about CHERI can be found on http://cheri-cpu.org and
in the following Technical Reports:

An Introduction to CHERI
https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-941.pdf

Capability Hardware Enhanced RISC Instructions: CHERI Instruction-Set
Architecture
https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-927.pdf

CHERI C/C++ Programming Guide
https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-947.pdf

FreeBSD Source:
---------------
This is the top level of the FreeBSD source directory.

FreeBSD is an operating system used to power modern servers, desktops, and embedded platforms.
A large community has continually developed it for more than thirty years.
Its advanced networking, security, and storage features have made FreeBSD the platform of choice for many of the busiest web sites and most pervasive embedded networking and storage devices.

For copyright information, please see [the file COPYRIGHT](COPYRIGHT) in this directory.
Additional copyright information also exists for some sources in this tree - please see the specific source directories for more information.

The Makefile in this directory supports a number of targets for building components (or all) of the FreeBSD source tree.
See build(7), config(8), [FreeBSD handbook on building userland](https://docs.freebsd.org/en/books/handbook/cutting-edge/#makeworld), and [Handbook for kernels](https://docs.freebsd.org/en/books/handbook/kernelconfig/) for more information, including setting make(1) variables.

Source Roadmap:
---------------
| Directory | Description |
| --------- | ----------- |
| bin | System/user commands. |
| cddl | Various commands and libraries under the Common Development and Distribution License. |
| contrib | Packages contributed by 3rd parties. |
| crypto | Cryptography stuff (see [crypto/README](crypto/README)). |
| etc | Template files for /etc. |
| gnu | Commands and libraries under the GNU General Public License (GPL) or Lesser General Public License (LGPL). Please see [gnu/COPYING](gnu/COPYING) and [gnu/COPYING.LIB](gnu/COPYING.LIB) for more information. |
| include | System include files. |
| kerberos5 | Kerberos5 (Heimdal) package. |
| lib | System libraries. |
| libexec | System daemons. |
| release | Release building Makefile & associated tools. |
| rescue | Build system for statically linked /rescue utilities. |
| sbin | System commands. |
| secure | Cryptographic libraries and commands. |
| share | Shared resources. |
| stand | Boot loader sources. |
| sys | Kernel sources (see [sys/README.md](sys/README.md)). |
| targets | Support for experimental `DIRDEPS_BUILD` |
| tests | Regression tests which can be run by Kyua.  See [tests/README](tests/README) for additional information. |
| tools | Utilities for regression testing and miscellaneous tasks. |
| usr.bin | User commands. |
| usr.sbin | System administration commands. |

For information on synchronizing your source tree with one or more of the FreeBSD Project's development branches, please see [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/cutting-edge/#current-stable).
