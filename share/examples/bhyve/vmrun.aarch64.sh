#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2013 NetApp, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#

FBSDRUN=/usr/sbin/bhyve

DEFAULT_MEMSIZE=512M
DEFAULT_CPUS=2
DEFAULT_TAPDEV=tap0
DEFAULT_CONSOLE=stdio

DEFAULT_NIC=virtio-net
DEFAULT_DISK=virtio-blk
DEFAULT_VIRTIO_DISK="./diskdev"
DEFAULT_ISOFILE="./release.iso"

errmsg() {
	echo "*** $1"
}

usage() {
	local msg=$1

	echo "Usage: vmrun.sh [-AhiTv] [-c <CPUs>] [-C <console>]" \
	    "[-d <disk file>]"
	echo "                [-f <path of firmware>]" \
	    "[-F <size>]"
	echo "                [-G [w][address:]port] [-H <directory>]"
	echo "                [-I <location of installation iso>]"
	echo "                [-m <memsize>]" \
	    "[-n <network adapter emulation type>]"
	echo "                [-P <port>] [-t <tapdev>] <vmname>"
	echo ""
	echo "       -h: display this help message"
	echo "       -A: use AHCI disk emulation instead of ${DEFAULT_DISK}"
	echo "       -c: number of virtual cpus (default: ${DEFAULT_CPUS})"
	echo "       -C: console device (default: ${DEFAULT_CONSOLE})"
	echo "       -d: virtio diskdev file (default: ${DEFAULT_VIRTIO_DISK})"
	echo "       -f: Use a specific firmware"
	echo "       -G: bind the GDB stub to the specified address"
	echo "       -i: force boot of the Installation CDROM image"
	echo "       -I: Installation CDROM image location" \
	    "(default: ${DEFAULT_ISOFILE})"
	echo "       -m: memory size (default: ${DEFAULT_MEMSIZE})"
	echo "       -n: network adapter emulation type" \
	    "(default: ${DEFAULT_NIC})"
	echo "       -t: tap device for virtio-net (default: $DEFAULT_TAPDEV)"
	echo ""
	[ -n "$msg" ] && errmsg "$msg"
	exit 1
}

if [ `id -u` -ne 0 ]; then
	errmsg "This script must be executed with superuser privileges"
	exit 1
fi

kldstat -n vmm > /dev/null 2>&1 
if [ $? -ne 0 ]; then
	errmsg "vmm.ko is not loaded"
	exit 1
fi

force_install=0
isofile=${DEFAULT_ISOFILE}
memsize=${DEFAULT_MEMSIZE}
console=${DEFAULT_CONSOLE}
cpus=${DEFAULT_CPUS}
nic=${DEFAULT_NIC}
tap_total=0
disk_total=0
disk_emulation=${DEFAULT_DISK}
bhyverun_opt=""

# EFI-specific options
firmware="/usr/local64/share/u-boot/u-boot-bhyve-arm64/u-boot.bin"

while getopts Ac:C:d:f:G:hH:iI:m:n:t: c ; do
	case $c in
	A)
		disk_emulation="ahci-hd"
		;;
	c)
		cpus=${OPTARG}
		;;
	C)
		console=${OPTARG}
		;;
	d)
		disk_dev=${OPTARG%%,*}
		disk_opts=${OPTARG#${disk_dev}}
		eval "disk_dev${disk_total}=\"${disk_dev}\""
		eval "disk_opts${disk_total}=\"${disk_opts}\""
		disk_total=$(($disk_total + 1))
		;;
	f)
		firmware="${OPTARG}"
		;;
	G)
		bhyverun_opt="${bhyverun_opt} -G ${OPTARG}"
		;;
	i)
		force_install=1
		;;
	I)
		isofile=${OPTARG}
		;;
	m)
		memsize=${OPTARG}
		;;
	n)
		nic=${OPTARG}
		;;
	t)
		eval "tap_dev${tap_total}=\"${OPTARG}\""
		tap_total=$(($tap_total + 1))
		;;
	*)
		usage
		;;
	esac
done

if [ $tap_total -eq 0 ] ; then
    tap_total=1
    tap_dev0="${DEFAULT_TAPDEV}"
fi
if [ $disk_total -eq 0 ] ; then
    disk_total=1
    disk_dev0="${DEFAULT_VIRTIO_DISK}"

fi

shift $((${OPTIND} - 1))

if [ $# -ne 1 ]; then
	usage "virtual machine name not specified"
fi

vmname="$1"

if [ ! -f ${firmware} ]; then
	echo "Error: Firmware ${firmware} doesn't exist." \
	    "Try: pkg64 install u-boot-bhyve-arm64"
	exit 1
fi

make_and_check_diskdev()
{
    local virtio_diskdev="$1"
    # Create the virtio diskdev file if needed
    if [ ! -e ${virtio_diskdev} ]; then
	    echo "virtio disk device file \"${virtio_diskdev}\" does not exist."
	    echo "Creating it ..."
	    truncate -s 8G ${virtio_diskdev} > /dev/null
    fi

    if [ ! -r ${virtio_diskdev} ]; then
	    echo "virtio disk device file \"${virtio_diskdev}\" is not readable"
	    exit 1
    fi

    if [ ! -w ${virtio_diskdev} ]; then
	    echo "virtio disk device file \"${virtio_diskdev}\" is not writable"
	    exit 1
    fi
}

echo "Launching virtual machine \"$vmname\" ..."

first_diskdev="$disk_dev0"

sysctl hw.vmm.destroy="${vmname}" > /dev/null 2>&1

while [ 1 ]; do

	file -s ${first_diskdev} | grep "boot sector" > /dev/null
	rc=$?
	if [ $rc -ne 0 ]; then
		file -s ${first_diskdev} | \
		    grep ": Unix Fast File sys" > /dev/null
		rc=$?
	fi
	if [ $rc -ne 0 ]; then
		need_install=1
	else
		need_install=0
	fi

	if [ $force_install -eq 1 -o $need_install -eq 1 ]; then
		if [ ! -r ${isofile} ]; then
			echo -n "Installation image \"${isofile}\" "
			echo    "is not readable"
			exit 1
		fi
		installer_opt="-s 1:0,virtio-blk,${isofile}"
	else
		i=0
		while [ $i -lt $disk_total ] ; do
			eval "disk=\$disk_dev${i}"
			i=$(($i + 1))
		done
		installer_opt=""
	fi

	#
	# Build up args for additional tap and disk devices now.
	#
	nextslot=2  # slot 0 is hostbridge, slot 1 is ISO
	devargs=""  # accumulate disk/tap args here
	i=0
	while [ $i -lt $tap_total ] ; do
	    eval "tapname=\$tap_dev${i}"
	    devargs="$devargs -s $nextslot:0,${nic},${tapname} "
	    nextslot=$(($nextslot + 1))
	    i=$(($i + 1))
	done

	i=0
	while [ $i -lt $disk_total ] ; do
	    eval "disk=\$disk_dev${i}"
	    eval "opts=\$disk_opts${i}"
	    make_and_check_diskdev "${disk}"
	    devargs="$devargs -s $nextslot:0,$disk_emulation,${disk}${opts} "
	    nextslot=$(($nextslot + 1))
	    i=$(($i + 1))
	done

	${FBSDRUN} -c ${cpus} -m ${memsize} ${bhyverun_opt}		\
		-s 0:0,hostbridge					\
		${devargs}						\
		-o bootrom=${firmware}					\
		-o console=${console}					\
		${installer_opt}					\
		${vmname}

	bhyve_exit=$?
	# bhyve returns the following status codes:
	#  0 - VM has been reset
	#  1 - VM has been powered off
	#  2 - VM has been halted
	#  3 - VM generated a triple fault
	#  all other non-zero status codes are errors
	#
	if [ $bhyve_exit -ne 0 ]; then
		break
	fi
done


case $bhyve_exit in
	0|1|2)
		# Cleanup /dev/vmm entry when bhyve did not exit
		# due to an error.
		sysctl hw.vmm.destroy="${vmname}" > /dev/null 2>&1
		;;
esac

exit $bhyve_exit
