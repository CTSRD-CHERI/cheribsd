#!/bin/sh

# Install loader, kernel, and enough of userland to boot in QEMU and echo
# "Hello world." from init, as a very quick smoke test for CI.  Uses QEMU's
# virtual FAT filesystem to avoid the need to create a disk image.  While
# designed for CI automated testing, this script can also be run by hand as
# a quick smoke-test.  The rootgen.sh and related scripts generate much more
# extensive tests for many combinations of boot env (ufs, zfs, geli, etc).
#
# $FreeBSD$

set -e

die()
{
	echo "$*" 1>&2
	exit 1
}

tempdir_cleanup()
{
	trap - EXIT SIGINT SIGHUP SIGTERM SIGQUIT
	rm -rf ${ROOTDIR}
}

tempdir_setup()
{
	# Create minimal directory structure and populate it.
	# Caller must cd ${SRCTOP} before calling this function.

	for dir in dev bin efi/boot etc lib libexec sbin usr/lib usr/libexec; do
		mkdir -p ${ROOTDIR}/${dir}
	done

	# Install kernel, loader and minimal userland.

	make -DNO_ROOT DESTDIR=${ROOTDIR} \
	    MODULES_OVERRIDE= \
	    WITHOUT_DEBUG_FILES=yes \
	    WITHOUT_KERNEL_SYMBOLS=yes \
	    installkernel
	for dir in stand \
	    lib/libc lib/libedit lib/ncurses \
	    libexec/rtld-elf \
	    bin/sh sbin/init sbin/shutdown; do
		make -DNO_ROOT DESTDIR=${ROOTDIR} INSTALL="install -U" \
		    WITHOUT_DEBUG_FILES= \
		    WITHOUT_MAN= \
		    WITHOUT_PROFILE= \
		    WITHOUT_TESTS= \
		    WITHOUT_TOOLCHAIN= \
		    -C ${dir} install
	done

	# Put loader in standard EFI location.
	mv ${ROOTDIR}/boot/loader.efi ${ROOTDIR}/efi/boot/BOOTx64.EFI

	# Configuration files.
	cat > ${ROOTDIR}/boot/loader.conf <<EOF
vfs.root.mountfrom="msdosfs:/dev/ada0s1"
autoboot_delay=-1
boot_verbose=YES
EOF
	cat > ${ROOTDIR}/etc/rc <<EOF
#!/bin/sh

echo "Hello world."
/sbin/shutdown -p now
EOF

	# Entropy needed to boot, see r346250 and followup commits/discussion.
	dd if=/dev/random of=${ROOTDIR}/boot/entropy bs=4k count=1

	# Remove unnecessary files to keep FAT filesystem size down.
	rm -rf ${ROOTDIR}/METALOG ${ROOTDIR}/usr/lib
}

# Locate the top of the source tree, to run make install from.
: ${SRCTOP:=$(make -V SRCTOP)}
if [ -z "${SRCTOP}" ]; then
	die "Cannot locate top of source tree"
fi

# Locate the uefi firmware file used by qemu.
: ${OVMF:=/usr/local/share/uefi-edk2-qemu/QEMU_UEFI_CODE-x86_64.fd}
if [ ! -r "${OVMF}" ]; then
	die "Cannot read UEFI firmware file ${OVMF}"
fi

# Create a temp dir to hold the boot image.
ROOTDIR=$(mktemp -d -t ci-qemu-test-fat-root)
trap tempdir_cleanup EXIT SIGINT SIGHUP SIGTERM SIGQUIT

# Populate the boot image in a temp dir.
( cd ${SRCTOP} && tempdir_setup )

# And, boot in QEMU.
: ${BOOTLOG:=${TMPDIR:-/tmp}/ci-qemu-test-boot.log}
timeout 300 \
    qemu-system-x86_64 -m 256M -nodefaults \
   	-drive if=pflash,format=raw,readonly,file=${OVMF} \
        -serial stdio -vga none -nographic -monitor none \
        -snapshot -hda fat:${ROOTDIR} 2>&1 | tee ${BOOTLOG}

# Check whether we succesfully booted...
if grep -q 'Hello world.' ${BOOTLOG}; then
	echo "OK"
else
	die "Did not boot successfully, see ${BOOTLOG}"
fi
