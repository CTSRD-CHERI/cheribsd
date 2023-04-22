#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023 Klara, Inc.
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

mnt="$(realpath ${TMPDIR:-/tmp})/mnt"

# expected SHA256 checksum of file contained in test tarball
sum=4da2143234486307bb44eaa610375301781a577d1172f362b88bb4b1643dee62

tar() {
	if [ -n "${TARFS_USE_GNU_TAR}" ] ; then
		gtar --posix --absolute-names "$@"
	else
		bsdtar "$@"
	fi
}

mktar() {
	"$(atf_get_srcdir)"/mktar ${TARFS_USE_GNU_TAR+-g} "$@"
}

atf_test_case tarfs_basic cleanup
tarfs_basic_head() {
	atf_set "descr" "Basic function test"
	atf_set "require.user" "root"
}
tarfs_basic_body() {
	local tarball="${PWD}/tarfs_test.tar.zst"
	kldload -n tarfs || atf_skip "This test requires tarfs and could not load it"
	mkdir "${mnt}"
	mktar "${tarball}"
	atf_check mount -rt tarfs "${tarball}" "${mnt}"
	atf_check -o match:"^${tarball} on ${mnt} \(tarfs," mount
	atf_check_equal "$(stat -f%d,%i "${mnt}"/sparse_file)" "$(stat -f%d,%i "${mnt}"/hard_link)"
	atf_check_equal "$(stat -f%d,%i "${mnt}"/sparse_file)" "$(stat -L -f%d,%i "${mnt}"/short_link)"
	atf_check_equal "$(stat -f%d,%i "${mnt}"/sparse_file)" "$(stat -L -f%d,%i "${mnt}"/long_link)"
	atf_check -o inline:"${sum}\n" sha256 -q "${mnt}"/sparse_file
	atf_check -o inline:"2,40755\n" stat -f%l,%p "${mnt}"/directory
	atf_check -o inline:"1,100644\n" stat -f%l,%p "${mnt}"/file
	atf_check -o inline:"2,100644\n" stat -f%l,%p "${mnt}"/hard_link
	atf_check -o inline:"1,120755\n" stat -f%l,%p "${mnt}"/long_link
	atf_check -o inline:"1,120755\n" stat -f%l,%p "${mnt}"/short_link
	atf_check -o inline:"2,100644\n" stat -f%l,%p "${mnt}"/sparse_file
	atf_check -o inline:"3,40755\n" stat -f%l,%p "${mnt}"
}
tarfs_basic_cleanup() {
	umount "${mnt}" || true
}

atf_test_case tarfs_basic_gnu cleanup
tarfs_basic_gnu_head() {
	atf_set "descr" "Basic function test using GNU tar"
	atf_set "require.user" "root"
	atf_set "require.progs" "gtar"
}
tarfs_basic_gnu_body() {
	TARFS_USE_GNU_TAR=true
	tarfs_basic_body
}
tarfs_basic_gnu_cleanup() {
	tarfs_basic_cleanup
}

atf_test_case tarfs_notdir_device cleanup
tarfs_notdir_device_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561"
	atf_set "require.user" "root"
}
tarfs_notdir_device_body() {
	kldload -n tarfs || atf_skip "This test requires tarfs and could not load it"
	mkdir "${mnt}"
	atf_check mknod d b 0xdead 0xbeef
	tar -cf tarfs_notdir.tar d
	rm d
	mkdir d
	echo "boom" >d/f
	tar -rf tarfs_notdir.tar d/f
	atf_check -s not-exit:0 -e match:"Invalid" \
	    mount -rt tarfs tarfs_notdir.tar "${mnt}"
}
tarfs_notdir_device_cleanup() {
	umount "${mnt}" || true
}

atf_test_case tarfs_notdir_device_gnu cleanup
tarfs_notdir_device_gnu_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561 using GNU tar"
	atf_set "require.user" "root"
	atf_set "require.progs" "gtar"
}
tarfs_notdir_device_gnu_body() {
	TARFS_USE_GNU_TAR=true
	tarfs_notdir_device_body
}
tarfs_notdir_device_gnu_cleanup() {
	tarfs_notdir_device_cleanup
}

atf_test_case tarfs_notdir_dot cleanup
tarfs_notdir_dot_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561"
	atf_set "require.user" "root"
}
tarfs_notdir_dot_body() {
	kldload -n tarfs || atf_skip "This test requires tarfs and could not load it"
	mkdir "${mnt}"
	echo "hello" >d
	tar -cf tarfs_notdir.tar d
	rm d
	mkdir d
	echo "world" >d/f
	tar -rf tarfs_notdir.tar d/./f
	atf_check -s not-exit:0 -e match:"Invalid" \
	    mount -rt tarfs tarfs_notdir.tar "${mnt}"
}
tarfs_notdir_dot_cleanup() {
	umount "${mnt}" || true
}

atf_test_case tarfs_notdir_dot_gnu cleanup
tarfs_notdir_dot_gnu_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561 using GNU tar"
	atf_set "require.user" "root"
	atf_set "require.progs" "gtar"
}
tarfs_notdir_dot_gnu_body() {
	TARFS_USE_GNU_TAR=true
	tarfs_notdir_dot_body
}
tarfs_notdir_dot_gnu_cleanup() {
	tarfs_notdir_dot_cleanup
}

atf_test_case tarfs_notdir_dotdot cleanup
tarfs_notdir_dotdot_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561"
	atf_set "require.user" "root"
}
tarfs_notdir_dotdot_body() {
	kldload -n tarfs || atf_skip "This test requires tarfs and could not load it"
	mkdir "${mnt}"
	echo "hello" >d
	tar -cf tarfs_notdir.tar d
	rm d
	mkdir d
	echo "world" >f
	tar -rf tarfs_notdir.tar d/../f
	atf_check -s not-exit:0 -e match:"Invalid" \
	    mount -rt tarfs tarfs_notdir.tar "${mnt}"
}
tarfs_notdir_dotdot_cleanup() {
	umount "${mnt}" || true
}

atf_test_case tarfs_notdir_dotdot_gnu cleanup
tarfs_notdir_dotdot_gnu_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561 using GNU tar"
	atf_set "require.user" "root"
	atf_set "require.progs" "gtar"
}
tarfs_notdir_dotdot_gnu_body() {
	TARFS_USE_GNU_TAR=true
	tarfs_notdir_dotdot_body
}
tarfs_notdir_dotdot_gnu_cleanup() {
	tarfs_notdir_dotdot_cleanup
}

atf_test_case tarfs_notdir_file cleanup
tarfs_notdir_file_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561"
	atf_set "require.user" "root"
}
tarfs_notdir_file_body() {
	kldload -n tarfs || atf_skip "This test requires tarfs and could not load it"
	mkdir "${mnt}"
	echo "hello" >d
	tar -cf tarfs_notdir.tar d
	rm d
	mkdir d
	echo "world" >d/f
	tar -rf tarfs_notdir.tar d/f
	atf_check -s not-exit:0 -e match:"Invalid" \
	    mount -rt tarfs tarfs_notdir.tar "${mnt}"
}
tarfs_notdir_file_cleanup() {
	umount "${mnt}" || true
}

atf_test_case tarfs_notdir_file_gnu cleanup
tarfs_notdir_file_gnu_head() {
	atf_set "descr" "Regression test for PR 269519 and 269561 using GNU tar"
	atf_set "require.user" "root"
	atf_set "require.progs" "gtar"
}
tarfs_notdir_file_gnu_body() {
	TARFS_USE_GNU_TAR=true
	tarfs_notdir_file_body
}
tarfs_notdir_file_gnu_cleanup() {
	tarfs_notdir_file_cleanup
}

atf_init_test_cases() {
	atf_add_test_case tarfs_basic
	atf_add_test_case tarfs_basic_gnu
	atf_add_test_case tarfs_notdir_device
	atf_add_test_case tarfs_notdir_device_gnu
	atf_add_test_case tarfs_notdir_dot
	atf_add_test_case tarfs_notdir_dot_gnu
	atf_add_test_case tarfs_notdir_dotdot
	atf_add_test_case tarfs_notdir_dotdot_gnu
	atf_add_test_case tarfs_notdir_file
	atf_add_test_case tarfs_notdir_file_gnu
}
