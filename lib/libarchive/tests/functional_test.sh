#!/bin/sh
# Copyright 2015 EMC Corp.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

SRCDIR=$(atf_get_srcdir)
TESTER="${SRCDIR}/libarchive_test"

check()
{
	local testcase=${1}; shift
	if [ "$(atf_config_get include_slow_tests false)" != "true" ]; then
		# Skip fuzz tests and reduce size for the large tests since
		# otherwise these tests time out on slow platforms such as
		# QEMU RISC-V.
		export TEST_SLOW_HOST=1
		export SKIP_TEST_FUZZ=1
	fi

	atf_check -o ignore -s exit:0 ${TESTER} -d -r "${SRCDIR}" -v "${testcase}"
}

atf_init_test_cases()
{
	# Redirect stderr to stdout for the usage message because if you don't
	# kyua list/kyua test will break:
	# https://github.com/jmmv/kyua/issues/149
	testcases=$(${TESTER} -h 2>&1 | awk 'p != 0 && $1 ~ /^[0-9]+:/ { print $NF } /Available tests:/ { p=1 }')
	for testcase in ${testcases}; do
		atf_test_case ${testcase}
		eval "${testcase}_body() { check ${testcase}; }"
		atf_add_test_case ${testcase}
	done
}
