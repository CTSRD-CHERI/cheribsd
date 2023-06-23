#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023 Konrad Witaszczyk
#
# This software was developed by the University of Cambridge Computer
# Laboratory (Department of Computer Science and Technology) under Office of
# Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
# with Secure Hardware (SWISH)").
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

DRY_RUNS="10"
ITERATIONS="50"
NENTRIES_LIMIT="100"

debug() {
	echo "${*}" >&2
}

die() {
	echo "${*}" >&2
	exit 1
}

check() {
	"${@}"
	if [ $? -ne 0 ]; then
		die "Failed command: ${@}."
	fi
}

usage() {
	die "usage: compartment_test.sh entry|compressor enabled|disabled"
}

counters_reset() {
	check sudo sysctl -q security.compartment.counters.entry=0 >/dev/null
}

counters_check() {
	local _nentries

	_nentries="${1}"

	calledentries=$(sudo sysctl -n security.compartment.counters.entry)
	if [ "${_nentries}" -ne "${calledentries}" ]; then
		die "Invalid number of entries: ${calledentries} instead of ${_nentries}."
	fi
}

main() {
	local _ii _nentries _statsfile _status _test _test_sysctl

	_test="${1}"
	_status="${2}"

	case "${_test}" in
	entry|compressor)
		;;
	*)
		usage
		;;
	esac

	case "${_status}" in
	enabled|disabled)
		;;
	*)
		usage
		;;
	esac

	_statsfile="stats/$(basename $(dirname $(sysctl -n kern.bootfile)))_${_status}_$(date "+%Y-%m-%d.%H:%M:%S").txt"
	check mkdir -p stats

	case "${_test}" in
	entry)
		sudo sysctl -q security.compartment.test.entry.init=1 >/dev/null
		_test_sysctl="entry.call"
		;;
	compressor)
		sudo sysctl -q security.compartment.test.compressor.flush=1 >/dev/null 2>&1
		sudo sysctl -q security.compartment.test.compressor.fini=1 >/dev/null 2>&1
		check sudo sysctl -q security.compartment.test.compressor.init=1 >/dev/null
		_test_sysctl="compressor.write"
		;;
	esac

	for nentries in $(jot ${NENTRIES_LIMIT} 1); do
		debug "Running experiments with nentries=${nentries}."

		for ii in $(jot ${DRY_RUNS} 0); do
			counters_reset

			check sudo sysctl -q security.compartment.test.${_test_sysctl}=${nentries} >/dev/null

			counters_check "${nentries}"
		done

		for ii in $(jot ${ITERATIONS} 0); do
			for counter in INST_RETIRED CPU_CYCLES L1I_CACHE L1I_CACHE_REFILL; do
				counters_reset

				result=$(sudo pmcstat -p "${counter}" sysctl -q security.compartment.test.${_test_sysctl}=${nentries} 2>&1)
				if [ $? -ne 0 ]; then
					die "Failed to call write: ${result}"
				fi
				result=$(echo "${result}" |
				    tail +3 |
				    awk '{print $1}')

				if [ "${_status}" = "enabled" ]; then
					counters_check "${nentries}"
				else
					counters_check 0
				fi

				printf "%s %s %s\n" "${nentries}" "${counter}" "${result}" >>"${_statsfile}"
			done
		done
	done

	case "${_test}" in
	entry)
		;;
	compressor)
		check sudo sysctl -q security.compartment.test.compressor.flush=1 >/dev/null
		check sudo sysctl -q security.compartment.test.compressor.fini=1 >/dev/null
		;;
	esac
}

main "${@}"
