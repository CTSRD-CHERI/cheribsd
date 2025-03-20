#
# Copyright (c) 2025 Konrad Witaszczyk
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This software was developed by SRI International, the University of
# Cambridge Computer Laboratory (Department of Computer Science and
# Technology), and Capabilities Limited under Defense Advanced Research
# Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
#

usage() {
	echo "usage: ${0} ldscript-template"
	exit 1
}

die() {
	echo ${*} >&2
	exit 1
}

main() {
	local _files _ldscript _policies _replacewith

	_ldscript="${1}"
	[ -n "${_ldscript}" ] || usage

	_policies=$(find . -name 'kernel*.json')
	if [ $? -ne 0 ]; then
		die "Unable to find policy files."
	fi

	if [ -z "${_policies}" ]; then
		die "No policy files were found."
	fi

	_policies=$(echo "${_policies}" | sort)
	_files=$(jq -r '.TCB.files | join(" ")' ${_policies})
	if [ $? -ne 0 ]; then
		die "Unable to parse policies."
	fi

	_files=$(echo ${_files}| tr '\n' ' ')
	if [ -z "${_files}" ]; then
		die "No TCB files are defined in policies."
	fi

	_replacewith=""
	for _file in ${_files}; do
		if [ -z "${_replacewith}" ]; then
			_replacewith="${_file}(\\1)"
		else
			_replacewith="${_replacewith} ${_file}(\\1)"
		fi
	done
	sed -E "s@TCB_FILES\(([^)]*)\)@${_replacewith}@g" "${_ldscript}"
}

main "${@}"
