#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024 Konrad Witaszczyk
#
# This software was developed by SRI International, the University of
# Cambridge Computer Laboratory (Department of Computer Science and
# Technology), and Capabilities Limited under Defense Advanced Research
# Projects Agency (DARPA) Contract No. HR001123C0031 ("MTSS").
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

main() {
	local _flags _hasflags _ii _objects _outputfile _parentobject _ret
	local _objcopytargs

	_ret=0

	_ii=0
	_hasflags=0
	for _arg in "${@}"; do
		if [ "${_hasflags}" -eq 1 ]; then
			if [ "${_ii}" -eq 0 ]; then
				_outputfile="${_arg}"
			elif [ "${_ii}" -eq 1 ]; then
				_parentobject="${_arg}"
			else
				_objects="${_objects} ${_arg}"
			fi
			_ii=$((_ii + 1))
		elif [ "${_arg}" = "-o" ]; then
			_hasflags=1
		else
			_flags="${_flags} ${_arg}"
		fi
	done

	_objcopytargs=
	for _object in ${_objects}; do
		_objcopytargs="${_objcopytargs} -T ${_object}.mo"
	done

	for _object in ${_objects} ${_parentobject}; do
		${LD} ${_flags} -o ${_object}.mo ${_object}
		_ret=$?
		[ ${_ret} -eq 0 ] || break
	done

	if [ ${_ret} -eq 0 ]; then
		${OBJCOPY_MO} ${_objcopytargs} ${_parentobject}.mo \
		    ${_outputfile}
		_ret=$?
	fi

	for _object in ${_objects} ${_parentobject}; do
		rm ${_object}.mo
	done

	return $_ret
}

main "${@}"
