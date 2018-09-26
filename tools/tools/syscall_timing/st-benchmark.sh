#!/bin/sh -e

ST_ROOT=`pwd`
RESULTS="${ST_ROOT}/results"

run_st() {
	NAME="$1"

	ST="${ST_ROOT}/${NAME}/syscall_timing"
	chmod +x "${ST}"

#	echo "${0}: binary details:"
#	file "${ST}"

	# Avoid creating the statcounters output for this one.
	export STATCOUNTERS_OUTPUT="/dev/null"
	TEST_LIST=`${ST} 2>&1 | sed 1d`

	OUTPUT="${RESULTS}/${NAME}"
	echo "${0}: test results will be at ${OUTPUT}/"

	mkdir -p "${OUTPUT}"
	for t in ${TEST_LIST}; do
		export STATCOUNTERS_OUTPUT="${OUTPUT}/${t}.statcounters"
		"${ST}" "${t}" | sed "1,2d" > "${OUTPUT}/${t}"
	done
}

echo "${0}: uname:"
uname -a

echo "${0}: invariants/witness:"
sysctl -a | grep -E '(invariants|witness)' || true

run_st "cheri"
run_st "hybrid"
#run_st "mips"

echo "${0}: done"

tar zcvf /tmp/syscall_timing-output.tgz "${ST_ROOT}"

echo "DONE RUNNING BENCHMARKS"
