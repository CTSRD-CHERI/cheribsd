#!/bin/sh

BENCHMARKS="coping_1 coping_10 coping_100 coping_1000 coping_10000 coping_100000 coping_1000000 pipeping_1 pipeping_10 pipeping_100 pipeping_1000 pipeping_10000 pipeping_100000 pipeping_1000000"

CONAME="meh"

touch results.txt

copong "${CONAME}" &

for b in ${BENCHMARKS}; do
	export STATCOUNTERS_OUTPUT="${b}.statcounters"
	syscall_timing -s 600 -i 1000 -l 1 -n "${CONAME}" "${b}" | tee -a results.txt
	unset STATCOUNTERS_OUTPUT
	syscall_timing -s 600 -i 1000 -l 1 -n "${CONAME}" -r "${b}.out" -c cycle -c inst -c itlb_miss -c dtlb_miss "${b}" | tee -a results.txt
done
