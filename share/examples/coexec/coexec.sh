#!/bin/sh -e

coexec $$ `which pie` -vs &
coexec $$ `which pie` -vs &
coexec $$ `which pie` -vs &
sleep 0.1
procstat -v $$
