#!/bin/sh

UPSTREAM_TAG=$(cat .last_merge)

git diff --name-only ${UPSTREAM_TAG} | \
    grep -v -E '(\.(clang-format|editorconfig|github|last_merge|mergify_pause_paths|require_clean_build)|CHERI-UPDATING.md|CMakeLists.txt|Jenkinsfile|cheri|subrepo-openzfs|bin/helloworld|diff-to-upstream.sh|lib/libstatcounters|usr.bin/qtrace)' | \
    xargs git diff ${UPSTREAM_TAG} --
