#!/bin/sh

UPSTREAM_TAG=$(cat .last_merge)

git diff --name-only ${UPSTREAM_TAG} | \
    grep -v -E '(\.(clang-format|editorconfig|github|last_merge|mergify_pause_paths|require_clean_build)|CHERI-UPDATING.md|CMakeLists.txt|Jenkinsfile|cheri|bin/(helloworld|shmem_bench)|contrib/libpng|diff-to-upstream.sh|lib/lib(png|statcounters)|usr.bin/qtrace)' | \
    xargs git diff ${UPSTREAM_TAG} --
