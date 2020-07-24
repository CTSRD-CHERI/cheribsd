#!/bin/sh

UPSTREAM_TAG=$(cat .last_merge)

git diff --name-only ${UPSTREAM_TAG} | \
    grep -v -E '(\.(clang-format|editorconfig|last_merge|mergify_pause_paths)|CMakeLists.txt|cheri|bin/(auxargs|helloworld|shmem_bench)|contrib/(curl|gdb|jpeg|libpng|netsurf)|^ctsrd|diff-to-upstream.sh|gnu/usr.bin/gdb|lib/(lib(curl|helloworld|jpeg|png|statcounters)|netsurf)|libexec/.*-helper|share/netsurf|usr.bin/(capsize|nsfb|qtrace))' | \
    xargs git diff ${UPSTREAM_TAG} --
