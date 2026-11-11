#!/bin/sh
git checkout wip
git commit -am "WIP $(date -Iseconds)"
git push dev
ssh morellobox 'cd ~/cheri/cheribuild && ./cheribuild.py cheribsd-morello-purecap --cheribsd/build-options "CHERI_STACK_TEMP_SAFETY=yes" --subdir "libexec/rtld-elf/ lib/libsys/"'
