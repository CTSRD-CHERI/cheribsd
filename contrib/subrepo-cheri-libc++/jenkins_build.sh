#!/usr/bin/env bash
set -xe

if [[ -e "$WORKSPACE/cheribuild" ]]; then
	git -C "$WORKSPACE/cheribuild" pull --rebase origin master
else
	git clone https://github.com/CTSRD-CHERI/cheribuild.git "$WORKSPACE/cheribuild"
fi

cd "$WORKSPACE"
rm -rf "$WORKSPACE/tarball"
INSTALL_PREFIX=/usr


EXTRA_CHERIBUILD_ARGS=--keep-install-dir --install-prefix=$INSTALL_PREFIX
# extract the CHERIBSD SDK
$WORKSPACE/cheribuild/jenkins-cheri-build.py --extract-sdk
# configure LLVM to get llvm-lit
$WORKSPACE/cheribuild/jenkins-cheri-build.py --build llvm --llvm/llvm-only --configure-only --without-sdk --cpu=native

if [ "$CPU" = "mips-baremetal" ]; then
    JOB_SUFFIX="-baremetal --force-update --output-path cherisdk/baremetal --cpu=mips"
    "$WORKSPACE/cheribuild/jenkins-cheri-build.py" extract-sdk --cpu=mips
    ln -s "$(which true)" cherisdk/bin/ranlib
    "$WORKSPACE/cheribuild/jenkins-cheri-build.py" --build --install-prefix=/ newlib$JOB_SUFFIX
    INSTALL_PREFIX=/mips64-qemu-elf
else
    # libunwind not supported on baremetal
    "$WORKSPACE/cheribuild/jenkins-cheri-build.py" --build $EXTRA_CHERIBUILD_ARGS libunwind$JOB_SUFFIX
fi
# create all the files required by LLVMExports.cmake
(cd $WORKSPACE/cherisdk/bin && touch clang-check opt llc lli llvm-lto2 llvm-lto llvm-c-test \
         llvm-dsymutil llvm-dwp llvm-nm llvm-ar llvm-rtdyld \
         llvm-extract llvm-xray llvm-split llvm-cov llvm-symbolizer llvm-dwarfdump \
         llvm-link llvm-stress llvm-cxxdump llvm-cvtres llvm-cat llvm-as \
         llvm-diff llvm-modextract llvm-dis llvm-pdbdump llvm-profdata \
         llvm-opt-report llvm-bcanalyzer llvm-mcmarkup llvm-lib llvm-ranlib llvm-tblgen \
         verify-uselistorder sanstats clang-offload-bundler c-index-test \
         clang-import-test bugpoint sancov obj2yaml yaml2obj)

if [ "$CPU" = "mips-baremetal" ]; then
    "$WORKSPACE/cheribuild/jenkins-cheri-build.py" --build $EXTRA_CHERIBUILD_ARGS compiler-rt$JOB_SUFFIX
fi
"$WORKSPACE/cheribuild/jenkins-cheri-build.py" --build $EXTRA_CHERIBUILD_ARGS libcxxrt$JOB_SUFFIX

# For libcxx non-native builds just assume the test passed if the binary compiled for now.
if [ "$CPU" != "native" ] ; then
	ADDITIONAL_LIBCXX_ARGS="--libcxx/only-compile-tests "
fi

test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N '' -f $WORKSPACE/id_ed25519 < /dev/null


"$WORKSPACE/cheribuild/jenkins-cheri-build.py" --build $EXTRA_CHERIBUILD_ARGS $ADDITIONAL_LIBCXX_ARGS libcxx$JOB_SUFFIX


rm -f shard*.xml
rm -f shard*.output
rm -f libcxx-test-results.xml

if [ "$CPU" = "mips" ] ; then
    # add a symlink to the expected MIPS disk image name (since we are using the CHERI256 one)
	export QEMU_CHERI_PATH=qemu-system-cheri256
    ln -sfvn "$(basename $DISK_IMAGE_ARTIFACT)" freebsd-malta64-mfs-root-minimal-cheribuild-kernel.bz2
fi

function test_jenkins_cheribuild() {
    "$WORKSPACE/cheribuild/jenkins-cheri-build.py" --libcxx/parallel-test-jobs 16 --test-ssh-key "$WORKSPACE/id_ed25519.pub" --test $EXTRA_CHERIBUILD_ARGS $1 || echo "$1 tests failed!"
}
# Run the libunwind tests
test_jenkins_cheribuild libunwind$JOB_SUFFIX
test_jenkins_cheribuild libcxxrt$JOB_SUFFIX
test_jenkins_cheribuild libcxx$JOB_SUFFIX

# merge the individual junit files: (TODO: should be done by cheribuild)
if [ "$CPU" != "native" ] ; then
    # install junitparser to merge the xml files
    pip3 install --user junitparser
    test -e ~/.local/bin/junitparser

    ~/.local/bin/junitparser merge shard*.xml libcxx-test-results.xml
fi

# save some space
rm -rf "$LIBCXX_BUILD_DIR"

