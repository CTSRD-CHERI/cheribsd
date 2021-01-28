@Library('ctsrd-jenkins-scripts') _

class GlobalVars { // "Groovy"
    public static boolean archiveArtifacts = false
    public static boolean isTestSuiteJob = false
}

echo("JOB_NAME='${env.JOB_NAME}', JOB_BASE_NAME='${env.JOB_BASE_NAME}'")
def rateLimit = rateLimitBuilds(throttle: [count: 1, durationName: 'hour', userBoost: true])
if (env.JOB_NAME.contains("CheriBSD-testsuite") ||
    (env.CHANGE_ID && pullRequest.labels.contains('run-full-testsuite'))) {
    GlobalVars.isTestSuiteJob = true
    // This job takes a long time to run (approximately 20 hours) so limit it to twice a week
    rateLimit = rateLimitBuilds(throttle: [count: 2, durationName: 'week', userBoost: true])
    echo("RUNNING FREEBSD TEST SUITE")
}

// Set job properties:
def jobProperties = [[$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
                     copyArtifactPermission('*'), // Downstream jobs (may) need the kernels/disk images
                     rateLimit]
// Don't archive sysroot/disk image/kernel images for pull requests and non-default branches:
def archiveBranches = ['master', 'dev']
if (!env.CHANGE_ID && archiveBranches.contains(env.BRANCH_NAME)) {
    if (!GlobalVars.isTestSuiteJob) {
        // Don't archive disk images for the test suite job
        GlobalVars.archiveArtifacts = true
    }
    // For branches other than the master branch, only keep the last two artifacts to save disk space
    if (env.BRANCH_NAME != 'master') {
        jobProperties.add(buildDiscarder(logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '2')))
    }
}
// Add an architecture selector for manual builds
def allArchitectures = [
    "aarch64", "amd64",
    "mips64", "mips64-hybrid", "mips64-purecap",
    "morello-hybrid",
    // XXX: Enable once kernel-toolchain can handle aarch64c: "morello-purecap",
    "riscv64", "riscv64-hybrid", "riscv64-purecap"
]
jobProperties.add(parameters([text(defaultValue: allArchitectures.join('\n'),
        description: 'The architectures (cheribuild suffixes) to build for (one per line)',
        name: 'architectures')]))
// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties(jobProperties)

jobs = [:]

def buildImageAndRunTests(params, String suffix) {
    stage("Building disk image") {
        sh "./cheribuild/jenkins-cheri-build.py --build disk-image-${suffix} ${params.extraArgs}"
    }
    // No need for minimal images when running the testsuite
    if (!GlobalVars.isTestSuiteJob && (suffix.startsWith('mips64') || suffix.startsWith('riscv64'))) {
        stage("Building MFS_ROOT kernels") {
            sh label: "Building minimal disk image", script: "./cheribuild/jenkins-cheri-build.py --build disk-image-minimal-${suffix} ${params.extraArgs}"
            sh label: "Building MFS_ROOT kernels", script: "./cheribuild/jenkins-cheri-build.py --build cheribsd-mfs-root-kernel-${suffix} --cheribsd-mfs-root-kernel-${suffix}/build-fpga-kernels ${params.extraArgs}"
            // Move MFS_ROOT kernels into tarball/ so they aren't deleted
            sh "mv -fv kernel-${suffix}* tarball/"
        }
    }
    if (suffix.startsWith("morello")) {
        echo("Can't run tests on the FVP yet!")
        maybeArchiveArtifacts(params, suffix)
        return
    }
    stage("Running tests (${suffix})") {
        // copy qemu archive and run directly on the host
        dir("qemu-${params.buildOS}") { deleteDir() }
        copyArtifacts projectName: "qemu/qemu-cheri", filter: "qemu-${params.buildOS}/**", target: '.', fingerprintArtifacts: false
        sh label: 'generate SSH key', script: 'test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N \'\' -f $WORKSPACE/id_ed25519 < /dev/null'

        sh 'find qemu* && ls -lah'
        // TODO: run full testsuite (ideally in parallel)
        def testExtraArgs = ['--no-timestamped-test-subdir', "--test-output-dir=\$WORKSPACE/test-results/${suffix}"]
        if (GlobalVars.isTestSuiteJob) {
            testExtraArgs += ['--kyua-tests-files', '/usr/tests/Kyuafile',
                              '--no-run-cheribsdtest', // only run kyua tests
                              '--disable-coredumps',  // coredumps slow down the testsuite unnecessarily
            ]
        } else {
            // Run a small subset of tests to check that we didn't break running tests (since the full testsuite takes too long)
            testExtraArgs += ['--kyua-tests-files', '/usr/tests/bin/cat/Kyuafile']
        }
        sh label: "Run tests in QEMU", script: """
rm -rf test-results && mkdir -p test-results/${suffix}
# The test script returns 2 if the tests step is unstable, any other non-zero exit code is a fatal error
exit_code=0
./cheribuild/jenkins-cheri-build.py --test run-${suffix} '--test-extra-args=${testExtraArgs.join(" ")}' ${params.extraArgs} --test-ssh-key \$WORKSPACE/id_ed25519.pub || exit_code=\$?
if [ \${exit_code} -eq 2 ]; then
    echo "Test script encountered a non-fatal error - probably some of the tests failed."
elif [ \${exit_code} -ne 0 ]; then
    echo "Test script got fatal error: exit code \${exit_code}"
    exit \${exit_code}
fi
find test-results
"""
        def summary = junitReturnCurrentSummary allowEmptyResults: false, keepLongStdio: true, testResults: "test-results/${suffix}/*.xml"
        def testResultMessage = "Test summary: ${summary.totalCount}, Failures: ${summary.failCount}, Skipped: ${summary.skipCount}, Passed: ${summary.passCount}"
        echo("${suffix}: ${testResultMessage}")
        if (summary.passCount == 0 || summary.totalCount == 0) {
            params.statusFailure("No tests successful? ${testResultMessage}")
        } else if (summary.failCount != 0) {
            // Note: Junit set should have set stage/build status to unstable already, but we still need to set
            // the per-configuration status, since Jenkins doesn't have a build result for each parallel branch.
            params.statusUnstable("Unstable test results: ${testResultMessage}")
            // If there were test failures, we archive the JUnitXML file to simplify debugging
            archiveArtifacts allowEmptyArchive: true, artifacts: "test-results/${suffix}/*.xml", onlyIfSuccessful: false
        }
    }
    maybeArchiveArtifacts(params, suffix)
}

def maybeArchiveArtifacts(params, String suffix) {
    if (GlobalVars.archiveArtifacts) {
        if (GlobalVars.isTestSuiteJob) {
            error("Should not happen!")
        }
        stage("Archiving artifacts") {
            // Archive disk image
            sh label: 'Compress kernel and images', script: """
rm -fv *.img *.xz kernel*
mv -v tarball/rootfs/boot/kernel/kernel tarball/kernel
mv -v tarball/*.img tarball/kernel* .
# Use xz -T0 to speed up compression by using multiple threads
xz -T0 *.img kernel*
"""
            // Create sysroot archive (this is installed to cherisdk rather than the tarball)
            // Seems like some Java versions require write permissions to the .xz files:
            // java.nio.file.AccessDeniedException: /usr/local/jenkins/jobs/CheriBSD-pipeline/branches/PR-616/builds/14/archive/kernel.xz
            //     at sun.nio.fs.UnixException.translateToIOException(UnixException.java:84)
            //     at sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:102)
            //     at sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:107)
            //     at sun.nio.fs.UnixFileSystemProvider.newByteChannel(UnixFileSystemProvider.java:214)
            //     at java.nio.file.spi.FileSystemProvider.newOutputStream(FileSystemProvider.java:434)
            //     at java.nio.file.Files.newOutputStream(Files.java:216)
            sh label: 'Create sysroot archive', script: """
./cheribuild/jenkins-cheri-build.py cheribsd-sysroot-${suffix} --keep-install-dir --build --cheribsd/install-dir=\${WORKSPACE}/tarball/rootfs
rm -f cheribsd-sysroot.tar.xz
# Note: we use *sdk here to handle both tarball/cherisdk/ and tarball/morello-sdk/
mv tarball/*sdk/sysroot-${suffix}.tar.gz cheribsd-sysroot.tar.xz
rm -rf tarball artifacts-*
chmod +w *.xz
mkdir -p "artifacts-${suffix}"
mv -v *.xz "artifacts-${suffix}"
ls -la "artifacts-${suffix}/"
"""
            archiveArtifacts allowEmptyArchive: false, artifacts: "artifacts-${suffix}/cheribsd-sysroot.tar.xz, artifacts-${suffix}/*.img.xz, artifacts-${suffix}/kernel*.xz", fingerprint: true, onlyIfSuccessful: true
        }
    }
}

// Work around for https://issues.jenkins.io/browse/JENKINS-46941
// Jenkins appears to use the last selected manual override for automatically triggered builds.
// Therefore, only read the parameter value for manually-triggered builds.
def selectedArchitectures = isManualBuild() ? params.architectures.split('\n') : allArchitectures
echo("Selected architectures: ${selectedArchitectures}")
selectedArchitectures.each { suffix ->
    String name = "cheribsd-${suffix}"
    jobs[suffix] = { ->
        def extraBuildOptions = '-s'
        if (GlobalVars.isTestSuiteJob) {
            // Enable additional debug checks when running the testsuite
            extraBuildOptions += ' -DMALLOC_DEBUG'
        }
        // XXX: Remove once dev can build a purecap world
        if (suffix.startsWith("morello")) {
            def gitBranch = 'master'
            if (env.CHANGE_ID) {
                gitBranch = env.CHANGE_TARGET
            } else if (env.BRANCH_NAME) {
                gitBranch = env.BRANCH_NAME
            }
            if (gitBranch != 'morello-dev') {
                extraBuildOptions += ' -DWITHOUT_COMPAT_CHERIABI'
            }
        }
        def cheribuildArgs = ["'--cheribsd/build-options=${extraBuildOptions}'",
                              '--keep-install-dir',
                              '--install-prefix=/rootfs',
                              '--cheribsd/build-tests',]
        if (GlobalVars.isTestSuiteJob) {
            cheribuildArgs.add('--cheribsd/debug-info')
        } else {
            cheribuildArgs.add('--cheribsd/no-debug-info')
        }
        cheribuildProject(target: "cheribsd-${suffix}", architecture: suffix,
                extraArgs: cheribuildArgs.join(" "),
                skipArchiving: true, skipTarball: true,
                sdkCompilerOnly: true, // We only need clang not the CheriBSD sysroot since we are building that.
                // XXX: Remove once morello-dev is gone
                customGitCheckoutDir: suffix.startsWith('morello') ? 'morello-cheribsd' : 'cheribsd',
                gitHubStatusContext: GlobalVars.isTestSuiteJob ? "testsuite/${suffix}" : "ci/${suffix}",
                // Delete stale compiler/sysroot
                beforeBuild: { params -> 
                    dir('cherisdk') { deleteDir() } 
                    sh label: 'Deleting outputs from previous builds', script: 'rm -rfv artifacts-* tarball kernel*'
                },
                /* Custom function to run tests since --test will not work (yet) */
                runTests: false,
                afterBuild: { params -> buildImageAndRunTests(params, suffix) })
    }
}

boolean runParallel = true
echo("Running jobs in parallel: ${runParallel}")
if (runParallel) {
    jobs.failFast = false
    parallel jobs
} else {
    jobs.each { key, value ->
        echo("RUNNING ${key}")
        value()
    }
}
