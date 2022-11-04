@Library('ctsrd-jenkins-scripts') _

import java.time.Instant
import java.time.format.DateTimeFormatter

class GlobalVars { // "Groovy"
    public static String buildTimestamp = null
    public static boolean archiveArtifacts = false
    public static boolean isTestSuiteJob = false
    public static List<String> selectedPurecapKernelArchitectures = []
}

GlobalVars.buildTimestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(currentBuild.startTimeInMillis));

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
def jobProperties = [
        [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
        copyArtifactPermission('*'), // Downstream jobs (may) need the kernels/disk images
        rateLimit,
]
// Don't archive sysroot/disk image/kernel images for pull requests and non-default/releng branches:
def archiveBranches = ['main', 'master', 'dev']
if (!env.CHANGE_ID && (archiveBranches.contains(env.BRANCH_NAME) || env.BRANCH_NAME.startsWith('releng/'))) {
    if (!GlobalVars.isTestSuiteJob) {
        // Don't archive disk images for the test suite job
        GlobalVars.archiveArtifacts = true
    }
    // For branches other than the master/main and releng branches, only keep the last two artifacts to save disk space
    if (env.BRANCH_NAME != 'main' && env.BRANCH_NAME != 'master' && !env.BRANCH_NAME.startsWith('releng/')) {
        jobProperties.add(buildDiscarder(logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '2')))
    }
}
// Add an architecture selector for manual builds
def allArchitectures = [
        "aarch64", "amd64",
        "morello-hybrid", "morello-purecap",
        "riscv64", "riscv64-hybrid", "riscv64-purecap"
]
jobProperties.add(parameters([
        text(defaultValue: allArchitectures.join('\n'),
             description: 'The architectures (cheribuild suffixes) to build for (one per line)',
             name: 'architectures'),
        text(defaultValue: ["riscv64-hybrid", "riscv64-purecap", "morello-hybrid", "morello-purecap"].join('\n'),
             description: 'The architectures (cheribuild suffixes) to build a purecap kernel for (one per line)',
             name: 'purecapKernelArchitectures'),
]))
// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties(jobProperties)

jobs = [:]

GlobalVars.selectedPurecapKernelArchitectures = params.purecapKernelArchitectures.split('\n')

def runTestStep(params, String testSuffix, String suffix, testExtraArgs, extraArgs) {
    testExtraArgs.add("--test-output-dir=\$WORKSPACE/test-results/${testSuffix}")
    sh label: "Run ${testSuffix} tests in QEMU", script: """
rm -rf test-results/${testSuffix} && mkdir -p test-results/${testSuffix}
# The test script returns 2 if the tests step is unstable, any other non-zero exit code is a fatal error
exit_code=0
./cheribuild/jenkins-cheri-build.py --test run-${suffix} '--test-extra-args=${testExtraArgs.join(" ")}' ${params.extraArgs} ${extraArgs.join(" ")} --test-ssh-key \$WORKSPACE/id_ed25519.pub || exit_code=\$?
if [ \${exit_code} -eq 2 ]; then
    echo "Test script encountered a non-fatal error - probably some of the tests failed."
elif [ \${exit_code} -ne 0 ]; then
    echo "Test script got fatal error: exit code \${exit_code}"
    exit \${exit_code}
fi
find test-results
"""
    def summary = junitReturnCurrentSummary allowEmptyResults: false, keepLongStdio: true,
                                            testResults: "test-results/${testSuffix}/*.xml"
    def testResultMessage = "Test summary: ${summary.totalCount}, Failures: ${summary.failCount}, Skipped: ${summary.skipCount}, Passed: ${summary.passCount}"
    echo("${testSuffix}: ${testResultMessage}")
    if (summary.passCount == 0 || summary.totalCount == 0) {
        params.statusFailure("No tests successful? ${testResultMessage}")
    } else if (summary.failCount != 0) {
        // Note: Junit set should have set stage/build status to unstable already, but we still need to set
        // the per-configuration status, since Jenkins doesn't have a build result for each parallel branch.
        params.statusUnstable("Unstable test results: ${testResultMessage}")
        // If there were test failures, we archive the JUnitXML file to simplify debugging
        archiveArtifacts allowEmptyArchive: true, artifacts: "test-results/${testSuffix}/*.xml", onlyIfSuccessful: false
    }
}

def buildImage(params, String suffix) {
    stage("Building disk images") {
        sh label: "Building full disk image",
           script: "./cheribuild/jenkins-cheri-build.py --build disk-image-${suffix} ${params.extraArgs}"
        // No need for minimal images when running the testsuite
        if (!GlobalVars.isTestSuiteJob) {
            sh label: "Building minimal disk image",
               script: "./cheribuild/jenkins-cheri-build.py --build disk-image-minimal-${suffix} ${params.extraArgs}"
        }
    }
    // No need for MFS_ROOT kernels when running the testsuite
    if (!GlobalVars.isTestSuiteJob && (suffix.startsWith('aarch64') || suffix.startsWith('morello') || suffix.startsWith('riscv64'))) {
        def extraKernelsArgs = []
        // AArch64/Morello doesn't have FPGA-specific kernels, and currently lacks MFS-ROOT-NODEBUG kernel configs
        if (suffix.startsWith('riscv64')) {
            extraKernelsArgs += [
                    '--cheribsd/build-bench-kernels',
                    '--cheribsd/build-fpga-kernels',
            ]
        } else {
            // Override default from the earlier main build step
            extraKernelsArgs += [
                    '--cheribsd/no-build-bench-kernels',
            ]
        }
        stage("Building MFS_ROOT kernels") {
            sh label: "Building MFS_ROOT disk image",
               script: "./cheribuild/jenkins-cheri-build.py --build disk-image-mfs-root-${suffix} ${params.extraArgs}"
            sh label: "Building MFS_ROOT kernels",
               script: "./cheribuild/jenkins-cheri-build.py --build cheribsd-mfs-root-kernel-${suffix} ${params.extraArgs} ${extraKernelsArgs.join(" ")}"
            // Move MFS_ROOT kernels into tarball/ so they aren't deleted
            sh "mv -fv kernel-${suffix}* tarball/"
        }
    }
}

def runTests(params, String suffix) {
    def testExtraArgs = ['--no-timestamped-test-subdir']
    if (GlobalVars.isTestSuiteJob) {
        testExtraArgs += [
                '--kyua-tests-files', '/usr/tests/Kyuafile',
                '--no-run-cheribsdtest', // only run kyua tests
        ]
    } else {
        // Run a small subset of tests to check that we didn't break running tests (since the full testsuite takes too long)
        testExtraArgs += ['--kyua-tests-files', '/usr/tests/bin/cat/Kyuafile']
    }

    stage("Test setup") {
        // copy qemu archive and run directly on the host
        dir("qemu-${params.buildOS}") { deleteDir() }
        copyArtifacts projectName: 'qemu/qemu-cheri', filter: "qemu-${params.buildOS}/**", target: '.',
                      fingerprintArtifacts: false
        sh label: 'generate SSH key',
           script: 'test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N \'\' -f $WORKSPACE/id_ed25519 < /dev/null'
        sh 'find qemu* && ls -lah'
    }

    // Run test configurations in parallel (if there is be more than one).
    if (GlobalVars.selectedPurecapKernelArchitectures.contains(suffix)) {
        def testSteps = [:]
        testSteps["Test ${suffix} hybrid kernel"] = { ->
            runTestStep(params, "${suffix}-hybrid-kernel", suffix, testExtraArgs,
                        ["--run-${suffix}/kernel-abi hybrid"])
        }
        testSteps["Test ${suffix} purecap kernel"] = { ->
            runTestStep(params, "${suffix}-purecap-kernel", suffix, testExtraArgs,
                        ["--run-${suffix}/kernel-abi purecap"])
        }
        testSteps.failFast = false
        parallel testSteps
    } else {
        // Otherwise run it directly here in a stage() instead of parallel() to improve
        // the Jenkins visualization.
        stage("Test ${suffix}") {
            runTestStep(params, "${suffix}", suffix, testExtraArgs, [])
        }
    }
}

def buildRelease(params, String suffix) {
    if (!GlobalVars.isTestSuiteJob) {
        stage("Building release images") {
            sh label: "Building release images",
               // params.extraArgs includes --install-prefix=/rootfs but we
               // don't want the release media to end up there, so override it
               // to the top-level output directory.
               script: "./cheribuild/jenkins-cheri-build.py --build cheribsd-release-${suffix} --cheribsd-release/install-dir=\${WORKSPACE}/tarball ${params.extraArgs}"
        }
    }
}

def buildImageAndRunTests(params, String suffix) {
    buildImage(params, suffix)
    runTests(params, suffix)
    buildRelease(params, suffix)
    maybeArchiveArtifacts(params, suffix)
}

def maybeArchiveArtifacts(params, String suffix) {
    if (GlobalVars.archiveArtifacts) {
        if (GlobalVars.isTestSuiteJob) {
            error("Should not happen!")
        }
        stage("Archiving artifacts") {
            sh label: 'Create metadata file', script: """
ABI_VERSION=`awk '/^#define[[:space:]]+__CheriBSD_version/{print \$3}' tarball/rootfs/usr/include/sys/param.h`
# ABI_VERSION is YYYYMMDD, perform approximate sanity check
case "\$ABI_VERSION" in
202[2-9][0-1][0-9][0-3][0-9])
    ;;
*)
    echo >&2 "__CheriBSD_version '\$ABI_VERSION' has an unexpected value"
    ;;
esac
tee metadata.json <<EOF
{
    "abi-version": "\$ABI_VERSION",
    "architecture": "${suffix}",
    "branch": "${env.BRANCH_NAME}",
    "commit": "${params.gitInfo.GIT_COMMIT}",
    "timestamp": "${GlobalVars.buildTimestamp}"
}
EOF
"""
            // Archive disk image
            sh label: 'Compress kernel and images', script: """
rm -fv *.img *.xz kernel*
rm -rfv ftp
mv -v tarball/rootfs/boot/kernel/kernel tarball/kernel
mv -v tarball/*.img tarball/kernel* tarball/ftp .
rm -fv *-mini-memstick.img
case "${suffix}" in
riscv64*)
    # QEMU kernel configs hard-code wrong rootfs for installer, and kernel
    # lives outside disk image, so don't archive known-broken installer images
    rm -fv *-memstick.img
    ;;
*)
    mv -v *-memstick.img "cheribsd-memstick-${suffix}.img"
    ;;
esac
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
./cheribuild/jenkins-cheri-build.py cheribsd-sysroot-${suffix} --keep-install-dir --build \
    --cheribsd/install-dir=\${WORKSPACE}/tarball/rootfs \
    --cheribsd-sysroot/install-dir \${WORKSPACE}/tarball/sysroot
rm -f cheribsd-sysroot.tar.xz
# Cheribuild prior to https://github.com/CTSRD-CHERI/cheribuild/pull/180
# created a .tar.gz archive, newer versions create a tar.xz archive.
# Use a glob to handle both cases.
# XXX: Replace .* with .xz once the cheribuild PR has been merged
mv tarball/sysroot-${suffix}.tar.* cheribsd-sysroot.tar.xz
rm -rf tarball artifacts-*
chmod +w *.xz
mkdir -p "artifacts-${suffix}"
mv -v metadata.json "artifacts-${suffix}"
mv -v *.xz "artifacts-${suffix}"
tar -cJvf "artifacts-${suffix}/cheribsd-ftp-${suffix}.tar.xz" ftp
ls -la "artifacts-${suffix}/"
"""
            archiveArtifacts allowEmptyArchive: false,
                             artifacts: "artifacts-${suffix}/cheribsd-sysroot.tar.xz, artifacts-${suffix}/*.img.xz, artifacts-${suffix}/kernel*.xz, artifacts-${suffix}/cheribsd-ftp*.tar.xz, artifacts-${suffix}/metadata.json",
                             fingerprint: true, onlyIfSuccessful: true
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
            extraBuildOptions += ' -DWITHOUT_MALLOC_PRODUCTION'
        }
        def cheribuildArgs = [
                "'--cheribsd/build-options=${extraBuildOptions}'",
                '--cheribsd/default-kernel-abi=hybrid',
                '--keep-install-dir',
                '--install-prefix=/rootfs',
                '--cheribsd/build-tests',
                '--cheribsd/build-bench-kernels',
                '--cheribsd/with-manpages',
                '--cheribsd/debug-info',
                '--cheribsd/debug-files',
        ]
        if (GlobalVars.selectedPurecapKernelArchitectures.contains(suffix)) {
            cheribuildArgs.add('--cheribsd/build-alternate-abi-kernels')
        }
        cheribuildProject(target: "cheribsd-${suffix}", architecture: suffix,
                          extraArgs: cheribuildArgs.join(" "),
                          skipArchiving: true, skipTarball: true,
                          sdkCompilerOnly: true,
                          // We only need clang not the CheriBSD sysroot since we are building that.
                          customGitCheckoutDir: 'cheribsd',
                          gitHubStatusContext: GlobalVars.isTestSuiteJob ? "testsuite/${suffix}" : "ci/${suffix}",
                          // Delete stale compiler/sysroot
                          beforeBuild: { params ->
                              dir('cherisdk') { deleteDir() }
                              sh label: 'Deleting outputs from previous builds',
                                 script: 'rm -rfv artifacts-* tarball kernel*'
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
