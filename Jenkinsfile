@Library('ctsrd-jenkins-scripts') _

class GlobalVars { // "Groovy"
    public static boolean archiveArtifacts = false;
    public static boolean isTestSuiteJob = false;
}

if (env.CHANGE_ID && !shouldBuildPullRequest()) {
    echo "Not building this pull request."
    return
}

echo("JOB_NAME='${env.JOB_NAME}', JOB_BASE_NAME='${env.JOB_BASE_NAME}'")
def rateLimit = rateLimitBuilds(throttle: [count: 1, durationName: 'hour', userBoost: true])
if (env.JOB_NAME.contains("CheriBSD-testsuite")) {
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
// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties(jobProperties)

jobs = [:]

def buildImageAndRunTests(params, String suffix) {
    stage("Building disk image") {
        sh "./cheribuild/jenkins-cheri-build.py --build disk-image-${suffix} ${params.extraArgs}"
    }
    // No need for minimal images when running the testsuite
    if (!GlobalVars.isTestSuiteJob && (suffix.startsWith('mips64') || suffix.startsWith('riscv64'))) {
        stage("Building minimal disk image") {
            sh "./cheribuild/jenkins-cheri-build.py --build disk-image-minimal-${suffix} ${params.extraArgs}"
        }
        stage("Building MFS_ROOT kernels") {
            sh "./cheribuild/jenkins-cheri-build.py --build cheribsd-mfs-root-kernel-${suffix} --cheribsd-mfs-root-kernel-${suffix}/build-fpga-kernels ${params.extraArgs}"
        }
    }
    stage("Running tests") {
        def haveCheritest = suffix.endsWith('-hybrid') || suffix.endsWith('-purecap')
        // copy qemu archive and run directly on the host
        dir("qemu-${params.buildOS}") { deleteDir() }
        copyArtifacts projectName: "qemu/qemu-cheri", filter: "qemu-${params.buildOS}/**", target: '.', fingerprintArtifacts: false
        sh label: 'generate SSH key', script: 'test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N \'\' -f $WORKSPACE/id_ed25519 < /dev/null'

        sh 'find qemu* && ls -lah'
        // TODO: run full testsuite (ideally in parallel)
        def testExtraArgs = ['--no-timestamped-test-subdir']
        if (GlobalVars.isTestSuiteJob) {
            testExtraArgs += ['--kyua-tests-files', '/usr/tests/Kyuafile',
                              '--no-run-cheritest', // only run kyua tests
            ]
        } else {
            // Run a small subset of tests to check that we didn't break running tests (since the full testsuite takes too long)
            testExtraArgs += ['--kyua-tests-files', '/usr/tests/bin/cat/Kyuafile']
        }
        def exitCode = sh returnStatus: true, label: "Run tests in QEMU", script: """
rm -rf cheribsd-test-results && mkdir cheribsd-test-results
./cheribuild/jenkins-cheri-build.py --test run-${suffix} '--test-extra-args=${testExtraArgs.join(" ")}' ${params.extraArgs} --test-ssh-key \$WORKSPACE/id_ed25519.pub
find cheribsd-test-results
"""
        def summary = junitReturnCurrentSummary allowEmptyResults: false, keepLongStdio: true, testResults: 'cheribsd-test-results/*.xml'
        def testResultMessage = "Test summary: ${summary.totalCount}, Failures: ${summary.failCount}, Skipped: ${summary.skipCount}, Passed: ${summary.passCount}"
        echo("${suffix}: ${testResultMessage}")
        if (exitCode != 0 || summary.failCount != 0) {
            // Note: Junit set should have set stage/build status to unstable already, but we still need to set
            // the per-configuration status, since Jenkins doesn't have a build result for each parallel branch.
            params.statusUnstable("Test script returned ${exitCode}! ${testResultMessage}")
        }
        if (summary.passCount == 0 || summary.totalCount == 0) {
            params.statusFailure("No tests successful? ${testResultMessage}")
        }
    }
    if (GlobalVars.archiveArtifacts) {
        if (GlobalVars.isTestSuiteJob) {
            error("Should not happen!")
        }
        stage("Archiving artifacts") {
            // Archive disk image
            sh label: 'Compress kernel and images', script: '''
rm -fv *.img *.xz kernel*
mv -v tarball/*.img tarball/rootfs/boot/kernel/kernel .
# Use xz -T0 to speed up compression by using multiple threads
xz -T0 *.img kernel*
'''
            // Create sysroot archive (this is installed to cherisdk rather than the tarball)
            sh label: 'Create sysroot archive', script: """
rm -rf tarball artifacts-*
mkdir tarball && mv -f cherisdk/sysroot tarball/sysroot
./cheribuild/jenkins-cheri-build.py --tarball cheribsd-sysroot-${suffix} --tarball-name cheribsd-sysroot.tar.xz
ls -la
# Seems like some Java versions require write permissions:
# java.nio.file.AccessDeniedException: /usr/local/jenkins/jobs/CheriBSD-pipeline/branches/PR-616/builds/14/archive/kernel.xz
#	at sun.nio.fs.UnixException.translateToIOException(UnixException.java:84)
#	at sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:102)
#	at sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:107)
#	at sun.nio.fs.UnixFileSystemProvider.newByteChannel(UnixFileSystemProvider.java:214)
#	at java.nio.file.spi.FileSystemProvider.newOutputStream(FileSystemProvider.java:434)
#	at java.nio.file.Files.newOutputStream(Files.java:216)
chmod +w *.xz
mkdir -p "artifacts-${suffix}"
mv -v *.xz "artifacts-${suffix}"
ls -la "artifacts-${suffix}/"
"""
            archiveArtifacts allowEmptyArchive: false, artifacts: "artifacts-${suffix}/cheribsd-sysroot.tar.xz, artifacts-${suffix}/*.img.xz, artifacts-${suffix}/kernel*.xz", fingerprint: true, onlyIfSuccessful: true
        }
    }
}

["mips64", "mips64-hybrid", "mips64-purecap", "riscv64", "riscv64-hybrid", "riscv64-purecap", "amd64", "aarch64"].each { suffix ->
    String name = "cheribsd-${suffix}"
    jobs[suffix] = { ->
        def extraBuildOptions = '-s'
        if (GlobalVars.isTestSuiteJob) {
            // Enable additional debug checks when running the testsuite
            extraBuildOptions += ' -DMALLOC_DEBUG'
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
                customGitCheckoutDir: 'cheribsd',
                gitHubStatusContext: GlobalVars.isTestSuiteJob ? "testsuite/${suffix}" : "ci/${suffix}",
                // Delete stale compiler/sysroot
                beforeBuild: { params -> dir('cherisdk') { deleteDir() } },
                /* Custom function to run tests since --test will not work (yet) */
                runTests: false, afterBuild: { params -> buildImageAndRunTests(params, suffix) })
    }
}

["mips64-hybrid", "mips64-purecap", "riscv64-hybrid", "riscv64-purecap"].each { suffix ->
    String name = "cheribsd-purecap-kern-${suffix}"
    jobs[name] = { ->
        cheribuildProject(target: "cheribsd-${suffix}", architecture: suffix,
                extraArgs: "--cheribsd/build-options=-s --cheribsd/no-debug-info --keep-install-dir --install-prefix=/rootfs --cheribsd/build-tests --cheribsd-${suffix}/pure-cap-kernel",
                skipArchiving: true, skipTarball: true,
                sdkCompilerOnly: true, // We only need clang not the CheriBSD sysroot since we are building that.
                customGitCheckoutDir: 'cheribsd',
                gitHubStatusContext: "ci/${name}",
                /* Custom function to run tests since --test will not work (yet) */
                runTests: false, afterBuild: { params -> buildImageAndRunTests(params, suffix) }
        )
    }
}

boolean runParallel = true;
echo("Running jobs in parallel: ${runParallel}")
if (runParallel) {
    jobs.failFast = false
    parallel jobs
} else {
    jobs.each { key, value ->
        echo("RUNNING ${key}")
        value();
    }
}
