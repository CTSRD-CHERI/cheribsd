@Library('ctsrd-jenkins-scripts') _

class GlobalVars { // "Groovy"
    public static boolean archiveArtifacts = false;
}

if (env.CHANGE_ID && !shouldBuildPullRequest()) {
    echo "Not building this pull request."
    return
}

// Set job properties:
def jobProperties = [rateLimitBuilds([count: 1, durationName: 'hour', userBoost: true]),
                     [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
                     copyArtifactPermission('*'), // Downstream jobs need the kernels/disk images
]
// Don't archive sysroot/disk image/kernel images for pull requests and non-default branches:
def archiveBranches = ['master', 'dev']
if (!env.CHANGE_ID && archiveBranches.contains(env.BRANCH_NAME)) {
    GlobalVars.archiveArtifacts = true
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
    if (suffix.startsWith('mips') || suffix.startsWith('riscv64')) {
        stage("Building minimal disk image") {
            sh "./cheribuild/jenkins-cheri-build.py --build disk-image-minimal-${suffix} ${params.extraArgs}"
        }
        stage("Building MFS_ROOT kernels") {
            sh "./cheribuild/jenkins-cheri-build.py --build cheribsd-mfs-root-kernel-${suffix} --cheribsd-mfs-root-kernel-${suffix}/build-fpga-kernels ${params.extraArgs}"
        }
    } else {
	echo("Cannot build MFS_ROOT kernels for ${suffix} yet")
    }
    stage("Running tests") {
        def haveCheritest = suffix.endsWith('-hybrid') || suffix.endsWith('-purecap')
        // copy qemu archive and run directly on the host
        dir("qemu-${params.buildOS}") { deleteDir() }
        copyArtifacts projectName: "qemu/qemu-cheri", filter: "qemu-${params.buildOS}/**", target: '.', fingerprintArtifacts: false
        sh label: 'generate SSH key', script: 'test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N \'\' -f $WORKSPACE/id_ed25519 < /dev/null'
        def testExtraArgs = '--no-timestamped-test-subdir'
        def exitCode = sh returnStatus: true, label: "Run tests in QEMU", script: """
rm -rf cheribsd-test-results && mkdir cheribsd-test-results
test -e \$WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N '' -f \$WORKSPACE/id_ed25519 < /dev/null
./cheribuild/jenkins-cheri-build.py --test run-${suffix} '--test-extra-args=${testExtraArgs}' ${params.extraArgs} --test-ssh-key \$WORKSPACE/id_ed25519.pub
find cheribsd-test-results
"""
        if (haveCheritest) {
            def summary = junit allowEmptyResults: !haveCheritest, keepLongStdio: true, testResults: 'cheribsd-test-results/cheri*.xml'
            echo("${suffix} test summary: ${summary.totalCount}, Failures: ${summary.failCount}, Skipped: ${summary.skipCount}, Passed: ${summary.passCount}")
            if (exitCode != 0 || summary.failCount != 0) {
                // Note: Junit set should have set stage/build status to unstable already, but we still need to set
                // the per-configuration status, since Jenkins doesn't have a build result for each parallel branch.
                params.statusUnstable("Test script returned ${exitCode}, failed tests: ${summary.failCount}")
            }
            if (summary.passCount == 0 || summary.totalCount == 0) {
                params.statusFailure("No tests successful?")
            }
        } else {
            // No cheritest, just check that that the test script exited successfully
            if (exitCode != 0) {
                params.statusUnstable("Test script returned ${exitCode}")
            }
        }
    }
    if (GlobalVars.archiveArtifacts) {
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

["mips-nocheri", "mips-hybrid", "mips-purecap", "riscv64", "riscv64-hybrid", "riscv64-purecap", "amd64", "aarch64"].each { suffix ->
    String name = "cheribsd-${suffix}"
    jobs[suffix] = { ->
        cheribuildProject(target: "cheribsd-${suffix}", architecture: suffix,
                extraArgs: '--cheribsd/build-options=-s --cheribsd/no-debug-info --keep-install-dir --install-prefix=/rootfs --cheribsd/build-tests',
                skipArchiving: true, skipTarball: true,
                sdkCompilerOnly: true, // We only need clang not the CheriBSD sysroot since we are building that.
                customGitCheckoutDir: 'cheribsd',
                gitHubStatusContext: "ci/${suffix}",
                // Delete stale compiler/sysroot
                beforeBuild: { params -> dir('cherisdk') { deleteDir() } },
                /* Custom function to run tests since --test will not work (yet) */
                runTests: false, afterBuild: { params -> buildImageAndRunTests(params, suffix) })
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
