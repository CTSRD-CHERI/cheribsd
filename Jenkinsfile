@Library('ctsrd-jenkins-scripts') _

properties([disableConcurrentBuilds(),
            disableResume(),
            [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
            [$class: 'CopyArtifactPermissionProperty', projectNames: '*'],
            [$class: 'JobPropertyImpl', throttle: [count: 1, durationName: 'hour', userBoost: true]],
            durabilityHint('PERFORMANCE_OPTIMIZED'),
            pipelineTriggers([githubPush()])
])

jobs = [:]

def buildImageAndRunTests(params, String suffix) {
    if (!suffix.startsWith("mips-")) {
        echo("Cannot run tests for ${suffix} yet")
        return
    }
    stage("Building disk image") {
        sh "./cheribuild/jenkins-cheri-build.py --build disk-image-${suffix} ${params.extraArgs}"
    }
    stage("Running tests") {
        // copy qemu archive and run directly on the host
        dir("qemu-${params.buildOS}") { deleteDir() }
        copyArtifacts projectName: "qemu/qemu-cheri", filter: "qemu-${params.buildOS}/**", target: '.', fingerprintArtifacts: false
        sh label: 'generate SSH key', script: 'test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N \'\' -f $WORKSPACE/id_ed25519 < /dev/null'
        sh label: "Run tests in QEMU", script: """
rm -rf cheribsd-test-results && mkdir cheribsd-test-results
./cheribuild/jenkins-cheri-build.py --test run-${suffix} --test-extra-args=--no-timestamped-test-subdir ${params.extraArgs} --test-ssh-key \$WORKSPACE/id_ed25519.pub
find cheribsd-test-results
"""
        def summary = junit allowEmptyResults: false, keepLongStdio: true, testResults: 'cheribsd-test-results/cheri*.xml'
        echo ("${suffix} test summary: ${summary.totalCount}, Failures: ${summary.failCount}, Skipped: ${summary.skipCount}, Passed: ${summary.passCount}")
        if (summary.failCount != 0) {
            // Note: Junit set should have set stage/build status to unstable already, but we still need to set
            // the per-configuration status, since Jenkins doesn't have a build result for each parallel branch.
            params.result = 'UNSTABLE'
        }
        if (summary.passCount == 0 || summary.totalCount == 0) {
            params.result = 'FAILURE'
            error("No tests successful?")
        }
    }
}

["mips-nocheri", "mips-hybrid", "mips-purecap", "riscv64", "riscv64-hybrid", "riscv64-purecap", "native"].each { suffix ->
    String name = "cheribsd-${suffix}"
    if (suffix != "mips-hybrid") {
        return // reduce load on jenkins while testing this PR
    }
    jobs[name] = { ->
        cheribuildProject(target: "cheribsd-${suffix}", architecture: suffix,
                extraArgs: '--cheribsd/build-options=-s --cheribsd/no-debug-info --keep-install-dir --install-prefix=/rootfs --cheribsd/build-tests',
                skipArchiving: true, skipTarball: true,
                sdkCompilerOnly: true, // We only need clang not the CheriBSD sysroot since we are building that.
                customGitCheckoutDir: 'cheribsd',
                gitHubStatusContext: "ci/${suffix}",
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
if (env.CHANGE_ID) {
    deleteDir() // Avoid using up all Jenkins disk space
}
