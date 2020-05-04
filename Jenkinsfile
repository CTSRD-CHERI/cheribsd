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
    try{
    if (!suffix.startsWith("mips-")) {
        echo("Cannot run tests for ${suffix} yet")
        return
    }
    stage("Building disk image") {
        sh "./cheribuild/jenkins-cheri-build.py --build disk-image-${suffix} ${params.extraArgs}"
    }
    stage("Running tests") {
        sh 'rm -rf cheribsd-test-results && mkdir cheribsd-test-results'
        sh "./cheribuild/jenkins-cheri-build.py --test run-${suffix} --test-extra-args=--no-timestamped-test-subdir ${params.extraArgs}"
        sh 'find cheribsd-test-results'
        junit allowEmptyResults: false, keepLongStdio: true, testResults: 'cheribsd-test-results/cheri*.xml'
    }
    } finally {
	    sh "find ."  // check what files exist
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
