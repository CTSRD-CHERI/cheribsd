@Library('ctsrd-jenkins-scripts') _

properties([disableConcurrentBuilds(),
            disableResume(),
            [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
            [$class: 'CopyArtifactPermissionProperty', projectNames: '*'],
            [$class: 'JobPropertyImpl', throttle: [count: 2, durationName: 'hour', userBoost: true]],
            durabilityHint('PERFORMANCE_OPTIMIZED'),
            pipelineTriggers([githubPush()])
])

jobs = [:]

for (i in ["mips-nocheri", "cheri", "purecap", "riscv64", "riscv64-hybrid", "riscv64-purecap", "native"]) {
    String suffix = "${i}" // work around stupid groovy lambda captures
    String name = "cheribsd-${suffix}"
    jobs[name] = { ->
        cheribuildProject(target: "cheribsd-${suffix}",
            extraArgs: '--cheribsd/build-options=-s --cheribsd/no-debug-info',
            skipArchiving: true,
            customGitCheckoutDir: 'cheribsd',
            gitHubStatusContext: "ci/${suffix}",
            runTests: false, /* TODO: run cheritest */)
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
