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

for (i in ["mips-nocheri", "cheri", "purecap"]) {
    String suffix = "${i}" // work around stupid groovy lambda captures
    String name = "cheribsd-${suffix}"
    jobs[name] = { ->
        cheribuildProject(target: "cheribsd-${suffix}", cpu: suffix == 'mips-nocheri' ? 'mips': 'cheri128',
            extraArgs: '--cheribsd/build-options=-s --cheribsd/no-debug-info',
            skipArchiving: true,
            customGitCheckoutDir: 'cheribsd',
            runTests: false, /* TODO: run cheritest */)
    }
}

boolean runParallel = true;
echo("Running jobs in parallel: ${runParallel}")
if (runParallel) {
    jobs.failFast = true
    parallel jobs
} else {
    jobs.each { key, value ->
        echo("RUNNING ${key}")
        value();
    }
}
