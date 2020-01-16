@Library('ctsrd-jenkins-scripts') _

properties([disableConcurrentBuilds(),
            disableResume(),
            [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
            [$class: 'CopyArtifactPermissionProperty', projectNames: '*'],
            [$class: 'JobPropertyImpl', throttle: [count: 2, durationName: 'hour', userBoost: true]],
            durabilityHint('PERFORMANCE_OPTIMIZED'),
            pipelineTriggers([githubPush()])
])

jobs = []

for (i in ["mips", "cheri", "purecap"]) {
    String suffix = "${i}" // work around stupid groovy lambda captures
    String name = "cheribsd-${suffix}"
    jobs[name] = cheribuildProject(target: "cheribsd-${suffix}", cpu: suffix == 'mips' ? 'mips': 'cheri128',
            extraArgs: '',
            skipArchiving: true,
            runTests: false, /* TODO: run cheritest */)
}

boolean runParallel = true;
if (runParallel) {
    jobs.failFast = true
    parallel jobs
} else {
    jobs.each { key, value ->
        echo("RUNNING $key")
        value();
    }
}
