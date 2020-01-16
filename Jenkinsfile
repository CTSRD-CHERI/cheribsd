@Library('ctsrd-jenkins-scripts') _

properties([disableConcurrentBuilds(),
            disableResume(),
            [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/cheribsd/'],
            [$class: 'CopyArtifactPermissionProperty', projectNames: '*'],
            [$class: 'JobPropertyImpl', throttle: [count: 2, durationName: 'hour', userBoost: true]],
            durabilityHint('PERFORMANCE_OPTIMIZED'),
            pipelineTriggers([githubPush()])
])

for (i in ["mips", "cheri", "purecap"]) {
    String suffix = "${i}" // work around stupid groovy lambda captures
    cheribuildProject(target: "cheribsd-${suffix}", cpu: suffix == 'mips' ? 'mips': 'cheri128',
            extraArgs: '',
            skipArchiving: true,
            runTests: false, /* TODO: run cheritest */
            /* sequential: true, // for now run all in order until we have it stable */)
}
