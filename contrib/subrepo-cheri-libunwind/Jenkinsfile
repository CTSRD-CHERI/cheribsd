// reuse the same jenkins node for all the builds
def doBuild(args) {
	def commonArgs = [
			target: 'libunwind',
			nodeLabel: null,
			skipScm: true,  // only the first run handles the SCM
			extraArgs: '--install-prefix=/']
	cheribuildProject(commonArgs + args)
}

node('linux') {
	doBuild([cpu: 'mips', skipScm: false])
	doBuild([cpu: 'native', skipArtifacts: true]) // we can reuse artifacts from last build
	doBuild([cpu: 'cheri128'])
	doBuild([cpu: 'cheri256'])
	// TODO: libunwind baremetal
	/* doBuild(target: 'libunwind-baremetal', cpu: 'mips', ,
			artifactsToCopy: [[job: 'Newlib-baremetal-mips/master', filter: 'newlib-baremetal-mips.tar.xz']],
			beforeBuild: 'mkdir -p cherisdk/baremetal && tar xzf newlib-baremetal-mips.tar.xz -C cherisdk/baremetal; ls -laR cheribsd/baremetal')
	*/
}
