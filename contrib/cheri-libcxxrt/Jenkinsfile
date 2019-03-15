def doBuild(args) {
	def commonArgs = [
			target: 'libcxxrt',
			allocateNode: false,
			skipScm: true,  // only the first run handles the SCM
			extraArgs: '--install-prefix=/']
	cheribuildProject(commonArgs + args)
}

node('linux') {
	doBuild(target: 'libcxxrt-baremetal', cpu: 'mips', skipScm: false,
			artifactsToCopy: [[job: 'Newlib-baremetal-mips/master', filter: 'newlib-baremetal-mips.tar.xz']],
			beforeBuild: 'mkdir -p cherisdk/baremetal && tar xzf newlib-baremetal-mips.tar.xz -C cherisdk/baremetal; ls -laR cheribsd/baremetal')
	doBuild([cpu: 'mips', skipArtifacts: true]) // we can reuse artifacts from last build
	doBuild([target: 'libcxxrt', cpu: 'cheri128', skipScm: true, allocateNode: false])
	doBuild([target: 'libcxxrt', cpu: 'cheri256', skipScm: true, allocateNode: false])
	doBuild([target: 'libcxxrt', cpu: 'native', skipScm: true, allocateNode: false])
}