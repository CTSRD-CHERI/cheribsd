# $FreeBSD$

####
# CHERI SPECIFIC EXCLUDE
# The followings cause instability, make the system stuck, or timeout on CHERI.
# Ideally, this list will be made empty.
####

# aggs - goes into timeout. Probably missing dependencies. Not important.
exclude SKIP common/aggs/tst.aggpackbanner.ksh

# aggs - times are to short. With a faster cpu will probably work.
exclude EXFAIL common/aggs/tst.clear.d
exclude EXFAIL common/aggs/tst.cleardenormalize.d

# aggs - small deltas in the output.
exclude EXFAIL common/aggs/tst.neglquant.d
exclude EXFAIL common/aggs/tst.negquant.d

# arrays - Registers acronyms not defined for mips (should be in reg.d.in)
exclude EXFAIL common/arrays/tst.uregsarray.d

# dtraceUtil - preprocessor
exclude EXFAIL common/dtraceUtil/man.AddSearchPath.d

# dtraceutil - -m option make the system to stuck
exclude SKIP common/dtraceUtil/tst.DestructWithModule.d.ksh

# env - depends on ksh
exclude EXFAIL common/env/tst.unsetenv2.ksh
exclude EXFAIL common/dtraceUtil/tst.DefineNameWithCPP.d.ksh

# json gives problem
exclude SKIP common/json/usdt.d

# funcs - lockstat doesn't work? or nexted exceptions are generated?
exclude SKIP common/func/tst.mutex_owner.d

# fbt - when all the probes are enabled, the system is stucks
exclude SKIP common/misc/tst.schrock.ksh
exclude SKIP common/misc/tst.roch.d
exclude SKIP common/fbtprovider/tst.basic.d
exclude SKIP common/fbtprovider/tst.return.d
exclude SKIP common/fbtprovider/tst.tailcall.d
exclude SKIP common/docsExamples/specopen.d
exclude SKIP common/safety/tst.stddev.d
exclude SKIP common/safety/tst.uid.d
exclude SKIP common/safety/tst.strtok.d
exclude SKIP common/safety/tst.progenyof.d
exclude SKIP common/safety/tst.uregs.d
exclude SKIP common/safety/tst.rw.d
exclude SKIP common/safety/tst.zonename.d
exclude SKIP common/safety/tst.errno.d
exclude SKIP common/safety/tst.strstr.d
exclude SKIP common/safety/tst.unalign.d
exclude SKIP common/safety/tst.ddi_pathname.d
exclude SKIP common/safety/tst.stack.d
exclude SKIP common/safety/tst.index.d
exclude SKIP common/safety/tst.substr.d
exclude SKIP common/safety/tst.jid.d
exclude SKIP common/safety/tst.random.d
exclude SKIP common/safety/tst.jailname.d
exclude SKIP common/safety/tst.basename.d
exclude SKIP common/safety/tst.ustackdepth.d
exclude SKIP common/safety/tst.gid.d
exclude SKIP common/safety/tst.hton.d
exclude SKIP common/safety/tst.vahole.d
exclude SKIP common/safety/tst.null.d
exclude SKIP common/safety/tst.dirname.d
exclude SKIP common/safety/tst.strjoin.d
exclude SKIP common/safety/tst.ustack.d
exclude SKIP common/safety/tst.execname.d
exclude SKIP common/safety/tst.stackdepth.d
exclude SKIP common/safety/tst.pid.d
exclude SKIP common/safety/tst.ucaller.d
exclude SKIP common/safety/tst.msgsize.d
exclude SKIP common/safety/tst.strchr.d
exclude SKIP common/safety/tst.caller.d
exclude SKIP common/safety/tst.cleanpath.d
exclude SKIP common/safety/tst.ppid.d
exclude SKIP common/safety/tst.violentdeath.ksh
exclude SKIP common/safety/tst.msgdsize.d


# timeout for some reason
exclude SKIP builtinvar/t_dtrace_contrib:tst_arg1to8clause_d
exclude SKIP builtinvar/t_dtrace_contrib:tst_arg0clause_d

# causes trap
exclude SKIP bitfields/t_dtrace_contrib:tst_SizeofBitField_d

# stuck
exclude SKIP common/buffering/tst.alignring.d
exclude SKIP common/pid/tst.args1.d

# ip - they all require ksh
exclude EXFAIL tst.ipv4localicmp.ksh
exclude EXFAIL tst.ipv4localsctp.ksh
exclude EXFAIL tst.ipv4localtcp.ksh
exclude EXFAIL tst.ipv4localudp.ksh
exclude EXFAIL tst.ipv4localudplite.ksh
exclude EXFAIL tst.ipv4remoteicmp.ksh
exclude EXFAIL tst.ipv4remotesctp.ksh
exclude EXFAIL tst.ipv4remotetcp.ksh
exclude EXFAIL tst.ipv4remoteudp.ksh
exclude EXFAIL tst.ipv4remoteudplite.ksh
exclude EXFAIL tst.ipv6localicmp.ksh
exclude EXFAIL tst.ipv6remoteicmp.ksh
exclude EXFAIL tst.localsctpstate.ksh
exclude EXFAIL tst.localtcpstate.ksh
exclude EXFAIL tst.remotesctpstate.ksh
exclude EXFAIL tst.remotetcpstate.ksh

# usdt available in cheri
exclude SKIP common/usdt/argmap.d
exclude SKIP common/usdt/args.d
exclude SKIP common/usdt/forker.d
exclude SKIP common/usdt/prov.d
exclude SKIP common/usdt/prov.h
exclude SKIP common/usdt/tst.andpid.ksh
exclude SKIP common/usdt/tst.argmap.c
exclude SKIP common/usdt/tst.argmap.d
exclude SKIP common/usdt/tst.args.c
exclude SKIP common/usdt/tst.args.d
exclude SKIP common/usdt/tst.badguess.ksh
exclude SKIP common/usdt/tst.corruptenv.ksh
exclude SKIP common/usdt/tst.dlclose1.ksh
exclude SKIP common/usdt/tst.dlclose2.ksh
exclude SKIP common/usdt/tst.dlclose3.ksh
exclude SKIP common/usdt/tst.eliminate.ksh
exclude SKIP common/usdt/tst.enabled.ksh
exclude SKIP common/usdt/tst.enabled2.ksh
exclude SKIP common/usdt/tst.entryreturn.ksh
exclude SKIP common/usdt/tst.fork.ksh
exclude SKIP common/usdt/tst.forker.c
exclude SKIP common/usdt/tst.forker.ksh
exclude SKIP common/usdt/tst.guess32.ksh
exclude SKIP common/usdt/tst.guess64.ksh
exclude SKIP common/usdt/tst.header.ksh
exclude SKIP common/usdt/tst.include.ksh
exclude SKIP common/usdt/tst.linkpriv.ksh
exclude SKIP common/usdt/tst.linkunpriv.ksh
exclude SKIP common/usdt/tst.multiple.ksh
exclude SKIP common/usdt/tst.multiprov.ksh
exclude SKIP common/usdt/tst.nodtrace.ksh
exclude SKIP common/usdt/tst.noprobes.ksh
exclude SKIP common/usdt/tst.noreap.ksh
exclude SKIP common/usdt/tst.noreapring.ksh
exclude SKIP common/usdt/tst.onlyenabled.ksh
exclude SKIP common/usdt/tst.reap.ksh
exclude SKIP common/usdt/tst.reeval.ksh
exclude SKIP common/usdt/tst.sameprovmulti.ksh
exclude SKIP common/usdt/tst.static.ksh
exclude SKIP common/usdt/tst.static2.ksh
exclude SKIP common/usdt/tst.user.ksh

# ustack - ksh not available in CHERI
exclude EXFAIL common/ustack/tst.bigstack.d
exclude EXFAIL common/ustack/tst.depth.ksh





