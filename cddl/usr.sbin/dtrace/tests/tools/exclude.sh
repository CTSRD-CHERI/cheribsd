# $FreeBSD$

# This file lists DTrace tests which are known to fail or hang/crash the
# system. They were pulled from the legacy DTrace test infrastructure in
# tools/tests/dtrace and may be out of date.
#
# Tests are listed here generally because one or more of the following is true:
#
# 1) The test is broken (usually because it assumes it's running on Solaris and
#    the test encodes some sort of Solarisism).
# 2) The functionality being tested is buggy (often but not always the result
#    of a FreeBSD-specific bug).
# 3) The test relies on DTrace functionality that's not yet available in FreeBSD
#    (e.g. tests for a specific SDT provider that we don't have).
#
# An end goal is to remove this file, concentrating first on instances of
# 1) and 2).
#
# The SKIP variable contains tests that should not be executed at all. The
# EXFAIL variable contains tests that are expected to fail when run. Please
# avoid adding tests to SKIP unless it really is necessary; with EXFAIL, tests
# that begin passing as the result of a change are visible in the test summary.

exclude()
{
    case $2 in
    # Handle globbing later
    *"*"*) ;;
    # No globbing needed
    *)
        eval $1=\"\$$1\\n$2\"
        return
        ;;
    esac
    for file in ${TESTBASE}/${2}; do
        case ${file} in
            # Invalid glob
            "${TESTBASE}/${2}") echo "Invalid exclude for $2" >&2; exit 1; ;;
        esac
        exclude "$1" "${file##${TESTBASE}/}"
    done
}

exclude EXFAIL common/aggs/tst.subr.d
exclude EXFAIL common/dtraceUtil/tst.ELFGenerationOut.d.ksh
exclude EXFAIL common/dtraceUtil/tst.ELFGenerationWithO.d.ksh
exclude EXFAIL common/funcs/tst.copyin.d
exclude EXFAIL common/funcs/tst.copyinto.d
exclude EXFAIL common/funcs/tst.ddi_pathname.d
exclude EXFAIL common/io/tst.fds.d
exclude EXFAIL common/mdb/tst.dtracedcmd.ksh
exclude EXFAIL common/misc/tst.dofmax.ksh
exclude EXFAIL common/misc/tst.include.ksh
exclude EXFAIL common/safety/tst.copyin2.d
exclude EXFAIL common/safety/tst.msgdsize.d
exclude EXFAIL common/safety/tst.msgsize.d
exclude EXFAIL common/scalars/tst.misc.d
exclude EXFAIL common/scalars/tst.selfarray2.d
exclude EXFAIL common/sched/tst.enqueue.d
exclude EXFAIL common/speculation/tst.SpecSizeVariations3.d
exclude EXFAIL common/tracemem/err.D_TRACEMEM_ADDR.badaddr.d
exclude EXFAIL common/translators/tst.TestTransStability2.ksh
exclude EXFAIL common/types/tst.struct.d
exclude EXFAIL common/types/tst.typedef.d

# We don't have a cpc provider.
exclude SKIP common/cpc/err.D_PDESC_ZERO.lowfrequency.d
exclude SKIP common/cpc/err.D_PDESC_ZERO.malformedoverflow.d
exclude SKIP common/cpc/err.D_PDESC_ZERO.nonexistentevent.d
exclude SKIP common/cpc/err.cpcvscpustatpart1.ksh
exclude SKIP common/cpc/err.cpcvscpustatpart2.ksh
exclude SKIP common/cpc/err.cputrackfailtostart.ksh
exclude SKIP common/cpc/err.cputrackterminates.ksh
exclude SKIP common/cpc/err.toomanyenablings.d
exclude SKIP common/cpc/tst.allcpus.ksh
exclude SKIP common/cpc/tst.genericevent.d
exclude SKIP common/cpc/tst.platformevent.ksh

# We don't have a mib provider.
exclude EXFAIL common/mib/tst.icmp.ksh
exclude EXFAIL common/mib/tst.tcp.ksh
exclude EXFAIL common/mib/tst.udp.ksh

# At the moment dtrace(1) always needs to run as root.
exclude SKIP common/privs/tst.fds.ksh
exclude SKIP common/privs/tst.func_access.ksh
exclude SKIP common/privs/tst.getf.ksh
exclude SKIP common/privs/tst.kpriv.ksh
exclude SKIP common/privs/tst.op_access.ksh
exclude SKIP common/privs/tst.procpriv.ksh
exclude SKIP common/privs/tst.providers.ksh
exclude SKIP common/privs/tst.unpriv_funcs.ksh

# These tests hang for reasons unknown.
exclude SKIP common/buffering/tst.ring3.d
exclude SKIP common/funcs/tst.chill.ksh
exclude SKIP common/funcs/tst.index.d

# No Java support at the moment.
exclude EXFAIL common/java_api/tst.Abort.ksh
exclude EXFAIL common/java_api/tst.Bean.ksh
exclude EXFAIL common/java_api/tst.Close.ksh
exclude EXFAIL common/java_api/tst.Drop.ksh
exclude EXFAIL common/java_api/tst.Enable.ksh
exclude EXFAIL common/java_api/tst.FunctionLookup.ksh
exclude EXFAIL common/java_api/tst.GetAggregate.ksh
exclude EXFAIL common/java_api/tst.MaxConsumers.ksh
exclude EXFAIL common/java_api/tst.MultiAggPrinta.ksh
exclude EXFAIL common/java_api/tst.ProbeData.ksh
exclude EXFAIL common/java_api/tst.ProbeDescription.ksh
exclude EXFAIL common/java_api/tst.StateMachine.ksh
exclude EXFAIL common/java_api/tst.StopLock.ksh

# Expects specific formatting from banner(6).
exclude EXFAIL common/aggs/tst.aggpackbanner.ksh

# Test assumes we're running on a Solaris kernel.
exclude EXFAIL common/misc/tst.roch.d
exclude EXFAIL common/predicates/tst.argsnotcached.d
exclude EXFAIL common/safety/tst.vahole.d

# Tests that depend on the plockstat provider.
exclude EXFAIL common/plockstat/tst.available.d
exclude EXFAIL common/plockstat/tst.libmap.d
exclude EXFAIL common/usdt/tst.andpid.ksh

# Depends on java.
exclude SKIP common/drops/drp.DTRACEDROP_STKSTROVERFLOW.d

# Interrupt priority isn't relevant on FreeBSD.
exclude SKIP common/builtinvar/tst.ipl.d
exclude SKIP common/builtinvar/tst.ipl1.d

# These tests rely on being able to find a host via broadcast pings.
exclude EXFAIL common/ip/tst.ipv4remotesctp.ksh
exclude EXFAIL common/ip/tst.ipv4remotetcp.ksh
exclude EXFAIL common/ip/tst.ipv4remoteudp.ksh
exclude EXFAIL common/ip/tst.ipv4remoteudplite.ksh
exclude EXFAIL common/ip/tst.ipv6remoteicmp.ksh
exclude EXFAIL common/ip/tst.ipv4remoteicmp.ksh
exclude EXFAIL common/ip/tst.remotesctpstate.ksh
exclude EXFAIL common/ip/tst.remotetcpstate.ksh

# Tries to enable pid$target:libc::entry, though there's no "libc" module.
# Currently unsure as to whether this might be a libproc bug.
exclude EXFAIL common/pid/tst.probemod.ksh

# Assumes date(1) has a pid$target::main:return probe.
exclude EXFAIL common/pid/tst.newprobes.ksh

# libproc+librtld_db don't handle dlopen(2) yet.
exclude EXFAIL common/pid/tst.provregex2.ksh
exclude EXFAIL common/pid/tst.provregex4.ksh

# This test appears to be invalid. dtrace is supposed to press on if a
# depends_on pragma cannot be satisfied, per the comment above
# dt_load_libs_dir() in libdtrace.
exclude EXFAIL common/pragma/err.invalidlibdep.ksh

# This test checks for a leading tab on a line before #define. That is illegal
# on Solaris, but the clang pre-processor on FreeBSD is happy with code like
# that.
exclude EXFAIL common/preprocessor/err.D_PRAGCTL_INVAL.tabdefine.d

# This test uses proc:::signal-handle, which we don't appear to have.
exclude EXFAIL common/proc/tst.signal.ksh

# This test uses proc:::lwp-start, which we don't appear to have.
exclude EXFAIL common/proc/tst.startexit.ksh

# This test causes a panic at the moment because fbt instruments the lock class'
# lc_owned method.
exclude SKIP common/safety/tst.rw.d

# Depends on some implementation details of the runtime linker.
exclude EXFAIL common/vars/tst.ucaller.ksh

# These rely on process attributes that FreeBSD doesn't carry.
exclude EXFAIL common/scripting/tst.projid.ksh
exclude EXFAIL common/scripting/tst.taskid.ksh

# Depends on tst.chasestrings.exe being ELF32. See r326181 and r326285.
exclude EXFAIL common/uctf/err.user64mode.ksh

# This test expects its test program to be installed without CTF data, but
# the rest of the programs for this feature need CTF data. Not yet sure how
# to build that.
exclude EXFAIL common/uctf/tst.libtype.ksh

# libproc doesn't have linkmap support yet.
exclude EXFAIL common/uctf/tst.linkmap.ksh

# Uses Sun-specific compiler options.
exclude EXFAIL common/usdt/tst.badguess.ksh
exclude EXFAIL common/usdt/tst.guess32.ksh
exclude EXFAIL common/usdt/tst.guess64.ksh

# Depends on non-standard static linker behaviour.
exclude EXFAIL common/usdt/tst.eliminate.ksh

# Generated headers include <sys/sdt.h>, so _DTRACE_VERSION is always defined.
exclude EXFAIL common/usdt/tst.nodtrace.ksh

# The second dtrace -G invocation returns an error with "no probes found," which
# makes sense to me. Not yet sure what the expected behaviour is here.
exclude EXFAIL common/usdt/tst.static2.ksh

# Uses the Solaris-specific ppriv(1).
exclude EXFAIL common/usdt/tst.user.ksh

# Triggers a lock assertion by using the raise() action from a profile probe.
exclude SKIP common/ustack/tst.spin.ksh

####
# CHERI SPECIFIC EXCLUDE
# The followings cause instability, make the system stuck, or timeout on CHERI.
# Ideally, this list will be made empty.
####

# json gives problem
exclude SKIP common/json/usdt.d

# fbt not ready yet
exclude SKIP common/fbtprovider/err.D_PDESC_ZERO.notreturn.d
exclude SKIP common/fbtprovider/tst.basic.d
exclude SKIP common/fbtprovider/tst.functionentry.d
exclude SKIP common/fbtprovider/tst.functionreturnvalue.d
exclude SKIP common/fbtprovider/tst.ioctlargs.d
exclude SKIP common/fbtprovider/tst.offset.d
exclude SKIP common/fbtprovider/tst.offsetzero.d
exclude SKIP common/fbtprovider/tst.return.d
exclude SKIP common/fbtprovider/tst.return0.d
exclude SKIP common/fbtprovider/tst.tailcall.d

# timeout for some reason
exclude SKIP builtinvar/t_dtrace_contrib:tst_arg1to8clause_d
exclude SKIP builtinvar/t_dtrace_contrib:tst_arg0clause_d

# causes core dump
exclude SKIP bitfields/t_dtrace_contrib:tst_SizeofBitField_d

# Some of them cause the system to stuck:
exclude SKIP common/dtraceUtil/err.D_PDESC_ZERO.InvalidDescription1.d
exclude SKIP common/dtraceUtil/man.AddSearchPath.d
exclude SKIP common/dtraceUtil/man.APIVersion.d
exclude SKIP common/dtraceUtil/man.CoalesceTrace.d
exclude SKIP common/dtraceUtil/man.ELFGeneration.d
exclude SKIP common/dtraceUtil/man.IncludedFilePath.d
exclude SKIP common/dtraceUtil/man.ListProbesWithFunctions
exclude SKIP common/dtraceUtil/man.ListProbesWithIDs
exclude SKIP common/dtraceUtil/man.ListProbesWithModules
exclude SKIP common/dtraceUtil/man.ListProbesWithNames
exclude SKIP common/dtraceUtil/man.ListProbesWithProviders
exclude SKIP common/dtraceUtil/man.ShowCompilerCode.d
exclude SKIP common/dtraceUtil/man.TraceFunctions
exclude SKIP common/dtraceUtil/man.TraceIDs
exclude SKIP common/dtraceUtil/man.TraceModule
exclude SKIP common/dtraceUtil/man.TraceNames
exclude SKIP common/dtraceUtil/man.TraceProvider
exclude SKIP common/dtraceUtil/man.VerboseStabilityReport.d
exclude SKIP common/dtraceUtil/tst.AddSearchPath.d.ksh
exclude SKIP common/dtraceUtil/tst.BufsizeGiga.d.ksh
exclude SKIP common/dtraceUtil/tst.BufsizeKilo.d.ksh
exclude SKIP common/dtraceUtil/tst.BufsizeMega.d.ksh
exclude SKIP common/dtraceUtil/tst.BufsizeTera.d.ksh
exclude SKIP common/dtraceUtil/tst.DataModel32.d.ksh
exclude SKIP common/dtraceUtil/tst.DataModel64.d.ksh
exclude SKIP common/dtraceUtil/tst.DefineNameWithCPP.d.ksh
exclude SKIP common/dtraceUtil/tst.DefineNameWithCPP.d.ksh.out
exclude SKIP common/dtraceUtil/tst.DestructWithFunction.d.ksh
exclude SKIP common/dtraceUtil/tst.DestructWithFunction.d.ksh.out
exclude SKIP common/dtraceUtil/tst.DestructWithID.d.ksh
exclude SKIP common/dtraceUtil/tst.DestructWithID.d.ksh.out
exclude SKIP common/dtraceUtil/tst.DestructWithModule.d.ksh
exclude SKIP common/dtraceUtil/tst.DestructWithModule.d.ksh.out
exclude SKIP common/dtraceUtil/tst.DestructWithName.d.ksh
exclude SKIP common/dtraceUtil/tst.DestructWithName.d.ksh.out
exclude SKIP common/dtraceUtil/tst.DestructWithoutW.d.ksh
exclude SKIP common/dtraceUtil/tst.DestructWithProvider.d.ksh
exclude SKIP common/dtraceUtil/tst.DestructWithProvider.d.ksh.out
exclude SKIP common/dtraceUtil/tst.ELFGenerationOut.d.ksh
exclude SKIP common/dtraceUtil/tst.ELFGenerationWithO.d.ksh
exclude SKIP common/dtraceUtil/tst.ExitStatus1.d.ksh
exclude SKIP common/dtraceUtil/tst.ExitStatus2.d.ksh
exclude SKIP common/dtraceUtil/tst.ExtraneousProbeIds.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidFuncName1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidFuncName2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidId1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidId2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidId3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidModule1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidModule2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidModule3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidModule4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidProbeIdentifier.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidProvider1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidProvider2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidProvider3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidProvider4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc5.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc6.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc7.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc8.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceFunc9.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID5.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID6.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceID7.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule5.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule6.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule7.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceModule8.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName5.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName6.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName7.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName8.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceName9.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceProvider1.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceProvider2.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceProvider3.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceProvider4.d.ksh
exclude SKIP common/dtraceUtil/tst.InvalidTraceProvider5.d.ksh
exclude SKIP common/dtraceUtil/tst.MultipleInvalidProbeId.d.ksh
exclude SKIP common/dtraceUtil/tst.PreprocessorStatement.d.ksh
exclude SKIP common/dtraceUtil/tst.QuietMode.d.ksh
exclude SKIP common/dtraceUtil/tst.QuietMode.d.ksh.out
exclude SKIP common/dtraceUtil/tst.TestCompile.d.ksh
exclude SKIP common/dtraceUtil/tst.TestCompile.d.ksh.out
exclude SKIP common/dtraceUtil/tst.UnDefineNameWithCPP.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroFunctionProbes.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroFunctionProbes.d.ksh.out
exclude SKIP common/dtraceUtil/tst.ZeroModuleProbes.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroModuleProbes.d.ksh.out
exclude SKIP common/dtraceUtil/tst.ZeroNameProbes.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroNameProbes.d.ksh.out
exclude SKIP common/dtraceUtil/tst.ZeroProbeIdentfier.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroProbesWithoutZ.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroProviderProbes.d.ksh
exclude SKIP common/dtraceUtil/tst.ZeroProviderProbes.d.ksh.out

# stuck
exclude SKIP common/buffering/tst.alignring.d
exclude SKIP common/pid/tst.args1.d

# ksh dependency
exclude SKIP common/env/tst.setenv1.ksh
exclude SKIP common/env/tst.setenv2.ksh
exclude SKIP common/env/tst.setenv3.ksh
exclude SKIP common/env/tst.unsetenv1.ksh

# usdt not ready
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
exclude SKIP common/usdt/tst.dlclose1.ksh.out
exclude SKIP common/usdt/tst.dlclose2.ksh
exclude SKIP common/usdt/tst.dlclose2.ksh.out
exclude SKIP common/usdt/tst.dlclose3.ksh
exclude SKIP common/usdt/tst.eliminate.ksh
exclude SKIP common/usdt/tst.enabled.ksh
exclude SKIP common/usdt/tst.enabled.ksh.out
exclude SKIP common/usdt/tst.enabled2.ksh
exclude SKIP common/usdt/tst.enabled2.ksh.out
exclude SKIP common/usdt/tst.entryreturn.ksh
exclude SKIP common/usdt/tst.entryreturn.ksh.out
exclude SKIP common/usdt/tst.fork.ksh
exclude SKIP common/usdt/tst.fork.ksh.out
exclude SKIP common/usdt/tst.forker.c
exclude SKIP common/usdt/tst.forker.ksh
exclude SKIP common/usdt/tst.guess32.ksh
exclude SKIP common/usdt/tst.guess64.ksh
exclude SKIP common/usdt/tst.header.ksh
exclude SKIP common/usdt/tst.include.ksh
exclude SKIP common/usdt/tst.linkpriv.ksh
exclude SKIP common/usdt/tst.linkunpriv.ksh
exclude SKIP common/usdt/tst.multiple.ksh
exclude SKIP common/usdt/tst.multiple.ksh.out
exclude SKIP common/usdt/tst.multiprov.ksh
exclude SKIP common/usdt/tst.multiprov.ksh.out
exclude SKIP common/usdt/tst.nodtrace.ksh
exclude SKIP common/usdt/tst.noprobes.ksh
exclude SKIP common/usdt/tst.noreap.ksh
exclude SKIP common/usdt/tst.noreapring.ksh
exclude SKIP common/usdt/tst.onlyenabled.ksh
exclude SKIP common/usdt/tst.reap.ksh
exclude SKIP common/usdt/tst.reeval.ksh
exclude SKIP common/usdt/tst.sameprovmulti.ksh
exclude SKIP common/usdt/tst.sameprovmulti.ksh.out
exclude SKIP common/usdt/tst.static.ksh
exclude SKIP common/usdt/tst.static.ksh.out
exclude SKIP common/usdt/tst.static2.ksh
exclude SKIP common/usdt/tst.static2.ksh.out
exclude SKIP common/usdt/tst.user.ksh
exclude SKIP common/usdt/tst.user.ksh.out

