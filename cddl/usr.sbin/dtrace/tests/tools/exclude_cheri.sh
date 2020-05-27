# $FreeBSD$

####
# CHERI SPECIFIC EXCLUDE
# The followings cause instability, make the system stuck, or timeout on CHERI.
# Ideally, this list will be made empty.
####

# missing curpsinfo due to missing symbol
exclude EXFAIL common/aggs/err.D_KEY_TYPE.badkey4.d

# goes into timeout. Probably missing dependencies. Not important.
exclude SKIP common/aggs/tst.aggpackbanner.ksh

# times are to short. With a faster cpu will probably work.
exclude EXFAIL common/aggs/tst.clear.d
exclude EXFAIL common/aggs/tst.cleardenormalize.d

# smal deltas in the output.
exclude EXFAIL common/aggs/tst.neglquant.d
exclude EXFAIL common/aggs/tst.negquant.d

# Registers acronyms not defined for mips (should be in reg.d.in)
exclude EXFAIL common/arrays/tst.uregsarray.d


# json gives problem
exclude SKIP common/json/usdt.d

# fbt::: doesn't work in cheri, yet.

exclude SKIP common/fbtprovider/tst.return.d
exclude SKIP common/fbtprovider/tst.tailcall.d
exclude SKIP common/misc/tst.roch.d
exclude SKIP common/safety/tst.basename.d
exclude SKIP common/safety/tst.cleanpath.d
exclude SKIP common/safety/tst.ddi_pathname.d
exclude SKIP common/safety/tst.dirname.d
exclude SKIP common/safety/tst.index.d
exclude SKIP common/safety/tst.msgdsize.d
exclude SKIP common/safety/tst.strchr.d
exclude SKIP common/safety/tst.strjoin.d
exclude SKIP common/safety/tst.strstr.d
exclude SKIP common/safety/tst.strtok.d


# timeout for some reason
exclude SKIP builtinvar/t_dtrace_contrib:tst_arg1to8clause_d
exclude SKIP builtinvar/t_dtrace_contrib:tst_arg0clause_d

# causes trap
exclude SKIP bitfields/t_dtrace_contrib:tst_SizeofBitField_d

# stuck
exclude SKIP common/buffering/tst.alignring.d
exclude SKIP common/pid/tst.args1.d


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