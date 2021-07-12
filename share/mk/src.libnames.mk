# $FreeBSD$
#
# The include file <src.libnames.mk> define library names suitable
# for INTERNALLIB and PRIVATELIB definition

.if !target(__<bsd.init.mk>__) && !target(__<Makefile.libcompat>__)
.error src.libnames.mk cannot be included directly.
.endif

.if !target(__<src.libnames.mk>__)
__<src.libnames.mk>__:

.include <src.opts.mk>

_PRIVATELIBS=	\
		atf_c \
		atf_cxx \
		auditd \
		bsdstat \
		cheribsdtest_dynamic \
		devdctl \
		event1 \
		gmock \
		gtest \
		gmock_main \
		gtest_main \
		heimipcc \
		heimipcs \
		ldns \
		sqlite3 \
		ssh \
		ucl \
		unbound \
		zstd

_PRIVATELIBS+=	png

_INTERNALLIBS=	\
		amu \
		c_nossp_pic \
		cron \
		elftc \
		fifolog \
		ifconfig \
		ipf \
		lpr \
		lua \
		lutok \
		netbsd \
		ntp \
		ntpevent \
		openbsd \
		opts \
		parse \
		pe \
		pmcstat \
		sl \
		sm \
		smdb \
		smutil \
		telnet \
		vers

.if ${MK_BSNMP} == "yes"
_INTERNALLIBS+=	bsnmptools
.endif

_LIBRARIES=	\
		${_PRIVATELIBS} \
		${_INTERNALLIBS} \
		${LOCAL_LIBRARIES} \
		80211 \
		9p \
		alias \
		archive \
		asn1 \
		avl \
		be \
		begemot \
		bluetooth \
		bsdxml \
		bsm \
		bsnmp \
		bz2 \
		c \
		c_cheri \
		c_nosyscalls \
		c_pic \
		calendar \
		cam \
		casper \
		cheri \
		cheri_caprevoke \
		cheri_support \
		cheri_syscalls \
		cap_dns \
		cap_fileargs \
		cap_grp \
		cap_net \
		cap_pwd \
		cap_sysctl \
		cap_syslog \
		com_err \
		compiler_rt \
		crypt \
		crypto \
		ctf \
		curl \
		cuse \
		cxxrt \
		devctl \
		devdctl \
		devinfo \
		devstat \
		dialog \
		dl \
		dpv \
		dtrace \
		dwarf \
		edit \
		efivar \
		elf \
		execinfo \
		fetch \
		figpar \
		geom \
		gnuregex \
		gpio \
		gssapi \
		gssapi_krb5 \
		hdb \
		helloworld \
		heimbase \
		heimntlm \
		heimsqlite \
		hx509 \
		icp \
		ipsec \
		ipt \
		jail \
		jpeg \
		kadm5clnt \
		kadm5srv \
		kafs5 \
		kdc \
		kiconv \
		krb5 \
		kvm \
		l \
		lzma \
		m \
		malloc_simple \
		magic \
		md \
		memstat \
		mp \
		mt \
		ncurses \
		ncursesw \
		netgraph \
		netmap \
		ngatm \
		nv \
		nvpair \
		opencsd \
		opie \
		pam \
		panel \
		panelw \
		pcap \
		pcsclite \
		pjdlog \
		pmc \
		proc \
		procstat \
		pthread \
		radius \
		regex \
		roken \
		rpcsec_gss \
		rpcsvc \
		rt \
		rtld_db \
		sbuf \
		sdp \
		sm \
		smb \
		spl \
		ssl \
		ssp_nonshared \
		stats \
		statcounters \
		stdthreads \
		supcplusplus \
		syscalls \
		sysdecode \
		tacplus \
		termcap \
		termcapw \
		tpool \
		ufs \
		ugidfw \
		ulog \
		umem \
		usb \
		usbhid \
		util \
		uutil \
		vmmapi \
		wind \
		wrap \
		xo \
		y \
		ypclnt \
		z \
		zfs_core \
		zfs \
		zfsbootenv \
		zpool \
		zutil

.if ${MK_BLACKLIST} != "no"
_LIBRARIES+= \
		blacklist \

.endif

.if ${MK_OFED} != "no"
_LIBRARIES+= \
		cxgb4 \
		ibcm \
		ibmad \
		ibnetdisc \
		ibumad \
		ibverbs \
		mlx4 \
		mlx5 \
		rdmacm \
		osmcomp \
		opensm \
		osmvendor
.endif

.if ${MK_BEARSSL} == "yes"
_LIBRARIES+= \
		bearssl \
		secureboot \

LIBBEARSSL?=	${LIBBEARSSLDIR}/libbearssl.a
LIBSECUREBOOT?=	${LIBSECUREBOOTDIR}/libsecureboot.a
.endif

.if ${MK_VERIEXEC} == "yes"
_LIBRARIES+= veriexec

LIBVERIEXEC?=	${LIBVERIEXECDIR}/libveriexec.a
.endif

# Each library's LIBADD needs to be duplicated here for static linkage of
# 2nd+ order consumers.  Auto-generating this would be better.
_DP_80211=	sbuf bsdxml
_DP_9p=		sbuf
_DP_archive=	z bz2 lzma bsdxml zstd
_DP_zstd=	pthread
.if ${MK_BLACKLIST} != "no"
_DP_blacklist+=	pthread
.endif
_DP_crypto=	pthread
.if ${MK_OPENSSL} != "no"
_DP_archive+=	crypto
.else
_DP_archive+=	md
.endif
_DP_sqlite3=	pthread
_DP_ssl=	crypto
_DP_ssh=	crypto crypt z
.if ${MK_LDNS} != "no"
_DP_ssh+=	ldns
.endif
_DP_edit=	ncursesw
.if ${MK_OPENSSL} != "no"
_DP_bsnmp=	crypto
.endif
_DP_geom=	bsdxml sbuf
_DP_cam=	sbuf
_DP_kvm=	elf
_DP_casper=	nv
_DP_cap_dns=	nv
_DP_cap_fileargs=	nv
_DP_cap_grp=	nv
_DP_cap_pwd=	nv
_DP_cap_sysctl=	nv
_DP_cap_syslog=	nv
.if ${MK_OFED} != "no"
_DP_pcap=	ibverbs mlx5
.endif
_DP_pjdlog=	util
_DP_png=	z
_DP_opie=	md
_DP_usb=	pthread
_DP_unbound=	ssl crypto pthread
_DP_rt=	pthread
.if ${MK_OPENSSL} == "no"
_DP_radius=	md
.else
_DP_radius=	crypto
.endif
_DP_rtld_db=	elf procstat
_DP_procstat=	kvm util elf
.if ${MK_CXX} == "yes"
.if ${MK_LIBCPLUSPLUS} != "no"
_DP_proc=	cxxrt
.else
_DP_proc=	supcplusplus
.endif
.endif
.if ${MK_CDDL} != "no"
_DP_proc+=	ctf
.endif
_DP_proc+=	elf procstat rtld_db util
_DP_mp=	crypto
_DP_memstat=	kvm
_DP_magic=	z
_DP_mt=		sbuf bsdxml
_DP_ldns=	ssl crypto
_DP_lua=	m
_DP_lutok=	lua
.if ${MK_OPENSSL} != "no"
_DP_fetch=	ssl crypto
.else
_DP_fetch=	md
.endif
_DP_execinfo=	elf
_DP_dwarf=	elf
_DP_dpv=	dialog figpar util ncursesw
_DP_dialog=	ncursesw m
_DP_cuse=	pthread
_DP_atf_cxx=	atf_c
_DP_gtest=	pthread regex
_DP_gmock=	gtest
_DP_gmock_main=	gmock
_DP_gtest_main=	gtest
_DP_devstat=	kvm
_DP_pam=	radius tacplus opie md util
.if ${MK_KERBEROS} != "no"
_DP_pam+=	krb5
.endif
.if ${MK_OPENSSH} != "no"
_DP_pam+=	ssh
.endif
.if ${MK_NIS} != "no"
_DP_pam+=	ypclnt
.endif
_DP_roken=	crypt
_DP_kadm5clnt=	com_err krb5 roken
_DP_kadm5srv=	com_err hdb krb5 roken
_DP_heimntlm=	crypto com_err krb5 roken
_DP_hx509=	asn1 com_err crypto roken wind
_DP_hdb=	asn1 com_err krb5 roken sqlite3
_DP_asn1=	com_err roken
_DP_kdc=	roken hdb hx509 krb5 heimntlm asn1 crypto
_DP_wind=	com_err roken
_DP_heimbase=	pthread
_DP_heimipcc=	heimbase roken pthread
_DP_heimipcs=	heimbase roken pthread
_DP_kafs5=	asn1 krb5 roken
_DP_krb5+=	asn1 com_err crypt crypto hx509 roken wind heimbase heimipcc
_DP_gssapi_krb5+=	gssapi krb5 crypto roken asn1 com_err
_DP_lzma=	md pthread
_DP_ucl=	m
_DP_vmmapi=	util
_DP_opencsd=	cxxrt
_DP_ctf=	spl z
_DP_dtrace=	ctf elf proc pthread rtld_db
_DP_xo=		util
_DP_ztest=	geom m nvpair umem zpool pthread avl zfs_core spl zutil zfs uutil icp
# The libc dependencies are not strictly needed but are defined to make the
# assert happy.
_DP_c=		compiler_rt
_DP_c_nosyscalls=		compiler_rt
.if ${MK_SSP} != "no" && !${MACHINE_ABI:Mpurecap} && \
    (${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH:Mpower*} != "")
_DP_c+=		ssp_nonshared
_DP_c_nosyscalls+=		ssp_nonshared
.endif
_DP_stats=	sbuf pthread
_DP_stdthreads=	pthread
_DP_tacplus=	md
_DP_panel=	ncurses
_DP_panelw=	ncursesw
_DP_rpcsec_gss=	gssapi
_DP_smb=	kiconv
_DP_ulog=	md
_DP_fifolog=	z
_DP_ipf=	kvm
_DP_tpool=	spl
_DP_uutil=	avl nvpair spl
_DP_zfs=	md pthread umem util uutil m avl bsdxml crypto geom nvpair \
	z zfs_core zutil
_DP_zfsbootenv= zfs nvpair
_DP_zfs_core=	nvpair
_DP_avl=	nvpair
_DP_zpool=	md pthread z icp spl nvpair avl umem
_DP_zutil=	avl tpool
_DP_be=		zfs spl nvpair zfsbootenv
_DP_netmap=
_DP_ifconfig=	m

# OFED support
.if ${MK_OFED} != "no"
_DP_cxgb4=	ibverbs pthread
_DP_ibcm=	ibverbs
_DP_ibmad=	ibumad
_DP_ibnetdisc=	osmcomp ibmad ibumad
_DP_ibumad=	
_DP_ibverbs=
_DP_mlx4=	ibverbs pthread
_DP_mlx5=	ibverbs pthread
_DP_rdmacm=	ibverbs
_DP_osmcomp=	pthread
_DP_opensm=	pthread osmcomp
_DP_osmvendor=	ibumad pthread osmcomp
.endif

_DP_helloworld=	cheri

# Define special cases
LDADD_supcplusplus=	-lsupc++
LIBATF_C=	${LIBDESTDIR}${LIBDIR_BASE}/libprivateatf-c.a
LIBATF_CXX=	${LIBDESTDIR}${LIBDIR_BASE}/libprivateatf-c++.a
LDADD_atf_c=	-lprivateatf-c
LDADD_atf_cxx=	-lprivateatf-c++

LIBGMOCK=	${LIBDESTDIR}${LIBDIR_BASE}/libprivategmock.a
LIBGMOCK_MAIN=	${LIBDESTDIR}${LIBDIR_BASE}/libprivategmock_main.a
LIBGTEST=	${LIBDESTDIR}${LIBDIR_BASE}/libprivategtest.a
LIBGTEST_MAIN=	${LIBDESTDIR}${LIBDIR_BASE}/libprivategtest_main.a
LDADD_gmock=	-lprivategmock
LDADD_gtest=	-lprivategtest
LDADD_gmock_main= -lprivategmock_main
LDADD_gtest_main= -lprivategtest_main

.for _l in ${_PRIVATELIBS}
LIB${_l:tu}?=	${LIBDESTDIR}${LIBDIR_BASE}/libprivate${_l}.a
.endfor

.if ${MK_PIE} != "no"
PIE_SUFFIX=	_pie
.endif

.for _l in ${_LIBRARIES}
.if ${_INTERNALLIBS:M${_l}} || !defined(SYSROOT)
LDADD_${_l}_L+=		-L${LIB${_l:tu}DIR}
.endif
DPADD_${_l}?=	${LIB${_l:tu}}
.if ${_PRIVATELIBS:M${_l}}
LDADD_${_l}?=	-lprivate${_l}
.elif ${_INTERNALLIBS:M${_l}}
LDADD_${_l}?=	${LDADD_${_l}_L} -l${_l:S/${PIE_SUFFIX}//}${PIE_SUFFIX}
.else
LDADD_${_l}?=	${LDADD_${_l}_L} -l${_l}
.endif
# Add in all dependencies for static linkage.
.if defined(_DP_${_l}) && (${_INTERNALLIBS:M${_l}} || \
    (defined(NO_SHARED) && ${NO_SHARED:tl} != "no"))
.for _d in ${_DP_${_l}}
DPADD_${_l}+=	${DPADD_${_d}}
LDADD_${_l}+=	${LDADD_${_d}}
.endfor
.endif
.endfor

# These are special cases where the library is broken and anything that uses
# it needs to add more dependencies.  Broken usually means that it has a
# cyclic dependency and cannot link its own dependencies.  This is bad, please
# fix the library instead.
# Unless the library itself is broken then the proper place to define
# dependencies is _DP_* above.

# libatf-c++ exposes libatf-c abi hence we need to explicit link to atf_c for
# atf_cxx
DPADD_atf_cxx+=	${DPADD_atf_c}
LDADD_atf_cxx+=	${LDADD_atf_c}

DPADD_gmock+=	${DPADD_gtest}
LDADD_gmock+=	${LDADD_gtest}

DPADD_gmock_main+=	${DPADD_gmock}
LDADD_gmock_main+=	${LDADD_gmock}

DPADD_gtest_main+=	${DPADD_gtest}
LDADD_gtest_main+=	${LDADD_gtest}

# Detect LDADD/DPADD that should be LIBADD, before modifying LDADD here.
_BADLDADD=
.for _l in ${LDADD:M-l*:N-l*/*:C,^-l,,}
.if ${_LIBRARIES:M${_l}} && !${_PRIVATELIBS:M${_l}}
_BADLDADD+=	${_l}
.endif
.endfor
.if !empty(_BADLDADD)
.error ${.CURDIR}: These libraries should be LIBADD+=foo rather than DPADD/LDADD+=-lfoo: ${_BADLDADD}
.endif

.for _l in ${LIBADD}
DPADD+=		${DPADD_${_l}}
LDADD+=		${LDADD_${_l}}
.endfor

_LIB_OBJTOP?=	${OBJTOP}
# INTERNALLIB definitions.
LIBELFTCDIR=	${_LIB_OBJTOP}/lib/libelftc
LIBELFTC?=	${LIBELFTCDIR}/libelftc${PIE_SUFFIX}.a

LIBLUADIR=	${_LIB_OBJTOP}/lib/liblua
LIBLUA?=	${LIBLUADIR}/liblua${PIE_SUFFIX}.a

LIBLUTOKDIR=	${_LIB_OBJTOP}/lib/liblutok
LIBLUTOK?=	${LIBLUTOKDIR}/liblutok${PIE_SUFFIX}.a

LIBPEDIR=	${_LIB_OBJTOP}/lib/libpe
LIBPE?=		${LIBPEDIR}/libpe${PIE_SUFFIX}.a

LIBOPENBSDDIR=	${_LIB_OBJTOP}/lib/libopenbsd
LIBOPENBSD?=	${LIBOPENBSDDIR}/libopenbsd${PIE_SUFFIX}.a

LIBSMDIR=	${_LIB_OBJTOP}/lib/libsm
LIBSM?=		${LIBSMDIR}/libsm${PIE_SUFFIX}.a

LIBSMDBDIR=	${_LIB_OBJTOP}/lib/libsmdb
LIBSMDB?=	${LIBSMDBDIR}/libsmdb${PIE_SUFFIX}.a

LIBSMUTILDIR=	${_LIB_OBJTOP}/lib/libsmutil
LIBSMUTIL?=	${LIBSMUTILDIR}/libsmutil${PIE_SUFFIX}.a

LIBNETBSDDIR?=	${_LIB_OBJTOP}/lib/libnetbsd
LIBNETBSD?=	${LIBNETBSDDIR}/libnetbsd${PIE_SUFFIX}.a

LIBVERSDIR?=	${_LIB_OBJTOP}/kerberos5/lib/libvers
LIBVERS?=	${LIBVERSDIR}/libvers${PIE_SUFFIX}.a

LIBSLDIR=	${_LIB_OBJTOP}/kerberos5/lib/libsl
LIBSL?=		${LIBSLDIR}/libsl${PIE_SUFFIX}.a

LIBIFCONFIGDIR=	${_LIB_OBJTOP}/lib/libifconfig
LIBIFCONFIG?=	${LIBIFCONFIGDIR}/libifconfig${PIE_SUFFIX}.a

LIBIPFDIR=	${_LIB_OBJTOP}/sbin/ipf/libipf
LIBIPF?=	${LIBIPFDIR}/libipf${PIE_SUFFIX}.a

LIBTELNETDIR=	${_LIB_OBJTOP}/lib/libtelnet
LIBTELNET?=	${LIBTELNETDIR}/libtelnet${PIE_SUFFIX}.a

LIBCRONDIR=	${_LIB_OBJTOP}/usr.sbin/cron/lib
LIBCRON?=	${LIBCRONDIR}/libcron${PIE_SUFFIX}.a

LIBNTPDIR=	${_LIB_OBJTOP}/usr.sbin/ntp/libntp
LIBNTP?=	${LIBNTPDIR}/libntp${PIE_SUFFIX}.a

LIBNTPEVENTDIR=	${_LIB_OBJTOP}/usr.sbin/ntp/libntpevent
LIBNTPEVENT?=	${LIBNTPEVENTDIR}/libntpevent${PIE_SUFFIX}.a

LIBOPTSDIR=	${_LIB_OBJTOP}/usr.sbin/ntp/libopts
LIBOPTS?=	${LIBOPTSDIR}/libopts${PIE_SUFFIX}.a

LIBPARSEDIR=	${_LIB_OBJTOP}/usr.sbin/ntp/libparse
LIBPARSE?=	${LIBPARSEDIR}/libparse${PIE_SUFFIX}.a

LIBLPRDIR=	${_LIB_OBJTOP}/usr.sbin/lpr/common_source
LIBLPR?=	${LIBLPRDIR}/liblpr${PIE_SUFFIX}.a

LIBFIFOLOGDIR=	${_LIB_OBJTOP}/usr.sbin/fifolog/lib
LIBFIFOLOG?=	${LIBFIFOLOGDIR}/libfifolog${PIE_SUFFIX}.a

LIBBSNMPTOOLSDIR=	${_LIB_OBJTOP}/usr.sbin/bsnmpd/tools/libbsnmptools
LIBBSNMPTOOLS?=	${LIBBSNMPTOOLSDIR}/libbsnmptools${PIE_SUFFIX}.a

LIBAMUDIR=	${_LIB_OBJTOP}/usr.sbin/amd/libamu
LIBAMU?=	${LIBAMUDIR}/libamu${PIE_SUFFIX}.a

LIBBEDIR=	${_LIB_OBJTOP}/lib/libbe
LIBBE?=		${LIBBEDIR}/libbe${PIE_SUFFIX}.a

LIBPMCSTATDIR=	${_LIB_OBJTOP}/lib/libpmcstat
LIBPMCSTAT?=	${LIBPMCSTATDIR}/libpmcstat${PIE_SUFFIX}.a

LIBC_NOSSP_PICDIR=	${_LIB_OBJTOP}/lib/libc
LIBC_NOSSP_PIC?=	${LIBC_NOSSP_PICDIR}/libc_nossp_pic${PIE_SUFFIX}.a

# Define a directory for each library.  This is useful for adding -L in when
# not using a --sysroot or for meta mode bootstrapping when there is no
# Makefile.depend.  These are sorted by directory.
LIBAVLDIR=	${_LIB_OBJTOP}/cddl/lib/libavl
LIBCTFDIR=	${_LIB_OBJTOP}/cddl/lib/libctf
LIBDTRACEDIR=	${_LIB_OBJTOP}/cddl/lib/libdtrace
LIBICPDIR=	${_LIB_OBJTOP}/cddl/lib/libicp
LIBNVPAIRDIR=	${_LIB_OBJTOP}/cddl/lib/libnvpair
LIBUMEMDIR=	${_LIB_OBJTOP}/cddl/lib/libumem
LIBUUTILDIR=	${_LIB_OBJTOP}/cddl/lib/libuutil
LIBZFSDIR=	${_LIB_OBJTOP}/cddl/lib/libzfs
LIBZFS_COREDIR=	${_LIB_OBJTOP}/cddl/lib/libzfs_core
LIBZFSBOOTENVDIR=	${_LIB_OBJTOP}/cddl/lib/libzfsbootenv
LIBZPOOLDIR=	${_LIB_OBJTOP}/cddl/lib/libzpool
LIBZUTILDIR=	${_LIB_OBJTOP}/cddl/lib/libzutil
LIBTPOOLDIR=	${_LIB_OBJTOP}/cddl/lib/libtpool

# OFED support
LIBCXGB4DIR=	${_LIB_OBJTOP}/lib/ofed/libcxgb4
LIBIBCMDIR=	${_LIB_OBJTOP}/lib/ofed/libibcm
LIBIBMADDIR=	${_LIB_OBJTOP}/lib/ofed/libibmad
LIBIBNETDISCDIR=${_LIB_OBJTOP}/lib/ofed/libibnetdisc
LIBIBUMADDIR=	${_LIB_OBJTOP}/lib/ofed/libibumad
LIBIBVERBSDIR=	${_LIB_OBJTOP}/lib/ofed/libibverbs
LIBMLX4DIR=	${_LIB_OBJTOP}/lib/ofed/libmlx4
LIBMLX5DIR=	${_LIB_OBJTOP}/lib/ofed/libmlx5
LIBRDMACMDIR=	${_LIB_OBJTOP}/lib/ofed/librdmacm
LIBOSMCOMPDIR=	${_LIB_OBJTOP}/lib/ofed/complib
LIBOPENSMDIR=	${_LIB_OBJTOP}/lib/ofed/libopensm
LIBOSMVENDORDIR=${_LIB_OBJTOP}/lib/ofed/libvendor

LIBDIALOGDIR=	${_LIB_OBJTOP}/gnu/lib/libdialog
LIBGNUREGEXDIR=	${_LIB_OBJTOP}/gnu/lib/libregex
LIBSSPDIR=	${_LIB_OBJTOP}/lib/libssp
LIBSSP_NONSHAREDDIR=	${_LIB_OBJTOP}/lib/libssp_nonshared
LIBASN1DIR=	${_LIB_OBJTOP}/kerberos5/lib/libasn1
LIBGSSAPI_KRB5DIR=	${_LIB_OBJTOP}/kerberos5/lib/libgssapi_krb5
LIBGSSAPI_NTLMDIR=	${_LIB_OBJTOP}/kerberos5/lib/libgssapi_ntlm
LIBGSSAPI_SPNEGODIR=	${_LIB_OBJTOP}/kerberos5/lib/libgssapi_spnego
LIBHDBDIR=	${_LIB_OBJTOP}/kerberos5/lib/libhdb
LIBHEIMBASEDIR=	${_LIB_OBJTOP}/kerberos5/lib/libheimbase
LIBHEIMIPCCDIR=	${_LIB_OBJTOP}/kerberos5/lib/libheimipcc
LIBHEIMIPCSDIR=	${_LIB_OBJTOP}/kerberos5/lib/libheimipcs
LIBHEIMNTLMDIR=	${_LIB_OBJTOP}/kerberos5/lib/libheimntlm
LIBHX509DIR=	${_LIB_OBJTOP}/kerberos5/lib/libhx509
LIBKADM5CLNTDIR=	${_LIB_OBJTOP}/kerberos5/lib/libkadm5clnt
LIBKADM5SRVDIR=	${_LIB_OBJTOP}/kerberos5/lib/libkadm5srv
LIBKAFS5DIR=	${_LIB_OBJTOP}/kerberos5/lib/libkafs5
LIBKDCDIR=	${_LIB_OBJTOP}/kerberos5/lib/libkdc
LIBKRB5DIR=	${_LIB_OBJTOP}/kerberos5/lib/libkrb5
LIBROKENDIR=	${_LIB_OBJTOP}/kerberos5/lib/libroken
LIBWINDDIR=	${_LIB_OBJTOP}/kerberos5/lib/libwind
LIBATF_CDIR=	${_LIB_OBJTOP}/lib/atf/libatf-c
LIBATF_CXXDIR=	${_LIB_OBJTOP}/lib/atf/libatf-c++
LIBGMOCKDIR=	${_LIB_OBJTOP}/lib/googletest/gmock
LIBGMOCK_MAINDIR=	${_LIB_OBJTOP}/lib/googletest/gmock_main
LIBGTESTDIR=	${_LIB_OBJTOP}/lib/googletest/gtest
LIBGTEST_MAINDIR=	${_LIB_OBJTOP}/lib/googletest/gtest_main
LIBALIASDIR=	${_LIB_OBJTOP}/lib/libalias/libalias
LIBBLACKLISTDIR=	${_LIB_OBJTOP}/lib/libblacklist
LIBBLOCKSRUNTIMEDIR=	${_LIB_OBJTOP}/lib/libblocksruntime
LIBBSNMPDIR=	${_LIB_OBJTOP}/lib/libbsnmp/libbsnmp
LIBCASPERDIR=	${_LIB_OBJTOP}/lib/libcasper/libcasper
LIBCAP_DNSDIR=	${_LIB_OBJTOP}/lib/libcasper/services/cap_dns
LIBCAP_GRPDIR=	${_LIB_OBJTOP}/lib/libcasper/services/cap_grp
LIBCAP_PWDDIR=	${_LIB_OBJTOP}/lib/libcasper/services/cap_pwd
LIBCAP_SYSCTLDIR=	${_LIB_OBJTOP}/lib/libcasper/services/cap_sysctl
LIBCAP_SYSLOGDIR=	${_LIB_OBJTOP}/lib/libcasper/services/cap_syslog
LIBBSDXMLDIR=	${_LIB_OBJTOP}/lib/libexpat
LIBKVMDIR=	${_LIB_OBJTOP}/lib/libkvm
LIBPTHREADDIR=	${_LIB_OBJTOP}/lib/libthr
LIBMDIR=	${_LIB_OBJTOP}/lib/msun
LIBFORMDIR=	${_LIB_OBJTOP}/lib/ncurses/form
LIBFORMLIBWDIR=	${_LIB_OBJTOP}/lib/ncurses/formw
LIBMENUDIR=	${_LIB_OBJTOP}/lib/ncurses/menu
LIBMENULIBWDIR=	${_LIB_OBJTOP}/lib/ncurses/menuw
LIBNCURSESDIR=	${_LIB_OBJTOP}/lib/ncurses/ncurses
LIBNCURSESWDIR=	${_LIB_OBJTOP}/lib/ncurses/ncursesw
LIBPANELDIR=	${_LIB_OBJTOP}/lib/ncurses/panel
LIBPANELWDIR=	${_LIB_OBJTOP}/lib/ncurses/panelw
LIBCRYPTODIR=	${_LIB_OBJTOP}/secure/lib/libcrypto
LIBSPLDIR=	${_LIB_OBJTOP}/cddl/lib/libspl
LIBSSHDIR=	${_LIB_OBJTOP}/secure/lib/libssh
LIBSSLDIR=	${_LIB_OBJTOP}/secure/lib/libssl
LIBTEKENDIR=	${_LIB_OBJTOP}/sys/teken/libteken
LIBEGACYDIR=	${_LIB_OBJTOP}/tools/build
LIBLNDIR=	${_LIB_OBJTOP}/usr.bin/lex/lib

LIBTERMCAPDIR=	${LIBNCURSESDIR}
LIBTERMCAPWDIR=	${LIBNCURSESWDIR}

# Default other library directories to lib/libNAME.
.for lib in ${_LIBRARIES}
LIB${lib:tu}DIR?=	${_LIB_OBJTOP}/lib/lib${lib}
.endfor

# Validate that listed LIBADD are valid.
.for _l in ${LIBADD}
.if empty(_LIBRARIES:M${_l})
_BADLIBADD+= ${_l}
.endif
.endfor
.if !empty(_BADLIBADD)
.error ${.CURDIR}: Invalid LIBADD used which may need to be added to ${_this:T}: ${_BADLIBADD}
.endif

# Sanity check that libraries are defined here properly when building them.
.if defined(LIB) && ${_LIBRARIES:M${LIB}} != ""
.if !empty(LIBADD) && \
    (!defined(_DP_${LIB}) || ${LIBADD:O:u} != ${_DP_${LIB}:O:u})
.error ${.CURDIR}: Missing or incorrect _DP_${LIB} entry in ${_this:T}.  Should match LIBADD for ${LIB} ('${LIBADD}' vs '${_DP_${LIB}}')
.endif
# Note that OBJTOP is not yet defined here but for the purpose of the check
# it is fine as it resolves to the SRC directory.
.if !defined(LIB${LIB:tu}DIR) || !exists(${SRCTOP}/${LIB${LIB:tu}DIR:S,^${_LIB_OBJTOP}/,,})
.error ${.CURDIR}: Missing or incorrect value for LIB${LIB:tu}DIR in ${_this:T}: ${LIB${LIB:tu}DIR:S,^${_LIB_OBJTOP}/,,}
.endif
.if ${_INTERNALLIBS:M${LIB}} != "" && !defined(LIB${LIB:tu})
.error ${.CURDIR}: Missing value for LIB${LIB:tu} in ${_this:T}.  Likely should be: LIB${LIB:tu}?= $${LIB${LIB:tu}DIR}/lib${LIB}.a
.endif
.endif

.endif	# !target(__<src.libnames.mk>__)
