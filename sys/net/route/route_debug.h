/*-
 * Copyright (c) 2021
 * 	Alexander V. Chernikov <melifaro@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _NET_ROUTE_DEBUG_H_
#define _NET_ROUTE_DEBUG_H_

#include <sys/sysctl.h>
#include <sys/syslog.h>


/* DEBUG logic */
#if defined(DEBUG_MOD_NAME) && defined(DEBUG_MAX_LEVEL)

#define DEBUG_VAR_NAME                  	_DEBUG_VAR_NAME(DEBUG_MOD_NAME)
#define _DEBUG_VAR_NAME(a)			_DEBUG_VAR_NAME_INDIRECT(a)
#define _DEBUG_VAR_NAME_INDIRECT(prefix)	prefix##_debug_level

#define DEBUG_PREFIX_NAME			_DEBUG_PREFIX_NAME(DEBUG_MOD_NAME)
#define _DEBUG_PREFIX_NAME(n)			__DEBUG_PREFIX_NAME(n)
#define __DEBUG_PREFIX_NAME(n)			#n

#define	_DECLARE_DEBUG(_default_level)  	        		\
	SYSCTL_DECL(_net_route_debug);					\
	static int DEBUG_VAR_NAME = _default_level;	                \
        SYSCTL_INT(_net_route_debug, OID_AUTO, DEBUG_VAR_NAME,          \
		CTLFLAG_RW | CTLFLAG_RWTUN,				\
                &(DEBUG_VAR_NAME), 0, "debuglevel")

/* Additional tracing levels not defined by log.h */
#ifndef	LOG_DEBUG2
#define	LOG_DEBUG2	8
#endif
#ifndef LOG_DEBUG3
#define LOG_DEBUG3      9
#endif

#define _output			printf
#define	_DEBUG_PASS_MSG(_l)	(DEBUG_VAR_NAME >= (_l))

/*
 * Logging for events specific for particular family and fib
 * Example: [nhop_neigh] inet.0 find_lle: nhop nh#4/inet/vtnet0/10.0.0.1: mapped to lle NULL
 */
#define	FIB_LOG(_l, _fib, _fam, _fmt, ...)	FIB_LOG_##_l(_l, _fib, _fam, _fmt, ## __VA_ARGS__)
#define	_FIB_LOG(_l, _fib, _fam, _fmt, ...)	if (_DEBUG_PASS_MSG(_l)) {	\
	_output("[" DEBUG_PREFIX_NAME "] %s.%u %s: " _fmt "\n", rib_print_family(_fam), _fib, __func__, ##__VA_ARGS__);	\
}

/* Same as FIB_LOG, but uses nhop to get fib and family */
#define FIB_NH_LOG(_l, _nh, _fmt, ...)  FIB_LOG_##_l(_l, nhop_get_fibnum(_nh), nhop_get_upper_family(_nh), _fmt, ## __VA_ARGS__)

/*
 * Generic logging for routing subsystem
 * Example: [nhop_neigh] nhops_update_neigh: L2 prepend update from lle/inet/valid/vtnet0/10.0.0.157
 */
#define	RT_LOG(_l, _fmt, ...)	RT_LOG_##_l(_l, _fmt, ## __VA_ARGS__)
#define	_RT_LOG(_l, _fmt, ...)	if (_DEBUG_PASS_MSG(_l)) {	\
	_output("[" DEBUG_PREFIX_NAME "] %s: " _fmt "\n",  __func__, ##__VA_ARGS__);	\
}


/*
 * Wrapper logic to avoid compiling high levels of debugging messages for production systems.
 */
#if DEBUG_MAX_LEVEL>=LOG_DEBUG2
#define	FIB_LOG_LOG_DEBUG3	_FIB_LOG
#define	RT_LOG_LOG_DEBUG3	_RT_LOG
#else
#define	FIB_LOG_LOG_DEBUG3(_l, _fib, _fam, _fmt, ...)
#define	RT_LOG_LOG_DEBUG3(_l, _fmt, ...)
#endif
#if DEBUG_MAX_LEVEL>=LOG_DEBUG2
#define	FIB_LOG_LOG_DEBUG2	_FIB_LOG
#define	RT_LOG_LOG_DEBUG2	_RT_LOG
#else
#define	FIB_LOG_LOG_DEBUG2(_l, _fib, _fam, _fmt, ...)
#define	RT_LOG_LOG_DEBUG2(_l, _fmt, ...)
#endif
#if DEBUG_MAX_LEVEL>=LOG_DEBUG
#define	FIB_LOG_LOG_DEBUG	_FIB_LOG
#define	RT_LOG_LOG_DEBUG	_RT_LOG
#else
#define	FIB_LOG_LOG_DEBUG(_l, _fib, _fam, _fmt, ...)
#define	RT_LOG_LOG_DEBUG(_l, _fmt, ...)
#endif
#if DEBUG_MAX_LEVEL>=LOG_INFO
#define	FIB_LOG_LOG_INFO	_FIB_LOG
#define	RT_LOG_LOG_INFO	_RT_LOG
#else
#define	FIB_LOG_LOG_INFO(_l, _fib, _fam, _fmt, ...)
#define	RT_LOG_LOG_INFO(_l, _fmt, ...)
#endif
#define	FIB_LOG_LOG_NOTICE	_FIB_LOG
#define	FIB_LOG_LOG_ERR         _FIB_LOG
#define	FIB_LOG_LOG_WARNING	_FIB_LOG
#define	RT_LOG_LOG_NOTICE	_RT_LOG
#define	RT_LOG_LOG_ERR          _RT_LOG
#define	RT_LOG_LOG_WARNING	_RT_LOG

#endif

/* Helpers for fancy-printing various objects */
struct nhop_object;
struct llentry;
struct nhop_neigh;

char *nhop_print_buf(const struct nhop_object *nh, char *buf, size_t bufsize);
char *llentry_print_buf(const struct llentry *lle, struct ifnet *ifp, int family, char *buf,
    size_t bufsize);
char *llentry_print_buf_lltable(const struct llentry *lle, char *buf, size_t bufsize);
char *neigh_print_buf(const struct nhop_neigh *nn, char *buf, size_t bufsize);

#endif
