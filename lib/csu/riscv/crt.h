/* $FreeBSD$ */

#ifndef _CRT_H_
#define _CRT_H_

#ifdef __CHERI_PURE_CAPABILITY__
#undef HAVE_CTORS	/* Only .init_array for purecap */
// #define INIT_CALL_SEQ(func)	"cllc cra, " __STRING(func) "; cjalr cra, cra"
#else
#define	HAVE_CTORS
#define	INIT_CALL_SEQ(func)	"call " __STRING(func)
#endif

#endif
