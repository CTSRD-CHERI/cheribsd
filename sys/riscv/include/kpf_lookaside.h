#ifndef _KPF_LOOKASIDE_H_
#define _KPF_LOOKASIDE_H_

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * Install a symbol into the kpf_lookaside linker set.  The section is
	 * marked "w" to silence linker warning about a reloc in a RO section.
	 */
#define KPF_LOOKASIDE_SET_MEMBER(sym)                      \
	.section set_kpf_lookaside_table, "aw", @progbits; \
	.chericap sym ;                                    \
	.previous
#else
#define KPF_LOOKASIDE_SET_MEMBER(sym)                      \
	.section set_kpf_lookaside_table, "a", @progbits;  \
	.quad sym ;                                        \
	.previous
#endif

#ifdef KPF_LOOKASIDE_TABLE
#define KPF_LOOKASIDE(target, selector)                                     \
	.rodata ;                                                           \
	__CONCAT(kpf_lookaside_, __LINE__) :                                \
	.quad target ;                                                      \
	.quad selector ;                                                    \
	.size __CONCAT(kpf_lookaside_, __LINE__),                           \
	    . - __CONCAT(kpf_lookaside_, __LINE__) ;                        \
	.previous ;                                                         \
	KPF_LOOKASIDE_SET_MEMBER(__CONCAT(kpf_lookaside_, __LINE__))
#else
#define KPF_LOOKASIDE(target, selector)
#endif

/* On fault, jump PC to fsu_fault_lookaside */
#define KPF_SEL_FSU		0

/* On fault, advance past offending instruction with register a0 holding -1 */
#define KPF_SEL_A0_NEG_ONE	1

#endif /* _KFP_LOOKASIDE_H_ */
