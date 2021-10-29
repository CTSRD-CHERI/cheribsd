/*
 * Copyright 2009-2016 Samy Al Bahra.
 * Copyright 2013-2016 Olivier Houchard.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef CK_PR_AARCH64_LLSC_H
#define CK_PR_AARCH64_LLSC_H

#ifndef CK_PR_H
#error Do not include this file directly, use ck_pr.h
#endif

#include <ck_md.h>

CK_CC_INLINE static bool
ck_pr_cas_64_2_value(uint64_t target[2], uint64_t compare[2], uint64_t set[2], uint64_t value[2])
{
        uint64_t tmp1, tmp2;

        __asm__ __volatile__("1:"
                             "ldxp %0, %1, [%4]\n"
                             "mov %2, %0\n"
                             "mov %3, %1\n"
                             "eor %0, %0, %5\n"
                             "eor %1, %1, %6\n"
                             "orr %1, %0, %1\n"
                             "mov %w0, #0\n"
                             "cbnz %1, 2f\n"
                             "stxp %w0, %7, %8, [%4]\n"
                             "cbnz %w0, 1b\n"
                             "mov %w0, #1\n"
                             "2:"
                             : "=&r" (tmp1), "=&r" (tmp2), "=&r" (value[0]), "=&r" (value[1])
                             : CK_MD_ATOMIC_PTR_CONSTR (target),
                              "r" (compare[0]), "r" (compare[1]), "r" (set[0]), "r" (set[1])
                             : "cc", "memory");

        return (tmp1);
}

#ifdef __CHERI_PURE_CAPABILITY__
CK_CC_INLINE static bool
ck_pr_cas_ptr_2_value(void *target, void *compare, void *set, void *value)
{
        uintptr_t *cmpp = compare;
        uintptr_t *setp = set;
        uintptr_t *valuep = value;
        void *tmp1, *tmp2;
        int ret;

        __asm__ __volatile__("1:"
                             "ldxp %1, %2, [%5];"
                             "mov %3, %1;"
                             "mov %4, %2;"
                             "mov %w0, #0;"
                             "cmp %1, %6;"
                             "b.ne 2f;"
                             "cmp %2, %7;"
                             "b.ne 2f;"
                             "stxp %w0, %8, %9, [%5];"
                             "cbnz %w0, 1b;"
                             "mov %w0, #1;"
                             "2:"
                             : "=&r" (ret), "=&C" (tmp1), "=&C" (tmp2),
                               "=&C" (valuep[0]), "=&C" (valuep[1])
                             : "C" (target), "C" (cmpp[0]), "C" (cmpp[1]),
                               "C" (setp[0]), "C" (setp[1])
                             : "cc", "memory");

        return (ret);
}
#else
CK_CC_INLINE static bool
ck_pr_cas_ptr_2_value(void *target, void *compare, void *set, void *value)
{
        return (ck_pr_cas_64_2_value(CK_CPP_CAST(uint64_t *, target),
                                   CK_CPP_CAST(uint64_t *, compare),
                                   CK_CPP_CAST(uint64_t *, set),
                                   CK_CPP_CAST(uint64_t *, value)));
}
#endif

CK_CC_INLINE static bool
ck_pr_cas_64_2(uint64_t target[2], uint64_t compare[2], uint64_t set[2])
{
        uint64_t tmp1, tmp2;

        __asm__ __volatile__("1:"
                             "ldxp %0, %1, [%2]\n"
                             "eor %0, %0, %3\n"
                             "eor %1, %1, %4\n"
                             "orr %1, %0, %1\n"
                             "mov %w0, #0\n"
                             "cbnz %1, 2f\n"
                             "stxp %w0, %5, %6, [%2]\n"
                             "cbnz %w0, 1b\n"
                             "mov %w0, #1\n"
                             "2:"
                             : "=&r" (tmp1), "=&r" (tmp2)
                             : CK_MD_ATOMIC_PTR_CONSTR (target), "r" (compare[0]),
                               "r" (compare[1]), "r" (set[0]), "r" (set[1])
                             : "cc", "memory");

        return (tmp1);
}

#ifdef __CHERI_PURE_CAPABILITY__
CK_CC_INLINE static bool
ck_pr_cas_ptr_2(void *target, void *compare, void *set)
{
        uintptr_t *cmpp = compare;
        uintptr_t *setp = set;
        void *tmp1, *tmp2;
        int ret;

        __asm__ __volatile__("1:"
                             "ldxp %1, %2, [%3];"
                             "mov %w0, #0;"
                             "cmp %1, %4;"
                             "b.ne 2f;"
                             "cmp %2, %5;"
                             "b.ne 2f;"
                             "stxp %w0, %6, %7, [%3];"
                             "cbnz %w0, 1b;"
                             "mov %w0, #1;"
                             "2:"
                             : "=&r" (ret), "=&C" (tmp1), "=&C" (tmp2)
                             : "C" (target), "C" (cmpp[0]), "C" (cmpp[1]),
                               "C" (setp[0]), "C" (setp[1])
                             : "cc", "memory");

        return (ret);
}
#else
CK_CC_INLINE static bool
ck_pr_cas_ptr_2(void *target, void *compare, void *set)
{
        return (ck_pr_cas_64_2(CK_CPP_CAST(uint64_t *, target),
                             CK_CPP_CAST(uint64_t *, compare),
                             CK_CPP_CAST(uint64_t *, set)));
}
#endif


#define CK_PR_CAS(N, M, T, W, R, C)					\
        CK_CC_INLINE static bool					\
        ck_pr_cas_##N##_value(M *target, T compare, T set, M *value)	\
        {								\
                T previous;						\
                int tmp;						\
                __asm__ __volatile__("1:\n"				\
                                     "ldxr" W " %" R "0, [%2]\n"	\
                                     "cmp  %" R "0, %" R "4\n"		\
                                     "b.ne 2f\n"			\
                                     "stxr" W " %w1, %" R "3, [%2]\n"	\
                                     "cbnz %w1, 1b\n"			\
                                     "2:"				\
                    : "=&"C (previous),					\
                      "=&r" (tmp)					\
                    : CK_MD_ATOMIC_PTR_CONSTR (target),			\
                      C (set),						\
                      C (compare)					\
                    : "memory", "cc");					\
                *(T *)value = previous;					\
                return (previous == compare);				\
        }								\
        CK_CC_INLINE static bool					\
        ck_pr_cas_##N(M *target, T compare, T set)			\
        {								\
                T previous;						\
                int tmp;						\
                __asm__ __volatile__(					\
                                     "1:"				\
                                     "ldxr" W " %" R "0, [%2]\n"	\
                                     "cmp  %" R "0, %" R "4\n"		\
                                     "b.ne 2f\n"			\
                                     "stxr" W " %w1, %" R "3, [%2]\n"	\
                                     "cbnz %w1, 1b\n"			\
                                     "2:"				\
                    : "=&"C (previous),					\
                      "=&r" (tmp)					\
                    : CK_MD_ATOMIC_PTR_CONSTR (target),			\
                      C (set),						\
                      C (compare)					\
                    : "memory", "cc");					\
                return (previous == compare);				\
        }

CK_PR_CAS(ptr, void, void *, "", "", CK_MD_ATOMIC_PTR_CONSTR)

#define CK_PR_CAS_S(N, M, W, R)	CK_PR_CAS(N, M, M, W, R, "r")
CK_PR_CAS_S(64, uint64_t, "", "")
#ifndef CK_PR_DISABLE_DOUBLE
CK_PR_CAS_S(double, double, "", "")
#endif
CK_PR_CAS_S(32, uint32_t, "", "w")
CK_PR_CAS_S(uint, unsigned int, "", "w")
CK_PR_CAS_S(int, int, "", "w")
CK_PR_CAS_S(16, uint16_t, "h", "w")
CK_PR_CAS_S(8, uint8_t, "b", "w")
CK_PR_CAS_S(short, short, "h", "w")
CK_PR_CAS_S(char, char, "b", "w")


#undef CK_PR_CAS_S
#undef CK_PR_CAS

#define CK_PR_FAS(N, M, T, W, R, C)				\
        CK_CC_INLINE static T					\
        ck_pr_fas_##N(M *target, T v)				\
        {							\
                T previous;					\
                int tmp;					\
                __asm__ __volatile__("1:"			\
                                     "ldxr" W " %" R "0, [%2]\n"\
                                     "stxr" W " %w1, %" R "3, [%2]\n"\
                                     "cbnz %w1, 1b\n"		\
                                        : "=&"C (previous),	\
                                          "=&r" (tmp)		\
                                        : CK_MD_ATOMIC_PTR_CONSTR (target),	\
                                          C     (v)		\
                                        : "memory", "cc");	\
                return (previous);				\
        }

#define CK_PR_FAS_REG(N, M, T, W, R) CK_PR_FAS(N, M, T, W, R, "r")

CK_PR_FAS_REG(64, uint64_t, uint64_t, "", "")
CK_PR_FAS_REG(32, uint32_t, uint32_t, "", "w")
CK_PR_FAS(ptr, void, void *, "", "", CK_MD_ATOMIC_PTR_CONSTR)
CK_PR_FAS_REG(int, int, int, "", "w")
CK_PR_FAS_REG(uint, unsigned int, unsigned int, "", "w")
CK_PR_FAS_REG(16, uint16_t, uint16_t, "h", "w")
CK_PR_FAS_REG(8, uint8_t, uint8_t, "b", "w")
CK_PR_FAS_REG(short, short, short, "h", "w")
CK_PR_FAS_REG(char, char, char, "b", "w")

#undef CK_PR_FAS_REG
#undef CK_PR_FAS

#define CK_PR_UNARY(O, N, M, T, I, W, R, C)			\
        CK_CC_INLINE static void				\
        ck_pr_##O##_##N(M *target)				\
        {							\
                T previous = 0;					\
                int tmp = 0;					\
                __asm__ __volatile__("1:"			\
                                     "ldxr" W " %" R "0, [%2]\n"\
                                      I "\n"			\
                                     "stxr" W " %w1, %" R "0, [%2]\n"	\
                                     "cbnz %w1, 1b\n"		\
                                        : "=&"C (previous),	\
                                          "=&r" (tmp)		\
                                        : CK_MD_ATOMIC_PTR_CONSTR (target)	\
                                        : "memory", "cc");	\
                return;						\
        }

CK_PR_UNARY(inc, ptr, void, void *, "add %0, %0, #1", "", "",
        CK_MD_ATOMIC_PTR_CONSTR)
CK_PR_UNARY(dec, ptr, void, void *, "sub %0, %0, #1", "", "",
        CK_MD_ATOMIC_PTR_CONSTR)
#ifdef __CHERI_PURE_CAPABILITY__
/*
 * Bitwise NOT on a pointer value is weird. This should arguably not
 * exist. In CHERI we create a NULL-derived capability with the
 * cursor set to the bitwise NOT of the address value.
 */
CK_CC_INLINE static void
ck_pr_not_ptr(void *target)
{
        void *previous = NULL;
        ptraddr_t tmp2;
        int tmp1 = 0;

        __asm__ __volatile__("1:"
                             "ldxr %0, [%3];"
                             "gcvalue %2, %0;"
                             "mov %0, czr;"
                             "mvn %2, %2;"
                             "scvalue %0, %2;"
                             "stxr %w1, %0, [%3];"
                             "cbnz %w1, 1b;"
                             : "=&C" (previous),
                               "=&r" (tmp1),
                               "=&r" (tmp2)
                             : "C" (target)
                             : "memory", "cc");
        return;
}
#else
CK_PR_UNARY(not, ptr, void, void *, "mvn %0, %0", "", "", "r")
#endif
CK_PR_UNARY(inc, 64, uint64_t, uint64_t, "add %0, %0, #1", "", "", "r")
CK_PR_UNARY(dec, 64, uint64_t, uint64_t, "sub %0, %0, #1", "", "", "r")
CK_PR_UNARY(not, 64, uint64_t, uint64_t, "mvn %0, %0", "", "", "r")

#define CK_PR_UNARY_S(S, T, W)					\
        CK_PR_UNARY(inc, S, T, T, "add %w0, %w0, #1", W, "w", "r")	\
        CK_PR_UNARY(dec, S, T, T, "sub %w0, %w0, #1", W, "w", "r")	\
        CK_PR_UNARY(not, S, T, T, "mvn %w0, %w0", W, "w", "r")	\

CK_PR_UNARY_S(32, uint32_t, "")
CK_PR_UNARY_S(uint, unsigned int, "")
CK_PR_UNARY_S(int, int, "")
CK_PR_UNARY_S(16, uint16_t, "h")
CK_PR_UNARY_S(8, uint8_t, "b")
CK_PR_UNARY_S(short, short, "h")
CK_PR_UNARY_S(char, char, "b")

#undef CK_PR_UNARY_S
#undef CK_PR_UNARY

#define CK_PR_BINARY(O, N, M, T, I, W, R)			\
        CK_CC_INLINE static void				\
        ck_pr_##O##_##N(M *target, T delta)			\
        {							\
                T previous;					\
                int tmp;					\
                __asm__ __volatile__("1:"			\
                                     "ldxr" W " %" R "0, [%2]\n"\
                                      I " %" R "0, %" R "0, %" R "3\n"	\
                                     "stxr" W " %w1, %" R "0, [%2]\n"	\
                                     "cbnz %w1, 1b\n"		\
                                        : "=&r" (previous),	\
                                          "=&r" (tmp)		\
                                        : CK_MD_ATOMIC_PTR_CONSTR (target),	\
                                          "r" (delta)		\
                                        : "memory", "cc");	\
                return;						\
        }

#ifdef __CHERI_PURE_CAPABILITY__
#define CK_PR_BINARY_PTR(O, M, T, I, W, R)			\
        CK_CC_INLINE static void				\
        ck_pr_##O##_ptr(void *target, uintptr_t delta)		\
        {							\
                uintptr_t previous;				\
                ptraddr_t tmp1, tmp2;				\
                int res;					\
                __asm__ __volatile__("1:"			\
                                     "ldxr %0, [%4];"		\
                                     "gcvalue %2, %0;"		\
                                     "gcvalue %3, %5;"		\
                                     I " %2, %2, %3;"		\
                                     "scvalue %0, %2;"		\
                                     "stxr %w1, %0, [%4];"	\
                                     "cbnz %w1, 1b;"		\
                                        : "=&C" (previous),	\
                                          "=&r" (res),		\
                                          "=&r" (tmp1),		\
                                          "=&r" (tmp2)		\
                                        : "C" (target),		\
                                          "C" (delta)		\
                                        : "memory", "cc");	\
                return;						\
}
#else
#define CK_PR_BINARY_PTR(O, M, T, I, W, R)			\
        CK_PR_BINARY(O, ptr, M, T, I, W, R)
#endif

CK_PR_BINARY_PTR(and, void, uintptr_t, "and", "", "")
CK_PR_BINARY_PTR(add, void, uintptr_t, "add", "", "")
CK_PR_BINARY_PTR(or, void, uintptr_t, "orr", "", "")
CK_PR_BINARY_PTR(sub, void, uintptr_t, "sub", "", "")
CK_PR_BINARY_PTR(xor, void, uintptr_t, "eor", "", "")

CK_PR_BINARY(and, 64, uint64_t, uint64_t, "and", "", "")
CK_PR_BINARY(add, 64, uint64_t, uint64_t, "add", "", "")
CK_PR_BINARY(or, 64, uint64_t, uint64_t, "orr", "", "")
CK_PR_BINARY(sub, 64, uint64_t, uint64_t, "sub", "", "")
CK_PR_BINARY(xor, 64, uint64_t, uint64_t, "eor", "", "")

#define CK_PR_BINARY_S(S, T, W)				\
        CK_PR_BINARY(and, S, T, T, "and", W, "w")	\
        CK_PR_BINARY(add, S, T, T, "add", W, "w")	\
        CK_PR_BINARY(or, S, T, T, "orr", W, "w")	\
        CK_PR_BINARY(sub, S, T, T, "sub", W, "w")	\
        CK_PR_BINARY(xor, S, T, T, "eor", W, "w")

CK_PR_BINARY_S(32, uint32_t, "")
CK_PR_BINARY_S(uint, unsigned int, "")
CK_PR_BINARY_S(int, int, "")
CK_PR_BINARY_S(16, uint16_t, "h")
CK_PR_BINARY_S(8, uint8_t, "b")
CK_PR_BINARY_S(short, short, "h")
CK_PR_BINARY_S(char, char, "b")

#undef CK_PR_BINARY_PTR
#undef CK_PR_BINARY_S
#undef CK_PR_BINARY

CK_CC_INLINE static void *
ck_pr_faa_ptr(void *target, uintptr_t delta)
{
        uintptr_t previous, r;
        int tmp;

        __asm__ __volatile__("1:"
                             "ldxr %0, [%3]\n"
                             "add %1, %4, %0\n"
                             "stxr %w2, %1, [%3]\n"
                             "cbnz %w2, 1b\n"
                                : "=&" CK_MD_ATOMIC_PTR_CONSTR (previous),
                                  "=&" CK_MD_ATOMIC_PTR_CONSTR (r),
                                  "=&r" (tmp)
                                : CK_MD_ATOMIC_PTR_CONSTR (target),
                                  CK_MD_ATOMIC_PTR_CONSTR (delta)
                                : "memory", "cc");

        return (void *)(previous);
}

CK_CC_INLINE static uint64_t
ck_pr_faa_64(uint64_t *target, uint64_t delta)
{
        uint64_t previous, r, tmp;

        __asm__ __volatile__("1:"
                             "ldxr %0, [%3]\n"
                             "add %1, %4, %0\n"
                             "stxr %w2, %1, [%3]\n"
                             "cbnz %w2, 1b;"
                                : "=&r" (previous),
                                  "=&r" (r),
                                  "=&r" (tmp)
                                : CK_MD_ATOMIC_PTR_CONSTR (target),
                                  "r"   (delta)
                                : "memory", "cc");

        return (previous);
}

#define CK_PR_FAA(S, T, W)						\
        CK_CC_INLINE static T						\
        ck_pr_faa_##S(T *target, T delta)				\
        {								\
                T previous, r, tmp;					\
                __asm__ __volatile__("1:"				\
                                     "ldxr" W " %w0, [%3]\n"		\
                                     "add %w1, %w4, %w0\n"		\
                                     "stxr" W " %w2, %w1, [%3]\n"	\
                                     "cbnz %w2, 1b\n"			\
                                        : "=&r" (previous),		\
                                          "=&r" (r),			\
                                          "=&r" (tmp)			\
                                        : CK_MD_ATOMIC_PTR_CONSTR (target),	\
                                          "r"   (delta)			\
                                        : "memory", "cc");		\
                return (previous);					\
        }

CK_PR_FAA(32, uint32_t, "")
CK_PR_FAA(uint, unsigned int, "")
CK_PR_FAA(int, int, "")
CK_PR_FAA(16, uint16_t, "h")
CK_PR_FAA(8, uint8_t, "b")
CK_PR_FAA(short, short, "h")
CK_PR_FAA(char, char, "b")

#undef CK_PR_FAA

#endif /* CK_PR_AARCH64_LLSC_H */
