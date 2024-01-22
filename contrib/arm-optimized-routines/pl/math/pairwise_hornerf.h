/*
 * Helper macros for single-precision pairwise Horner polynomial evaluation.
 *
 * Copyright (c) 2022-2023, Arm Limited.
 * SPDX-License-Identifier: MIT OR Apache-2.0 WITH LLVM-exception
 */

#if V_SUPPORTED
#define FMA v_fma_f32
#else
#define FMA fmaf
#endif

#include "pairwise_horner_wrap.h"
