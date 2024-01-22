/*
 * Single-precision vector sin function.
 *
 * Copyright (c) 2019-2022, Arm Limited.
 * SPDX-License-Identifier: MIT OR Apache-2.0 WITH LLVM-exception
 */

#include "mathlib.h"
#include "v_math.h"
#if V_SUPPORTED

static const float Poly[] = {
  /* 1.886 ulp error */
  0x1.5b2e76p-19f,
  -0x1.9f42eap-13f,
  0x1.110df4p-7f,
  -0x1.555548p-3f,
};
#define Pi1 v_f32 (0x1.921fb6p+1f)
#define Pi2 v_f32 (-0x1.777a5cp-24f)
#define Pi3 v_f32 (-0x1.ee59dap-49f)
#define A3 v_f32 (Poly[3])
#define A5 v_f32 (Poly[2])
#define A7 v_f32 (Poly[1])
#define A9 v_f32 (Poly[0])
#define RangeVal v_f32 (0x1p20f)
#define TinyBound v_f32 (0x1p-61f)
#define InvPi v_f32 (0x1.45f306p-2f)
#define Shift v_f32 (0x1.8p+23f)
#define AbsMask v_u32 (0x7fffffff)

VPCS_ATTR
static v_f32_t
specialcase (v_f32_t x, v_f32_t y, v_u32_t cmp)
{
  /* Fall back to scalar code.  */
  return v_call_f32 (sinf, x, y, cmp);
}

VPCS_ATTR
v_f32_t
V_NAME(sinf) (v_f32_t x)
{
  v_f32_t n, r, r2, y;
  v_u32_t sign, odd, cmp, ir;

  ir = v_as_u32_f32 (x) & AbsMask;
  r = v_as_f32_u32 (ir);
  sign = v_as_u32_f32 (x) & ~AbsMask;

#if WANT_SIMD_EXCEPT
  cmp = v_cond_u32 ((ir - v_as_u32_f32 (TinyBound)
		     >= v_as_u32_f32 (RangeVal) - v_as_u32_f32 (TinyBound)));
  if (unlikely (v_any_u32 (cmp)))
    /* If fenv exceptions are to be triggered correctly, set any special lanes
       to 1 (which is neutral w.r.t. fenv). These lanes will be fixed by
       specialcase later.  */
    r = v_sel_f32 (cmp, v_f32 (1), r);
#else
  cmp = v_cond_u32 (ir >= v_as_u32_f32 (RangeVal));
#endif

  /* n = rint(|x|/pi) */
  n = v_fma_f32 (InvPi, r, Shift);
  odd = v_as_u32_f32 (n) << 31;
  n -= Shift;

  /* r = |x| - n*pi  (range reduction into -pi/2 .. pi/2) */
  r = v_fma_f32 (-Pi1, n, r);
  r = v_fma_f32 (-Pi2, n, r);
  r = v_fma_f32 (-Pi3, n, r);

  /* y = sin(r) */
  r2 = r * r;
  y = v_fma_f32 (A9, r2, A7);
  y = v_fma_f32 (y, r2, A5);
  y = v_fma_f32 (y, r2, A3);
  y = v_fma_f32 (y * r2, r, r);

  /* sign fix */
  y = v_as_f32_u32 (v_as_u32_f32 (y) ^ sign ^ odd);

  if (unlikely (v_any_u32 (cmp)))
    return specialcase (x, y, cmp);
  return y;
}
VPCS_ALIAS
#endif
