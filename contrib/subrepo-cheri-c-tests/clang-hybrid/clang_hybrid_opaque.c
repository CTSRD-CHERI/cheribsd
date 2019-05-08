/*-
 * Copyright (c) 2013 Michael Roe
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#include <assert.h>
#include <machine/sysarch.h>

#include "cheri_c_test.h"

/*
 * Align the structure to avoid representability exceptions
 * when sealing 128-bit capabilities
 */
#define SEALED_BOUND_ALIGN (1 << 12)
#define __seal_align __attribute__((aligned(SEALED_BOUND_ALIGN)))

#ifndef _SIZE_T_DECLARED
typedef __SIZE_TYPE__ size_t;
#endif

struct example {
  int x;
} __seal_align;

typedef struct example * __capability example_t;

static void * __capability example_key;

/* If we used the following declaration, the compiler would automatically
 * insert calls to csealdata and cunseal. Instead, we explicitly seal and
 * unseal using compiler built-ins.
 *
 * #pragma opaque example_t example_key
 */

static struct example example_object = {0};

void example_init(void)
{
/*
 * example_key will be used to seal and unseal variables of type example_t.
 * Set its base+offset to the otype we want to use. Note that otypes must
 * be in the range 0 to 2^24-1.
 */
  void * __capability sealing_cap;
  assert(sysarch(CHERI_GET_SEALCAP, &sealing_cap) == 0);
  example_key = __builtin_cheri_offset_set(sealing_cap, 4);
}

static __attribute__((noinline)) example_t example_constructor(void)
{
  struct example *ptr;
  example_t result;

  ptr = &example_object;

  result = (example_t) __builtin_cheri_perms_and((__cheri_tocap struct example * __capability) ptr, 0xd);

  result = __builtin_cheri_seal(result, example_key);

  return result;
}

int example_method(example_t o)
{
example_t p;

  p = __builtin_cheri_unseal(o, example_key);
  p->x++;
  return p->x;
}

BEGIN_TEST(clang_hybrid_opaque)
example_t e;
int r;

  example_init();
  e = example_constructor();
  r = example_method(e);
  assert(r == 1);

  assert(faults == 0);
END_TEST
