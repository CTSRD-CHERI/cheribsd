/*-
 * Copyright (c) 2012 David T. Chisnall
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

#if !defined(NAME) || !defined(TYPE)
#error Define NAME and TYPE before including this file
#endif

#define REALLY_PREFIX_SUFFIX(x,y) x ## y
#define PREFIX_SUFFIX(x, y) REALLY_PREFIX_SUFFIX(x, y)
#define PREFIX(x) PREFIX_SUFFIX(NAME, x)

static TYPE PREFIX(_data)[] = {1, 2, 3, 4, 5, 6, 7, 8};

int PREFIX(_test)(void);
int PREFIX(_test)(void)
{
  TYPE * dataptr = PREFIX(_data); // __cheri_cast doesn't allow array-to-pointer
  TYPE * __capability datacp = (__cheri_tocap TYPE* __capability)dataptr;

  for (size_t i=0; i<(sizeof(PREFIX(_data))/sizeof(*PREFIX(_data))); i++)
  {
#if NOP_HACK
    TYPE a = datacp[i];
    TYPE b = PREFIX(_data)[i];
    DEBUG_NOP();
    DEBUG_NOP();
    assert(a == b);
#else
    assert(datacp[i] == PREFIX(_data)[i]);
#endif
  }

  return 0;
}
#undef NAME
#undef TYPE
