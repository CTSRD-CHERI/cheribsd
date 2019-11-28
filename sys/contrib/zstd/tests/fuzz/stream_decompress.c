/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 */

/**
 * This fuzz target attempts to decompress the fuzzed data with the simple
 * decompression function to ensure the decompressor never crashes.
 */

#define ZSTD_STATIC_LINKING_ONLY

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "fuzz_helpers.h"
#include "zstd.h"
#include "fuzz_data_producer.h"

static size_t const kBufSize = ZSTD_BLOCKSIZE_MAX;

static ZSTD_DStream *dstream = NULL;
static void* buf = NULL;
uint32_t seed;

static ZSTD_outBuffer makeOutBuffer(FUZZ_dataProducer_t *producer)
{
  ZSTD_outBuffer buffer = { buf, 0, 0 };

  buffer.size = (FUZZ_dataProducer_uint32Range(producer, 1, kBufSize));
  FUZZ_ASSERT(buffer.size <= kBufSize);

  return buffer;
}

static ZSTD_inBuffer makeInBuffer(const uint8_t **src, size_t *size,
                                  FUZZ_dataProducer_t *producer)
{
  ZSTD_inBuffer buffer = { *src, 0, 0 };

  FUZZ_ASSERT(*size > 0);
  buffer.size = (FUZZ_dataProducer_uint32Range(producer, 1, *size));
  FUZZ_ASSERT(buffer.size <= *size);
  *src += buffer.size;
  *size -= buffer.size;

  return buffer;
}

int LLVMFuzzerTestOneInput(const uint8_t *src, size_t size)
{
    /* Give a random portion of src data to the producer, to use for
    parameter generation. The rest will be used for (de)compression */
    FUZZ_dataProducer_t *producer = FUZZ_dataProducer_create(src, size);
    size = FUZZ_dataProducer_reserveDataPrefix(producer);

    /* Allocate all buffers and contexts if not already allocated */
    if (!buf) {
      buf = malloc(kBufSize);
        FUZZ_ASSERT(buf);
      }

    if (!dstream) {
        dstream = ZSTD_createDStream();
        FUZZ_ASSERT(dstream);
    } else {
        FUZZ_ZASSERT(ZSTD_DCtx_reset(dstream, ZSTD_reset_session_only));
    }

    while (size > 0) {
        ZSTD_inBuffer in = makeInBuffer(&src, &size, producer);
        while (in.pos != in.size) {
            ZSTD_outBuffer out = makeOutBuffer(producer);
            size_t const rc = ZSTD_decompressStream(dstream, &out, &in);
            if (ZSTD_isError(rc)) goto error;
        }
    }

error:
#ifndef STATEFUL_FUZZING
    ZSTD_freeDStream(dstream); dstream = NULL;
#endif
    FUZZ_dataProducer_free(producer);
    return 0;
}
