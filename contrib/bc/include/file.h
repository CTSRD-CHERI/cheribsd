/*
 * *****************************************************************************
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018-2021 Gavin D. Howard and contributors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * *****************************************************************************
 *
 * Definitions for implementing buffered I/O on my own terms.
 *
 */

#ifndef BC_FILE_H
#define BC_FILE_H

#include <stdarg.h>

#include <vector.h>

#define BC_FILE_ULL_LENGTH (21)

/// The file struct.
typedef struct BcFile {

	// The actual file descriptor.
	int fd;

	// The buffer for the file.
	char *buf;

	// The length (number of actual chars) in the buffer.
	size_t len;

	// The capacity (max number of chars) of the buffer.
	size_t cap;

} BcFile;

#if BC_ENABLE_HISTORY

/// Types of flushing. These are important because of history and printing
/// strings without newlines, something that users could use as their own
/// prompts.
typedef enum BcFlushType {

	/// Do not clear the stored partial line, but don't add to it.
	BC_FLUSH_NO_EXTRAS_NO_CLEAR,

	/// Do not clear the stored partial line and add to it.
	BC_FLUSH_SAVE_EXTRAS_NO_CLEAR,

	/// Clear the stored partial line and do not save the new stuff either.
	BC_FLUSH_NO_EXTRAS_CLEAR,

	/// Clear the stored partial line, but save the new stuff.
	BC_FLUSH_SAVE_EXTRAS_CLEAR,

} BcFlushType;

#else // BC_ENABLE_HISTORY

// These make sure that the BcFlushType parameter disappears if history is not
// used.

#define bc_file_putchar(f, t, c) bc_file_putchar(f, c)
#define bc_file_flushErr(f, t) bc_file_flushErr(f)
#define bc_file_flush(f, t) bc_file_flush(f)
#define bc_file_write(f, t, b, n) bc_file_write(f, b, n)
#define bc_file_puts(f, t, s) bc_file_puts(f, s)

#endif // BC_ENABLE_HISTORY

/**
 * Initialize a file.
 * @param f    The file to initialize.
 * @param fd   The file descriptor.
 * @param buf  The buffer for the file.
 * @param cap  The capacity of the buffer.
 */
void bc_file_init(BcFile *f, int fd, char *buf, size_t cap);

/**
 * Frees a file, including flushing it.
 * @param f  The file to free.
 */
void bc_file_free(BcFile *f);

/**
 * Print a char into the file.
 * @param f     The file to print to.
 * @param type  The flush type.
 * @param c     The character to write.
 */
void bc_file_putchar(BcFile *restrict f, BcFlushType type, uchar c);

/**
 * Flush and return an error if it failed. This is meant to be used when needing
 * to flush in error situations when an error is already in flight. It would be
 * a very bad deal to throw another error.
 * @param f     The file to flush.
 * @param type  The flush type.
 * @return      A status indicating if an error occurred.
 */
BcStatus bc_file_flushErr(BcFile *restrict f, BcFlushType type);

/**
 * Flush and throw an error on failure.
 * @param f     The file to flush.
 * @param type  The flush type.
 */
void bc_file_flush(BcFile *restrict f, BcFlushType type);

/**
 * Write the contents of buf to the file.
 * @param f     The file to flush.
 * @param type  The flush type.
 * @param buf   The buffer whose contents will be written to the file.
 * @param n     The length of buf.
 */
void bc_file_write(BcFile *restrict f, BcFlushType type,
                   const char *buf, size_t n);

/**
 * Write to the file like fprintf would. This is very rudimentary.
 * @param f    The file to flush.
 * @param fmt  The format string.
 */
void bc_file_printf(BcFile *restrict f, const char *fmt, ...);

/**
 * Write to the file like vfprintf would. This is very rudimentary.
 * @param f    The file to flush.
 * @param fmt  The format string.
 */
void bc_file_vprintf(BcFile *restrict f, const char *fmt, va_list args);

/**
 * Write str to the file.
 * @param f     The file to flush.
 * @param type  The flush type.
 * @param str   The string to write to the file.
 */
void bc_file_puts(BcFile *restrict f, BcFlushType type, const char *str);

#if BC_ENABLE_HISTORY

// Some constant flush types for ease of use.
extern const BcFlushType bc_flush_none;
extern const BcFlushType bc_flush_err;
extern const BcFlushType bc_flush_save;

#endif // BC_ENABLE_HISTORY

#endif // BC_FILE_H
