#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>

struct pidfh;

__BEGIN_DECLS
int humanize_number(char *buf, size_t len, int64_t bytes,
    const char *suffix, int scale, int flags);
int expand_number(const char *_buf, uint64_t *_num);

int flopen(const char *_path, int _flags, ...);
int flopenat(int dirfd, const char *path, int flags, ...);

char   *fparseln(FILE *, size_t *, size_t *, const char[3], int);
__END_DECLS

/* Values for humanize_number(3)'s flags parameter. */
#define HN_DECIMAL		0x01
#define HN_NOSPACE		0x02
#define HN_B			0x04
#define HN_DIVISOR_1000		0x08
#define HN_IEC_PREFIXES		0x10

/* Values for humanize_number(3)'s scale parameter. */
#define HN_GETSCALE		0x10
#define HN_AUTOSCALE		0x20

/*
 * fparseln() specific operation flags.
 */
#define FPARSELN_UNESCESC	0x01
#define FPARSELN_UNESCCONT	0x02
#define FPARSELN_UNESCCOMM	0x04
#define FPARSELN_UNESCREST	0x08
#define FPARSELN_UNESCALL	0x0f
