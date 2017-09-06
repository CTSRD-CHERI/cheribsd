#ifndef _DTRACE_TYPES_H_
#define _DTRACE_TYPES_H_

#ifndef _LP64
#if BYTE_ORDER == _BIG_ENDIAN
#define	DTRACE_PTR(type, name)	uint32_t name##pad; type *name
#else
#define	DTRACE_PTR(type, name)	type *name; uint32_t name##pad
#endif
#else
#define	DTRACE_PTR(type, name)	type *name
#endif


typedef uint32_t dtrace_id_t;		/* probe identifier */
typedef uint32_t dtrace_epid_t;		/* enabled probe identifier */
typedef uint32_t dtrace_aggid_t;	/* aggregation identifier */
typedef int64_t dtrace_aggvarid_t;	/* aggregation variable identifier */
typedef uint16_t dtrace_actkind_t;	/* action kind */
typedef int64_t dtrace_optval_t;	/* option value */
typedef uint32_t dtrace_cacheid_t;	/* predicate cache identifier */


/*
 * DTrace Buffer Interface
 *
 * In order to get a snapshot of the principal or aggregation buffer,
 * user-level passes a buffer description to the kernel with the dtrace_bufdesc
 * structure.  This describes which CPU user-level is interested in, and
 * where user-level wishes the kernel to snapshot the buffer to (the
 * dtbd_data field).  The kernel uses the same structure to pass back some
 * information regarding the buffer:  the size of data actually copied out, the
 * number of drops, the number of errors, the offset of the oldest record,
 * and the time of the snapshot.
 *
 * If the buffer policy is a "switch" policy, taking a snapshot of the
 * principal buffer has the additional effect of switching the active and
 * inactive buffers.  Taking a snapshot of the aggregation buffer _always_ has
 * the additional effect of switching the active and inactive buffers.
 */
typedef struct dtrace_bufdesc {
	uint64_t dtbd_size;			/* size of buffer */
	uint32_t dtbd_cpu;			/* CPU or DTRACE_CPUALL */
	uint32_t dtbd_errors;			/* number of errors */
	uint64_t dtbd_drops;			/* number of drops */
	DTRACE_PTR(char, dtbd_data);		/* data */
	uint64_t dtbd_oldest;			/* offset of oldest record */
	uint64_t dtbd_timestamp;		/* hrtime of snapshot */
} dtrace_bufdesc_t;

typedef struct {
	void	*dof;		/* DOF userland address written to driver. */
	int	n_matched;	/* # matches returned by driver. */
} dtrace_enable_io_t;

typedef struct dtrace_aggdesc {
	DTRACE_PTR(char, dtagd_name);		/* not filled in by kernel */
	dtrace_aggvarid_t dtagd_varid;		/* not filled in by kernel */
	int dtagd_flags;			/* not filled in by kernel */
	dtrace_aggid_t dtagd_id;		/* aggregation ID */
	dtrace_epid_t dtagd_epid;		/* enabled probe ID */
	uint32_t dtagd_size;			/* size in bytes */
	int dtagd_nrecs;			/* number of records */
	uint32_t dtagd_pad;			/* explicit padding */
	dtrace_recdesc_t dtagd_rec[1];		/* record descriptions */
} dtrace_aggdesc_t;

typedef struct dtrace_recdesc {
	dtrace_actkind_t dtrd_action;		/* kind of action */
	uint32_t dtrd_size;			/* size of record */
	uint32_t dtrd_offset;			/* offset in ECB's data */
	uint16_t dtrd_alignment;		/* required alignment */
	uint16_t dtrd_format;			/* format, if any */
	uintptr_t dtrd_arg;			/* action argument */
	uintptr_t dtrd_uarg;			/* user argument */
} dtrace_recdesc_t;

typedef struct dtrace_fmtdesc {
	DTRACE_PTR(char, dtfd_string);		/* format string */
	int dtfd_length;			/* length of format string */
	uint16_t dtfd_format;			/* format identifier */
} dtrace_fmtdesc_t;

/*
 * Each record in the buffer (dtbd_data) begins with a header that includes
 * the epid and a timestamp.  The timestamp is split into two 4-byte parts
 * so that we do not require 8-byte alignment.
 */
typedef struct dtrace_rechdr {
	dtrace_epid_t dtrh_epid;		/* enabled probe id */
	uint32_t dtrh_timestamp_hi;		/* high bits of hrtime_t */
	uint32_t dtrh_timestamp_lo;		/* low bits of hrtime_t */
} dtrace_rechdr_t;

#define	DTRACEIOC_BUFSNAP	_IOW('x',4,dtrace_bufdesc_t *)	
							/* snapshot buffer */
#define	DTRACEIOC_ENABLE	_IOWR('x',6,dtrace_enable_io_t)
							/* enable probes */
#define	DTRACEIOC_AGGSNAP	_IOW('x',7,dtrace_bufdesc_t *)
							/* snapshot agg. */
#define	DTRACEIOC_AGGDESC	_IOW('x',15,dtrace_aggdesc_t *)	
							/* get agg. desc. */
#define	DTRACEIOC_FORMAT	_IOWR('x',16,dtrace_fmtdesc_t)	
							/* get format str */
#define	DTRACEIOC_DOFGET	_IOW('x',17,dof_hdr_t *)
							/* get DOF */
#endif
