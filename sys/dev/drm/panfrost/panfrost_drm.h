/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2014-2018 Broadcom
 * Copyright © 2019 Collabora ltd.
 */

#ifndef _PANFROST_DRM_H_
#define _PANFROST_DRM_H_

#define DRM_PANFROST_SUBMIT			0x00
#define DRM_PANFROST_WAIT_BO			0x01
#define DRM_PANFROST_CREATE_BO			0x02
#define DRM_PANFROST_MMAP_BO			0x03
#define DRM_PANFROST_GET_PARAM			0x04
#define DRM_PANFROST_GET_BO_OFFSET		0x05
#define DRM_PANFROST_PERFCNT_ENABLE		0x06
#define DRM_PANFROST_PERFCNT_DUMP		0x07
#define DRM_PANFROST_MADVISE			0x08

#define DRM_IOCTL_PANFROST_SUBMIT		DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_SUBMIT, struct drm_panfrost_submit)
#define DRM_IOCTL_PANFROST_WAIT_BO		DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_WAIT_BO, struct drm_panfrost_wait_bo)
#define DRM_IOCTL_PANFROST_CREATE_BO		DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_CREATE_BO, struct drm_panfrost_create_bo)
#define DRM_IOCTL_PANFROST_MMAP_BO		DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_MMAP_BO, struct drm_panfrost_mmap_bo)
#define DRM_IOCTL_PANFROST_GET_PARAM		DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_GET_PARAM, struct drm_panfrost_get_param)
#define DRM_IOCTL_PANFROST_GET_BO_OFFSET	DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_GET_BO_OFFSET, struct drm_panfrost_get_bo_offset)
#define DRM_IOCTL_PANFROST_MADVISE		DRM_IOWR(DRM_COMMAND_BASE + DRM_PANFROST_MADVISE, struct drm_panfrost_madvise)

#define PANFROST_JD_REQ_FS (1 << 0)
/**
 * struct drm_panfrost_submit - ioctl argument for submitting commands to the 3D
 * engine.
 *
 * This asks the kernel to have the GPU execute a render command list.
 */
#ifdef _KERNEL
struct drm_panfrost_submit64 {

	/** Address to GPU mapping of job descriptor */
	uint64_t jc;

	/** An optional array of sync objects to wait on before starting this job. */
	uint64_t in_syncs;

	/** Number of sync objects to wait on before starting this job. */
	uint32_t in_sync_count;

	/** An optional sync object to place the completion fence in. */
	uint32_t out_sync;

	/** Pointer to a u32 array of the BOs that are referenced by the job. */
	uint64_t bo_handles;

	/** Number of BO handles passed in (size is that times 4). */
	uint32_t bo_handle_count;

	/** A combination of PANFROST_JD_REQ_* */
	uint32_t requirements;
};
#endif

struct drm_panfrost_submit {

	/** Address to GPU mapping of job descriptor */
	uint64_t jc;

	/** An optional array of sync objects to wait on before starting this job. */
	kuint64cap_t in_syncs;

	/** Number of sync objects to wait on before starting this job. */
	uint32_t in_sync_count;

	/** An optional sync object to place the completion fence in. */
	uint32_t out_sync;

	/** Pointer to a u32 array of the BOs that are referenced by the job. */
	kuint64cap_t bo_handles;

	/** Number of BO handles passed in (size is that times 4). */
	uint32_t bo_handle_count;

	/** A combination of PANFROST_JD_REQ_* */
	uint32_t requirements;
};

/**
 * struct drm_panfrost_wait_bo - ioctl argument for waiting for
 * completion of the last DRM_PANFROST_SUBMIT on a BO.
 *
 * This is useful for cases where multiple processes might be
 * rendering to a BO and you want to wait for all rendering to be
 * completed.
 */
struct drm_panfrost_wait_bo {
	uint32_t handle;
	uint32_t pad;
	__s64 timeout_ns;	/* absolute */
};

#define PANFROST_BO_NOEXEC	1
#define PANFROST_BO_HEAP	2

/**
 * struct drm_panfrost_create_bo - ioctl argument for creating Panfrost BOs.
 *
 * There are currently no values for the flags argument, but it may be
 * used in a future extension.
 */
struct drm_panfrost_create_bo {
	uint32_t size;
	uint32_t flags;
	/** Returned GEM handle for the BO. */
	uint32_t handle;
	/* Pad, must be zero-filled. */
	uint32_t pad;
	/**
	 * Returned offset for the BO in the GPU address space.  This offset
	 * is private to the DRM fd and is valid for the lifetime of the GEM
	 * handle.
	 *
	 * This offset value will always be nonzero, since various HW
	 * units treat 0 specially.
	 */
	uint64_t offset;
};

/**
 * struct drm_panfrost_mmap_bo - ioctl argument for mapping Panfrost BOs.
 *
 * This doesn't actually perform an mmap.  Instead, it returns the
 * offset you need to use in an mmap on the DRM device node.  This
 * means that tools like valgrind end up knowing about the mapped
 * memory.
 *
 * There are currently no values for the flags argument, but it may be
 * used in a future extension.
 */
struct drm_panfrost_mmap_bo {
	/** Handle for the object being mapped. */
	uint32_t handle;
	uint32_t flags;
	/** offset into the drm node to use for subsequent mmap call. */
	uint64_t offset;
};

enum drm_panfrost_param {
	DRM_PANFROST_PARAM_GPU_PROD_ID,
	DRM_PANFROST_PARAM_GPU_REVISION,
	DRM_PANFROST_PARAM_SHADER_PRESENT,
	DRM_PANFROST_PARAM_TILER_PRESENT,
	DRM_PANFROST_PARAM_L2_PRESENT,
	DRM_PANFROST_PARAM_STACK_PRESENT,
	DRM_PANFROST_PARAM_AS_PRESENT,
	DRM_PANFROST_PARAM_JS_PRESENT,
	DRM_PANFROST_PARAM_L2_FEATURES,
	DRM_PANFROST_PARAM_CORE_FEATURES,
	DRM_PANFROST_PARAM_TILER_FEATURES,
	DRM_PANFROST_PARAM_MEM_FEATURES,
	DRM_PANFROST_PARAM_MMU_FEATURES,
	DRM_PANFROST_PARAM_THREAD_FEATURES,
	DRM_PANFROST_PARAM_MAX_THREADS,
	DRM_PANFROST_PARAM_THREAD_MAX_WORKGROUP_SZ,
	DRM_PANFROST_PARAM_THREAD_MAX_BARRIER_SZ,
	DRM_PANFROST_PARAM_COHERENCY_FEATURES,
	DRM_PANFROST_PARAM_TEXTURE_FEATURES0,
	DRM_PANFROST_PARAM_TEXTURE_FEATURES1,
	DRM_PANFROST_PARAM_TEXTURE_FEATURES2,
	DRM_PANFROST_PARAM_TEXTURE_FEATURES3,
	DRM_PANFROST_PARAM_JS_FEATURES0,
	DRM_PANFROST_PARAM_JS_FEATURES1,
	DRM_PANFROST_PARAM_JS_FEATURES2,
	DRM_PANFROST_PARAM_JS_FEATURES3,
	DRM_PANFROST_PARAM_JS_FEATURES4,
	DRM_PANFROST_PARAM_JS_FEATURES5,
	DRM_PANFROST_PARAM_JS_FEATURES6,
	DRM_PANFROST_PARAM_JS_FEATURES7,
	DRM_PANFROST_PARAM_JS_FEATURES8,
	DRM_PANFROST_PARAM_JS_FEATURES9,
	DRM_PANFROST_PARAM_JS_FEATURES10,
	DRM_PANFROST_PARAM_JS_FEATURES11,
	DRM_PANFROST_PARAM_JS_FEATURES12,
	DRM_PANFROST_PARAM_JS_FEATURES13,
	DRM_PANFROST_PARAM_JS_FEATURES14,
	DRM_PANFROST_PARAM_JS_FEATURES15,
	DRM_PANFROST_PARAM_NR_CORE_GROUPS,
	DRM_PANFROST_PARAM_THREAD_TLS_ALLOC,
	DRM_PANFROST_PARAM_AFBC_FEATURES,
};

struct drm_panfrost_get_param {
	uint32_t param;
	uint32_t pad;
	uint64_t value;
};

/**
 * Returns the offset for the BO in the GPU address space for this DRM fd.
 * This is the same value returned by drm_panfrost_create_bo, if that was called
 * from this DRM fd.
 */
struct drm_panfrost_get_bo_offset {
	uint32_t handle;
	uint32_t pad;
	uint64_t offset;
};

struct drm_panfrost_perfcnt_enable {
	uint32_t enable;
	/*
	 * On bifrost we have 2 sets of counters, this parameter defines the
	 * one to track.
	 */
	uint32_t counterset;
};

struct drm_panfrost_perfcnt_dump {
	uint64_t buf_ptr;
};

/* madvise provides a way to tell the kernel in case a buffers contents
 * can be discarded under memory pressure, which is useful for userspace
 * bo cache where we want to optimistically hold on to buffer allocate
 * and potential mmap, but allow the pages to be discarded under memory
 * pressure.
 *
 * Typical usage would involve madvise(DONTNEED) when buffer enters BO
 * cache, and madvise(WILLNEED) if trying to recycle buffer from BO cache.
 * In the WILLNEED case, 'retained' indicates to userspace whether the
 * backing pages still exist.
 */
#define PANFROST_MADV_WILLNEED 0	/* backing pages are needed, status returned in 'retained' */
#define PANFROST_MADV_DONTNEED 1	/* backing pages not needed */

struct drm_panfrost_madvise {
	uint32_t handle;         /* in, GEM handle */
	uint32_t madv;           /* in, PANFROST_MADV_x */
	uint32_t retained;       /* out, whether backing store still exists */
};

#endif /* _PANFROST_DRM_H_ */
