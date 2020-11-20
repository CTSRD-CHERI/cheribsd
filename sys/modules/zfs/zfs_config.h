/*
 * $FreeBSD$
 */

/* zfs_config.h.  Generated from zfs_config.h.in by configure.  */
/* zfs_config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
/* #undef ENABLE_NLS */

/* bio_end_io_t wants 1 arg */
/* #undef HAVE_1ARG_BIO_END_IO_T */

/* lookup_bdev() wants 1 arg */
/* #undef HAVE_1ARG_LOOKUP_BDEV */

/* submit_bio() wants 1 arg */
/* #undef HAVE_1ARG_SUBMIT_BIO */

/* bdi_setup_and_register() wants 2 args */
/* #undef HAVE_2ARGS_BDI_SETUP_AND_REGISTER */

/* lookup_bdev() wants 2 args */
/* #undef HAVE_2ARGS_LOOKUP_BDEV */

/* vfs_getattr wants 2 args */
/* #undef HAVE_2ARGS_VFS_GETATTR */

/* zlib_deflate_workspacesize() wants 2 args */
/* #undef HAVE_2ARGS_ZLIB_DEFLATE_WORKSPACESIZE */

/* bdi_setup_and_register() wants 3 args */
/* #undef HAVE_3ARGS_BDI_SETUP_AND_REGISTER */

/* vfs_getattr wants 3 args */
/* #undef HAVE_3ARGS_VFS_GETATTR */

/* vfs_getattr wants 4 args */
/* #undef HAVE_4ARGS_VFS_GETATTR */

/* kernel has access_ok with 'type' parameter */
/* #undef HAVE_ACCESS_OK_TYPE */

/* posix_acl has refcount_t */
/* #undef HAVE_ACL_REFCOUNT */

/* Define if host toolchain supports AES */
#define HAVE_AES 1

#ifdef __amd64__
#ifndef RESCUE
/* Define if host toolchain supports AVX */
#define HAVE_AVX 1
#endif

/* Define if host toolchain supports AVX2 */
#define HAVE_AVX2 1

/* Define if host toolchain supports AVX512BW */
#define HAVE_AVX512BW 1

/* Define if host toolchain supports AVX512CD */
#define HAVE_AVX512CD 1

/* Define if host toolchain supports AVX512DQ */
#define HAVE_AVX512DQ 1

/* Define if host toolchain supports AVX512ER */
#define HAVE_AVX512ER 1

/* Define if host toolchain supports AVX512F */
#define HAVE_AVX512F 1

/* Define if host toolchain supports AVX512IFMA */
#define HAVE_AVX512IFMA 1

/* Define if host toolchain supports AVX512PF */
#define HAVE_AVX512PF 1

/* Define if host toolchain supports AVX512VBMI */
#define HAVE_AVX512VBMI 1

/* Define if host toolchain supports AVX512VL */
#define HAVE_AVX512VL 1
#endif

/* bio->bi_opf is defined */
/* #undef HAVE_BIO_BI_OPF */

/* bio->bi_status exists */
/* #undef HAVE_BIO_BI_STATUS */

/* bio has bi_iter */
/* #undef HAVE_BIO_BVEC_ITER */

/* bio_set_dev() is available */
/* #undef HAVE_BIO_SET_DEV */

/* bio_set_dev() GPL-only */
/* #undef HAVE_BIO_SET_DEV_GPL_ONLY */

/* bio_set_op_attrs is available */
/* #undef HAVE_BIO_SET_OP_ATTRS */

/* blkdev_reread_part() exists */
/* #undef HAVE_BLKDEV_REREAD_PART */

/* blkg_tryget() is available */
/* #undef HAVE_BLKG_TRYGET */

/* blkg_tryget() GPL-only */
/* #undef HAVE_BLKG_TRYGET_GPL_ONLY */

/* blk_alloc_queue() expects request function */
/* #undef HAVE_BLK_ALLOC_QUEUE_REQUEST_FN */

/* blk queue backing_dev_info is dynamic */
/* #undef HAVE_BLK_QUEUE_BDI_DYNAMIC */

/* blk_queue_flag_clear() exists */
/* #undef HAVE_BLK_QUEUE_FLAG_CLEAR */

/* blk_queue_flag_set() exists */
/* #undef HAVE_BLK_QUEUE_FLAG_SET */

/* blk_queue_flush() is available */
/* #undef HAVE_BLK_QUEUE_FLUSH */

/* blk_queue_flush() is GPL-only */
/* #undef HAVE_BLK_QUEUE_FLUSH_GPL_ONLY */

/* blk_queue_secdiscard() is available */
/* #undef HAVE_BLK_QUEUE_SECDISCARD */

/* blk_queue_secure_erase() is available */
/* #undef HAVE_BLK_QUEUE_SECURE_ERASE */

/* blk_queue_write_cache() exists */
/* #undef HAVE_BLK_QUEUE_WRITE_CACHE */

/* blk_queue_write_cache() is GPL-only */
/* #undef HAVE_BLK_QUEUE_WRITE_CACHE_GPL_ONLY */

/* Define to 1 if you have the Mac OS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the Mac OS X function
   CFLocaleCopyPreferredLanguages in the CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYPREFERREDLANGUAGES */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* clear_inode() is available */
/* #undef HAVE_CLEAR_INODE */

/* dentry uses const struct dentry_operations */
/* #undef HAVE_CONST_DENTRY_OPERATIONS */

/* current_time() exists */
/* #undef HAVE_CURRENT_TIME */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
/* #undef HAVE_DCGETTEXT */

/* DECLARE_EVENT_CLASS() is available */
/* #undef HAVE_DECLARE_EVENT_CLASS */

/* sops->dirty_inode() wants flags */
/* #undef HAVE_DIRTY_INODE_WITH_FLAGS */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* d_make_root() is available */
/* #undef HAVE_D_MAKE_ROOT */

/* d_prune_aliases() is available */
/* #undef HAVE_D_PRUNE_ALIASES */

/* dops->d_revalidate() operation takes nameidata */
/* #undef HAVE_D_REVALIDATE_NAMEIDATA */

/* eops->encode_fh() wants child and parent inodes */
/* #undef HAVE_ENCODE_FH_WITH_INODE */

/* sops->evict_inode() exists */
/* #undef HAVE_EVICT_INODE */

/* fops->aio_fsync() exists */
/* #undef HAVE_FILE_AIO_FSYNC */

/* file_dentry() is available */
/* #undef HAVE_FILE_DENTRY */

/* file_inode() is available */
/* #undef HAVE_FILE_INODE */

/* iops->follow_link() cookie */
/* #undef HAVE_FOLLOW_LINK_COOKIE */

/* iops->follow_link() nameidata */
/* #undef HAVE_FOLLOW_LINK_NAMEIDATA */

/* fops->fsync() with range */
/* #undef HAVE_FSYNC_RANGE */

/* fops->fsync() without dentry */
/* #undef HAVE_FSYNC_WITHOUT_DENTRY */

/* generic_start_io_acct()/generic_end_io_acct() available */
/* #undef HAVE_GENERIC_IO_ACCT_3ARG */

/* generic_start_io_acct()/generic_end_io_acct() 4 arg available */
/* #undef HAVE_GENERIC_IO_ACCT_4ARG */

/* generic_readlink is global */
/* #undef HAVE_GENERIC_READLINK */

/* generic_setxattr() exists */
/* #undef HAVE_GENERIC_SETXATTR */

/* generic_write_checks() takes kiocb */
/* #undef HAVE_GENERIC_WRITE_CHECKS_KIOCB */

/* Define if the GNU gettext() function is already present or preinstalled. */
/* #undef HAVE_GETTEXT */

/* get_disk_and_module() is available */
/* #undef HAVE_GET_DISK_AND_MODULE */

/* iops->get_link() cookie */
/* #undef HAVE_GET_LINK_COOKIE */

/* iops->get_link() delayed */
/* #undef HAVE_GET_LINK_DELAYED */

/* group_info->gid exists */
/* #undef HAVE_GROUP_INFO_GID */

/* Define if you have the iconv() function and it works. */
#define HAVE_ICONV 1

/* yes */
/* #undef HAVE_INODE_LOCK_SHARED */

/* inode_set_flags() exists */
/* #undef HAVE_INODE_SET_FLAGS */

/* inode_set_iversion() exists */
/* #undef HAVE_INODE_SET_IVERSION */

/* inode->i_*time's are timespec64 */
/* #undef HAVE_INODE_TIMESPEC64_TIMES */

/* timestamp_truncate() exists */
/* #undef HAVE_INODE_TIMESTAMP_TRUNCATE */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* in_compat_syscall() is available */
/* #undef HAVE_IN_COMPAT_SYSCALL */

/* yes */
/* #undef HAVE_IO_SCHEDULE_TIMEOUT */

/* Define to 1 if you have the `issetugid' function. */
#define HAVE_ISSETUGID 1

/* kernel has kernel_fpu_* functions */
/* #undef HAVE_KERNEL_FPU */

/* kernel has asm/fpu/api.h */
/* #undef HAVE_KERNEL_FPU_API_HEADER */

/* kernel fpu internal */
/* #undef HAVE_KERNEL_FPU_INTERNAL */

/* uncached_acl_sentinel() exists */
/* #undef HAVE_KERNEL_GET_ACL_HANDLE_CACHE */

/* kernel does stack verification */
/* #undef HAVE_KERNEL_OBJTOOL */

/* kernel_read() take loff_t pointer */
/* #undef HAVE_KERNEL_READ_PPOS */

/* timer_list.function gets a timer_list */
/* #undef HAVE_KERNEL_TIMER_FUNCTION_TIMER_LIST */

/* struct timer_list has a flags member */
/* #undef HAVE_KERNEL_TIMER_LIST_FLAGS */

/* timer_setup() is available */
/* #undef HAVE_KERNEL_TIMER_SETUP */

/* kernel_write() take loff_t pointer */
/* #undef HAVE_KERNEL_WRITE_PPOS */

/* kmem_cache_create_usercopy() exists */
/* #undef HAVE_KMEM_CACHE_CREATE_USERCOPY */

/* kstrtoul() exists */
/* #undef HAVE_KSTRTOUL */

/* ktime_get_coarse_real_ts64() exists */
/* #undef HAVE_KTIME_GET_COARSE_REAL_TS64 */

/* ktime_get_raw_ts64() exists */
/* #undef HAVE_KTIME_GET_RAW_TS64 */

/* kvmalloc exists */
/* #undef HAVE_KVMALLOC */

/* kernel has large stacks */
/* #undef HAVE_LARGE_STACKS */

/* Define if you have libaio */
/* #undef HAVE_LIBAIO */

/* Define if you have libblkid */
/* #undef HAVE_LIBBLKID */

/* Define if you have libssl */
#define HAVE_LIBSSL 1

/* Define to 1 if you have the `tirpc' library (-ltirpc). */
/* #undef HAVE_LIBTIRPC */

/* Define if you have libudev */
/* #undef HAVE_LIBUDEV */

/* Define if udev_device_get_is_initialized is available */
/* #undef HAVE_LIBUDEV_UDEV_DEVICE_GET_IS_INITIALIZED */

/* Define if you have libuuid */
/* #undef HAVE_LIBUUID */

/* lseek_execute() is available */
/* #undef HAVE_LSEEK_EXECUTE */

/* makedev() is declared in sys/mkdev.h */
/* #undef HAVE_MAKEDEV_IN_MKDEV */

/* makedev() is declared in sys/sysmacros.h */
/* #undef HAVE_MAKEDEV_IN_SYSMACROS */

/* Noting that make_request_fn() returns blk_qc_t */
/* #undef HAVE_MAKE_REQUEST_FN_RET_QC */

/* Noting that make_request_fn() returns void */
/* #undef HAVE_MAKE_REQUEST_FN_RET_VOID */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* iops->create()/mkdir()/mknod() take umode_t */
/* #undef HAVE_MKDIR_UMODE_T */

/* Define to 1 if you have the `mlockall' function. */
#define HAVE_MLOCKALL 1

/* Define if host toolchain supports MOVBE */
#define HAVE_MOVBE 1

/* new_sync_read()/new_sync_write() are available */
/* #undef HAVE_NEW_SYNC_READ */

/* iops->getattr() takes a path */
/* #undef HAVE_PATH_IOPS_GETATTR */

/* Define if host toolchain supports PCLMULQDQ */
#define HAVE_PCLMULQDQ 1

/* posix_acl_chmod() exists */
/* #undef HAVE_POSIX_ACL_CHMOD */

/* posix_acl_from_xattr() needs user_ns */
/* #undef HAVE_POSIX_ACL_FROM_XATTR_USERNS */

/* posix_acl_release() is available */
/* #undef HAVE_POSIX_ACL_RELEASE */

/* posix_acl_release() is GPL-only */
/* #undef HAVE_POSIX_ACL_RELEASE_GPL_ONLY */

/* posix_acl_valid() wants user namespace */
/* #undef HAVE_POSIX_ACL_VALID_WITH_NS */

/* proc_ops structure exists */
/* #undef HAVE_PROC_OPS_STRUCT */

/* iops->put_link() cookie */
/* #undef HAVE_PUT_LINK_COOKIE */

/* iops->put_link() delayed */
/* #undef HAVE_PUT_LINK_DELAYED */

/* iops->put_link() nameidata */
/* #undef HAVE_PUT_LINK_NAMEIDATA */

/* If available, contains the Python version number currently in use. */
#define HAVE_PYTHON "3.7"

/* qat is enabled and existed */
/* #undef HAVE_QAT */

/* iops->rename() wants flags */
/* #undef HAVE_RENAME_WANTS_FLAGS */

/* REQ_DISCARD is defined */
/* #undef HAVE_REQ_DISCARD */

/* REQ_FLUSH is defined */
/* #undef HAVE_REQ_FLUSH */

/* REQ_OP_DISCARD is defined */
/* #undef HAVE_REQ_OP_DISCARD */

/* REQ_OP_FLUSH is defined */
/* #undef HAVE_REQ_OP_FLUSH */

/* REQ_OP_SECURE_ERASE is defined */
/* #undef HAVE_REQ_OP_SECURE_ERASE */

/* REQ_PREFLUSH is defined */
/* #undef HAVE_REQ_PREFLUSH */

/* struct rw_semaphore has member activity */
/* #undef HAVE_RWSEM_ACTIVITY */

/* struct rw_semaphore has atomic_long_t member count */
/* #undef HAVE_RWSEM_ATOMIC_LONG_COUNT */

/* linux/sched/signal.h exists */
/* #undef HAVE_SCHED_SIGNAL_HEADER */

/* setattr_prepare() is available */
/* #undef HAVE_SETATTR_PREPARE */

/* iops->set_acl() exists */
/* #undef HAVE_SET_ACL */

/* set_cached_acl() is usable */
/* #undef HAVE_SET_CACHED_ACL_USABLE */

/* struct shrink_control exists */
/* #undef HAVE_SHRINK_CONTROL_STRUCT */

/* new shrinker callback wants 2 args */
/* #undef HAVE_SINGLE_SHRINKER_CALLBACK */

/* ->count_objects exists */
/* #undef HAVE_SPLIT_SHRINKER_CALLBACK */

#if defined(__amd64__) || defined(__i386__)
/* Define if host toolchain supports SSE */
#define HAVE_SSE 1

/* Define if host toolchain supports SSE2 */
#define HAVE_SSE2 1

/* Define if host toolchain supports SSE3 */
#define HAVE_SSE3 1

/* Define if host toolchain supports SSE4.1 */
#define HAVE_SSE4_1 1

/* Define if host toolchain supports SSE4.2 */
#define HAVE_SSE4_2 1

/* Define if host toolchain supports SSSE3 */
#define HAVE_SSSE3 1
#endif

/* STACK_FRAME_NON_STANDARD is defined */
/* #undef HAVE_STACK_FRAME_NON_STANDARD */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* super_setup_bdi_name() exits */
/* #undef HAVE_SUPER_SETUP_BDI_NAME */

/* super_block->s_user_ns exists */
/* #undef HAVE_SUPER_USER_NS */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* i_op->tmpfile() exists */
/* #undef HAVE_TMPFILE */

/* totalhigh_pages() exists */
/* #undef HAVE_TOTALHIGH_PAGES */

/* kernel has totalram_pages() */
/* #undef HAVE_TOTALRAM_PAGES_FUNC */

/* kernel has __kernel_fpu_* functions */
/* #undef HAVE_UNDERSCORE_KERNEL_FPU */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* iops->getattr() takes a vfsmount */
/* #undef HAVE_VFSMOUNT_IOPS_GETATTR */

/* aops->direct_IO() uses iovec */
/* #undef HAVE_VFS_DIRECT_IO_IOVEC */

/* aops->direct_IO() uses iov_iter without rw */
/* #undef HAVE_VFS_DIRECT_IO_ITER */

/* aops->direct_IO() uses iov_iter with offset */
/* #undef HAVE_VFS_DIRECT_IO_ITER_OFFSET */

/* aops->direct_IO() uses iov_iter with rw and offset */
/* #undef HAVE_VFS_DIRECT_IO_ITER_RW_OFFSET */

/* fops->iterate() is available */
/* #undef HAVE_VFS_ITERATE */

/* fops->iterate_shared() is available */
/* #undef HAVE_VFS_ITERATE_SHARED */

/* fops->readdir() is available */
/* #undef HAVE_VFS_READDIR */

/* fops->read/write_iter() are available */
/* #undef HAVE_VFS_RW_ITERATE */

/* __vmalloc page flags exists */
/* #undef HAVE_VMALLOC_PAGE_KERNEL */

/* yes */
/* #undef HAVE_WAIT_ON_BIT_ACTION */

/* wait_queue_entry_t exists */
/* #undef HAVE_WAIT_QUEUE_ENTRY_T */

/* wq_head->head and wq_entry->entry exist */
/* #undef HAVE_WAIT_QUEUE_HEAD_ENTRY */

/* xattr_handler->get() wants dentry */
/* #undef HAVE_XATTR_GET_DENTRY */

/* xattr_handler->get() wants both dentry and inode */
/* #undef HAVE_XATTR_GET_DENTRY_INODE */

/* xattr_handler->get() wants xattr_handler */
/* #undef HAVE_XATTR_GET_HANDLER */

/* xattr_handler has name */
/* #undef HAVE_XATTR_HANDLER_NAME */

/* xattr_handler->list() wants dentry */
/* #undef HAVE_XATTR_LIST_DENTRY */

/* xattr_handler->list() wants xattr_handler */
/* #undef HAVE_XATTR_LIST_HANDLER */

/* xattr_handler->list() wants simple */
/* #undef HAVE_XATTR_LIST_SIMPLE */

/* xattr_handler->set() wants dentry */
/* #undef HAVE_XATTR_SET_DENTRY */

/* xattr_handler->set() wants both dentry and inode */
/* #undef HAVE_XATTR_SET_DENTRY_INODE */

/* xattr_handler->set() wants xattr_handler */
/* #undef HAVE_XATTR_SET_HANDLER */

/* Define if you have zlib */
#define HAVE_ZLIB 1

/* __posix_acl_chmod() exists */
/* #undef HAVE___POSIX_ACL_CHMOD */

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* kernel exports FPU functions */
/* #undef KERNEL_EXPORTS_X86_FPU */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* make_request_fn() return type */
/* #undef MAKE_REQUEST_FN_RET */

/* hardened module_param_call */
/* #undef MODULE_PARAM_CALL_CONST */

/* struct shrink_control has nid */
/* #undef SHRINK_CONTROL_HAS_NID */

/* Defined for legacy compatibility. */
#define SPL_META_ALIAS ZFS_META_ALIAS

/* Defined for legacy compatibility. */
#define SPL_META_RELEASE ZFS_META_RELEASE

/* Defined for legacy compatibility. */
#define SPL_META_VERSION ZFS_META_VERSION

/* True if ZFS is to be compiled for a FreeBSD system */
#define SYSTEM_FREEBSD 1

/* True if ZFS is to be compiled for a Linux system */
/* #undef SYSTEM_LINUX */

/* zfs debugging enabled */
/* #define ZFS_DEBUG 1 */

/* /dev/zfs minor */
/* #undef ZFS_DEVICE_MINOR */

/* enum node_stat_item contains NR_FILE_PAGES */
/* #undef ZFS_ENUM_NODE_STAT_ITEM_NR_FILE_PAGES */

/* enum node_stat_item contains NR_INACTIVE_ANON */
/* #undef ZFS_ENUM_NODE_STAT_ITEM_NR_INACTIVE_ANON */

/* enum node_stat_item contains NR_INACTIVE_FILE */
/* #undef ZFS_ENUM_NODE_STAT_ITEM_NR_INACTIVE_FILE */

/* enum node_stat_item contains NR_SLAB_RECLAIMABLE */
/* #undef ZFS_ENUM_NODE_STAT_ITEM_NR_SLAB_RECLAIMABLE */

/* enum zone_stat_item contains NR_FILE_PAGES */
/* #undef ZFS_ENUM_ZONE_STAT_ITEM_NR_FILE_PAGES */

/* enum zone_stat_item contains NR_INACTIVE_ANON */
/* #undef ZFS_ENUM_ZONE_STAT_ITEM_NR_INACTIVE_ANON */

/* enum zone_stat_item contains NR_INACTIVE_FILE */
/* #undef ZFS_ENUM_ZONE_STAT_ITEM_NR_INACTIVE_FILE */

/* enum zone_stat_item contains NR_SLAB_RECLAIMABLE */
/* #undef ZFS_ENUM_ZONE_STAT_ITEM_NR_SLAB_RECLAIMABLE */

/* global_node_page_state() exists */
/* #undef ZFS_GLOBAL_NODE_PAGE_STATE */

/* global_zone_page_state() exists */
/* #undef ZFS_GLOBAL_ZONE_PAGE_STATE */

/* Define to 1 if GPL-only symbols can be used */
/* #undef ZFS_IS_GPL_COMPATIBLE */

/* Define the project alias string. */
#define ZFS_META_ALIAS "zfs-0.8.0-1"

/* Define the project author. */
#define ZFS_META_AUTHOR "OpenZFS on Linux"

/* Define the project release date. */
/* #undef ZFS_META_DATA */

/* Define the maximum compatible kernel version. */
#define ZFS_META_KVER_MAX "5.6"

/* Define the minimum compatible kernel version. */
#define ZFS_META_KVER_MIN "3.10"

/* Define the project license. */
#define ZFS_META_LICENSE "CDDL"

/* Define the libtool library 'age' version information. */
/* #undef ZFS_META_LT_AGE */

/* Define the libtool library 'current' version information. */
/* #undef ZFS_META_LT_CURRENT */

/* Define the libtool library 'revision' version information. */
/* #undef ZFS_META_LT_REVISION */

/* Define the project name. */
#define ZFS_META_NAME "zfs"

/* Define the project release. */
#define ZFS_META_RELEASE "1"

/* Define the project version. */
#define ZFS_META_VERSION "0.8.0"

