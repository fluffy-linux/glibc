/* FSWC: helpers shared by the index reader and builder.
   Copyright (C) 2026 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _FSWC_INTERNAL_H
#define _FSWC_INTERNAL_H 1

#include <fswc-index.h>
#include <sys/ioctl.h>

/* Kernel interfaces newer than some build hosts' headers (Linux 6.8+;
   Fluffy supports only the host kernel and its own, both 7.x).  Values
   from include/uapi/linux/{stat,mount,nsfs,pidfd}.h.  */
#define FSWC_STATX_MNT_ID_UNIQUE  0x00004000U
#define FSWC_STATX_ATTR_MOUNT_ROOT 0x00002000ULL
#define FSWC_STATMOUNT_SB_BASIC   0x00000001ULL
#define FSWC_STATMOUNT_MNT_NS_ID  0x00000040ULL
#define FSWC_LSMT_ROOT            0xffffffffffffffffULL
#define FSWC_MNT_ID_REQ_SIZE_VER1 32u
#define FSWC_NS_GET_ID            _IOR (0xb7, 13, uint64_t)
#define FSWC_PIDFD_GET_USER_NS    _IO (0xff, 9)
#define FSWC_SQUASHFS_MAGIC       0x73717368u

#ifndef __NR_statmount
# define __NR_statmount 457
#endif
#ifndef __NR_listmount
# define __NR_listmount 458
#endif

struct fswc_mnt_id_req
{
  uint32_t size;
  uint32_t mnt_ns_fd;
  uint64_t mnt_id;
  uint64_t param;
  uint64_t mnt_ns_id;
};

/* The fixed part of struct statmount up to mnt_ns_id.  */
struct fswc_statmount
{
  uint32_t size, mnt_opts;
  uint64_t mask;
  uint32_t sb_dev_major, sb_dev_minor;
  uint64_t sb_magic;
  uint32_t sb_flags, fs_type;
  uint64_t mnt_id, mnt_parent_id;
  uint32_t mnt_id_old, mnt_parent_id_old;
  uint64_t mnt_attr, mnt_propagation, mnt_peer_group, mnt_master;
  uint64_t propagate_from;
  uint32_t mnt_root, mnt_point;
  uint64_t mnt_ns_id;
  uint64_t spare[64];
};

/* Register the configured prefixes (idempotent).  */
extern void __fswc_prefixes_init (void) attribute_hidden;

/* Add PATH as a prefix whose directories all count as sealed.  */
extern const struct fswc_prefix *__fswc_register_test_prefix
  (const char *path, size_t len) attribute_hidden;

extern const struct fswc_prefix *__fswc_find_prefix (const char *path,
                                                     size_t len)
  attribute_hidden;

extern bool __fswc_prefix_state (const char *prefix,
                                 struct fswc_prefix_state *out)
  attribute_hidden;
extern bool __fswc_mntns_id (uint64_t mnt_id, uint64_t *out) attribute_hidden;
extern bool __fswc_userns_id (uint64_t *out) attribute_hidden;

/* Visit, in ascending order, the ID of every mount beneath MNT_ID.  Stops
   early if VISIT returns false.  Returns false if listmount failed or
   VISIT stopped it.  */
extern bool __fswc_each_mount_beneath (uint64_t mnt_id,
                                       bool (*visit) (uint64_t, void *),
                                       void *closure) attribute_hidden;

/* Open the per-identity directory, creating it if CREATE.  Returns -1
   unless it is a 0700 directory owned by EUID.  */
extern int __fswc_open_dir (uint32_t euid, uint64_t userns_id, bool create)
  attribute_hidden;

/* "idx-<mntns>-<dev>-<ino>" or "lock-..." into BUF (at least 96 bytes).  */
extern void __fswc_index_name (char *buf, const char *kind,
                               uint64_t mntns_id, uint64_t dev, uint64_t ino)
  attribute_hidden;

extern char *__fswc_fmt_u64 (char *p, uint64_t v) attribute_hidden;

/* Map NAME in DIRFD and check its header, sections, and that it
   describes STATE for EUID in USERNS_ID and MNTNS_ID.  */
extern bool __fswc_map_index (int dirfd, const char *name, uint32_t euid,
                              uint64_t userns_id, uint64_t mntns_id,
                              const struct fswc_prefix_state *state,
                              struct fswc_index *out) attribute_hidden;

/* Do the mounts beneath IDX's prefix match the snapshot?  */
extern bool __fswc_mounts_match (const struct fswc_index *idx)
  attribute_hidden;

/* Forget negative results so that a newly built index is found.  */
extern void __fswc_reset_cache (void) attribute_hidden;

#endif /* fswc-internal.h */
