/* FSWC index: format and reader interface.
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

#ifndef _FSWC_INDEX_H
#define _FSWC_INDEX_H 1

/* FSWC answers one question: what is at <prefix>/<pkg>/<relpath>?  It
   answers from an immutable snapshot of the read-only packages under
   <prefix>, and only after proving the snapshot still matches the kernel.
   Every answer is a hint: when in doubt it says "ask the kernel".

   One index file exists per (euid, user namespace, mount namespace,
   prefix):

     /dev/shm/.fswc-<euid>-<userns_id>/idx-<mntns_id>-<dev>-<ino>

   where <dev> and <ino> identify the prefix directory.  The file is never
   modified after publication; a rebuild renames a new file over it.  */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FSWC_MAGIC   0x43575346u         /* "FSWC" in little-endian.  */
#define FSWC_VERSION 6u

struct fswc_idx_header
{
  uint32_t magic, version;
  uint64_t total_size;

  /* What the snapshot describes; checked before every use.  */
  uint64_t mntns_id;                /* Mount namespace (NS_GET_ID).  */
  uint64_t userns_id;               /* User namespace (NS_GET_ID).  */
  uint64_t prefix_mnt_id;           /* statx STATX_MNT_ID_UNIQUE.  */
  uint64_t prefix_dev, prefix_ino;
  int64_t prefix_ctime_sec;
  uint32_t prefix_ctime_nsec;
  uint32_t euid;                    /* geteuid () in USERNS_ID.  */
  uint32_t num_mounts, mounts_off;  /* Sorted IDs of every mount beneath
                                       the prefix's mount.  */

  /* Contents.  */
  uint32_t num_top, top_off;        /* Every name in <prefix>, byte order.  */
  uint32_t num_paths, paths_off;    /* Every relpath in every sealed
                                       package, byte order.  */
  uint32_t num_postings, postings_off;
  uint32_t strtab_off, strtab_size;
};

/* One name directly in <prefix>.  */
struct fswc_top
{
  uint32_t name_off;
  uint16_t name_len;
  uint8_t sealed;                   /* 1: indexed; 0: ask the kernel.  */
  uint8_t d_type;
};

/* One relative path ("bin", "bin/bash", ...) present in at least one
   sealed package.  Its postings say which packages have it and as what:
   POSTINGS[POSTING .. POSTING + COUNT) is sorted by package.  */
struct fswc_path
{
  uint32_t name_off, name_len;
  uint32_t posting, count;
};

/* A posting: (top index << 8) | d_type.  d_type is never DT_UNKNOWN.  */
#define FSWC_IDX_POSTING_TOP(p)   ((p) >> 8)
#define FSWC_IDX_POSTING_DTYPE(p) ((p) & 0xffu)

/* A mapped index whose bounds have been checked once.  */
struct fswc_index
{
  const struct fswc_idx_header *hdr;
  size_t size;
  const uint64_t *mounts;
  const struct fswc_top *top;
  const struct fswc_path *paths;
  const uint32_t *postings;
  const char *strtab;
};

/* Where a prefix directory is, as the kernel sees it.  */
struct fswc_prefix_state
{
  uint64_t mnt_id, dev, ino;
  int64_t ctime_sec;
  uint32_t ctime_nsec;
};

/* A prefix FSWC knows about: from the build configuration, or added by a
   test.  */
#define FSWC_PREFIX_MAX 256
struct fswc_prefix
{
  char path[FSWC_PREFIX_MAX];
  size_t len;
  bool test_sealed;             /* Every directory counts as sealed.  */
};

/* A mapped index for one prefix and euid.  Written once, then published
   by incrementing fswc_shared.num_slots; never changed or unmapped, since
   another thread or a vfork child may be using it.  */
struct fswc_slot
{
  const struct fswc_prefix *prefix;
  uint32_t euid;
  struct fswc_index idx;
};

/* Where no index was found, and the prefix's state then: don't look again
   until it changes.  */
struct fswc_miss
{
  const struct fswc_prefix *prefix;
  uint32_t euid;
  struct fswc_prefix_state state;
};

#define FSWC_MAX_PREFIXES 8
#define FSWC_MAX_SLOTS 16

/* All of FSWC's per-process state.  It lives in ld.so's _rtld_global
   (GL (dl_fswc)) so that an index mapped during library search also
   serves glob and execvp; static programs have their own.  Entries before
   a count never change once published.  LOCK is only ever try-locked:
   FSWC never blocks, so a caller that finds it busy takes the plain walk,
   and a fork while another thread holds it cannot deadlock the child.  */
struct fswc_shared
{
  int lock;
  int prefixes_done;
  unsigned int num_prefixes;
  struct fswc_prefix prefixes[FSWC_MAX_PREFIXES];
  unsigned int num_slots;
  struct fswc_slot slots[FSWC_MAX_SLOTS];
  unsigned int num_misses;      /* Under LOCK.  */
  struct fswc_miss misses[FSWC_MAX_PREFIXES];
};

/* Answers of __fswc_lookup besides a d_type (DT_DIR, DT_REG, ...).  */
#define FSWC_ABSENT  0                   /* Nothing there: ENOENT.  */
#define FSWC_KERNEL  (-1)                /* Ask the kernel.  */
#define FSWC_TOOLONG (-2)                /* A search-list candidate longer
                                            than the walker's path buffer
                                            (PATH_MAX): trying it would
                                            give ENAMETOOLONG.  Its PATH is
                                            NULL.  */

/* Return the index for the directory PREFIX (LEN bytes, absolute, no
   trailing slash) for the current euid, validated against the kernel
   now, or NULL if there is none or it is out of date.  Every call that
   expands a wildcard validates once, then makes any number of lookups.  */
extern const struct fswc_index *__fswc_index_get (const char *prefix,
                                                  size_t len)
  attribute_hidden;

/* Like __fswc_index_get, but never locks or maps: only an index that this
   process has already mapped qualifies.  */
extern const struct fswc_index *__fswc_index_peek (const char *prefix,
                                                   size_t len)
  attribute_hidden;

/* A relative path looked up once in an index, then answered per package
   cheaply: a search list asks the same question of every package.  */
#define FSWC_QUERY_DEPTH 7
struct fswc_query
{
  int fixed;                    /* If nonzero, the answer for every sealed
                                   package (DT_DIR for the package itself,
                                   FSWC_KERNEL for a path that is not plain
                                   or is too deep).  */
  const struct fswc_path *exact;  /* The path's entry, or NULL.  */
  unsigned int num_ancestors;
  const struct fswc_path *ancestors[FSWC_QUERY_DEPTH];  /* Nearest first;
                                                           only those some
                                                           package has.  */
};

extern void __fswc_query_prepare (struct fswc_query *q,
                                  const struct fswc_index *idx,
                                  const char *rel, size_t rel_len)
  attribute_hidden;

/* What is at <prefix>/<package TOP>/<Q's path>?  */
extern int __fswc_query_answer (const struct fswc_index *idx,
                                const struct fswc_query *q, uint32_t top)
  attribute_hidden;

/* What is at <prefix>/PKG/REL in IDX?  PKG is one path component; REL
   may be empty (the package itself).  */
extern int __fswc_lookup (const struct fswc_index *idx,
                          const char *pkg, size_t pkg_len,
                          const char *rel, size_t rel_len)
  attribute_hidden;

/* Per-call state of a wildcard expansion: the prefix validated last, and
   its index (NULL if none is valid).  Zero-initialize before the call.  */
/* A caller's way of listing a directory (glob's GLOB_ALTDIRFUNC hooks).
   NEXT returns each name in turn, then NULL.  */
struct fswc_lister
{
  void *(*open) (const char *dir, void *closure);
  const char *(*next) (void *stream, void *closure);
  void (*close) (void *stream, void *closure);
  void *closure;
};

struct fswc_call
{
  const void *prefix;
  const struct fswc_index *idx;
  bool no_lock;                 /* Never lock or map: only use indexes
                                   already mapped.  For execvp after
                                   vfork and posix_spawnp's child.  */
  const struct fswc_lister *lister;  /* If set, list directories with it
                                        and never consult an index, as
                                        caller hooks always bypass FSWC.  */
  bool no_index;                /* Visit every candidate the plain walk
                                   would (ld.so under LD_AUDIT or
                                   LD_DEBUG=libs, which must see them).  */
};

/* Does the search-list element P[0..LEN) have a component that is exactly
   "*"?  (GLOB.md 3.2.)  */
static inline bool
__fswc_has_star (const char *p, size_t len)
{
  for (size_t i = 0; i < len; ++i)
    if (p[i] == '*' && (i == 0 || p[i - 1] == '/')
        && (i + 1 == len || p[i + 1] == '/'))
      return true;
  return false;
}

/* One candidate of a search-list element, for __fswc_walk's VISIT.  */
struct fswc_candidate
{
  const char *path;             /* NUL-terminated; NULL for FSWC_TOOLONG.  */
  size_t len;
  int hint;                     /* A d_type, FSWC_ABSENT, FSWC_KERNEL, or
                                   FSWC_TOOLONG.  */
  /* For a candidate in a package of an indexed prefix: the index, the
     package's name, and where in PATH the package-relative part starts
     (just past PKG's "/"; may be LEN + 1), so that a consumer can look up
     further names in the same package.  IDX is NULL otherwise.  */
  const struct fswc_index *idx;
  const char *pkg;
  size_t pkg_len;
  uint32_t top;                 /* PKG's position in IDX's top list.  */
  size_t rel_off;
};

/* What lstat (FOLLOW false) or stat (FOLLOW true) would say about PATH,
   as a d_type, FSWC_ABSENT, or FSWC_KERNEL, validating PATH's prefix at
   most once per CALL.  */
extern int __fswc_answer (struct fswc_call *call, const char *path,
                          bool follow) attribute_hidden;

/* Expand one search-list element (GLOB.md 3.2): ELEM[0..LEN), with FILE
   (NUL-terminated, may be empty) appended to every candidate.  An element
   without a whole "*" component is its own single candidate; one with
   more than one has none.  When anything follows the "*", only
   directories (and symlinks to them) are candidates.  For each candidate,
   in order (byte order within the element), VISIT gets the path and a
   hint: a d_type when the index proves what is there, FSWC_ABSENT when it
   proves nothing is, FSWC_KERNEL when only the kernel knows, or
   FSWC_TOOLONG when the path does not fit in PATH_CAP.  Absent and
   too-long candidates are reported too, so that a consumer can account
   for them exactly as the plain walk would (execvp's errno).  VISIT
   returns false to stop.  PATH is a buffer of PATH_CAP bytes for building candidates;
   SCRATCH (SCRATCH_CAP bytes, at least 4 KiB, 8-byte aligned) holds a
   directory listing when there is no valid index.  Never allocates,
   locks (with CALL->no_lock), or consults the locale.  Returns 1 if
   VISIT stopped it, else 0.  */
extern int __fswc_walk (struct fswc_call *call, const char *elem,
                        size_t len, const char *file, char *path,
                        size_t path_cap, char *scratch, size_t scratch_cap,
                        bool (*visit) (const struct fswc_candidate *c,
                                       void *closure),
                        void *closure) attribute_hidden;

/* If PATH lies under a prefix that FSWC knows about, return that
   prefix's length (PATH[len] is '/'), else 0.  */
extern size_t __fswc_prefix_of (const char *path) attribute_hidden;

/* Build or refresh the indexes of the configured prefixes.  Called once
   from __libc_early_init in the initial namespace of a dynamically linked
   program; never in ld.so, after fork, or in an AT_SECURE process.  */
extern void __fswc_build_all (void) attribute_hidden;

/* Test-only: treat PREFIX as an FSWC prefix in this process, with every
   directory in it counting as sealed, then do OP.  Returns 0 if a valid
   index for PREFIX is now in use, else ENOENT (or ENOSPC if no more
   prefixes can be registered).  A build can decline, for example when
   the prefix changed within the current tick of the coarse clock, so
   callers retry.  GLIBC_PRIVATE; tst-fswc-oracle reaches it through
   dlsym.  */
enum
{
  FSWC_TEST_CHECK,              /* Only register and report.  */
  FSWC_TEST_BUILD,              /* Build the index now.  */
  FSWC_TEST_REMOVE,             /* Remove the index and its lock.  */
};
extern int __fswc_test_prefix (const char *prefix, int op);

#endif /* fswc-index.h */
