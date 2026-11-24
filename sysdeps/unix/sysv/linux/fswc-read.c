/* FSWC index reader: map, validate, look up.
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

#include <atomic.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ldsodefs.h>
#include <lowlevellock.h>
#include <limits.h>
#include <paths.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysdep.h>
#include <unistd.h>

#include "fswc-internal.h"

/* Registered prefixes.  */

#ifndef SHARED
struct fswc_shared _dl_fswc;
#endif
#define FS GL (dl_fswc)

/* See struct fswc_shared: never block.  */
static bool
fs_trylock (void)
{
  return lll_trylock (FS.lock) == 0;
}

static void
fs_unlock (void)
{
  lll_unlock (FS.lock, LLL_PRIVATE);
}

/* Add PATH[0..LEN) unless present.  Called with the lock held.  */
static const struct fswc_prefix *
add_prefix (const char *path, size_t len, bool test_sealed)
{
  unsigned int n = atomic_load_relaxed (&FS.num_prefixes);
  for (unsigned int i = 0; i < n; ++i)
    if (FS.prefixes[i].len == len
        && memcmp (FS.prefixes[i].path, path, len) == 0)
      {
        FS.prefixes[i].test_sealed |= test_sealed;
        return &FS.prefixes[i];
      }
  if (n == FSWC_MAX_PREFIXES || len == 0 || len >= FSWC_PREFIX_MAX)
    return NULL;
  struct fswc_prefix *p = &FS.prefixes[n];
  memcpy (p->path, path, len);
  p->path[len] = '\0';
  p->len = len;
  p->test_sealed = test_sealed;
  /* Publish the entry before the count that makes it visible.  */
  atomic_store_release (&FS.num_prefixes, n + 1);
  return p;
}

/* Every element of the colon-separated LIST (such as _PATH_DEFPATH) that
   has the form <prefix>, slash, star, then nothing or a slash, contributes
   <prefix>.  Only absolute prefixes without metacharacters qualify.  */
static void
add_prefixes_from (const char *list)
{
  while (*list != '\0')
    {
      const char *end = __strchrnul (list, ':');
      for (const char *s = list; s + 1 < end; ++s)
        if (s[0] == '/' && s[1] == '*' && (s + 2 == end || s[2] == '/'))
          {
            size_t len = s - list;
            if (len > 0 && list[0] == '/'
                && memchr (list, '*', len) == NULL
                && memchr (list, '?', len) == NULL
                && memchr (list, '[', len) == NULL)
              add_prefix (list, len, false);
            break;
          }
      list = *end == ':' ? end + 1 : end;
    }
}

const struct fswc_prefix *
__fswc_register_test_prefix (const char *path, size_t len)
{
  __fswc_prefixes_init ();
  if (!fs_trylock ())
    return NULL;
  const struct fswc_prefix *p = add_prefix (path, len, true);
  fs_unlock ();
  return p;
}

void
__fswc_prefixes_init (void)
{
  if (atomic_load_acquire (&FS.prefixes_done))
    return;
  /* If another thread is at it, this call simply finds no prefixes.  */
  if (!fs_trylock ())
    return;
  if (!FS.prefixes_done)
    {
      add_prefixes_from (_PATH_DEFPATH);
      add_prefixes_from (_PATH_STDPATH);
      atomic_store_release (&FS.prefixes_done, 1);
    }
  fs_unlock ();
}

const struct fswc_prefix *
__fswc_find_prefix (const char *path, size_t len)
{
  __fswc_prefixes_init ();
  unsigned int n = atomic_load_acquire (&FS.num_prefixes);
  for (unsigned int i = 0; i < n; ++i)
    if (FS.prefixes[i].len == len
        && memcmp (FS.prefixes[i].path, path, len) == 0)
      return &FS.prefixes[i];
  return NULL;
}

size_t
__fswc_prefix_of (const char *path)
{
  if (path[0] != '/')
    return 0;
  __fswc_prefixes_init ();
  unsigned int n = atomic_load_acquire (&FS.num_prefixes);
  for (unsigned int i = 0; i < n; ++i)
    {
      size_t len = FS.prefixes[i].len;
      /* strncmp stops at the end of a shorter PATH.  */
      if (strncmp (FS.prefixes[i].path, path, len) == 0
          && path[len] == '/')
        return len;
    }
  return 0;
}

/* Kernel identities.  */

bool
__fswc_prefix_state (const char *prefix, struct fswc_prefix_state *out)
{
  struct statx stx;
  if (INTERNAL_SYSCALL_CALL (statx, AT_FDCWD, prefix, AT_SYMLINK_NOFOLLOW,
                             STATX_TYPE | STATX_INO | STATX_CTIME
                             | FSWC_STATX_MNT_ID_UNIQUE, &stx) != 0
      || !(stx.stx_mask & FSWC_STATX_MNT_ID_UNIQUE)
      || !S_ISDIR (stx.stx_mode))
    return false;
  out->mnt_id = stx.stx_mnt_id;
  out->dev = ((uint64_t) stx.stx_dev_major << 32) | stx.stx_dev_minor;
  out->ino = stx.stx_ino;
  out->ctime_sec = stx.stx_ctime.tv_sec;
  out->ctime_nsec = stx.stx_ctime.tv_nsec;
  return true;
}

bool
__fswc_mntns_id (uint64_t mnt_id, uint64_t *out)
{
  struct fswc_mnt_id_req req =
    {
      .size = FSWC_MNT_ID_REQ_SIZE_VER1,
      .mnt_id = mnt_id,
      .param = FSWC_STATMOUNT_MNT_NS_ID,
    };
  struct fswc_statmount sm;
  if (INTERNAL_SYSCALL_CALL (statmount, &req, &sm, sizeof (sm), 0) != 0
      || !(sm.mask & FSWC_STATMOUNT_MNT_NS_ID))
    return false;
  *out = sm.mnt_ns_id;
  return true;
}

/* NS_GET_ID gives a 64-bit ID the kernel never reuses (unlike nsfs inode
   numbers), reached through a pidfd so that /proc is not needed.  */
bool
__fswc_userns_id (uint64_t *out)
{
  bool ok = false;
  long pid = INTERNAL_SYSCALL_CALL (getpid);
  long pfd = INTERNAL_SYSCALL_CALL (pidfd_open, pid, 0);
  if (INTERNAL_SYSCALL_ERROR_P (pfd))
    return false;
  long nsfd = INTERNAL_SYSCALL_CALL (ioctl, pfd, FSWC_PIDFD_GET_USER_NS, 0);
  if (!INTERNAL_SYSCALL_ERROR_P (nsfd))
    {
      ok = INTERNAL_SYSCALL_CALL (ioctl, nsfd, FSWC_NS_GET_ID, out) == 0;
      INTERNAL_SYSCALL_CALL (close, nsfd);
    }
  INTERNAL_SYSCALL_CALL (close, pfd);
  return ok;
}

bool
__fswc_each_mount_beneath (uint64_t mnt_id, bool (*visit) (uint64_t, void *),
                           void *closure)
{
  uint64_t ids[32];
  struct fswc_mnt_id_req req =
    { .size = FSWC_MNT_ID_REQ_SIZE_VER1, .mnt_id = mnt_id, .param = 0 };
  for (;;)
    {
      long n = INTERNAL_SYSCALL_CALL (listmount, &req, ids,
                                      sizeof (ids) / sizeof (ids[0]), 0);
      if (INTERNAL_SYSCALL_ERROR_P (n))
        return false;
      for (long i = 0; i < n; ++i)
        if (!visit (ids[i], closure))
          return false;
      if (n < (long) (sizeof (ids) / sizeof (ids[0])))
        return true;
      req.param = ids[n - 1];   /* Continue after the last ID.  */
    }
}

/* Names.  */

char *
__fswc_fmt_u64 (char *p, uint64_t v)
{
  char tmp[20];
  int n = 0;
  do
    tmp[n++] = '0' + v % 10;
  while ((v /= 10) != 0);
  while (n > 0)
    *p++ = tmp[--n];
  *p = '\0';
  return p;
}

int
__fswc_open_dir (uint32_t euid, uint64_t userns_id, bool create)
{
  char path[80];
  char *p = __mempcpy (path, "/dev/shm/.fswc-", 15);
  p = __fswc_fmt_u64 (p, euid);
  *p++ = '-';
  __fswc_fmt_u64 (p, userns_id);
  long fd = INTERNAL_SYSCALL_CALL (openat, AT_FDCWD, path,
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                                   | O_CLOEXEC, 0);
  if (fd == -ENOENT && create
      && INTERNAL_SYSCALL_CALL (mkdirat, AT_FDCWD, path, 0700) == 0)
    {
      fd = INTERNAL_SYSCALL_CALL (openat, AT_FDCWD, path,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                                  | O_CLOEXEC, 0);
      /* Whatever the umask removed.  */
      if (!INTERNAL_SYSCALL_ERROR_P (fd))
        INTERNAL_SYSCALL_CALL (fchmod, fd, 0700);
    }
  if (INTERNAL_SYSCALL_ERROR_P (fd))
    return -1;
  struct statx stx;
  if (INTERNAL_SYSCALL_CALL (statx, fd, "", AT_EMPTY_PATH,
                             STATX_TYPE | STATX_MODE | STATX_UID, &stx) != 0
      || !S_ISDIR (stx.stx_mode) || stx.stx_uid != euid
      || (stx.stx_mode & 07777) != 0700)
    {
      INTERNAL_SYSCALL_CALL (close, fd);
      return -1;
    }
  return fd;
}

void
__fswc_index_name (char *buf, const char *kind, uint64_t mntns_id,
                   uint64_t dev, uint64_t ino)
{
  char *p = __stpcpy (buf, kind);
  *p++ = '-';
  p = __fswc_fmt_u64 (p, mntns_id);
  *p++ = '-';
  p = __fswc_fmt_u64 (p, dev);
  *p++ = '-';
  __fswc_fmt_u64 (p, ino);
}

/* Mapping.  */

/* Is [OFF, OFF + COUNT * SIZE) inside an index of TOTAL bytes, with OFF
   aligned to ALIGN?  */
static bool
section_ok (uint64_t total, uint32_t off, uint64_t count, size_t size,
            size_t align)
{
  return off % align == 0 && off <= total
         && count <= (total - off) / size;
}

bool
__fswc_map_index (int dirfd, const char *name, uint32_t euid,
                  uint64_t userns_id, uint64_t mntns_id,
                  const struct fswc_prefix_state *state,
                  struct fswc_index *out)
{
  long fd = INTERNAL_SYSCALL_CALL (openat, dirfd, name,
                                   O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
  if (INTERNAL_SYSCALL_ERROR_P (fd))
    return false;
  struct statx stx;
  long r = INTERNAL_SYSCALL_CALL (statx, fd, "", AT_EMPTY_PATH,
                                  STATX_TYPE | STATX_MODE | STATX_UID
                                  | STATX_SIZE, &stx);
  void *map = MAP_FAILED;
  if (r == 0 && S_ISREG (stx.stx_mode) && stx.stx_uid == euid
      && (stx.stx_mode & 07777) == 0400
      && stx.stx_size >= sizeof (struct fswc_idx_header)
      && stx.stx_size <= SIZE_MAX)
    map = __mmap (NULL, stx.stx_size, PROT_READ, MAP_SHARED, fd, 0);
  INTERNAL_SYSCALL_CALL (close, fd);
  if (map == MAP_FAILED)
    return false;

  size_t size = stx.stx_size;
  const struct fswc_idx_header *h = map;
  const char *base = map;
  if (h->magic == FSWC_MAGIC && h->version == FSWC_VERSION
      && h->total_size == size
      && h->euid == euid && h->userns_id == userns_id
      && h->mntns_id == mntns_id
      && h->prefix_mnt_id == state->mnt_id
      && h->prefix_dev == state->dev && h->prefix_ino == state->ino
      && section_ok (size, h->mounts_off, h->num_mounts, sizeof (uint64_t),
                     _Alignof (uint64_t))
      && section_ok (size, h->top_off, h->num_top, sizeof (struct fswc_top),
                     _Alignof (struct fswc_top))
      && section_ok (size, h->paths_off, h->num_paths,
                     sizeof (struct fswc_path), _Alignof (struct fswc_path))
      && section_ok (size, h->postings_off, h->num_postings,
                     sizeof (uint32_t), _Alignof (uint32_t))
      && section_ok (size, h->strtab_off, h->strtab_size, 1, 1))
    {
      out->hdr = h;
      out->size = size;
      out->mounts = (const uint64_t *) (base + h->mounts_off);
      out->top = (const struct fswc_top *) (base + h->top_off);
      out->paths = (const struct fswc_path *) (base + h->paths_off);
      out->postings = (const uint32_t *) (base + h->postings_off);
      out->strtab = base + h->strtab_off;
      return true;
    }
  __munmap (map, size);
  return false;
}

/* Validation.  */

struct mounts_cursor
{
  const struct fswc_index *idx;
  uint32_t next;
};

static bool
mount_matches (uint64_t id, void *closure)
{
  struct mounts_cursor *c = closure;
  return c->next < c->idx->hdr->num_mounts
         && c->idx->mounts[c->next++] == id;
}

bool
__fswc_mounts_match (const struct fswc_index *idx)
{
  struct mounts_cursor c = { idx, 0 };
  return __fswc_each_mount_beneath (idx->hdr->prefix_mnt_id, mount_matches,
                                    &c)
         && c.next == idx->hdr->num_mounts;
}

/* Mapped indexes.  Each slot is written once, under the lock, and then
   published by incrementing FS.num_slots; it never changes or is unmapped
   afterwards, since another thread (or a vfork child) may be using it.
   That makes reading lock-free, which execvp after vfork and
   posix_spawnp's child need.  A newer index for the same prefix and euid
   takes a new slot; the table's size bounds what that can leak.  */
static bool
same_state (const struct fswc_prefix_state *a,
            const struct fswc_prefix_state *b)
{
  return a->mnt_id == b->mnt_id && a->dev == b->dev && a->ino == b->ino
         && a->ctime_sec == b->ctime_sec && a->ctime_nsec == b->ctime_nsec;
}

static bool
header_matches (const struct fswc_idx_header *h,
                const struct fswc_prefix_state *s)
{
  return h->prefix_mnt_id == s->mnt_id && h->prefix_dev == s->dev
         && h->prefix_ino == s->ino && h->prefix_ctime_sec == s->ctime_sec
         && h->prefix_ctime_nsec == s->ctime_nsec;
}

/* The newest published slot for P and EUID describing STATE, or NULL.
   Lock-free.  */
static const struct fswc_index *
find_slot (const struct fswc_prefix *p, uint32_t euid,
           const struct fswc_prefix_state *state)
{
  unsigned int n = atomic_load_acquire (&FS.num_slots);
  for (unsigned int i = n; i-- > 0; )
    if (FS.slots[i].prefix == p && FS.slots[i].euid == euid
        && header_matches (FS.slots[i].idx.hdr, state))
      return &FS.slots[i].idx;
  return NULL;
}

/* Map the index for P as it is in STATE into a new slot.  Called with
   the lock held.  */
static const struct fswc_index *
map_slot (const struct fswc_prefix *p, uint32_t euid,
          const struct fswc_prefix_state *state)
{
  struct fswc_miss *miss = NULL;
  for (unsigned int i = 0; i < FS.num_misses; ++i)
    if (FS.misses[i].prefix == p && FS.misses[i].euid == euid)
      miss = &FS.misses[i];
  if (miss != NULL && same_state (&miss->state, state))
    return NULL;
  unsigned int n = atomic_load_relaxed (&FS.num_slots);
  if (n == FSWC_MAX_SLOTS)
    return NULL;

  uint64_t userns_id, mntns_id;
  struct fswc_index idx;
  bool ok = false;
  if (__fswc_userns_id (&userns_id)
      && __fswc_mntns_id (state->mnt_id, &mntns_id))
    {
      int dirfd = __fswc_open_dir (euid, userns_id, false);
      if (dirfd >= 0)
        {
          char name[96];
          __fswc_index_name (name, "idx", mntns_id, state->dev, state->ino);
          ok = __fswc_map_index (dirfd, name, euid, userns_id, mntns_id,
                                 state, &idx);
          if (ok && !header_matches (idx.hdr, state))
            {
              /* An index for an earlier state of the prefix.  */
              __munmap ((void *) idx.hdr, idx.size);
              ok = false;
            }
          INTERNAL_SYSCALL_CALL (close, dirfd);
        }
    }
  if (!ok)
    {
      if (miss == NULL && FS.num_misses < FSWC_MAX_PREFIXES)
        {
          miss = &FS.misses[FS.num_misses++];
          miss->prefix = p;
          miss->euid = euid;
        }
      if (miss != NULL)
        miss->state = *state;
      return NULL;
    }
  FS.slots[n].prefix = p;
  FS.slots[n].euid = euid;
  FS.slots[n].idx = idx;
  atomic_store_release (&FS.num_slots, n + 1);
  return &FS.slots[n].idx;
}

/* The validated index for PREFIX, mapping it if MAY_MAP.  */
static const struct fswc_index *
index_for (const char *prefix, size_t len, bool may_map)
{
  const struct fswc_prefix *p = __fswc_find_prefix (prefix, len);
  if (p == NULL)
    return NULL;
  struct fswc_prefix_state state;
  if (!__fswc_prefix_state (p->path, &state))
    return NULL;
  uint32_t euid = INTERNAL_SYSCALL_CALL (geteuid);

  const struct fswc_index *idx = find_slot (p, euid, &state);
  if (idx == NULL && may_map)
    {
      if (fs_trylock ())
        {
          idx = find_slot (p, euid, &state);
          if (idx == NULL)
            idx = map_slot (p, euid, &state);
          fs_unlock ();
        }
    }
  if (idx != NULL && !__fswc_mounts_match (idx))
    idx = NULL;
  return idx;
}

const struct fswc_index *
__fswc_index_get (const char *prefix, size_t len)
{
  return index_for (prefix, len, true);
}

const struct fswc_index *
__fswc_index_peek (const char *prefix, size_t len)
{
  return index_for (prefix, len, false);
}

void
__fswc_reset_cache (void)
{
  if (fs_trylock ())
    {
      FS.num_misses = 0;
      fs_unlock ();
    }
}

/* Lookup.  */

/* The index for the prefix PREFIX[0..LEN) in CALL, validated at most once
   per call, or NULL.  */
static const struct fswc_index *
call_index (struct fswc_call *call, const char *prefix, size_t len)
{
  if (call->no_index)
    return NULL;
  /* Setting up the prefix list takes a lock.  */
  if (call->no_lock && !atomic_load_acquire (&FS.prefixes_done))
    return NULL;
  const struct fswc_prefix *p = __fswc_find_prefix (prefix, len);
  if (p == NULL)
    return NULL;
  if (call->prefix != p)
    {
      call->prefix = p;
      call->idx = call->no_lock ? __fswc_index_peek (p->path, p->len)
                                : __fswc_index_get (p->path, p->len);
    }
  return call->idx;
}

int
__fswc_answer (struct fswc_call *call, const char *path, bool follow)
{
  size_t plen = __fswc_prefix_of (path);
  if (plen == 0 || call_index (call, path, plen) == NULL)
    return FSWC_KERNEL;

  const char *pkg = path + plen + 1;
  const char *slash = __strchrnul (pkg, '/');
  if (slash == pkg)
    return FSWC_KERNEL;
  const char *rel = *slash == '/' ? slash + 1 : slash;
  int t = __fswc_lookup (call->idx, pkg, slash - pkg, rel, strlen (rel));
  /* stat follows a symlink; only the kernel knows where to.  */
  if (t == DT_LNK && follow)
    return FSWC_KERNEL;
  return t;
}

/* NAME of an index entry, if it lies inside the string table.  */
static const char *
entry_name (const struct fswc_index *idx, uint32_t off, uint32_t len)
{
  if (off > idx->hdr->strtab_size || len > idx->hdr->strtab_size - off)
    return NULL;
  return idx->strtab + off;
}

/* Byte-order comparison of A[0..ALEN) with B[0..BLEN).  */
static int
compare (const char *a, size_t alen, const char *b, size_t blen)
{
  int c = memcmp (a, b, alen < blen ? alen : blen);
  return c != 0 ? c : (alen > blen) - (alen < blen);
}

/* Index of the top-level entry NAME, or -1.  */
static long
find_top (const struct fswc_index *idx, const char *name, size_t len)
{
  size_t lo = 0, hi = idx->hdr->num_top;
  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;
      const struct fswc_top *t = &idx->top[mid];
      const char *s = entry_name (idx, t->name_off, t->name_len);
      if (s == NULL)
        return -1;
      int c = compare (name, len, s, t->name_len);
      if (c == 0)
        return mid;
      if (c < 0)
        hi = mid;
      else
        lo = mid + 1;
    }
  return -1;
}

/* The posting list of relative path REL, or NULL.  */
static const struct fswc_path *
find_path (const struct fswc_index *idx, const char *rel, size_t len)
{
  size_t lo = 0, hi = idx->hdr->num_paths;
  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;
      const struct fswc_path *e = &idx->paths[mid];
      const char *s = entry_name (idx, e->name_off, e->name_len);
      if (s == NULL)
        return NULL;
      int c = compare (rel, len, s, e->name_len);
      if (c == 0)
        return e;
      if (c < 0)
        hi = mid;
      else
        lo = mid + 1;
    }
  return NULL;
}

/* d_type of package TOP in E's postings, or FSWC_ABSENT.  */
static int
posting_of (const struct fswc_index *idx, const struct fswc_path *e,
            uint32_t top)
{
  if (e->posting > idx->hdr->num_postings
      || e->count > idx->hdr->num_postings - e->posting)
    return FSWC_KERNEL;
  const uint32_t *p = idx->postings + e->posting;
  size_t lo = 0, hi = e->count;
  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;
      uint32_t t = FSWC_IDX_POSTING_TOP (p[mid]);
      if (t == top)
        return FSWC_IDX_POSTING_DTYPE (p[mid]);
      if (t > top)
        hi = mid;
      else
        lo = mid + 1;
    }
  return FSWC_ABSENT;
}

/* Is REL a plain relative path: no empty, "." or ".." components and no
   leading or trailing slash?  */
static bool
normalized (const char *rel, size_t len)
{
  const char *end = rel + len;
  for (const char *c = rel; c <= end; )
    {
      const char *slash = memchr (c, '/', end - c);
      if (slash == NULL)
        slash = end;
      size_t n = slash - c;
      if (n == 0 || (n == 1 && c[0] == '.')
          || (n == 2 && c[0] == '.' && c[1] == '.'))
        return false;
      c = slash + 1;
    }
  return true;
}

void
__fswc_query_prepare (struct fswc_query *q, const struct fswc_index *idx,
                      const char *rel, size_t rel_len)
{
  q->fixed = 0;
  q->exact = NULL;
  q->num_ancestors = 0;
  if (rel_len == 0)
    {
      q->fixed = DT_DIR;        /* The package itself.  */
      return;
    }
  if (!normalized (rel, rel_len))
    {
      q->fixed = FSWC_KERNEL;
      return;
    }
  q->exact = find_path (idx, rel, rel_len);
  /* Ancestors some package has, nearest first.  */
  for (size_t n = rel_len; n > 0; )
    {
      while (n > 0 && rel[n - 1] != '/')
        --n;
      if (n == 0)
        break;
      --n;                      /* Drop the slash.  */
      const struct fswc_path *a = find_path (idx, rel, n);
      if (a == NULL)
        continue;
      if (q->num_ancestors == FSWC_QUERY_DEPTH)
        {
          q->fixed = FSWC_KERNEL;       /* Unusually deep; not worth it.  */
          return;
        }
      q->ancestors[q->num_ancestors++] = a;
    }
}

int
__fswc_query_answer (const struct fswc_index *idx, const struct fswc_query *q,
                     uint32_t top)
{
  if (top >= idx->hdr->num_top || !idx->top[top].sealed)
    return FSWC_KERNEL;
  if (q->fixed != 0)
    return q->fixed;
  if (q->exact != NULL)
    {
      int t = posting_of (idx, q->exact, top);
      if (t != FSWC_ABSENT)
        return t;
    }
  /* Not in this package.  The nearest ancestor this package has decides:
     a real directory means the path is absent; anything else (a symlink to
     follow, a file to fail with ENOTDIR) is the kernel's business.  */
  for (unsigned int i = 0; i < q->num_ancestors; ++i)
    {
      int t = posting_of (idx, q->ancestors[i], top);
      if (t == DT_DIR)
        return FSWC_ABSENT;
      if (t != FSWC_ABSENT)
        return FSWC_KERNEL;
    }
  return FSWC_ABSENT;
}

int
__fswc_lookup (const struct fswc_index *idx, const char *pkg,
               size_t pkg_len, const char *rel, size_t rel_len)
{
  long top = find_top (idx, pkg, pkg_len);
  if (top < 0)
    /* The validated snapshot lists every name in the prefix.  */
    return FSWC_ABSENT;
  struct fswc_query q;
  __fswc_query_prepare (&q, idx, rel, rel_len);
  return __fswc_query_answer (idx, &q, top);
}

/* Search lists.  */

struct walk
{
  struct fswc_call *call;
  const struct fswc_index *idx;  /* For the element's prefix, or NULL.  */
  const char *rest;             /* Components after the "*", or "".  */
  size_t rest_len;
  const char *file;             /* Appended to every candidate, or "".  */
  size_t file_len;
  char *path;                   /* PATH[0..BASE) is the prefix and "/".  */
  size_t cap, base;
  bool (*visit) (const struct fswc_candidate *, void *);
  void *closure;
  struct fswc_query query;      /* For <rest>/<file>, when IDX is set.  */
};

/* Append S[0..LEN) to W->path at *POS.  */
static bool
put (struct walk *w, size_t *pos, const char *s, size_t len)
{
  if (len >= w->cap - *pos)
    return false;
  memcpy (w->path + *pos, s, len);
  *pos += len;
  w->path[*pos] = '\0';
  return true;
}

/* Whether the entry whose path is in W->path is a directory, given its
   d_type.  A symlink or an unknown type costs one statx.  */
static bool
entry_is_dir (struct walk *w, unsigned char type)
{
  if (type == DT_DIR)
    return true;
  if (type != DT_LNK && type != DT_UNKNOWN)
    return false;
  struct statx stx;
  return INTERNAL_SYSCALL_CALL (statx, AT_FDCWD, w->path, 0, STATX_TYPE,
                                &stx) == 0
         && S_ISDIR (stx.stx_mode);
}

/* Visit the candidate in package NAME[0..LEN), which is entry TOP of the
   index (when there is one) and has d_type TYPE.  When anything follows
   the "*", only directories are packages: a plain file next to them is
   skipped, as glob ("<prefix>/" "*" "/bin") would skip it, so it can
   never decide the search's errno.  A candidate too long for the path
   buffer is still visited, as FSWC_TOOLONG, so that the search goes on
   past it as the plain walk would.  Returns 0 to go on, 1 if VISIT
   stopped.  */
static int
visit_package (struct walk *w, const char *name, size_t len, uint32_t top,
               unsigned char type)
{
  struct fswc_candidate toolong = { .hint = FSWC_TOOLONG, .top = top };
  size_t pos = w->base;
  if (!put (w, &pos, name, len))
    return w->visit (&toolong, w->closure) ? 0 : 1;
  if ((w->rest_len > 0 || w->file_len > 0) && !entry_is_dir (w, type))
    return 0;
  size_t rel = pos + 1;         /* Where <rest>/<file> starts.  */
  if ((w->rest_len > 0
       && (!put (w, &pos, "/", 1) || !put (w, &pos, w->rest, w->rest_len)))
      || (w->file_len > 0
          && (!put (w, &pos, "/", 1)
              || !put (w, &pos, w->file, w->file_len))))
    return w->visit (&toolong, w->closure) ? 0 : 1;
  struct fswc_candidate c =
    {
      .path = w->path, .len = pos, .idx = w->idx, .pkg = name,
      .pkg_len = len, .top = top, .rel_off = rel,
      .hint = w->idx == NULL ? FSWC_KERNEL
                             : __fswc_query_answer (w->idx, &w->query, top),
    };
  return w->visit (&c, w->closure) ? 0 : 1;
}

static bool
dot_name (const char *name)
{
  return name[0] == '.';
}

enum { WALK_DIRBUF = 4096 };   /* getdents64 buffer at the start of scratch.  */

/* Where the walk reads a directory's names: the kernel, or a caller's
   lister (glob with GLOB_ALTDIRFUNC).  */
struct dir_source
{
  const struct fswc_lister *lister;
  const char *dir;
  char *term;                   /* Write a NUL here while opening DIR, which
                                   is a prefix of the walk's path buffer
                                   (stack is scarce in ld.so).  */
  void *stream;                 /* Lister stream.  */
  int fd;                       /* Kernel directory.  */
  char *buf;                    /* getdents64 buffer.  */
  long len, pos;
};

static bool
source_open (struct dir_source *d)
{
  char saved = 0;
  if (d->term != NULL)
    {
      saved = *d->term;
      *d->term = '\0';
    }
  bool ok;
  if (d->lister != NULL)
    {
      d->stream = d->lister->open (d->dir, d->lister->closure);
      ok = d->stream != NULL;
    }
  else
    {
      d->fd = INTERNAL_SYSCALL_CALL (openat, AT_FDCWD, d->dir,
                                     O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
      d->len = d->pos = 0;
      ok = d->fd >= 0;
    }
  if (d->term != NULL)
    *d->term = saved;
  return ok;
}

static void
source_close (struct dir_source *d)
{
  if (d->lister != NULL)
    d->lister->close (d->stream, d->lister->closure);
  else
    INTERNAL_SYSCALL_CALL (close, d->fd);
}

/* The next name and its d_type, or NULL at the end.  A caller's lister
   gives no types; glob checks those candidates through its own hooks, so
   they count as directories here.  */
static const char *
source_next (struct dir_source *d, unsigned char *type)
{
  *type = DT_DIR;
  if (d->lister != NULL)
    return d->lister->next (d->stream, d->lister->closure);
  if (d->pos >= d->len)
    {
      d->len = INTERNAL_SYSCALL_CALL (getdents64, d->fd, d->buf,
                                     WALK_DIRBUF);
      d->pos = 0;
      if (d->len <= 0)
        return NULL;
    }
  const struct dirent64 *e = (const void *) (d->buf + d->pos);
  d->pos += e->d_reclen;
  *type = e->d_type;
  return e->d_name;
}

/* Whether a listing of N names whose lowest name byte is LOW has room for
   one more offset and NEED more bytes.  */
static bool
listing_room (size_t n, size_t low, size_t need)
{
  size_t offs_end = WALK_DIRBUF + (n + 1) * sizeof (uint32_t);
  return low >= offs_end && low - offs_end >= need;
}

/* Visit every package listed by D in byte order.  Each pass over the
   directory keeps in SCRATCH the smallest names above the last one
   visited, as many as fit, then visits them: a directory that fits takes
   one pass, a larger one a pass per SCRATCH-full, never more memory.
   SCRATCH holds the getdents64 buffer, then sorted offsets growing up and
   names (each after a byte with its d_type) growing down.

   BOUND is the smallest name a pass has left out (rejected for lack of
   room, or evicted for a smaller one).  Nothing at or above it is kept,
   so every name below it is in the listing, and the next pass can start
   after the largest one visited.  */
static int
walk_dir (struct walk *w, struct dir_source *d, char *scratch, size_t cap)
{
  d->buf = scratch;
  uint32_t *offs = (uint32_t *) (scratch + WALK_DIRBUF);
  char last[NAME_MAX + 1], bound[NAME_MAX + 1];
  bool have_last = false;
  for (;;)
    {
      size_t n = 0;
      size_t low = cap;
      bool have_bound = false;
      if (!source_open (d))
        return 0;
      unsigned char type;
      for (const char *name; (name = source_next (d, &type)) != NULL; )
        {
          size_t len = strlen (name) + 1;
          if (dot_name (name) || len > NAME_MAX + 1
              || (have_last && strcmp (name, last) <= 0)
              || (have_bound && strcmp (name, bound) >= 0))
            continue;
          /* Evict the largest names while that makes room for this
             smaller one.  */
          while (!listing_room (n, low, len + 1) && n > 0
                 && strcmp (scratch + offs[n - 1], name) > 0)
            {
              uint32_t v = offs[--n] - 1;       /* Its type byte.  */
              size_t vlen = strlen (scratch + v + 1) + 2;
              strcpy (bound, scratch + v + 1);
              have_bound = true;
              memmove (scratch + low + vlen, scratch + low, v - low);
              for (size_t i = 0; i < n; ++i)
                if (offs[i] < v)
                  offs[i] += vlen;
              low += vlen;
            }
          if (!listing_room (n, low, len + 1))
            {
              /* Larger than everything kept: wait for a later pass.  */
              if (!have_bound || strcmp (name, bound) < 0)
                strcpy (bound, name);
              have_bound = true;
              continue;
            }
          low -= len + 1;
          scratch[low] = type;
          memcpy (scratch + low + 1, name, len);
          size_t j = n++;
          while (j > 0 && strcmp (scratch + offs[j - 1], name) > 0)
            {
              offs[j] = offs[j - 1];
              --j;
            }
          offs[j] = low + 1;
        }
      source_close (d);

      for (size_t i = 0; i < n; ++i)
        {
          const char *name = scratch + offs[i];
          int r = visit_package (w, name, strlen (name), UINT32_MAX,
                                 scratch[offs[i] - 1]);
          if (r != 0)
            return r;
        }
      if (!have_bound || n == 0)
        return 0;
      strcpy (last, scratch + offs[n - 1]);
      have_last = true;
    }
}

int
__fswc_walk (struct fswc_call *call, const char *elem, size_t len,
             const char *file, char *path, size_t path_cap, char *scratch,
             size_t scratch_cap,
             bool (*visit) (const struct fswc_candidate *c, void *closure),
             void *closure)
{
  struct walk w =
    {
      .call = call, .file = file, .file_len = strlen (file),
      .path = path, .cap = path_cap, .visit = visit, .closure = closure,
    };

  /* Find the whole "*" components.  */
  size_t star = 0, stars = 0;
  for (size_t c = 0; c <= len; )
    {
      size_t e = c;
      while (e < len && elem[e] != '/')
        ++e;
      if (e - c == 1 && elem[c] == '*')
        {
          star = c;
          ++stars;
        }
      c = e + 1;
    }
  if (stars > 1)
    return 0;

  if (stars == 0)
    {
      /* A literal element; an empty one is the current directory.  */
      size_t pos = 0;
      if ((len == 0 ? !put (&w, &pos, ".", 1) : !put (&w, &pos, elem, len))
          || (w.file_len > 0
              && (!put (&w, &pos, "/", 1)
                  || !put (&w, &pos, file, w.file_len))))
        {
          struct fswc_candidate toolong = { .hint = FSWC_TOOLONG };
          return visit (&toolong, closure) ? 0 : 1;
        }
      struct fswc_candidate c =
        {
          .path = path, .len = pos,
          .hint = path[0] == '/' && call->lister == NULL
                  ? __fswc_answer (call, path, false) : FSWC_KERNEL,
        };
      return visit (&c, closure) ? 0 : 1;
    }

  /* "<prefix>/" "*" ["/" <rest>].  The prefix may be empty ("*" + "/bin",
     relative) or the root ("/" "*" "/bin").  */
  size_t prefix_len = star > 0 ? star - 1 : 0;
  w.rest = star + 1 < len ? elem + star + 2 : "";
  w.rest_len = star + 1 < len ? len - star - 2 : 0;
  size_t pos = 0;
  if (star > 0 && !put (&w, &pos, elem, star))   /* Includes the slash.  */
    /* A prefix too long to open has no candidates, like any directory
       that cannot be read.  */
    return 0;
  w.base = pos;

  if (prefix_len > 0 && elem[0] == '/' && call->lister == NULL)
    w.idx = call_index (call, elem, prefix_len);
  if (w.idx != NULL)
    {
      /* The same question for every package: "<rest>/<file>".  Build it
         where candidates will go, look it up once.  */
      size_t rel = w.base;
      if ((w.rest_len > 0 && !put (&w, &rel, w.rest, w.rest_len))
          || (w.rest_len > 0 && w.file_len > 0 && !put (&w, &rel, "/", 1))
          || (w.file_len > 0 && !put (&w, &rel, file, w.file_len)))
        /* Too long even without a package name: every candidate is
           FSWC_TOOLONG, which the plain walk below reports.  */
        w.idx = NULL;
      else
        __fswc_query_prepare (&w.query, w.idx, path + w.base,
                              rel - w.base);
    }
  if (w.idx != NULL)
    {

      /* Validation has just proved the prefix unchanged, so its names are
         the index's, already in byte order.  */
      for (uint32_t i = 0; i < w.idx->hdr->num_top; ++i)
        {
          const struct fswc_top *t = &w.idx->top[i];
          const char *name = entry_name (w.idx, t->name_off, t->name_len);
          if (name == NULL || t->name_len == 0 || name[0] == '.')
            continue;
          int r = visit_package (&w, name, t->name_len, i, t->d_type);
          if (r != 0)
            return r;
        }
      return 0;
    }

  /* The plain walk.  The prefix stays in PATH[0..PREFIX_LEN) while
     candidates are built after it, so it names the directory to read.  */
  struct dir_source d = { .lister = call->lister, .fd = -1 };
  if (star == 0)
    d.dir = ".";
  else if (prefix_len == 0)
    d.dir = "/";
  else
    {
      d.dir = path;
      d.term = path + prefix_len;
    }
  return walk_dir (&w, &d, scratch, scratch_cap);
}
