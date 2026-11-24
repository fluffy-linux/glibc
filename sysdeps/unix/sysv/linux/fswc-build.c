/* FSWC index builder.
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

/* Builds one index per configured prefix, at program startup, when the
   process finds none that is valid.  It runs in __libc_early_init before
   constructors and main, single-threaded, so it cannot call malloc (an
   interposed malloc is not initialized yet): all memory comes from
   anonymous mappings.  Any failure just means no index this time.  */

#include <atomic.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ldsodefs.h>
#include <libc-lock.h>
#include <limits.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysdep.h>
#include <time.h>
#include <unistd.h>

#include "fswc-internal.h"

/* Memory.  */

/* A growable anonymous mapping.  */
struct arena
{
  char *base;
  size_t used, cap;
};

static bool
reserve (struct arena *a, size_t more)
{
  if (more <= a->cap - a->used)
    return true;
  size_t cap = a->cap == 0 ? 1 << 16 : a->cap;
  while (cap - a->used < more)
    {
      if (cap > SIZE_MAX / 2)
        return false;
      cap *= 2;
    }
  void *p = a->base == NULL
            ? __mmap (NULL, cap, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
            : __mremap (a->base, a->cap, cap, MREMAP_MAYMOVE);
  if (p == MAP_FAILED)
    return false;
  a->base = p;
  a->cap = cap;
  return true;
}

static void *
push (struct arena *a, const void *data, size_t len)
{
  if (!reserve (a, len))
    return NULL;
  void *p = a->base + a->used;
  if (data != NULL)
    memcpy (p, data, len);
  a->used += len;
  return p;
}

static void
release (struct arena *a)
{
  if (a->base != NULL)
    __munmap (a->base, a->cap);
  a->base = NULL;
  a->used = a->cap = 0;
}

/* What the walk collects: one entry per path per package.  */
struct entry
{
  uint32_t name_off, name_len;  /* In the names arena.  */
  uint32_t top;
  uint8_t d_type;
};

struct build
{
  const struct fswc_prefix *prefix;
  struct fswc_prefix_state state;
  uint32_t euid;
  uint64_t userns_id, mntns_id;
  struct arena mounts;          /* uint64_t, ascending.  */
  struct arena tops;            /* struct fswc_top.  */
  struct arena names;           /* Top names, then relative paths.  */
  struct arena entries;         /* struct entry.  */
  struct arena scratch;         /* Directory listings during the walk.  */
  char rel[PATH_MAX];
};

static bool
collect_mount (uint64_t id, void *closure)
{
  return push (closure, &id, sizeof (id)) != NULL;
}

/* Byte-order comparison of two names in NAMES.  */
static int
compare_names (const struct arena *names, uint32_t aoff, uint32_t alen,
               uint32_t boff, uint32_t blen)
{
  int c = memcmp (names->base + aoff, names->base + boff,
                  alen < blen ? alen : blen);
  return c != 0 ? c : (alen > blen) - (alen < blen);
}

/* Directory reading.  */

/* One child of a directory, in the scratch arena.  */
struct child
{
  uint32_t name_off;            /* In scratch.  */
  uint16_t name_len;
  uint8_t d_type;
};

/* Append every child of DIRFD (but "." and "..") to scratch as struct
   child records followed by their names.  Returns the number of
   children and sets *FIRST to the scratch offset of the first record,
   or returns -1.  Records and names are interleaved, so the records are
   found by walking from *FIRST.  */
static long
list_dir (struct build *b, int dirfd, size_t *first)
{
  char buf[8192] __attribute__ ((aligned (8)));
  long count = 0;
  *first = b->scratch.used;
  for (;;)
    {
      long n = INTERNAL_SYSCALL_CALL (getdents64, dirfd, buf, sizeof (buf));
      if (n < 0)
        return -1;
      if (n == 0)
        return count;
      for (long off = 0; off < n; )
        {
          const struct dirent64 *d = (const void *) (buf + off);
          off += d->d_reclen;
          if (d->d_name[0] == '.'
              && (d->d_name[1] == '\0'
                  || (d->d_name[1] == '.' && d->d_name[2] == '\0')))
            continue;
          size_t len = strlen (d->d_name);
          struct child c = { .name_len = len, .d_type = d->d_type };
          /* Keep records 4-byte aligned: pad the name.  */
          size_t padded = (len + 4) & ~(size_t) 3;
          struct child *rec = push (&b->scratch, &c, sizeof (c));
          if (rec == NULL)
            return -1;
          rec->name_off = b->scratch.used;
          char *name = push (&b->scratch, NULL, padded);
          if (name == NULL)
            return -1;
          memcpy (name, d->d_name, len + 1);
          ++count;
        }
    }
}

static uint8_t
dtype_of (int dirfd, const char *name)
{
  struct statx stx;
  if (INTERNAL_SYSCALL_CALL (statx, dirfd, name, AT_SYMLINK_NOFOLLOW,
                             STATX_TYPE, &stx) != 0)
    return DT_UNKNOWN;
  return IFTODT (stx.stx_mode);
}

/* Can everyone list and search the directory DIRFD, and does no POSIX ACL
   restrict it?  Only such packages are sealed, because the index is
   shared by everything the euid runs and must not reveal or hide what
   the kernel would.  */
static bool
world_readable (int dirfd)
{
  struct statx stx;
  if (INTERNAL_SYSCALL_CALL (statx, dirfd, "", AT_EMPTY_PATH, STATX_MODE,
                             &stx) != 0
      || (stx.stx_mode & 0005) != 0005)
    return false;
  long r = INTERNAL_SYSCALL_CALL (fgetxattr, dirfd, "system.posix_acl_access",
                                  NULL, 0);
  return r == -ENODATA || r == -EOPNOTSUPP;
}

/* Walk the directory DIRFD at B->rel[0..REL_LEN) of package TOP, adding an
   entry for every path beneath it.  */
static bool
walk (struct build *b, int dirfd, size_t rel_len, uint32_t top, int depth)
{
  if (depth > 64 || !world_readable (dirfd))
    return false;
  size_t mark = b->scratch.used;
  size_t first;
  long count = list_dir (b, dirfd, &first);
  bool ok = count >= 0;
  size_t pos = first;
  for (long i = 0; ok && i < count; ++i)
    {
      struct child *c = (struct child *) (b->scratch.base + pos);
      pos = c->name_off + ((c->name_len + 4) & ~(size_t) 3);
      const char *name = b->scratch.base + c->name_off;
      size_t len = rel_len + (rel_len > 0) + c->name_len;
      if (len >= sizeof (b->rel))
        {
          ok = false;
          break;
        }
      char *end = b->rel + rel_len;
      if (rel_len > 0)
        *end++ = '/';
      memcpy (end, name, c->name_len);
      b->rel[len] = '\0';

      uint8_t t = c->d_type != DT_UNKNOWN ? c->d_type : dtype_of (dirfd, name);
      char *stored = push (&b->names, b->rel, len);
      struct entry e = { .name_len = len, .top = top, .d_type = t };
      if (stored == NULL || t == DT_UNKNOWN)
        {
          ok = false;
          break;
        }
      e.name_off = stored - b->names.base;
      if (push (&b->entries, &e, sizeof (e)) == NULL)
        {
          ok = false;
          break;
        }
      if (t == DT_DIR)
        {
          long fd = INTERNAL_SYSCALL_CALL (openat, dirfd, name,
                                           O_RDONLY | O_DIRECTORY
                                           | O_NOFOLLOW | O_CLOEXEC, 0);
          if (INTERNAL_SYSCALL_ERROR_P (fd))
            ok = false;
          else
            {
              ok = walk (b, fd, len, top, depth + 1);
              INTERNAL_SYSCALL_CALL (close, fd);
            }
        }
    }
  b->scratch.used = mark;
  return ok;
}

/* Is the top-level directory NAME in PFD a sealed package: the root of a
   SquashFS mount with nothing mounted beneath it?  Prefixes registered by
   a test count every directory.  */
static bool
sealable (struct build *b, int pfd, const char *name)
{
  struct statx stx;
  if (INTERNAL_SYSCALL_CALL (statx, pfd, name, AT_SYMLINK_NOFOLLOW,
                             STATX_TYPE | FSWC_STATX_MNT_ID_UNIQUE, &stx) != 0
      || !S_ISDIR (stx.stx_mode))
    return false;
  if (b->prefix->test_sealed)
    return true;
  if (!(stx.stx_attributes & FSWC_STATX_ATTR_MOUNT_ROOT)
      || !(stx.stx_mask & FSWC_STATX_MNT_ID_UNIQUE)
      || stx.stx_mnt_id == b->state.mnt_id)
    return false;
  struct fswc_mnt_id_req req =
    {
      .size = FSWC_MNT_ID_REQ_SIZE_VER1,
      .mnt_id = stx.stx_mnt_id,
      .param = FSWC_STATMOUNT_SB_BASIC,
    };
  struct fswc_statmount sm;
  if (INTERNAL_SYSCALL_CALL (statmount, &req, &sm, sizeof (sm), 0) != 0
      || !(sm.mask & FSWC_STATMOUNT_SB_BASIC)
      || sm.sb_magic != FSWC_SQUASHFS_MAGIC)
    return false;
  uint64_t one;
  struct fswc_mnt_id_req lreq =
    { .size = FSWC_MNT_ID_REQ_SIZE_VER1, .mnt_id = stx.stx_mnt_id };
  return INTERNAL_SYSCALL_CALL (listmount, &lreq, &one, 1, 0) == 0;
}

/* Read the prefix: one fswc_top per name, sorted; walk sealed packages.  */
static bool
scan (struct build *b)
{
  long pfd = INTERNAL_SYSCALL_CALL (openat, AT_FDCWD, b->prefix->path,
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                                    | O_CLOEXEC, 0);
  if (INTERNAL_SYSCALL_ERROR_P (pfd))
    return false;
  size_t first;
  long count = list_dir (b, pfd, &first);
  bool ok = count >= 0 && count < (1L << 24);
  size_t pos = first;
  for (long i = 0; ok && i < count; ++i)
    {
      struct child *c = (struct child *) (b->scratch.base + pos);
      pos = c->name_off + ((c->name_len + 4) & ~(size_t) 3);
      char *stored = push (&b->names, b->scratch.base + c->name_off,
                           c->name_len);
      struct fswc_top t = { .name_len = c->name_len, .d_type = c->d_type };
      if (stored == NULL)
        ok = false;
      else
        {
          t.name_off = stored - b->names.base;
          ok = push (&b->tops, &t, sizeof (t)) != NULL;
        }
    }
  b->scratch.used = 0;

  /* Sort the names (insertion sort: a prefix holds hundreds of names).  */
  struct fswc_top *tops = (struct fswc_top *) b->tops.base;
  size_t ntop = b->tops.used / sizeof (struct fswc_top);
  for (size_t i = 1; ok && i < ntop; ++i)
    {
      struct fswc_top cur = tops[i];
      size_t j = i;
      while (j > 0 && compare_names (&b->names, tops[j - 1].name_off,
                                     tops[j - 1].name_len, cur.name_off,
                                     cur.name_len) > 0)
        {
          tops[j] = tops[j - 1];
          --j;
        }
      tops[j] = cur;
    }

  /* Walk each sealed package; a package that cannot be walked completely
     stays unsealed and its partial entries are dropped.  */
  for (size_t i = 0; ok && i < ntop; ++i)
    {
      char name[NAME_MAX + 1];
      memcpy (name, b->names.base + tops[i].name_off, tops[i].name_len);
      name[tops[i].name_len] = '\0';
      if (tops[i].d_type == DT_UNKNOWN)
        tops[i].d_type = dtype_of (pfd, name);
      if (!sealable (b, pfd, name))
        continue;
      long fd = INTERNAL_SYSCALL_CALL (openat, pfd, name,
                                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                                       | O_CLOEXEC, 0);
      if (INTERNAL_SYSCALL_ERROR_P (fd))
        continue;
      size_t entries_mark = b->entries.used;
      size_t names_mark = b->names.used;
      b->rel[0] = '\0';
      bool walked = walk (b, fd, 0, i, 0);
      INTERNAL_SYSCALL_CALL (close, fd);
      if (walked)
        tops[i].sealed = 1;
      else
        {
          b->entries.used = entries_mark;
          b->names.used = names_mark;
        }
    }
  INTERNAL_SYSCALL_CALL (close, pfd);
  return ok;
}

/* Bottom-up merge sort of IDX[0..N) (indexes into ENTRIES) by (path,
   package), using TMP.  */
static void
sort_entries (const struct build *b, uint32_t *idx, uint32_t *tmp, size_t n)
{
  const struct entry *e = (const struct entry *) b->entries.base;
  for (size_t width = 1; width < n; width *= 2)
    {
      for (size_t lo = 0; lo < n; lo += 2 * width)
        {
          size_t mid = lo + width < n ? lo + width : n;
          size_t hi = lo + 2 * width < n ? lo + 2 * width : n;
          size_t i = lo, j = mid, k = lo;
          while (i < mid && j < hi)
            {
              const struct entry *x = &e[idx[i]], *y = &e[idx[j]];
              int c = compare_names (&b->names, x->name_off, x->name_len,
                                     y->name_off, y->name_len);
              if (c < 0 || (c == 0 && x->top <= y->top))
                tmp[k++] = idx[i++];
              else
                tmp[k++] = idx[j++];
            }
          while (i < mid)
            tmp[k++] = idx[i++];
          while (j < hi)
            tmp[k++] = idx[j++];
        }
      memcpy (idx, tmp, n * sizeof (*idx));
    }
}

/* Lay the index out in OUT: header, mounts, tops, paths, postings,
   strings.  */
static bool
assemble (struct build *b, struct arena *out)
{
  size_t nent = b->entries.used / sizeof (struct entry);
  size_t ntop = b->tops.used / sizeof (struct fswc_top);
  size_t nmount = b->mounts.used / sizeof (uint64_t);
  if (nent >= UINT32_MAX / 4 || b->names.used >= UINT32_MAX / 2)
    return false;

  struct arena order = { 0 };
  bool ok = reserve (&order, 2 * nent * sizeof (uint32_t) + 8);
  uint32_t *idx = (uint32_t *) order.base;
  if (ok)
    {
      for (size_t i = 0; i < nent; ++i)
        idx[i] = i;
      sort_entries (b, idx, idx + nent, nent);
    }

  /* Count distinct paths.  */
  const struct entry *e = (const struct entry *) b->entries.base;
  size_t npath = 0;
  for (size_t i = 0; ok && i < nent; ++i)
    if (i == 0 || compare_names (&b->names, e[idx[i - 1]].name_off,
                                 e[idx[i - 1]].name_len, e[idx[i]].name_off,
                                 e[idx[i]].name_len) != 0)
      ++npath;

  struct fswc_idx_header h =
    {
      .magic = FSWC_MAGIC,
      .version = FSWC_VERSION,
      .mntns_id = b->mntns_id,
      .userns_id = b->userns_id,
      .prefix_mnt_id = b->state.mnt_id,
      .prefix_dev = b->state.dev,
      .prefix_ino = b->state.ino,
      .prefix_ctime_sec = b->state.ctime_sec,
      .prefix_ctime_nsec = b->state.ctime_nsec,
      .euid = b->euid,
      .num_mounts = nmount,
      .num_top = ntop,
      .num_paths = npath,
      .num_postings = nent,
    };
  size_t off = sizeof (h);
  h.mounts_off = off;
  off += nmount * sizeof (uint64_t);
  h.top_off = off;
  off += ntop * sizeof (struct fswc_top);
  off = (off + 7) & ~(size_t) 7;
  h.paths_off = off;
  off += npath * sizeof (struct fswc_path);
  h.postings_off = off;
  off += nent * sizeof (uint32_t);
  h.strtab_off = off;
  /* The strings: every top name, then each distinct path once.  The
     names arena already holds them, with duplicates.  */
  size_t strtab_max = b->names.used;
  if (ok && (off > UINT32_MAX - strtab_max || !reserve (out, off + strtab_max)))
    ok = false;
  if (!ok)
    {
      release (&order);
      return false;
    }

  char *base = out->base;
  memset (base, 0, off);
  memcpy (base + h.mounts_off, b->mounts.base, nmount * sizeof (uint64_t));
  struct fswc_top *tops = (struct fswc_top *) (base + h.top_off);
  struct fswc_path *paths = (struct fswc_path *) (base + h.paths_off);
  uint32_t *postings = (uint32_t *) (base + h.postings_off);
  char *strtab = base + h.strtab_off;
  uint32_t str_used = 0;

  for (size_t i = 0; i < ntop; ++i)
    {
      const struct fswc_top *t = &((const struct fswc_top *) b->tops.base)[i];
      tops[i] = *t;
      tops[i].name_off = str_used;
      memcpy (strtab + str_used, b->names.base + t->name_off, t->name_len);
      str_used += t->name_len;
    }

  size_t p = (size_t) -1;
  for (size_t i = 0; i < nent; ++i)
    {
      const struct entry *x = &e[idx[i]];
      if (i == 0 || compare_names (&b->names, e[idx[i - 1]].name_off,
                                   e[idx[i - 1]].name_len, x->name_off,
                                   x->name_len) != 0)
        {
          ++p;
          paths[p].name_off = str_used;
          paths[p].name_len = x->name_len;
          paths[p].posting = i;
          paths[p].count = 0;
          memcpy (strtab + str_used, b->names.base + x->name_off,
                  x->name_len);
          str_used += x->name_len;
        }
      postings[i] = (x->top << 8) | x->d_type;
      ++paths[p].count;
    }

  h.strtab_size = str_used;
  h.total_size = h.strtab_off + str_used;
  memcpy (base, &h, sizeof (h));
  out->used = h.total_size;
  release (&order);
  return true;
}

/* Write DATA to a new file and rename it to NAME in DIRFD.  */
static bool
publish (int dirfd, const char *name, const char *data, size_t len)
{
  char tmp[64];
  char *p = __stpcpy (tmp, ".tmp-");
  p = __fswc_fmt_u64 (p, INTERNAL_SYSCALL_CALL (getpid));
  *p++ = '-';
  uint32_t salt = 0;
  INTERNAL_SYSCALL_CALL (getrandom, &salt, sizeof (salt), 1 /* NONBLOCK */);
  __fswc_fmt_u64 (p, salt);

  long fd = INTERNAL_SYSCALL_CALL (openat, dirfd, tmp,
                                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW
                                   | O_CLOEXEC, 0400);
  if (INTERNAL_SYSCALL_ERROR_P (fd))
    return false;
  bool ok = true;
  while (ok && len > 0)
    {
      long n = INTERNAL_SYSCALL_CALL (write, fd, data, len);
      if (n <= 0)
        ok = false;
      else
        {
          data += n;
          len -= n;
        }
    }
  ok = INTERNAL_SYSCALL_CALL (close, fd) == 0 && ok;
  if (ok)
    ok = INTERNAL_SYSCALL_CALL (renameat, dirfd, tmp, dirfd, name) == 0;
  if (!ok)
    INTERNAL_SYSCALL_CALL (unlinkat, dirfd, tmp, 0);
  return ok;
}

/* Sweeping.  */

/* Does the mount namespace MNTNS_ID still exist?  listmount on a dead
   namespace fails with ENOENT; on a live one we cannot inspect, EPERM.  */
static bool
mntns_gone (uint64_t mntns_id)
{
  uint64_t id;
  struct fswc_mnt_id_req req =
    {
      .size = FSWC_MNT_ID_REQ_SIZE_VER1,
      .mnt_id = FSWC_LSMT_ROOT,
      .mnt_ns_id = mntns_id,
    };
  return INTERNAL_SYSCALL_CALL (listmount, &req, &id, 1, 0) == -ENOENT;
}

/* Does this process have CAP_SYS_ADMIN (in its user namespace)?  Without
   it, listmount reports every other mount namespace as missing, live or
   not, so mntns_gone proves nothing.  */
static bool
sees_other_mntns (void)
{
  struct
  {
    uint32_t version;
    int pid;
  } hdr = { 0x20080522, 0 };    /* _LINUX_CAPABILITY_VERSION_3.  */
  struct
  {
    uint32_t effective, permitted, inheritable;
  } data[2];
  return (INTERNAL_SYSCALL_CALL (capget, &hdr, data) == 0
          && (data[0].effective & (1u << 21)) != 0);    /* CAP_SYS_ADMIN.  */
}

/* How old an index of a namespace that only might be gone must be before
   an unprivileged sweep removes it.  A live one removed by mistake costs
   its namespace one rebuild.  */
enum { UNSURE_AGE = 24 * 60 * 60 };

/* Was NAME in DIRFD last modified more than AGE seconds before NOW?  */
static bool
older_than (int dirfd, const char *name, int64_t now, int64_t age)
{
  struct statx stx;
  return INTERNAL_SYSCALL_CALL (statx, dirfd, name, AT_SYMLINK_NOFOLLOW,
                                STATX_MTIME, &stx) == 0
         && now - stx.stx_mtime.tv_sec > age;
}

/* In DIRFD, remove indexes and locks of dead mount namespaces, and
   temporary files older than a minute.  SURE says whether listmount can
   tell a dead namespace from one this process may not see; if not, only
   files older than UNSURE_AGE go.  Returns whether DIRFD is now empty.  */
static bool
sweep_dir (struct build *b, int dirfd, int64_t now, bool sure)
{
  size_t first;
  long count = list_dir (b, dirfd, &first);
  if (count < 0)
    return false;
  long kept = 0;
  size_t pos = first;
  for (long i = 0; i < count; ++i)
    {
      struct child *c = (struct child *) (b->scratch.base + pos);
      pos = c->name_off + ((c->name_len + 4) & ~(size_t) 3);
      const char *name = b->scratch.base + c->name_off;
      const char *ns = NULL;
      if (strncmp (name, "idx-", 4) == 0)
        ns = name + 4;
      else if (strncmp (name, "lock-", 5) == 0)
        ns = name + 5;
      bool remove = false;
      if (ns != NULL)
        {
          uint64_t id = 0;
          while (*ns >= '0' && *ns <= '9')
            id = id * 10 + (*ns++ - '0');
          remove = *ns == '-' && mntns_gone (id)
                   && (sure || older_than (dirfd, name, now, UNSURE_AGE));
        }
      else if (strncmp (name, ".tmp-", 5) == 0)
        remove = older_than (dirfd, name, now, 60);
      if (!(remove && INTERNAL_SYSCALL_CALL (unlinkat, dirfd, name, 0) == 0))
        ++kept;
    }
  b->scratch.used = first;
  return kept == 0;
}

/* Sweep every FSWC directory in /dev/shm that this euid owns: its own and
   those left by other user namespaces.  Each new namespace gets its own
   index and nothing else deletes one, so without this /dev/shm (RAM)
   grows until reboot.  The index is a hint, so deleting one costs at most
   a rebuild; processes that have it mapped keep their mapping.  */
static void
sweep (struct build *b)
{
  struct timespec ts;
  if (__clock_gettime (CLOCK_REALTIME_COARSE, &ts) != 0)
    return;
  long shm = INTERNAL_SYSCALL_CALL (openat, AT_FDCWD, "/dev/shm",
                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
  if (INTERNAL_SYSCALL_ERROR_P (shm))
    return;
  bool sure = sees_other_mntns ();
  size_t first;
  long count = list_dir (b, shm, &first);
  size_t pos = first;
  for (long i = 0; i < count; ++i)
    {
      /* Offsets, not pointers: sweep_dir may move the scratch arena.  */
      const struct child *c = (const struct child *) (b->scratch.base + pos);
      size_t name_off = c->name_off;
      pos = name_off + ((c->name_len + 4) & ~(size_t) 3);
      const char *name = b->scratch.base + name_off;
      if (strncmp (name, ".fswc-", 6) != 0 || strchr (name + 6, '-') == NULL)
        continue;
      long fd = INTERNAL_SYSCALL_CALL (openat, shm, name,
                                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                                       | O_CLOEXEC, 0);
      if (INTERNAL_SYSCALL_ERROR_P (fd))
        continue;
      struct statx stx;
      bool mine = INTERNAL_SYSCALL_CALL (statx, fd, "", AT_EMPTY_PATH,
                                         STATX_UID, &stx) == 0
                  && stx.stx_uid == b->euid;
      bool empty = mine && sweep_dir (b, fd, ts.tv_sec, sure);
      INTERNAL_SYSCALL_CALL (close, fd);
      if (empty)
        INTERNAL_SYSCALL_CALL (unlinkat, shm, b->scratch.base + name_off,
                               AT_REMOVEDIR);
    }
  INTERNAL_SYSCALL_CALL (close, shm);
}

/* Building.  */

static bool
same_mounts (const struct build *b)
{
  struct arena now = { 0 };
  bool ok = __fswc_each_mount_beneath (b->state.mnt_id, collect_mount, &now)
            && now.used == b->mounts.used
            && memcmp (now.base, b->mounts.base, now.used) == 0;
  release (&now);
  return ok;
}

static bool
build_one (const struct fswc_prefix *prefix)
{
  struct build *b = __mmap (NULL, sizeof (*b), PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (b == MAP_FAILED)
    return false;
  b->prefix = prefix;
  b->euid = INTERNAL_SYSCALL_CALL (geteuid);
  bool ok = false;
  int dirfd = -1;
  long lockfd = -1;

  if (!__fswc_userns_id (&b->userns_id)
      || !__fswc_prefix_state (prefix->path, &b->state)
      || !__fswc_mntns_id (b->state.mnt_id, &b->mntns_id))
    goto out;
  dirfd = __fswc_open_dir (b->euid, b->userns_id, true);
  if (dirfd < 0)
    goto out;

  /* One builder per index at a time; the others carry on without.  */
  char name[96];
  __fswc_index_name (name, "lock", b->mntns_id, b->state.dev, b->state.ino);
  lockfd = INTERNAL_SYSCALL_CALL (openat, dirfd, name,
                                  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                                  0600);
  if (INTERNAL_SYSCALL_ERROR_P (lockfd)
      || INTERNAL_SYSCALL_CALL (flock, lockfd, LOCK_EX | LOCK_NB) != 0)
    goto out;

  /* A change within the current tick of a coarse clock may not move the
     prefix's ctime, so a snapshot taken now could miss it.  Leave such a
     prefix for a later process.  */
  struct timespec now;
  if (__clock_gettime (CLOCK_REALTIME_COARSE, &now) != 0
      || b->state.ctime_sec > now.tv_sec
      || (b->state.ctime_sec == now.tv_sec
          && b->state.ctime_nsec >= (uint32_t) now.tv_nsec))
    goto out;

  if (!__fswc_each_mount_beneath (b->state.mnt_id, collect_mount, &b->mounts)
      || !scan (b))
    goto out;

  /* Discard the snapshot if anything moved while it was taken.  */
  struct fswc_prefix_state after;
  if (!__fswc_prefix_state (prefix->path, &after)
      || after.mnt_id != b->state.mnt_id || after.dev != b->state.dev
      || after.ino != b->state.ino || after.ctime_sec != b->state.ctime_sec
      || after.ctime_nsec != b->state.ctime_nsec
      || !same_mounts (b))
    goto out;

  struct arena file = { 0 };
  __fswc_index_name (name, "idx", b->mntns_id, b->state.dev, b->state.ino);
  ok = assemble (b, &file) && publish (dirfd, name, file.base, file.used);
  release (&file);
  if (ok)
    sweep (b);

out:
  if (lockfd >= 0)
    INTERNAL_SYSCALL_CALL (close, lockfd);
  if (dirfd >= 0)
    INTERNAL_SYSCALL_CALL (close, dirfd);
  release (&b->mounts);
  release (&b->tops);
  release (&b->names);
  release (&b->entries);
  release (&b->scratch);
  __munmap (b, sizeof (*b));
  return ok;
}

void
__fswc_build_all (void)
{
  if (__libc_enable_secure)
    return;
  __fswc_prefixes_init ();
  unsigned int n = atomic_load_acquire (&GL (dl_fswc).num_prefixes);
  for (unsigned int i = 0; i < n; ++i)
    {
      const struct fswc_prefix *p = &GL (dl_fswc).prefixes[i];
      /* Mapping a valid index here also serves this process's lookups.  */
      if (__fswc_index_get (p->path, p->len) == NULL && build_one (p))
        __fswc_reset_cache ();
    }
}

/* Remove PREFIX's index and lock file, if any.  */
static void
remove_index (const struct fswc_prefix *p)
{
  uint64_t userns_id, mntns_id;
  struct fswc_prefix_state state;
  if (!__fswc_userns_id (&userns_id) || !__fswc_prefix_state (p->path, &state)
      || !__fswc_mntns_id (state.mnt_id, &mntns_id))
    return;
  int dirfd = __fswc_open_dir (INTERNAL_SYSCALL_CALL (geteuid), userns_id,
                               false);
  if (dirfd < 0)
    return;
  char name[96];
  __fswc_index_name (name, "idx", mntns_id, state.dev, state.ino);
  INTERNAL_SYSCALL_CALL (unlinkat, dirfd, name, 0);
  __fswc_index_name (name, "lock", mntns_id, state.dev, state.ino);
  INTERNAL_SYSCALL_CALL (unlinkat, dirfd, name, 0);
  INTERNAL_SYSCALL_CALL (close, dirfd);
}

int
__fswc_test_prefix (const char *prefix, int op)
{
  size_t len = strlen (prefix);
  const struct fswc_prefix *p = __fswc_register_test_prefix (prefix, len);
  if (p == NULL)
    return ENOSPC;
  if (op == FSWC_TEST_BUILD)
    build_one (p);
  else if (op == FSWC_TEST_REMOVE)
    remove_index (p);
  __fswc_reset_cache ();
  return __fswc_index_get (p->path, p->len) != NULL ? 0 : ENOENT;
}
