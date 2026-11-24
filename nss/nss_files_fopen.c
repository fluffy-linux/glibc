/* Open an nss_files database file.
   Copyright (C) 2020-2026 Free Software Foundation, Inc.
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

#include <nss_files.h>

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <libio/libioP.h>
#include <not-cancel.h>
#include <paths.h>
#include <stdint.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define NSS_MULTIFILE_MAGIC UINT64_C (0x464c55464e53534d)

struct nss_multifile_seg
{
  int fd;
  off64_t start;
  off64_t size;
};

struct nss_multifile_cookie
{
  uint64_t magic;
  size_t nfiles;
  off64_t total_size;
  off64_t pos;
  struct nss_multifile_seg segs[];
};

static size_t
nss_multifile_locate (const struct nss_multifile_cookie *c, off64_t off)
{
  size_t lo = 0;
  size_t hi = c->nfiles;
  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;
      off64_t seg_end = c->segs[mid].start + c->segs[mid].size + 1;
      if (off < seg_end)
        hi = mid;
      else
        lo = mid + 1;
    }
  return lo;
}

static ssize_t
nss_multifile_read (void *vc, char *buf, size_t size)
{
  struct nss_multifile_cookie *c = vc;
  if (size == 0 || c->pos >= c->total_size)
    return 0;

  size_t total = 0;
  size_t idx = nss_multifile_locate (c, c->pos);

  while (total < size && idx < c->nfiles)
    {
      const struct nss_multifile_seg *seg = &c->segs[idx];
      off64_t rel = c->pos - seg->start;
      if (rel < seg->size)
        {
          off64_t avail = seg->size - rel;
          size_t want = size - total;
          if ((off64_t) want > avail)
            want = (size_t) avail;
          ssize_t nr = __pread64_nocancel (seg->fd, buf + total, want, rel);
          if (nr < 0)
            return total > 0 ? (ssize_t) total : -1;
          if (nr == 0)
            {
              /* Keep virtual offsets stable if a mutable file shrank.  */
              memset (buf + total, '\n', want);
              nr = (ssize_t) want;
            }
          total += (size_t) nr;
          c->pos += nr;
        }
      else
        {
          /* Virtual newline separator guaranteeing line termination.  */
          buf[total++] = '\n';
          c->pos += 1;
          ++idx;
        }
    }

  return (ssize_t) total;
}

static int
nss_multifile_seek (void *vc, off64_t *offset, int whence)
{
  struct nss_multifile_cookie *c = vc;
  off64_t target;

  switch (whence)
    {
    case SEEK_SET:
      target = *offset;
      break;
    case SEEK_CUR:
      if (__builtin_add_overflow (c->pos, *offset, &target))
        {
          __set_errno (EINVAL);
          return -1;
        }
      break;
    case SEEK_END:
      if (__builtin_add_overflow (c->total_size, *offset, &target))
        {
          __set_errno (EINVAL);
          return -1;
        }
      break;
    default:
      __set_errno (EINVAL);
      return -1;
    }

  if (target < 0)
    {
      __set_errno (EINVAL);
      return -1;
    }

  c->pos = target;
  *offset = target;
  return 0;
}

static int
nss_multifile_close (void *vc)
{
  struct nss_multifile_cookie *c = vc;
  for (size_t i = 0; i < c->nfiles; ++i)
    if (c->segs[i].fd >= 0)
      __close_nocancel_nostatus (c->segs[i].fd);
  free (c);
  return 0;
}

static const cookie_io_functions_t nss_multifile_io_funcs =
  {
    .read = nss_multifile_read,
    .write = NULL,
    .seek = nss_multifile_seek,
    .close = nss_multifile_close
  };

int
__nss_files_file_index (FILE *fp, off64_t offset)
{
  if (fp == NULL || fp->_fileno != -2 || offset < 0)
    return -1;
  if (_IO_JUMPS ((struct _IO_FILE_plus *) fp) != &_IO_cookie_jumps)
    return -1;

  const struct _IO_cookie_file *cf = (const struct _IO_cookie_file *) fp;
  const struct nss_multifile_cookie *c = cf->__cookie;
  if (c == NULL || c->magic != NSS_MULTIFILE_MAGIC || offset >= c->total_size)
    return -1;

  size_t idx = nss_multifile_locate (c, offset);
  return idx < c->nfiles ? (int) idx : -1;
}

static FILE *
nss_finalize_fp (FILE *fp)
{
  if (fp == NULL)
    return NULL;

  /* The stream is not shared across threads.  */
  __fsetlocking (fp, FSETLOCKING_BYCALLER);

  /* This tells libio that the file is seekable, and that fp->_offset
     is correct, ensuring that __ftello64 is efficient (bug 26257).  */
  if (__fseeko64 (fp, 0, SEEK_SET) < 0)
    {
      /* nss_files requires seekable files, to deal with repeated
         reads of the same line after reporting ERANGE.  */
      fclose (fp);
      __set_errno (ESPIPE);
      return NULL;
    }

  return fp;
}

static char *
nss_build_glob_pattern (const char *dirs, const char *rel)
{
  size_t rel_len = strlen (rel);
  size_t dirs_len = strlen (dirs);
  size_t nsegs = 1;
  for (size_t i = 0; i < dirs_len; ++i)
    if (dirs[i] == ':')
      ++nsegs;

  size_t cap = dirs_len + nsegs * (rel_len + 2) + 1;
  char *pat = malloc (cap);
  if (pat == NULL)
    return NULL;

  char *out = pat;
  const char *p = dirs;
  while (1)
    {
      const char *colon = strchr (p, ':');
      size_t dlen = colon != NULL ? (size_t) (colon - p) : strlen (p);
      while (dlen > 1 && p[dlen - 1] == '/')
        --dlen;
      if (dlen > 0)
        {
          if (out != pat)
            *out++ = ':';
          memcpy (out, p, dlen);
          out += dlen;
          if (p[dlen - 1] != '/')
            *out++ = '/';
          memcpy (out, rel, rel_len);
          out += rel_len;
        }
      if (colon == NULL)
        break;
      p = colon + 1;
    }
  *out = '\0';
  return pat;
}

FILE *
__nss_files_fopen (const char *path)
{
  if (path == NULL || strncmp (path, "/etc/", 5) != 0 || path[5] == '\0'
      || strpbrk (path + 5, "*?[\\:") != NULL)
    return nss_finalize_fp (fopen (path, "rce"));

  int saved_errno = errno;
  char *pat = nss_build_glob_pattern (_PATH_NSS_FILES_DIRS, path + 5);
  if (pat == NULL)
    return NULL;

  glob64_t gl;
  int gr = __glob64_notilde (pat, GLOB_PATHS, NULL, &gl);
  free (pat);

  if (gr == GLOB_NOSPACE)
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  if (gr != 0 || gl.gl_pathc == 0)
    {
      if (gr == 0)
        __globfree64 (&gl);
      __set_errno (saved_errno);
      return nss_finalize_fp (fopen (path, "rce"));
    }

  if (gl.gl_pathc == 1)
    {
      __set_errno (saved_errno);
      FILE *fp = nss_finalize_fp (fopen (gl.gl_pathv[0], "rce"));
      int open_err = errno;
      __globfree64 (&gl);
      if (fp == NULL)
        __set_errno (open_err);
      return fp;
    }

  size_t max_files = gl.gl_pathc;
  struct nss_multifile_cookie *c
    = malloc (sizeof (*c) + max_files * sizeof (c->segs[0]));
  if (c == NULL)
    {
      __globfree64 (&gl);
      return NULL;
    }

  c->magic = NSS_MULTIFILE_MAGIC;
  c->nfiles = 0;
  c->total_size = 0;
  c->pos = 0;
  int first_err = ENOENT;

  for (size_t i = 0; i < max_files; ++i)
    {
      int fd = __open64_nocancel (gl.gl_pathv[i], O_RDONLY | O_CLOEXEC);
      if (fd < 0)
        {
          if (first_err == ENOENT)
            first_err = errno;
          if (errno == ENOMEM || errno == EMFILE || errno == ENFILE)
            {
              first_err = errno;
              nss_multifile_close (c);
              __globfree64 (&gl);
              __set_errno (first_err);
              return NULL;
            }
          continue;
        }

      struct __stat64_t64 st;
      if (__fstat64_time64 (fd, &st) != 0 || S_ISDIR (st.st_mode)
          || st.st_size < 0)
        {
          if (S_ISDIR (st.st_mode) && first_err == ENOENT)
            first_err = EISDIR;
          __close_nocancel_nostatus (fd);
          continue;
        }

      off64_t next_total;
      if (__builtin_add_overflow (c->total_size, st.st_size, &next_total)
          || __builtin_add_overflow (next_total, (off64_t) 1, &next_total))
        {
          __close_nocancel_nostatus (fd);
          nss_multifile_close (c);
          __globfree64 (&gl);
          __set_errno (EOVERFLOW);
          return NULL;
        }

      c->segs[c->nfiles].fd = fd;
      c->segs[c->nfiles].start = c->total_size;
      c->segs[c->nfiles].size = st.st_size;
      c->total_size = next_total;
      ++c->nfiles;
    }

  __globfree64 (&gl);

  if (c->nfiles == 0)
    {
      free (c);
      __set_errno (saved_errno);
      FILE *fp = nss_finalize_fp (fopen (path, "rce"));
      if (fp == NULL && errno == ENOENT && first_err != ENOENT)
        __set_errno (first_err);
      return fp;
    }

  if (c->nfiles == 1)
    {
      int fd = c->segs[0].fd;
      free (c);
      __set_errno (saved_errno);
      FILE *fp = fdopen (fd, "rce");
      if (fp == NULL)
        {
          int err = errno;
          __close_nocancel_nostatus (fd);
          __set_errno (err);
          return NULL;
        }
      return nss_finalize_fp (fp);
    }

  FILE *fp = _IO_fopencookie (c, "r", nss_multifile_io_funcs);
  if (fp == NULL)
    {
      int err = errno;
      nss_multifile_close (c);
      __set_errno (err);
      return NULL;
    }

  __fsetlocking (fp, FSETLOCKING_BYCALLER);
  __set_errno (saved_errno);
  return fp;
}
libc_hidden_def (__nss_files_fopen)
