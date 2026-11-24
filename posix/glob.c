/* Copyright (C) 1991-2026 Free Software Foundation, Inc.
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

#ifndef _LIBC

/* Don't use __attribute__ __nonnull__ in this compilation unit.  Otherwise gcc
   optimizes away the pattern == NULL test below.  */
# define _GL_ARG_NONNULL(params)

# include <libc-config.h>

#endif

#include <glob.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>

#if defined _WIN32 && ! defined __CYGWIN__
# define WINDOWS32
#endif

#ifndef WINDOWS32
# include <pwd.h>
#endif

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

#ifdef _LIBC
# undef strdup
# define strdup(str) __strdup (str)
# define sysconf(id) __sysconf (id)
# define closedir(dir) __closedir (dir)
# define opendir(name) __opendir (name)
# undef dirfd
# define dirfd(str) __dirfd (str)
# define readdir(str) __readdir64 (str)
# define getpwnam_r(name, bufp, buf, len, res) \
    __getpwnam_r (name, bufp, buf, len, res)
# define FLEXIBLE_ARRAY_MEMBER
# ifndef struct_stat
#  define struct_stat           struct stat
# endif
# ifndef struct_stat64
#  define struct_stat64         struct stat64
# endif
# ifndef GLOB_LSTAT
#  define GLOB_LSTAT            gl_lstat
# endif
# ifndef GLOB_FSTATAT64
#  define GLOB_FSTATAT64        __fstatat64
# endif
# include <shlib-compat.h>
#else /* !_LIBC */
# define __glob                 glob
# define __getlogin_r(buf, len) getlogin_r (buf, len)
# define __fxstatat64(_, d, f, st, flag) fstatat (d, f, st, flag)
# ifndef __MVS__
#  define __alloca              alloca
# endif
# define __readdir              readdir
# define COMPILE_GLOB64
# define struct_stat            struct stat
# define struct_stat64          struct stat
# define GLOB_LSTAT             gl_lstat
# define GLOB_FSTATAT64         fstatat
#endif /* _LIBC */

#include <fnmatch.h>

#include <flexmember.h>
#include <glob_internal.h>
#include <scratch_buffer.h>
#if defined _LIBC && defined __linux__
# include <fswc-index.h>
# define GLOB_FSWC 1
#else
# define GLOB_FSWC 0
#endif

static const char *next_brace_sub (const char *begin, int flags) __THROWNL;

/* The type of ((struct dirent *) 0)->d_type is 'unsigned char' on most
   platforms, but 'unsigned int' in the mingw from mingw.org.  */
typedef uint_fast32_t dirent_type;

#if !defined _LIBC && !defined HAVE_STRUCT_DIRENT_D_TYPE
/* Any distinct values will do here.
   Undef any existing macros out of the way.  */
# undef DT_UNKNOWN
# undef DT_DIR
# undef DT_LNK
# define DT_UNKNOWN 0
# define DT_DIR 1
# define DT_LNK 2
#endif

/* A representation of a directory entry which does not depend on the
   layout of struct dirent, or the size of ino_t.  */
struct readdir_result
{
  const char *name;
#if defined _DIRENT_HAVE_D_TYPE || defined HAVE_STRUCT_DIRENT_D_TYPE
  dirent_type type;
#endif
};

/* Initialize and return type member of struct readdir_result.  */
static dirent_type
readdir_result_type (struct readdir_result d)
{
#if defined _DIRENT_HAVE_D_TYPE || defined HAVE_STRUCT_DIRENT_D_TYPE
# define D_TYPE_TO_RESULT(source) (source)->d_type,
  return d.type;
#else
# define D_TYPE_TO_RESULT(source)
  return DT_UNKNOWN;
#endif
}

/* Construct an initializer for a struct readdir_result object from a
   struct dirent *.  No copy of the name is made.  */
#define READDIR_RESULT_INITIALIZER(source) \
  {                                        \
    source->d_name,                        \
    D_TYPE_TO_RESULT (source)              \
  }

/* Call gl_readdir on STREAM.  This macro can be overridden to reduce
   type safety if an old interface version needs to be supported.  */
#ifndef GL_READDIR
# define GL_READDIR(pglob, stream) ((pglob)->gl_readdir (stream))
#endif

/* Extract name and type from directory entry.  No copy of the name is
   made.  If SOURCE is NULL, result name is NULL.  Keep in sync with
   convert_dirent64 below.  */
static struct readdir_result
convert_dirent (const struct dirent *source)
{
  if (source == NULL)
    {
      struct readdir_result result = { NULL, };
      return result;
    }
  struct readdir_result result = READDIR_RESULT_INITIALIZER (source);
  return result;
}

#ifndef COMPILE_GLOB64
/* Like convert_dirent, but works on struct dirent64 instead.  Keep in
   sync with convert_dirent above.  */
static struct readdir_result
convert_dirent64 (const struct dirent64 *source)
{
  if (source == NULL)
    {
      struct readdir_result result = { NULL, };
      return result;
    }
  struct readdir_result result = READDIR_RESULT_INITIALIZER (source);
  return result;
}
#endif

#ifndef _LIBC
/* The results of opendir() in this file are not used with dirfd and fchdir,
   and we do not leak fds to any single-threaded code that could use stdio,
   therefore save some unnecessary recursion in fchdir.c and opendir_safer.c.
   FIXME - if the kernel ever adds support for multi-thread safety for
   avoiding standard fds, then we should use opendir_safer.  */
# ifdef GNULIB_defined_opendir
#  undef opendir
# endif
# ifdef GNULIB_defined_closedir
#  undef closedir
# endif

/* Just use malloc.  */
# define __libc_use_alloca(n) false
# define alloca_account(len, avar) ((void) (len), (void) (avar), (void *) 0)
# define extend_alloca_account(buf, len, newlen, avar) \
    ((void) (buf), (void) (len), (void) (newlen), (void) (avar), (void *) 0)
#endif

#if GLOB_FSWC
/* The FSWC state of the glob call running in this thread: which prefix
   was validated, and the index if it is valid.  Each prefix is validated
   at most once per glob call.  */
static __thread struct fswc_call *glob_fswc_call;
#endif

/* fstatat (AT_FDCWD, NAME, ST, ATFLAGS) when the caller gave no
   GLOB_ALTDIRFUNC hooks.  Where FSWC can prove what NAME is, the answer
   comes from its index; otherwise from the kernel.  Callers only use the
   result and the file type.  */
static int
glob_fstatat (const char *name, struct_stat64 *st, int atflags)
{
#if GLOB_FSWC
  struct fswc_call local = { 0 };
  struct fswc_call *call = glob_fswc_call != NULL ? glob_fswc_call : &local;
  int t = __fswc_answer (call, name, !(atflags & AT_SYMLINK_NOFOLLOW));
  if (t == FSWC_ABSENT)
    {
      __set_errno (ENOENT);
      return -1;
    }
  if (t > 0)
    {
      memset (st, 0, sizeof (*st));
      st->st_mode = DTTOIF (t);
      return 0;
    }
#endif
  return GLOB_FSTATAT64 (AT_FDCWD, name, st, atflags);
}

static int
glob_lstat (glob_t *pglob, int flags, const char *fullname)
{
/* Use on glob-lstat-compat.c to provide a compat symbol which does not
   use lstat / gl_lstat.  */
  union
  {
    struct_stat st;
    struct_stat64 st64;
  } ust;
  return (__glibc_unlikely (flags & GLOB_ALTDIRFUNC)
          ? pglob->GLOB_LSTAT (fullname, &ust.st)
          : glob_fstatat (fullname, &ust.st64, AT_SYMLINK_NOFOLLOW));
}

/* Set *R = A + B.  Return true if the answer is mathematically
   incorrect due to overflow; in this case, *R is the low order
   bits of the correct answer.  */

static bool
size_add_wrapv (size_t a, size_t b, size_t *r)
{
#if 7 <= __GNUC__ && !defined __ICC
  return __builtin_add_overflow (a, b, r);
#else
  *r = a + b;
  return *r < a;
#endif
}

static bool
glob_use_alloca (size_t alloca_used, size_t len)
{
  size_t size;
  return (!size_add_wrapv (alloca_used, len, &size)
          && __libc_use_alloca (size));
}

static int glob_in_dir (const char *pattern, const char *directory,
                        int flags, int (*errfunc) (const char *, int),
                        glob_t *pglob, size_t alloca_used);
static int prefix_array (const char *prefix, char **array, size_t n) __THROWNL;
static int collated_compare (const void *, const void *) __THROWNL;


/* Return true if FILENAME is a directory or a symbolic link to a directory.
   Use FLAGS and PGLOB to resolve the filename.  */
static bool
is_dir (char const *filename, int flags, glob_t const *pglob)
{
  struct_stat st;
  struct_stat64 st64;
  return (__glibc_unlikely (flags & GLOB_ALTDIRFUNC)
          ? pglob->gl_stat (filename, &st) == 0 && S_ISDIR (st.st_mode)
          : (glob_fstatat (filename, &st64, 0) == 0
             && S_ISDIR (st64.st_mode)));
}

/* Find the end of the sub-pattern in a brace expression.  */
static const char *
next_brace_sub (const char *cp, int flags)
{
  size_t depth = 0;
  while (*cp != '\0')
    if ((flags & GLOB_NOESCAPE) == 0 && *cp == '\\')
      {
        if (*++cp == '\0')
          break;
        ++cp;
      }
    else
      {
        if ((*cp == '}' && depth-- == 0) || (*cp == ',' && depth == 0))
          break;

        if (*cp++ == '{')
          depth++;
      }

  return *cp != '\0' ? cp : NULL;
}

static const char *
glob_patscan (const char *string, const char *end, int delim, bool quote)
{
  int pnest = 0;
  int bnest = 0;
  bool skip = false;
  const char *bfirst = NULL;

  if (string >= end)
    return NULL;

  for (const char *s = string; *s != '\0'; ++s)
    {
      if (s >= end)
        return s;
      if (skip)
        {
          skip = false;
          continue;
        }
      switch (*s)
        {
        case '\\':
          if (quote)
            skip = true;
          break;
        case '[':
          if (bnest == 0)
            {
              bfirst = s + 1;
              if (*bfirst == '!' || *bfirst == '^')
                ++bfirst;
              ++bnest;
            }
          else if (s[1] == ':' || s[1] == '.' || s[1] == '=')
            {
              char type = s[1];
              const char *t = s + 2;
              while (*t != '\0' && (type == '.' || *t != ']'))
                {
                  if (*t == type && t[1] == ']')
                    {
                      s = t + 1;
                      break;
                    }
                  ++t;
                }
            }
          break;
        case ']':
          if (bnest > 0 && s != bfirst)
            {
              --bnest;
              bfirst = NULL;
            }
          break;
        case '(':
          if (bnest == 0)
            ++pnest;
          break;
        case ')':
          if (bnest == 0 && pnest-- <= 0)
            return s + 1;
          break;
        default:
          if (bnest == 0 && pnest == 0 && delim != 0 && *s == delim)
            return s + 1;
          break;
        }
    }
  return NULL;
}

static bool
is_extglob (const char *p)
{
  return ((p[0] == '?' || p[0] == '*' || p[0] == '+' || p[0] == '@'
           || p[0] == '!')
          && p[1] == '(');
}

static const char *
glob_dirscan (const char *pat, int dirsep, bool quote)
{
  const char *d = NULL;
  const char *pe = pat + strlen (pat);

  for (const char *p = pat; p && *p; ++p)
    {
      if (quote && *p == '\\')
        {
          if (p[1] != '\0' && p[1] != dirsep)
            ++p;
          continue;
        }
      if (is_extglob (p))
        {
          const char *np = glob_patscan (p + 2, pe, 0, quote);
          if (np == NULL || np == p + 2)
            continue;
          p = np - 1;
        }
      else if (*p == dirsep)
        d = p;
    }
  return d;
}

static bool skipname (const char *pat, const char *pat_end, const char *dname,
                      int flags);

static bool
extglob_skipname (const char *pat, const char *pat_end, const char *dname,
                  int flags)
{
  bool quote = !(flags & GLOB_NOESCAPE);
  bool wild = (*pat == '*' || *pat == '?');
  const char *pp = pat + 2;
  const char *pe = glob_patscan (pp, pat_end, 0, quote);
  if (pe == NULL || pe > pat_end || pe[-1] != ')')
    return false;

  if (pe == pat_end && memchr (pp, '|', pe - pp - 1) == NULL)
    return skipname (pp, pe - 1, dname, flags);

  bool r = true;
  const char *t;
  while ((t = glob_patscan (pp, pe, '|', quote)) != NULL)
    {
      const char *sub_end = (is_extglob (pp) && t[-1] == ')') ? t : t - 1;
      r = skipname (pp, sub_end, dname, flags);
      if (!r)
        return false;
      pp = t;
      if (pp == pe)
        break;
    }

  if (pp == pat_end)
    return r;

  if (wild && pe < pat_end)
    return skipname (pe, pat_end, dname, flags);

  return true;
}

static bool
skipname (const char *pat, const char *pat_end, const char *dname, int flags)
{
  bool quote = !(flags & GLOB_NOESCAPE);
  if ((flags & GLOB_EXTMATCH) && pat + 2 <= pat_end && is_extglob (pat))
    return extglob_skipname (pat, pat_end, dname, flags);

  bool is_dot_or_dotdot = (dname[0] == '.'
                           && (dname[1] == '\0'
                               || (dname[1] == '.' && dname[2] == '\0')));
  if ((flags & GLOB_SKIPDOTS) && is_dot_or_dotdot)
    return true;

  bool pat_starts_dot = (pat < pat_end
                         && (pat[0] == '.'
                             || (quote && pat + 1 < pat_end
                                 && pat[0] == '\\' && pat[1] == '.')));

  if ((flags & GLOB_PERIOD) && (flags & GLOB_DOTDOT) && !pat_starts_dot
      && is_dot_or_dotdot)
    return true;

  if (!(flags & GLOB_PERIOD) && dname[0] == '.' && !pat_starts_dot)
    return true;

  return false;
}

static inline int
glob_interm_period_flag (int flags)
{
  return (flags & (GLOB_DOTDOT | GLOB_SKIPDOTS)) ? (flags & GLOB_PERIOD) : 0;
}

/* Return 0 if DIR is a real directory, -2 if DIR is a symlink, -1 otherwise.  */
static int
glob_testdir (const char *dir, int flags, const glob_t *pglob, bool check_symlink)
{
  struct_stat st;
  struct_stat64 st64;
  if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
    {
      int r = check_symlink ? pglob->GLOB_LSTAT (dir, &st)
                            : pglob->gl_stat (dir, &st);
      if (r < 0)
        return -1;
      if (check_symlink && S_ISLNK (st.st_mode))
        return -2;
      return S_ISDIR (st.st_mode) ? 0 : -1;
    }
  else
    {
      int r = glob_fstatat (dir, &st64,
                            check_symlink ? AT_SYMLINK_NOFOLLOW : 0);
      if (r < 0)
        return -1;
      if (check_symlink && S_ISLNK (st64.st_mode))
        return -2;
      return S_ISDIR (st64.st_mode) ? 0 : -1;
    }
}

/* Internal flags for globstar_scan.  */
#define GS_ADDCURDIR 1
#define GS_NULLDIR   2

static int
globstar_scan (const char *sdir, int flags, int gs_flags,
               int (*errfunc) (const char *, int), glob_t *pglob)
{
  void *stream = (__builtin_expect (flags & GLOB_ALTDIRFUNC, 0)
                  ? (*pglob->gl_opendir) (sdir)
                  : opendir (sdir));
  if (stream == NULL)
    {
      if (errno != ENOTDIR
          && ((errfunc != NULL && (*errfunc) (sdir, errno))
              || (flags & GLOB_ERR)))
        return GLOB_ABORTED;
      return 0;
    }

  if (gs_flags & GS_ADDCURDIR)
    {
      size_t newcount = pglob->gl_pathc + pglob->gl_offs;
      if (newcount > SIZE_MAX / sizeof (char *) - 2)
        {
          if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
            (*pglob->gl_closedir) (stream);
          else
            closedir (stream);
          return GLOB_NOSPACE;
        }
      char **new_gl_pathv = realloc (pglob->gl_pathv,
                                     (newcount + 2) * sizeof (char *));
      if (new_gl_pathv == NULL)
        {
          if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
            (*pglob->gl_closedir) (stream);
          else
            closedir (stream);
          return GLOB_NOSPACE;
        }
      pglob->gl_pathv = new_gl_pathv;
      pglob->gl_pathv[newcount] = strdup ((gs_flags & GS_NULLDIR) ? "" : sdir);
      if (pglob->gl_pathv[newcount] == NULL)
        {
          if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
            (*pglob->gl_closedir) (stream);
          else
            closedir (stream);
          return GLOB_NOSPACE;
        }
      pglob->gl_pathv[newcount + 1] = NULL;
      ++pglob->gl_pathc;
    }

  size_t sdirlen = strlen (sdir);
  bool ign_dot = (gs_flags & GS_NULLDIR) && sdirlen == 1 && sdir[0] == '.';
  bool rm_dot = (sdirlen == 1 && sdir[0] == '.');

  while (1)
    {
      struct readdir_result d;
      if (__builtin_expect (flags & GLOB_ALTDIRFUNC, 0))
        d = convert_dirent (GL_READDIR (pglob, stream));
      else
        {
#ifdef COMPILE_GLOB64
          d = convert_dirent (__readdir (stream));
#else
          d = convert_dirent64 (__readdir64 (stream));
#endif
        }
      if (d.name == NULL)
        break;

      if (d.name[0] == '.'
          && (d.name[1] == '\0' || (d.name[1] == '.' && d.name[2] == '\0')))
        continue;

      if (skipname ("**", "**" + 2, d.name, flags))
        continue;

      size_t namelen = strlen (d.name);
      char *subdir;
      if (ign_dot || rm_dot)
        subdir = strdup (d.name);
      else if (sdirlen > 0 && sdir[sdirlen - 1] == '/')
        {
          subdir = malloc (sdirlen + namelen + 1);
          if (subdir != NULL)
            mempcpy (mempcpy (subdir, sdir, sdirlen), d.name, namelen + 1);
        }
      else
        {
          subdir = malloc (sdirlen + 1 + namelen + 1);
          if (subdir != NULL)
            {
              char *p = mempcpy (subdir, sdir, sdirlen);
              *p++ = '/';
              memcpy (p, d.name, namelen + 1);
            }
        }
      if (subdir == NULL)
        {
          if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
            (*pglob->gl_closedir) (stream);
          else
            closedir (stream);
          return GLOB_NOSPACE;
        }

      int isdir = glob_testdir (subdir, flags, pglob, true);
      if ((flags & GLOB_ONLYDIR) && isdir < 0
          && (isdir != -2 || glob_testdir (subdir, flags, pglob, false) < 0))
        {
          free (subdir);
          continue;
        }

      size_t newcount = pglob->gl_pathc + pglob->gl_offs;
      if (newcount > SIZE_MAX / sizeof (char *) - 2)
        {
          free (subdir);
          if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
            (*pglob->gl_closedir) (stream);
          else
            closedir (stream);
          return GLOB_NOSPACE;
        }
      char **new_gl_pathv = realloc (pglob->gl_pathv,
                                     (newcount + 2) * sizeof (char *));
      if (new_gl_pathv == NULL)
        {
          free (subdir);
          if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
            (*pglob->gl_closedir) (stream);
          else
            closedir (stream);
          return GLOB_NOSPACE;
        }
      pglob->gl_pathv = new_gl_pathv;
      pglob->gl_pathv[newcount] = subdir;
      pglob->gl_pathv[newcount + 1] = NULL;
      ++pglob->gl_pathc;

      if (isdir == 0)
        {
          int r = globstar_scan (subdir, flags, 0, errfunc, pglob);
          if (r != 0)
            {
              if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
                (*pglob->gl_closedir) (stream);
              else
                closedir (stream);
              return r;
            }
        }
    }

  int save = errno;
  if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
    (*pglob->gl_closedir) (stream);
  else
    closedir (stream);
  __set_errno (save);
  return 0;
}

#ifndef GLOB_ATTRIBUTE
# define GLOB_ATTRIBUTE
#endif

static int
GLOB_ATTRIBUTE
glob_body_inner (const char *pattern, int flags,
                 int (*errfunc) (const char *, int),
                 glob_t *pglob);


#if GLOB_FSWC
/* GLOB_PATHS: PATTERN is a search list (GLOB.md 3.2), expanded by the
   walker that execvp and ld.so use, so all three agree by construction.
   Elements are separated by every ':'; an empty element is "."; a whole
   "*" component (at most one per element) is the only wildcard; matches
   are in byte order within an element.  "{LIST}/NAME" appends a literal
   NAME to every element, LIST ending at the last "}/".  */

struct search_list
{
  glob_t *pglob;
  int flags;
  size_t matches;               /* In the current element.  */
  int error;
};

static int
search_list_add (glob_t *pglob, const char *path, bool slash)
{
  size_t n = pglob->gl_offs + pglob->gl_pathc;
  char **v = realloc (pglob->gl_pathv, (n + 2) * sizeof (char *));
  if (v == NULL)
    return GLOB_NOSPACE;
  pglob->gl_pathv = v;
  size_t len = strlen (path);
  char *copy = malloc (len + slash + 1);
  if (copy == NULL)
    return GLOB_NOSPACE;
  memcpy (copy, path, len);
  if (slash)
    copy[len++] = '/';
  copy[len] = '\0';
  v[n] = copy;
  v[n + 1] = NULL;
  ++pglob->gl_pathc;
  return 0;
}

/* The file type of PATH as lstat (FOLLOW false) or stat sees it, through
   the caller's hooks if it gave any; -1 if it does not exist.  */
static int
search_list_type (const struct search_list *sl, const char *path,
                  bool follow)
{
  if (sl->flags & GLOB_ALTDIRFUNC)
    {
      struct_stat st;
      int r = follow ? sl->pglob->gl_stat (path, &st)
                     : sl->pglob->GLOB_LSTAT (path, &st);
      return r == 0 ? IFTODT (st.st_mode) : -1;
    }
  struct_stat64 st;
  return glob_fstatat (path, &st, follow ? 0 : AT_SYMLINK_NOFOLLOW) == 0
         ? IFTODT (st.st_mode) : -1;
}

static void *
search_list_open (const char *dir, void *closure)
{
  glob_t *pglob = closure;
  return pglob->gl_opendir (dir);
}

static const char *
search_list_next (void *stream, void *closure)
{
  glob_t *pglob = closure;
  struct readdir_result d = convert_dirent (GL_READDIR (pglob, stream));
  return d.name;
}

static void
search_list_close (void *stream, void *closure)
{
  glob_t *pglob = closure;
  pglob->gl_closedir (stream);
}

static bool
search_list_candidate (const struct fswc_candidate *c, void *closure)
{
  struct search_list *sl = closure;
  const char *path = c->path;
  int hint = c->hint;
  if (hint == FSWC_ABSENT || hint == FSWC_TOOLONG)
    return true;
  if (hint < 0)
    {
      /* Only the kernel (or the caller's hooks) knows.  */
      hint = search_list_type (sl, path, false);
      if (hint < 0)
        return true;
    }
  bool is_dir = hint == DT_DIR;
  if (hint == DT_LNK && (sl->flags & (GLOB_ONLYDIR | GLOB_MARK)))
    is_dir = search_list_type (sl, path, true) == DT_DIR;
  if ((sl->flags & GLOB_ONLYDIR) && !is_dir)
    return true;
  sl->error = search_list_add (sl->pglob, path,
                               is_dir && (sl->flags & GLOB_MARK));
  ++sl->matches;
  return sl->error == 0;
}

static int
glob_search_list (const char *pattern, int flags, glob_t *pglob)
{
  const char *list = pattern;
  size_t list_len = strlen (pattern);
  const char *name = "";
  if (pattern[0] == '{')
    {
      /* A command name cannot contain '/', so the last "}/" ends LIST.  */
      for (const char *c = pattern + list_len; c-- > pattern + 1; )
        if (c[0] == '}' && c[1] == '/')
          {
            list = pattern + 1;
            list_len = c - list;
            name = c + 2;
            break;
          }
    }

  enum { PATH_CAP = 4096, SCRATCH_CAP = 64 * 1024 };
  char *mem = malloc (PATH_CAP + SCRATCH_CAP + 8);
  if (mem == NULL)
    return GLOB_NOSPACE;
  char *scratch = (char *) (((uintptr_t) mem + 7) & ~(uintptr_t) 7);
  char *path = scratch + SCRATCH_CAP;

  /* Caller hooks list the directories and bypass FSWC.  */
  struct fswc_lister lister =
    { search_list_open, search_list_next, search_list_close, pglob };
  struct fswc_call hooked = { .lister = &lister };
  struct fswc_call local = { 0 };
  struct fswc_call *call = (flags & GLOB_ALTDIRFUNC) ? &hooked
                           : glob_fswc_call != NULL ? glob_fswc_call : &local;
  struct search_list sl = { pglob, flags, 0, 0 };
  size_t before = pglob->gl_pathc;
  bool magic = false;
  const char *end = list + list_len;
  for (const char *e = list; ; )
    {
      const char *colon = memchr (e, ':', end - e);
      if (colon == NULL)
        colon = end;
      sl.matches = 0;
      bool star = __fswc_has_star (e, colon - e);
      magic |= star;
      int r = __fswc_walk (call, e, colon - e, name, path, PATH_CAP, scratch,
                           SCRATCH_CAP, search_list_candidate, &sl);
      /* With no match, GLOB_NOCHECK keeps the element itself, and
         GLOB_NOMAGIC does so for an element without a "*".  */
      if (sl.error == 0 && sl.matches == 0
          && ((flags & GLOB_NOCHECK) || ((flags & GLOB_NOMAGIC) && !star)))
        {
          /* The element itself ("." if empty), with NAME.  */
          size_t elen = colon > e ? (size_t) (colon - e) : 1;
          size_t nlen = strlen (name);
          if (elen + 1 + nlen >= PATH_CAP)
            sl.error = GLOB_NOSPACE;
          else
            {
              char *q = mempcpy (path, colon > e ? e : ".", elen);
              if (nlen > 0)
                {
                  *q++ = '/';
                  q = mempcpy (q, name, nlen);
                }
              *q = '\0';
              sl.error = search_list_add (pglob, path, false);
            }
        }
      (void) r;
      if (sl.error != 0 || colon == end)
        break;
      e = colon + 1;
    }
  free (mem);

  if (sl.error != 0)
    {
      if (!(flags & GLOB_APPEND))
        {
          globfree (pglob);
          pglob->gl_pathc = 0;
        }
      return sl.error;
    }
  pglob->gl_flags = (flags & ~GLOB_PATHS) | (magic ? GLOB_MAGCHAR : 0);
  return pglob->gl_pathc != before ? 0 : GLOB_NOMATCH;
}
#endif

/* Do glob searching for PATTERN, placing results in PGLOB.
   The bits defined above may be set in FLAGS.
   If a directory cannot be opened or read and ERRFUNC is not nil,
   it is called with the pathname that caused the error, and the
   'errno' value from the failing call; if it returns non-zero
   'glob' returns GLOB_ABORTED; if it returns zero, the error is ignored.
   If memory cannot be allocated for PGLOB, GLOB_NOSPACE is returned.
   Otherwise, 'glob' returns zero.  */
static int
GLOB_ATTRIBUTE
glob_body_inner (const char *pattern, int flags,
                 int (*errfunc) (const char *, int),
                 glob_t *pglob)
{
  const char *filename;
  char *dirname = NULL;
  size_t dirlen;
  int status;
  size_t oldcount;
  int meta;
  int dirname_modified;
  bool pat_is_pure_literal = false;
  int malloc_dirname = 0;
  glob_t dirs;
  int retval = 0;
  size_t alloca_used = 0;

  if (pattern == NULL || pglob == NULL || (flags & ~__GLOB_FLAGS) != 0)
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (!(flags & GLOB_DOOFFS))
    /* Have to do this so 'globfree' knows where to start freeing.  It
       also makes all the code that uses gl_offs simpler. */
    pglob->gl_offs = 0;

  if (!(flags & GLOB_APPEND))
    {
      pglob->gl_pathc = 0;
      if (!(flags & GLOB_DOOFFS))
        pglob->gl_pathv = NULL;
      else
        {
          size_t i;

          if (pglob->gl_offs >= ~((size_t) 0) / sizeof (char *))
            return GLOB_NOSPACE;

          pglob->gl_pathv = (char **) malloc ((pglob->gl_offs + 1)
                                              * sizeof (char *));
          if (pglob->gl_pathv == NULL)
            return GLOB_NOSPACE;

          for (i = 0; i <= pglob->gl_offs; ++i)
            pglob->gl_pathv[i] = NULL;
        }
    }

#if GLOB_FSWC
  if (flags & GLOB_PATHS)
    return glob_search_list (pattern, flags, pglob);
#endif

  /* POSIX requires all slashes to be matched.  This means that with
     a trailing slash we must match only directories.  */
  if (pattern[0] && pattern[strlen (pattern) - 1] == '/')
    flags |= GLOB_ONLYDIR;

  if (flags & GLOB_BRACE)
    {
      const char *begin;

      if (flags & GLOB_NOESCAPE)
        begin = strchr (pattern, '{');
      else
        {
          begin = pattern;
          while (1)
            {
              if (*begin == '\0')
                {
                  begin = NULL;
                  break;
                }

              if (*begin == '\\' && begin[1] != '\0')
                ++begin;
              else if (*begin == '{')
                break;

              ++begin;
            }
        }

      if (begin != NULL)
        {
          /* Allocate working buffer large enough for our work.  Note that
             we have at least an opening and closing brace.  */
          size_t firstc;
          char *alt_start;
          const char *p;
          const char *next;
          const char *rest;
          size_t rest_len;
          char *onealt;
          size_t pattern_len = strlen (pattern) - 1;
          int alloca_onealt = glob_use_alloca (alloca_used, pattern_len);
          if (alloca_onealt)
            onealt = alloca_account (pattern_len, alloca_used);
          else
            {
              onealt = malloc (pattern_len);
              if (onealt == NULL)
                return GLOB_NOSPACE;
            }

          /* We know the prefix for all sub-patterns.  */
          alt_start = mempcpy (onealt, pattern, begin - pattern);

          /* Find the first sub-pattern and at the same time find the
             rest after the closing brace.  */
          next = next_brace_sub (begin + 1, flags);
          if (next == NULL)
            {
              /* It is an invalid expression.  */
            illegal_brace:
              if (__glibc_unlikely (!alloca_onealt))
                free (onealt);
              flags &= ~GLOB_BRACE;
              goto no_brace;
            }

          /* Now find the end of the whole brace expression.  */
          rest = next;
          while (*rest != '}')
            {
              rest = next_brace_sub (rest + 1, flags);
              if (rest == NULL)
                /* It is an illegal expression.  */
                goto illegal_brace;
            }
          /* Please note that we now can be sure the brace expression
             is well-formed.  */
          rest_len = strlen (++rest) + 1;

          /* We have a brace expression.  BEGIN points to the opening {,
             NEXT points past the terminator of the first element, and END
             points past the final }.  We will accumulate result names from
             recursive runs for each brace alternative in the buffer using
             GLOB_APPEND.  */
          firstc = pglob->gl_pathc;

          p = begin + 1;
          while (1)
            {
              int result;

              /* Construct the new glob expression.  */
              mempcpy (mempcpy (alt_start, p, next - p), rest, rest_len);

              result = glob_body_inner (onealt,
                                        ((flags & ~(GLOB_NOCHECK | GLOB_NOMAGIC))
                                         | GLOB_APPEND),
                                        errfunc, pglob);

              /* If we got an error, return it.  */
              if (result && result != GLOB_NOMATCH)
                {
                  if (__glibc_unlikely (!alloca_onealt))
                    free (onealt);
                  if (!(flags & GLOB_APPEND))
                    {
                      globfree (pglob);
                      pglob->gl_pathc = 0;
                    }
                  return result;
                }

              if (*next == '}')
                /* We saw the last entry.  */
                break;

              p = next + 1;
              next = next_brace_sub (p, flags);
              assert (next != NULL);
            }

          if (__glibc_unlikely (!alloca_onealt))
            free (onealt);

          if (pglob->gl_pathc != firstc)
            /* We found some entries.  */
            return 0;
          else if (!(flags & (GLOB_NOCHECK|GLOB_NOMAGIC)))
            return GLOB_NOMATCH;
        }
    }

 no_brace:
  flags &= ~GLOB_PATHS;
  oldcount = pglob->gl_pathc + pglob->gl_offs;

  /* Find the filename.  */
  filename = ((flags & GLOB_EXTMATCH)
              ? glob_dirscan (pattern, '/', !(flags & GLOB_NOESCAPE))
              : strrchr (pattern, '/'));

#if defined __MSDOS__ || defined WINDOWS32
  /* The case of "d:pattern".  Since ':' is not allowed in
     file names, we can safely assume that wherever it
     happens in pattern, it signals the filename part.  This
     is so we could some day support patterns like "[a-z]:foo".  */
  if (filename == NULL)
    filename = strchr (pattern, ':');
#endif /* __MSDOS__ || WINDOWS32 */

  dirname_modified = 0;
  if (filename == NULL)
    {
      /* This can mean two things: a simple name or "~name".  The latter
         case is nothing but a notation for a directory.  */
      if ((flags & (GLOB_TILDE|GLOB_TILDE_CHECK)) && pattern[0] == '~')
        {
          dirname = (char *) pattern;
          dirlen = strlen (pattern);

          /* Set FILENAME to NULL as a special flag.  This is ugly but
             other solutions would require much more code.  We test for
             this special case below.  */
          filename = NULL;
        }
      else
        {
          if (__glibc_unlikely (pattern[0] == '\0'))
            {
              dirs.gl_pathv = NULL;
              goto no_matches;
            }

          filename = pattern;
          dirname = (char *) ".";
          dirlen = 0;
        }
    }
  else if (filename == pattern
           || (filename == pattern + 1 && pattern[0] == '\\'
               && (flags & GLOB_NOESCAPE) == 0))
    {
      /* "/pattern" or "\\/pattern".  */
      dirname = (char *) "/";
      dirlen = 1;
      ++filename;
    }
  else
    {
      char *newp;
      dirlen = filename - pattern;
#if defined __MSDOS__ || defined WINDOWS32
      if (*filename == ':'
          || (filename > pattern + 1 && filename[-1] == ':'))
        {
          char *drive_spec;

          ++dirlen;
          drive_spec = __alloca (dirlen + 1);
          *((char *) mempcpy (drive_spec, pattern, dirlen)) = '\0';
          /* For now, disallow wildcards in the drive spec, to
             prevent infinite recursion in glob.  */
          if (__glob_pattern_p (drive_spec, !(flags & GLOB_NOESCAPE)))
            return GLOB_NOMATCH;
          /* If this is "d:pattern", we need to copy ':' to DIRNAME
             as well.  If it's "d:/pattern", don't remove the slash
             from "d:/", since "d:" and "d:/" are not the same.*/
        }
#endif

      if (glob_use_alloca (alloca_used, dirlen + 1))
        newp = alloca_account (dirlen + 1, alloca_used);
      else
        {
          newp = malloc (dirlen + 1);
          if (newp == NULL)
            return GLOB_NOSPACE;
          malloc_dirname = 1;
        }
      *((char *) mempcpy (newp, pattern, dirlen)) = '\0';
      dirname = newp;
      ++filename;

#if defined __MSDOS__ || defined WINDOWS32
      bool drive_root = (dirlen > 1
                         && (dirname[dirlen - 1] == ':'
                             || (dirlen > 2 && dirname[dirlen - 2] == ':'
                                 && dirname[dirlen - 1] == '/')));
#else
      bool drive_root = false;
#endif

      if (filename[0] == '\0'
          && (dirlen > 1 || (dirlen == 1 && dirname[0] == '/'))
          && !drive_root)
        /* "pattern/" or "//".  Expand "pattern", appending slashes.  */
        {
          int orig_flags = flags;
          size_t orig_trailing_slashes = 0;
          if (flags & GLOB_KEEP_SLASHES)
            {
              size_t pat_len = (size_t) (filename - pattern);
              while (orig_trailing_slashes < pat_len
                     && pattern[pat_len - 1 - orig_trailing_slashes] == '/')
                ++orig_trailing_slashes;
            }
          if (!(flags & GLOB_NOESCAPE) && dirname[dirlen - 1] == '\\')
            {
              /* "pattern\\/".  Remove the final backslash if it hasn't
                 been quoted.  */
              char *p = (char *) &dirname[dirlen - 1];

              while (p > dirname && p[-1] == '\\') --p;
              if ((&dirname[dirlen] - p) & 1)
                {
                  *(char *) &dirname[--dirlen] = '\0';
                  flags &= ~(GLOB_NOCHECK | GLOB_NOMAGIC);
                }
            }
          /* Prevent stack overflows with many trailing '/' characters.  */
          for (char *p = &dirname[dirlen - 1];
               p > dirname && p[0] == '/'; --p)
            p[0] = '\0';
          int val = glob_body_inner (dirname, flags | GLOB_MARK, errfunc, pglob);
          if (val == 0)
            {
              if ((flags & GLOB_KEEP_SLASHES)
                  && orig_trailing_slashes > 1
                  && !(pglob->gl_flags & GLOB_MAGCHAR))
                {
                  for (size_t i = oldcount;
                       i < pglob->gl_pathc + pglob->gl_offs; ++i)
                    {
                      size_t len = strlen (pglob->gl_pathv[i]);
                      size_t cur_slashes = 0;
                      while (cur_slashes < len
                             && pglob->gl_pathv[i][len - 1 - cur_slashes] == '/')
                        ++cur_slashes;
                      if (cur_slashes >= orig_trailing_slashes)
                        continue;
                      size_t add_slashes = orig_trailing_slashes - cur_slashes;
                      char *newp = realloc (pglob->gl_pathv[i],
                                            len + add_slashes + 1);
                      if (newp == NULL)
                        {
                          if (flags & GLOB_APPEND)
                            {
                              size_t cur_end = pglob->gl_pathc + pglob->gl_offs;
                              for (size_t j = oldcount; j < cur_end; ++j)
                                free (pglob->gl_pathv[j]);
                              pglob->gl_pathv[oldcount] = NULL;
                              pglob->gl_pathc = oldcount - pglob->gl_offs;
                            }
                          else
                            {
                              globfree (pglob);
                              pglob->gl_pathc = 0;
                            }
                          retval = GLOB_NOSPACE;
                          goto out;
                        }
                      memset (newp + len, '/', add_slashes);
                      newp[len + add_slashes] = '\0';
                      pglob->gl_pathv[i] = newp;
                    }
                }
              pglob->gl_flags = ((pglob->gl_flags & ~GLOB_MARK)
                                 | (flags & GLOB_MARK));
            }
          else if (val == GLOB_NOMATCH && flags != orig_flags)
            {
              /* Make sure globfree (&dirs); is a nop.  */
              dirs.gl_pathv = NULL;
              flags = orig_flags;
              oldcount = pglob->gl_pathc + pglob->gl_offs;
              goto no_matches;
            }
          retval = val;
          goto out;
        }
    }

  if ((flags & (GLOB_TILDE|GLOB_TILDE_CHECK)) && dirname[0] == '~')
    {
      if (dirname[1] == '\0' || dirname[1] == '/'
          || (!(flags & GLOB_NOESCAPE) && dirname[1] == '\\'
              && (dirname[2] == '\0' || dirname[2] == '/')))
        {
          /* Look up home directory.  */
          char *home_dir = getenv ("HOME");
          int malloc_home_dir = 0;
          if (home_dir == NULL || home_dir[0] == '\0')
            {
#ifdef WINDOWS32
              /* Windows NT defines HOMEDRIVE and HOMEPATH.  But give
                 preference to HOME, because the user can change HOME.  */
              const char *home_drive = getenv ("HOMEDRIVE");
              const char *home_path = getenv ("HOMEPATH");

              if (home_drive != NULL && home_path != NULL)
                {
                  size_t home_drive_len = strlen (home_drive);
                  size_t home_path_len = strlen (home_path);
                  char *mem = alloca (home_drive_len + home_path_len + 1);

                  memcpy (mem, home_drive, home_drive_len);
                  memcpy (mem + home_drive_len, home_path, home_path_len + 1);
                  home_dir = mem;
                }
              else
                home_dir = "c:/users/default"; /* poor default */
#else
              int err;
              struct passwd *p;
              struct passwd pwbuf;
              struct scratch_buffer s;
              scratch_buffer_init (&s);
              while (true)
                {
                  p = NULL;
                  err = __getlogin_r (s.data, s.length);
                  if (err == 0)
                    {
# if defined HAVE_GETPWNAM_R || defined _LIBC
                      size_t ssize = strlen (s.data) + 1;
                      char *sdata = s.data;
                      err = getpwnam_r (sdata, &pwbuf, sdata + ssize,
                                        s.length - ssize, &p);
# else
                      p = getpwnam (s.data);
                      if (p == NULL)
                        err = errno;
# endif
                    }
                  if (err != ERANGE)
                    break;
                  if (!scratch_buffer_grow (&s))
                    {
                      retval = GLOB_NOSPACE;
                      goto out;
                    }
                }
              if (err == 0)
                {
                  home_dir = strdup (p->pw_dir);
                  malloc_home_dir = 1;
                }
              scratch_buffer_free (&s);
              if (err == 0 && home_dir == NULL)
                {
                  retval = GLOB_NOSPACE;
                  goto out;
                }
#endif /* WINDOWS32 */
            }
          if (home_dir == NULL || home_dir[0] == '\0')
            {
              if (__glibc_unlikely (malloc_home_dir))
                free (home_dir);
              if (flags & GLOB_TILDE_CHECK)
                {
                  retval = GLOB_NOMATCH;
                  goto out;
                }
              else
                {
                  home_dir = (char *) "~"; /* No luck.  */
                  malloc_home_dir = 0;
                }
            }
          /* Now construct the full directory.  */
          if (dirname[1] == '\0')
            {
              if (__glibc_unlikely (malloc_dirname))
                free (dirname);

              dirlen = strlen (home_dir);
              if (malloc_home_dir)
                {
                  dirname = home_dir;
                  malloc_dirname = 1;
                }
              else
                {
                  char *newp;
                  int use_alloca = glob_use_alloca (alloca_used, dirlen + 1);
                  if (use_alloca)
                    newp = alloca_account (dirlen + 1, alloca_used);
                  else
                    {
                      newp = malloc (dirlen + 1);
                      if (newp == NULL)
                        {
                          retval = GLOB_NOSPACE;
                          goto out;
                        }
                    }
                  memcpy (newp, home_dir, dirlen + 1);
                  dirname = newp;
                  malloc_dirname = !use_alloca;
                }
            }
          else
            {
              char *newp;
              size_t home_len = strlen (home_dir);
              int use_alloca = glob_use_alloca (alloca_used, home_len + dirlen);
              if (use_alloca)
                newp = alloca_account (home_len + dirlen, alloca_used);
              else
                {
                  newp = malloc (home_len + dirlen);
                  if (newp == NULL)
                    {
                      if (__glibc_unlikely (malloc_home_dir))
                        free (home_dir);
                      retval = GLOB_NOSPACE;
                      goto out;
                    }
                }

              mempcpy (mempcpy (newp, home_dir, home_len),
                       &dirname[1], dirlen);

              if (__glibc_unlikely (malloc_dirname))
                free (dirname);

              dirname = newp;
              dirlen += home_len - 1;
              malloc_dirname = !use_alloca;

              if (__glibc_unlikely (malloc_home_dir))
                free (home_dir);
            }
          dirname_modified = 1;
        }
      else
        {
#ifndef WINDOWS32
          /* Recognize ~user as a shorthand for the specified user's home
             directory.  */
          char *end_name = strchr (dirname, '/');
          char *user_name;
          int malloc_user_name = 0;
          char *unescape = NULL;

          if (!(flags & GLOB_NOESCAPE))
            {
              if (end_name == NULL)
                {
                  unescape = strchr (dirname, '\\');
                  if (unescape)
                    end_name = strchr (unescape, '\0');
                }
              else
                unescape = memchr (dirname, '\\', end_name - dirname);
            }
          if (end_name == NULL)
            user_name = dirname + 1;
          else
            {
              char *newp;
              if (glob_use_alloca (alloca_used, end_name - dirname))
                newp = alloca_account (end_name - dirname, alloca_used);
              else
                {
                  newp = malloc (end_name - dirname);
                  if (newp == NULL)
                    {
                      retval = GLOB_NOSPACE;
                      goto out;
                    }
                  malloc_user_name = 1;
                }
              if (unescape != NULL)
                {
                  char *p = mempcpy (newp, dirname + 1,
                                     unescape - dirname - 1);
                  char *q = unescape;
                  while (q != end_name)
                    {
                      if (*q == '\\')
                        {
                          if (q + 1 == end_name)
                            {
                              /* "~fo\\o\\" unescape to user_name "foo\\",
                                 but "~fo\\o\\/" unescape to user_name
                                 "foo".  */
                              if (filename == NULL)
                                *p++ = '\\';
                              break;
                            }
                          ++q;
                        }
                      *p++ = *q++;
                    }
                  *p = '\0';
                }
              else
                *((char *) mempcpy (newp, dirname + 1, end_name - dirname - 1))
                  = '\0';
              user_name = newp;
            }

          /* Look up specific user's home directory.  */
          {
            struct passwd *p;
            struct scratch_buffer pwtmpbuf;
            scratch_buffer_init (&pwtmpbuf);

#  if defined HAVE_GETPWNAM_R || defined _LIBC
            struct passwd pwbuf;

            while (getpwnam_r (user_name, &pwbuf,
                               pwtmpbuf.data, pwtmpbuf.length, &p)
                   == ERANGE)
              {
                if (!scratch_buffer_grow (&pwtmpbuf))
                  {
                    retval = GLOB_NOSPACE;
                    goto out;
                  }
              }
#  else
            p = getpwnam (user_name);
#  endif

            if (__glibc_unlikely (malloc_user_name))
              free (user_name);

            /* If we found a home directory use this.  */
            if (p != NULL)
              {
                size_t home_len = strlen (p->pw_dir);
                size_t rest_len = end_name == NULL ? 0 : strlen (end_name);
                /* dirname contains end_name; we can't free it now.  */
                char *prev_dirname =
                  (__glibc_unlikely (malloc_dirname) ? dirname : NULL);
                char *d;

                malloc_dirname = 0;

                if (glob_use_alloca (alloca_used, home_len + rest_len + 1))
                  dirname = alloca_account (home_len + rest_len + 1,
                                            alloca_used);
                else
                  {
                    dirname = malloc (home_len + rest_len + 1);
                    if (dirname == NULL)
                      {
                        free (prev_dirname);
                        scratch_buffer_free (&pwtmpbuf);
                        retval = GLOB_NOSPACE;
                        goto out;
                      }
                    malloc_dirname = 1;
                  }
                d = mempcpy (dirname, p->pw_dir, home_len);
                if (end_name != NULL)
                  d = mempcpy (d, end_name, rest_len);
                *d = '\0';

                free (prev_dirname);

                dirlen = home_len + rest_len;
                dirname_modified = 1;
              }
            else
              {
                if (flags & GLOB_TILDE_CHECK)
                  {
                    /* We have to regard it as an error if we cannot find the
                       home directory.  */
                    scratch_buffer_free (&pwtmpbuf);
                    retval = GLOB_NOMATCH;
                    goto out;
                  }
              }
            scratch_buffer_free (&pwtmpbuf);
          }
#else /* WINDOWS32 */
          /* On native Windows, access to a user's home directory
             (via GetUserProfileDirectory) or to a user's environment
             variables (via ExpandEnvironmentStringsForUser) requires
             the credentials of the user.  Therefore we cannot support
             the ~user syntax on this platform.
             Handling ~user specially (and treat it like plain ~) if
             user is getenv ("USERNAME") would not be a good idea,
             since it would make people think that ~user is supported
             in general.  */
          if (flags & GLOB_TILDE_CHECK)
            {
              retval = GLOB_NOMATCH;
              goto out;
            }
#endif /* WINDOWS32 */
        }
    }

  /* Now test whether we looked for "~" or "~NAME".  In this case we
     can give the answer now.  */
  if (filename == NULL)
    {
      size_t newcount = pglob->gl_pathc + pglob->gl_offs;
      char **new_gl_pathv;

      if (newcount > SIZE_MAX / sizeof (char *) - 2)
        {
        nospace:
          free (pglob->gl_pathv);
          pglob->gl_pathv = NULL;
          pglob->gl_pathc = 0;
          retval = GLOB_NOSPACE;
          goto out;
        }

      new_gl_pathv = realloc (pglob->gl_pathv,
                              (newcount + 2) * sizeof (char *));
      if (new_gl_pathv == NULL)
        goto nospace;
      pglob->gl_pathv = new_gl_pathv;

      if (flags & GLOB_MARK && is_dir (dirname, flags, pglob))
        {
          char *p;
          pglob->gl_pathv[newcount] = malloc (dirlen + 2);
          if (pglob->gl_pathv[newcount] == NULL)
            goto nospace;
          p = mempcpy (pglob->gl_pathv[newcount], dirname, dirlen);
          p[0] = '/';
          p[1] = '\0';
          if (__glibc_unlikely (malloc_dirname))
            free (dirname);
        }
      else
        {
          if (__glibc_unlikely (malloc_dirname))
            pglob->gl_pathv[newcount] = dirname;
          else
            {
              pglob->gl_pathv[newcount] = strdup (dirname);
              if (pglob->gl_pathv[newcount] == NULL)
                goto nospace;
            }
        }
      pglob->gl_pathv[++newcount] = NULL;
      ++pglob->gl_pathc;
      pglob->gl_flags = flags;

      return 0;
    }

  meta = __glob_pattern_type_ext (dirname, !(flags & GLOB_NOESCAPE),
                                  (flags & GLOB_EXTMATCH) != 0);
  bool dir_has_magic = (meta & (GLOBPAT_SPECIAL | GLOBPAT_BRACKET)) != 0;
  bool dir_casefold_scan
    = (!dir_has_magic && (flags & GLOB_CASEFOLD) != 0 && dirlen > 0
       && !(dirlen == 1 && (dirname[0] == '.' || dirname[0] == '/'))
       && !(dirlen == 2 && dirname[0] == '.' && dirname[1] == '.'));
  int fn_meta = __glob_pattern_type_ext (filename, !(flags & GLOB_NOESCAPE),
                                         (flags & GLOB_EXTMATCH) != 0);
  bool fn_has_magic = (fn_meta & (GLOBPAT_SPECIAL | GLOBPAT_BRACKET)) != 0;
  pat_is_pure_literal
    = (!dirname_modified && meta == GLOBPAT_NONE && fn_meta == GLOBPAT_NONE
       && !fn_has_magic);

  /* meta is 1 if correct glob pattern containing metacharacters.
     If meta has bit (1 << 2) set, it means there was an unterminated
     [ which we handle the same, using fnmatch.  Broken unterminated
     pattern bracket expressions ought to be rare enough that it is
     not worth special casing them, fnmatch will do the right thing.  */
  if (dir_has_magic || dir_casefold_scan)
    {
      /* The directory name contains metacharacters (or requires case-folding),
         so we have to glob for the directory, and then glob for
         the pattern in each directory found.  */
      size_t i;
      bool all_starstar = false;
      bool last_starstar = false;
      size_t ss_slash_pos = 0;
      char *d = dirname;

      if (!(flags & (GLOB_NOESCAPE | GLOB_DOTDOT)) && dirlen > 0
          && dirname[dirlen - 1] == '\\')
        {
          /* "foo\\/bar".  Remove the final backslash from dirname
             if it has not been quoted.  */
          char *p = (char *) &dirname[dirlen - 1];

          while (p > dirname && p[-1] == '\\') --p;
          if ((&dirname[dirlen] - p) & 1)
            *(char *) &dirname[--dirlen] = '\0';
        }

      if (flags & GLOB_GLOBSTAR)
        {
          /* Collapse leading sequence of ** patterns separated by slashes.  */
          if (d[0] == '*' && d[1] == '*' && (d[2] == '/' || d[2] == '\0'))
            {
              char *p = d;
              while (d[0] == '*' && d[1] == '*'
                     && (d[2] == '/' || d[2] == '\0'))
                {
                  p = d;
                  if (d[2] != '\0')
                    {
                      d += 3;
                      while (*d == '/')
                        ++d;
                      if (*d == '\0')
                        break;
                    }
                  else
                    break;
                }
              if (*d == '\0' || (d[0] == '*' && d[1] == '*' && d[2] == '\0'))
                all_starstar = true;
              d = p;
              if (all_starstar)
                {
                  d[2] = '\0';
                  dirlen = 2;
                }
              else
                dirlen = strlen (d);
            }

          /* Collapse trailing sequences of / ** in dirname.  */
          if (!all_starstar)
            {
              size_t dl = dirlen;
              size_t prev = dl;
              while (dl >= 3 && d[dl - 1] == '*' && d[dl - 2] == '*'
                     && d[dl - 3] == '/')
                {
                  prev = dl;
                  dl -= 3;
                  while (dl > 0 && d[dl - 1] == '/')
                    --dl;
                  if (dl < 3 || d[dl - 1] != '*' || d[dl - 2] != '*'
                      || d[dl - 3] != '/')
                    break;
                }
              if (dl != dirlen)
                {
                  last_starstar = true;
                  ss_slash_pos = prev - 3;
                }
              dirlen = prev;
              d[dirlen] = '\0';
            }

          if (last_starstar
              && filename[0] == '*' && filename[1] == '*'
              && filename[2] == '\0')
            {
              if (ss_slash_pos == 0)
                {
                  d = (char *) "/";
                  dirlen = 1;
                }
              else
                {
                  dirlen = ss_slash_pos;
                  while (dirlen > 1 && d[dirlen - 1] == '/')
                    --dirlen;
                  d[dirlen] = '\0';
                }
              last_starstar = false;
            }

          if (all_starstar
              && filename[0] == '*' && filename[1] == '*'
              && filename[2] == '\0')
            {
              if (__glibc_unlikely (malloc_dirname))
                {
                  free (dirname);
                  malloc_dirname = 0;
                }
              dirname = (char *) ".";
              dirlen = 0;
              goto only_filename;
            }
        }


      if (__glibc_unlikely ((flags & GLOB_ALTDIRFUNC) != 0))
        {
          /* Use the alternative access functions also in the recursive
             call.  */
          dirs.gl_opendir = pglob->gl_opendir;
          dirs.gl_readdir = pglob->gl_readdir;
          dirs.gl_closedir = pglob->gl_closedir;
          dirs.gl_stat = pglob->gl_stat;
          dirs.gl_lstat = pglob->gl_lstat;
        }

      if (all_starstar)
        {
          dirs.gl_pathc = 0;
          dirs.gl_pathv = NULL;
          dirs.gl_offs = 0;
          dirs.gl_flags = 0;
          status = globstar_scan (".", flags, GS_ADDCURDIR | GS_NULLDIR,
                                  errfunc, &dirs);
          if (status == 0 && dirs.gl_pathc == 0)
            status = GLOB_NOMATCH;
        }
      else if (last_starstar)
        {
          dirs.gl_pathc = 0;
          dirs.gl_pathv = NULL;
          dirs.gl_offs = 0;
          dirs.gl_flags = 0;

          glob_t base_dirs;
          memset (&base_dirs, 0, sizeof (base_dirs));
          if (__glibc_unlikely ((flags & GLOB_ALTDIRFUNC) != 0))
            {
              base_dirs.gl_opendir = pglob->gl_opendir;
              base_dirs.gl_readdir = pglob->gl_readdir;
              base_dirs.gl_closedir = pglob->gl_closedir;
              base_dirs.gl_stat = pglob->gl_stat;
              base_dirs.gl_lstat = pglob->gl_lstat;
            }

          const char *base_pat;
          if (ss_slash_pos == 0)
            base_pat = "/";
          else
            {
              d[ss_slash_pos] = '\0';
              base_pat = d;
            }

          status = glob_body_inner (base_pat,
                                    ((flags & (GLOB_ERR | GLOB_NOESCAPE
                                               | GLOB_ALTDIRFUNC
                                               | GLOB_EXTMATCH | GLOB_CASEFOLD
                                               | GLOB_SKIPDOTS | GLOB_GLOBSTAR
                                               | GLOB_DOTDOT | GLOB_TILDE
                                               | GLOB_TILDE_CHECK
                                               | glob_interm_period_flag (flags)))
                                     | GLOB_KEEP_SLASHES | GLOB_NOSORT
                                     | GLOB_ONLYDIR),
                                    errfunc, &base_dirs);
          if (status == 0)
            {
              int gs_scan_flags
                = ((flags & ~(GLOB_MARK | GLOB_NOCHECK | GLOB_NOMAGIC))
                   | GLOB_ONLYDIR);
              for (size_t b = 0; b < base_dirs.gl_pathc; ++b)
                {
                  char *bdir = base_dirs.gl_pathv[b];
                  if (glob_testdir (bdir, flags, pglob, false) < 0)
                    continue;

                  char **nv = realloc (dirs.gl_pathv,
                                       (dirs.gl_pathc + 2) * sizeof (char *));
                  if (nv == NULL)
                    {
                      status = GLOB_NOSPACE;
                      break;
                    }
                  dirs.gl_pathv = nv;
                  dirs.gl_pathv[dirs.gl_pathc] = strdup (bdir);
                  if (dirs.gl_pathv[dirs.gl_pathc] == NULL)
                    {
                      dirs.gl_pathv[dirs.gl_pathc] = NULL;
                      status = GLOB_NOSPACE;
                      break;
                    }
                  dirs.gl_pathv[++dirs.gl_pathc] = NULL;

                  glob_t ss_dirs;
                  memset (&ss_dirs, 0, sizeof (ss_dirs));
                  if (__glibc_unlikely ((flags & GLOB_ALTDIRFUNC) != 0))
                    {
                      ss_dirs.gl_opendir = pglob->gl_opendir;
                      ss_dirs.gl_readdir = pglob->gl_readdir;
                      ss_dirs.gl_closedir = pglob->gl_closedir;
                      ss_dirs.gl_stat = pglob->gl_stat;
                      ss_dirs.gl_lstat = pglob->gl_lstat;
                    }

                  size_t blen = strlen (bdir);
                  char *scan_root = bdir;
                  bool free_scan_root = false;
                  if (blen > 1 && bdir[blen - 1] == '/')
                    {
                      scan_root = malloc (blen + 2);
                      if (scan_root == NULL)
                        {
                          status = GLOB_NOSPACE;
                          break;
                        }
                      memcpy (scan_root, bdir, blen);
                      scan_root[blen] = '/';
                      scan_root[blen + 1] = '\0';
                      free_scan_root = true;
                    }

                  int gsr = globstar_scan (scan_root, gs_scan_flags, 0,
                                           errfunc, &ss_dirs);
                  if (free_scan_root)
                    free (scan_root);
                  if (gsr != 0)
                    {
                      globfree (&ss_dirs);
                      status = gsr;
                      break;
                    }

                  for (size_t k = 0; k < ss_dirs.gl_pathc; ++k)
                    {
                      char *sd = ss_dirs.gl_pathv[k];
                      if (glob_testdir (sd, flags, pglob, true) != 0)
                        continue;
                      nv = realloc (dirs.gl_pathv,
                                    (dirs.gl_pathc + 2) * sizeof (char *));
                      if (nv == NULL)
                        {
                          status = GLOB_NOSPACE;
                          break;
                        }
                      dirs.gl_pathv = nv;
                      dirs.gl_pathv[dirs.gl_pathc++] = sd;
                      dirs.gl_pathv[dirs.gl_pathc] = NULL;
                      ss_dirs.gl_pathv[k] = NULL;
                    }
                  globfree (&ss_dirs);
                  if (status != 0)
                    break;
                }
              if (status == 0 && dirs.gl_pathc == 0)
                status = GLOB_NOMATCH;
              if (status != 0)
                {
                  globfree (&dirs);
                  dirs.gl_pathv = NULL;
                  dirs.gl_pathc = 0;
                }
            }
          globfree (&base_dirs);
        }
      else
        {
          status = glob_body_inner (d,
                                    ((flags & (GLOB_ERR | GLOB_NOESCAPE
                                               | GLOB_ALTDIRFUNC
                                               | GLOB_EXTMATCH | GLOB_CASEFOLD
                                               | GLOB_SKIPDOTS | GLOB_GLOBSTAR
                                               | GLOB_DOTDOT | GLOB_TILDE
                                               | GLOB_TILDE_CHECK
                                               | glob_interm_period_flag (flags)))
                                     | GLOB_NOSORT | GLOB_ONLYDIR),
                                    errfunc, &dirs);
        }
      if (status != 0)
        {
          if (((flags & GLOB_NOCHECK) == 0
               && !(pat_is_pure_literal && (flags & GLOB_NOMAGIC)))
              || status != GLOB_NOMATCH)
            {
              retval = status;
              goto out;
            }
          goto no_matches;
        }

      /* We have successfully globbed the preceding directory name.
         For each name we found, call glob_in_dir on it and FILENAME,
         appending the results to PGLOB.  */
      for (i = 0; i < dirs.gl_pathc; ++i)
        {
          size_t old_pathc = pglob->gl_pathc;
          char *dentry = dirs.gl_pathv[i];
          bool nulldir = (dentry[0] == '\0');
          const char *dname = nulldir ? "." : dentry;

          if (all_starstar && !nulldir)
            {
              /* Do not descend into symlinked directories for ** /...  */
              if (glob_testdir (dname, flags, pglob, true) < 0)
                continue;
            }
          else if (!nulldir && !last_starstar && (flags & GLOB_GLOBSTAR))
            {
              if (glob_testdir (dname, flags, pglob, false) < 0)
                continue;
            }

          if ((flags & GLOB_GLOBSTAR)
              && filename[0] == '*' && filename[1] == '*'
              && filename[2] == '\0')
            {
              const char *sdir = dname;
              char *alloc_sdir = NULL;
              if (!nulldir && !dir_has_magic)
                {
                  size_t dlen = strlen (dname);
                  if (dlen > 0 && dname[dlen - 1] != '/')
                    {
                      alloc_sdir = malloc (dlen + 2);
                      if (alloc_sdir == NULL)
                        {
                          globfree (&dirs);
                          globfree (pglob);
                          pglob->gl_pathc = 0;
                          retval = GLOB_NOSPACE;
                          goto out;
                        }
                      memcpy (alloc_sdir, dname, dlen);
                      alloc_sdir[dlen] = '/';
                      alloc_sdir[dlen + 1] = '\0';
                      sdir = alloc_sdir;
                    }
                }
              status = globstar_scan (sdir, flags,
                                      (nulldir ? GS_NULLDIR : GS_ADDCURDIR),
                                      errfunc, pglob);
              free (alloc_sdir);
              if (status != 0)
                {
                  globfree (&dirs);
                  globfree (pglob);
                  pglob->gl_pathc = 0;
                  retval = status;
                  goto out;
                }
              if (nulldir)
                break;
              continue;
            }

          status = glob_in_dir (filename, dname,
                                ((flags | GLOB_APPEND)
                                 & ~(GLOB_NOCHECK | GLOB_NOMAGIC)),
                                errfunc, pglob, alloca_used);
          if (status == GLOB_NOMATCH)
            /* No matches in this directory.  Try the next.  */
            continue;

          if (status != 0)
            {
              globfree (&dirs);
              globfree (pglob);
              pglob->gl_pathc = 0;
              retval = status;
              goto out;
            }

          if (!nulldir)
            {
              /* Stick the directory on the front of each name.  */
              if (prefix_array (dname,
                                &pglob->gl_pathv[old_pathc + pglob->gl_offs],
                                pglob->gl_pathc - old_pathc))
                {
                  globfree (&dirs);
                  globfree (pglob);
                  pglob->gl_pathc = 0;
                  retval = GLOB_NOSPACE;
                  goto out;
                }
            }
        }

      if (dir_has_magic || fn_has_magic)
        flags |= GLOB_MAGCHAR;

      /* We have ignored the GLOB_NOCHECK flag in the 'glob_in_dir' calls.
         But if we have not found any matching entry and the GLOB_NOCHECK
         flag was set we must return the input pattern itself.  */
      if (pglob->gl_pathc + pglob->gl_offs == oldcount)
        {
        no_matches:
          /* No matches.  */
          if ((flags & GLOB_NOCHECK)
              || (pat_is_pure_literal && (flags & GLOB_NOMAGIC)))
            {
              size_t newcount = pglob->gl_pathc + pglob->gl_offs;
              char **new_gl_pathv;

              if (newcount > SIZE_MAX / sizeof (char *) - 2)
                {
                nospace2:
                  globfree (&dirs);
                  retval = GLOB_NOSPACE;
                  goto out;
                }

              new_gl_pathv = realloc (pglob->gl_pathv,
                                      (newcount + 2) * sizeof (char *));
              if (new_gl_pathv == NULL)
                goto nospace2;
              pglob->gl_pathv = new_gl_pathv;

              pglob->gl_pathv[newcount] = strdup (pattern);
              if (pglob->gl_pathv[newcount] == NULL)
                {
                  globfree (&dirs);
                  globfree (pglob);
                  pglob->gl_pathc = 0;
                  retval = GLOB_NOSPACE;
                  goto out;
                }

              ++pglob->gl_pathc;
              ++newcount;

              pglob->gl_pathv[newcount] = NULL;
              pglob->gl_flags = flags;
            }
          else
            {
              globfree (&dirs);
              retval = GLOB_NOMATCH;
              goto out;
            }
        }
      else
        pglob->gl_flags = flags;

      globfree (&dirs);
    }
  else
    {
    only_filename:;
      size_t old_pathc = pglob->gl_pathc;
      int orig_flags = flags;

      if (meta & GLOBPAT_BACKSLASH)
        {
          char *p = strchr (dirname, '\\'), *q;
          /* We need to unescape the dirname string.  */
          q = p;
          do
            {
              if (*p == '\\')
                {
                  *q = *++p;
                  --dirlen;
                }
              else
                *q = *p;
              ++q;
            }
          while (*p++ != '\0');
          dirname_modified = 1;
        }
      if (dirname_modified)
        flags &= ~(GLOB_NOCHECK | GLOB_NOMAGIC);
      if ((flags & GLOB_GLOBSTAR)
          && filename[0] == '*' && filename[1] == '*'
          && filename[2] == '\0')
        {
          /* Expand dir/ ** or **.  */
          if (dirlen > 0 && glob_testdir (dirname, flags, pglob, false) < 0)
            status = GLOB_NOMATCH;
          else
            {
              int gs_flags = (dirlen == 0 ? GS_NULLDIR : GS_ADDCURDIR);
              char *sdir = dirname;
              bool free_sdir = false;
              if (dirlen > 0 && dirname[dirlen - 1] != '/')
                {
                  sdir = malloc (dirlen + 2);
                  if (sdir == NULL)
                    {
                      retval = GLOB_NOSPACE;
                      goto out;
                    }
                  memcpy (sdir, dirname, dirlen);
                  sdir[dirlen] = '/';
                  sdir[dirlen + 1] = '\0';
                  free_sdir = true;
                }
              status = globstar_scan (sdir, flags, gs_flags, errfunc, pglob);
              if (free_sdir)
                free (sdir);
              if (status == 0)
                {
                  flags |= GLOB_MAGCHAR;
                  pglob->gl_flags = flags;
                  if (pglob->gl_pathc == old_pathc)
                    status = GLOB_NOMATCH;
                }
            }
          if (status != 0)
            {
              if ((orig_flags & GLOB_NOCHECK) && status == GLOB_NOMATCH
                  && pglob->gl_pathc + pglob->gl_offs == oldcount)
                {
                  dirs.gl_pathv = NULL;
                  flags = orig_flags;
                  goto no_matches;
                }
              retval = status;
              goto out;
            }
        }
      else
        {
          status = glob_in_dir (filename, dirname, flags, errfunc, pglob,
                                alloca_used);
          if (status != 0)
            {
              if (status == GLOB_NOMATCH && flags != orig_flags
                  && pglob->gl_pathc + pglob->gl_offs == oldcount)
                {
                  /* Make sure globfree (&dirs); is a nop.  */
                  dirs.gl_pathv = NULL;
                  flags = orig_flags;
                  goto no_matches;
                }
              retval = status;
              goto out;
            }

          if (dirlen > 0)
            {
              /* Stick the directory on the front of each name.  */
              if (prefix_array (dirname,
                                &pglob->gl_pathv[old_pathc + pglob->gl_offs],
                                pglob->gl_pathc - old_pathc))
                {
                  globfree (pglob);
                  pglob->gl_pathc = 0;
                  retval = GLOB_NOSPACE;
                  goto out;
                }
            }
        }
    }

  if (flags & GLOB_MARK)
    {
      /* Append slashes to directory names.  */
      size_t i;

      for (i = oldcount; i < pglob->gl_pathc + pglob->gl_offs; ++i)
        {
          size_t curlen = strlen (pglob->gl_pathv[i]);
          if (curlen > 0 && pglob->gl_pathv[i][curlen - 1] == '/')
            continue;
          if (is_dir (pglob->gl_pathv[i], flags, pglob))
            {
            size_t len = curlen + 2;
            char *new = realloc (pglob->gl_pathv[i], len);
            if (new == NULL)
              {
                globfree (pglob);
                pglob->gl_pathc = 0;
                retval = GLOB_NOSPACE;
                goto out;
              }
            strcpy (&new[len - 2], "/");
            pglob->gl_pathv[i] = new;
            }
        }
    }

  if (!(flags & GLOB_NOSORT) && pglob->gl_pathc + pglob->gl_offs - oldcount > 1)
    {
      /* Sort the vector.  */
      qsort (&pglob->gl_pathv[oldcount],
             pglob->gl_pathc + pglob->gl_offs - oldcount,
             sizeof (char *), collated_compare);
    }

 out:
  if (__glibc_unlikely (malloc_dirname))
    free (dirname);

  return retval;
}

/* Run one glob call with its own FSWC context (see glob_fstatat).  */
int
GLOB_ATTRIBUTE
__glob (const char *pattern, int flags, int (*errfunc) (const char *, int),
        glob_t *pglob)
{
#if GLOB_FSWC
  struct fswc_call call = { 0 };
  struct fswc_call *outer = glob_fswc_call;
  glob_fswc_call = &call;
#endif
  int r = glob_body_inner (pattern, flags, errfunc, pglob);
#if GLOB_FSWC
  glob_fswc_call = outer;
#endif
  return r;
}
#if defined _LIBC && !defined __glob
versioned_symbol (libc, __glob, glob, GLIBC_2_27);
libc_hidden_ver (__glob, glob)
#endif


/* Do a collated comparison of A and B.  */
static int
collated_compare (const void *a, const void *b)
{
  char *const *ps1 = a; char *s1 = *ps1;
  char *const *ps2 = b; char *s2 = *ps2;

  if (s1 == s2)
    return 0;
  if (s1 == NULL)
    return 1;
  if (s2 == NULL)
    return -1;
  int r = strcoll (s1, s2);
  return r != 0 ? r : strcmp (s1, s2);
}


/* Prepend DIRNAME to each of N members of ARRAY, replacing ARRAY's
   elements in place.  Return nonzero if out of memory, zero if successful.
   A slash is inserted between DIRNAME and each elt of ARRAY,
   unless DIRNAME is just "/".  Each old element of ARRAY is freed.  */
static int
prefix_array (const char *dirname, char **array, size_t n)
{
  size_t i;
  size_t dirlen = strlen (dirname);
  char dirsep_char = '/';

  if (dirlen == 1 && dirname[0] == '/')
    /* DIRNAME is just "/", so normal prepending would get us "//foo".
       We want "/foo" instead, so don't prepend any chars from DIRNAME.  */
    dirlen = 0;

#if defined __MSDOS__ || defined WINDOWS32
  if (dirlen > 1)
    {
      if (dirname[dirlen - 1] == '/' && dirname[dirlen - 2] == ':')
        /* DIRNAME is "d:/".  Don't prepend the slash from DIRNAME.  */
        --dirlen;
      else if (dirname[dirlen - 1] == ':')
        {
          /* DIRNAME is "d:".  Use ':' instead of '/'.  */
          --dirlen;
          dirsep_char = ':';
        }
    }
#endif

  for (i = 0; i < n; ++i)
    {
      size_t eltlen = strlen (array[i]) + 1;
      char *new = malloc (dirlen + 1 + eltlen);
      if (new == NULL)
        /* ARRAY[0..I) are the new names and the rest the old ones:
           every caller frees them all with globfree.  */
        return 1;

      {
        char *endp = mempcpy (new, dirname, dirlen);
        *endp++ = dirsep_char;
        mempcpy (endp, array[i], eltlen);
      }
      free (array[i]);
      array[i] = new;
    }

  return 0;
}

/* Like 'glob', but PATTERN is a final pathname component,
   and matches are searched for in DIRECTORY.
   The GLOB_NOSORT bit in FLAGS is ignored.  No sorting is ever done.
   The GLOB_APPEND flag is assumed to be set (always appends).  */
static int
glob_in_dir (const char *pattern, const char *directory, int flags,
             int (*errfunc) (const char *, int),
             glob_t *pglob, size_t alloca_used)
{
  size_t dirlen = strlen (directory);
  void *stream = NULL;
  struct scratch_buffer s;
  scratch_buffer_init (&s);
# define GLOBNAMES_MEMBERS(nnames) \
    struct globnames *next; size_t count; char *name[nnames];
  struct globnames { GLOBNAMES_MEMBERS (FLEXIBLE_ARRAY_MEMBER) };
  struct { GLOBNAMES_MEMBERS (64) } init_names_buf;
  struct globnames *init_names = (struct globnames *) &init_names_buf;
  struct globnames *names = init_names;
  struct globnames *names_alloca = init_names;
  size_t nfound = 0;
  size_t cur = 0;
  int meta;
  int save;
  int result;

  alloca_used += sizeof init_names_buf;

  init_names->next = NULL;
  init_names->count = ((sizeof init_names_buf
                        - offsetof (struct globnames, name))
                       / sizeof init_names->name[0]);

  meta = __glob_pattern_type_ext (pattern, !(flags & GLOB_NOESCAPE),
                                  (flags & GLOB_EXTMATCH) != 0);
  bool has_magic = (meta & (GLOBPAT_SPECIAL | GLOBPAT_BRACKET)) != 0;
  bool casefold_scan
    = (!has_magic && (flags & GLOB_CASEFOLD) != 0 && pattern[0] != '\0'
       && strcmp (pattern, ".") != 0 && strcmp (pattern, "..") != 0
       && strcmp (pattern, "\\.") != 0 && strcmp (pattern, "\\..") != 0);
  if (!casefold_scan && meta == GLOBPAT_NONE
      && (flags & (GLOB_NOCHECK | GLOB_NOMAGIC)))
    {
      /* We need not do any tests.  The PATTERN contains no meta
         characters and we must not return an error therefore the
         result will always contain exactly one name.  */
      flags |= GLOB_NOCHECK;
    }
  else if (!has_magic && !casefold_scan)
    {
      size_t patlen = strlen (pattern);
      char *unesc_pat = (char *) pattern;
      bool alloca_unesc = false;
      if (meta & GLOBPAT_BACKSLASH)
        {
          alloca_unesc = glob_use_alloca (alloca_used, patlen + 1);
          if (alloca_unesc)
            unesc_pat = alloca_account (patlen + 1, alloca_used);
          else
            {
              unesc_pat = malloc (patlen + 1);
              if (unesc_pat == NULL)
                return GLOB_NOSPACE;
            }
          const char *p = pattern;
          char *q = unesc_pat;
          while (*p != '\0')
            {
              if (*p == '\\' && p[1] != '\0')
                ++p;
              *q++ = *p++;
            }
          *q = '\0';
          patlen = q - unesc_pat;
        }

      size_t fullsize;
      bool alloca_fullname
        = (! size_add_wrapv (dirlen + 1, patlen + 1, &fullsize)
           && glob_use_alloca (alloca_used, fullsize));
      char *fullname;
      if (alloca_fullname)
        fullname = alloca_account (fullsize, alloca_used);
      else
        {
          fullname = malloc (fullsize);
          if (fullname == NULL)
            {
              if ((meta & GLOBPAT_BACKSLASH) && __glibc_unlikely (!alloca_unesc))
                free (unesc_pat);
              return GLOB_NOSPACE;
            }
        }

      mempcpy (mempcpy (mempcpy (fullname, directory, dirlen),
                        "/", 1),
               unesc_pat, patlen + 1);
      if ((flags & GLOB_ONLYDIR)
          ? is_dir (fullname, flags, pglob)
          : (glob_lstat (pglob, flags, fullname) == 0
             || errno == EOVERFLOW))
        {
          /* We found this file to be existing.  Copy the unescaped name
             into the result.  */
          names->name[cur] = strdup (unesc_pat);
          if (names->name[cur] == NULL)
            {
              if (__glibc_unlikely (!alloca_fullname))
                free (fullname);
              if ((meta & GLOBPAT_BACKSLASH) && __glibc_unlikely (!alloca_unesc))
                free (unesc_pat);
              goto memory_error;
            }
          ++cur;
          ++nfound;
        }

      if (__glibc_unlikely (!alloca_fullname))
        free (fullname);
      if ((meta & GLOBPAT_BACKSLASH) && __glibc_unlikely (!alloca_unesc))
        free (unesc_pat);
    }
  else
    {
      stream = (__builtin_expect (flags & GLOB_ALTDIRFUNC, 0)
                ? (*pglob->gl_opendir) (directory)
                : opendir (directory));
      if (stream == NULL)
        {
          if (errno != ENOTDIR
              && ((errfunc != NULL && (*errfunc) (directory, errno))
                  || (flags & GLOB_ERR)))
            return GLOB_ABORTED;
        }
      else
        {
          int dfd = dirfd (stream);
          int fnm_flags = (FNM_PATHNAME
                           | (!(flags & GLOB_PERIOD) ? FNM_PERIOD : 0)
                           | ((flags & GLOB_NOESCAPE) ? FNM_NOESCAPE : 0)
                           | ((flags & GLOB_EXTMATCH) ? FNM_EXTMATCH : 0)
                           | ((flags & GLOB_CASEFOLD) ? FNM_CASEFOLD : 0)
                           | ((flags & GLOB_DOTDOT) ? FNM_DOTDOT : 0));
          const char *pat_end = pattern + strlen (pattern);
          if (has_magic)
            flags |= GLOB_MAGCHAR;

          while (1)
            {
              struct readdir_result d;
              {
                if (__builtin_expect (flags & GLOB_ALTDIRFUNC, 0))
                  d = convert_dirent (GL_READDIR (pglob, stream));
                else
                  {
#ifdef COMPILE_GLOB64
                    d = convert_dirent (__readdir (stream));
#else
                    d = convert_dirent64 (__readdir64 (stream));
#endif
                  }
              }
              if (d.name == NULL)
                break;

              if (skipname (pattern, pat_end, d.name, flags))
                continue;

              /* If we shall match only directories use the information
                 provided by the dirent call if possible.  */
              if (flags & GLOB_ONLYDIR)
                switch (readdir_result_type (d))
                  {
                  default: continue;
                  case DT_DIR: break;
                  case DT_LNK: case DT_UNKNOWN:
                    /* The filesystem was too lazy to give us a hint,
                       so we have to do it the hard way.  */
                    if (__glibc_unlikely (dfd < 0 || flags & GLOB_ALTDIRFUNC))
                      {
                        size_t namelen = strlen (d.name);
                        size_t need = dirlen + 1 + namelen + 1;
                        if (s.length < need
                            && !scratch_buffer_set_array_size (&s, need, 1))
                          goto memory_error;
                        char *p = mempcpy (s.data, directory, dirlen);
                        *p = '/';
                        p += p[-1] != '/';
                        memcpy (p, d.name, namelen + 1);
                        if (! is_dir (s.data, flags, pglob))
                          continue;
                      }
                    else
                      {
                        struct_stat64 st64;
                        if (! (GLOB_FSTATAT64 (dfd, d.name, &st64, 0) == 0
                               && S_ISDIR (st64.st_mode)))
                          continue;
                      }
                  }

              if (fnmatch (pattern, d.name, fnm_flags) == 0)
                {
                  if (cur == names->count)
                    {
                      struct globnames *newnames;
                      size_t count = names->count * 2;
                      size_t nameoff = offsetof (struct globnames, name);
                      size_t size = FLEXSIZEOF (struct globnames, name,
                                                count * sizeof (char *));
                      if ((SIZE_MAX - nameoff) / 2 / sizeof (char *)
                          < names->count)
                        goto memory_error;
                      if (glob_use_alloca (alloca_used, size))
                        newnames = names_alloca
                          = alloca_account (size, alloca_used);
                      else if ((newnames = malloc (size))
                               == NULL)
                        goto memory_error;
                      newnames->count = count;
                      newnames->next = names;
                      names = newnames;
                      cur = 0;
                    }
                  names->name[cur] = strdup (d.name);
                  if (names->name[cur] == NULL)
                    goto memory_error;
                  ++cur;
                  ++nfound;
                  if (SIZE_MAX - pglob->gl_offs <= nfound)
                    goto memory_error;
                }
            }
        }
    }

  if (nfound == 0
      && ((flags & GLOB_NOCHECK)
          || (meta == GLOBPAT_NONE && (flags & GLOB_NOMAGIC))))
    {
      size_t len = strlen (pattern);
      nfound = 1;
      names->name[cur] = malloc (len + 1);
      if (names->name[cur] == NULL)
        goto memory_error;
      *((char *) mempcpy (names->name[cur++], pattern, len)) = '\0';
    }

  result = GLOB_NOMATCH;
  if (nfound != 0)
    {
      char **new_gl_pathv;
      result = 0;

      if (SIZE_MAX / sizeof (char *) - pglob->gl_pathc
          < pglob->gl_offs + nfound + 1)
        goto memory_error;

      new_gl_pathv
        = realloc (pglob->gl_pathv,
                   (pglob->gl_pathc + pglob->gl_offs + nfound + 1)
                    * sizeof (char *));

      if (new_gl_pathv == NULL)
        {
        memory_error:
          while (1)
            {
              struct globnames *old = names;
              for (size_t i = 0; i < cur; ++i)
                free (names->name[i]);
              names = names->next;
              /* NB: we will not leak memory here if we exit without
                 freeing the current block assigned to OLD.  At least
                 the very first block is always allocated on the stack
                 and this is the block assigned to OLD here.  */
              if (names == NULL)
                {
                  assert (old == init_names);
                  break;
                }
              cur = names->count;
              if (old == names_alloca)
                names_alloca = names;
              else
                free (old);
            }
          result = GLOB_NOSPACE;
        }
      else
        {
          while (1)
            {
              struct globnames *old = names;
              for (size_t i = 0; i < cur; ++i)
                new_gl_pathv[pglob->gl_offs + pglob->gl_pathc++]
                  = names->name[i];
              names = names->next;
              /* NB: we will not leak memory here if we exit without
                 freeing the current block assigned to OLD.  At least
                 the very first block is always allocated on the stack
                 and this is the block assigned to OLD here.  */
              if (names == NULL)
                {
                  assert (old == init_names);
                  break;
                }
              cur = names->count;
              if (old == names_alloca)
                names_alloca = names;
              else
                free (old);
            }

          pglob->gl_pathv = new_gl_pathv;

          pglob->gl_pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

          pglob->gl_flags = flags;
        }
    }

  if (stream != NULL)
    {
      save = errno;
      if (__glibc_unlikely (flags & GLOB_ALTDIRFUNC))
        (*pglob->gl_closedir) (stream);
      else
        closedir (stream);
      __set_errno (save);
    }

  scratch_buffer_free (&s);
  return result;
}
