/* glob when an allocation fails.
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

/* Every case below is run once to count the allocations glob makes
   and to record its result, and then once for each of those
   allocations with that one failing (as nss/tst-nss-malloc-failure-
   getlogin_r does), each run in a subprocess.  glob must then give the
   same result; or report GLOB_NOSPACE or GLOB_ABORTED, leaving in
   *PGLOB only names it matched (POSIX keeps what was found before the
   error, and a GLOB_APPEND caller's earlier matches come first unless
   glob freed them all, as upstream's error paths do); or give some of
   the matches, because glob skips a directory it cannot open and a name
   fnmatch fails on, as it always has (GLOB_NOMATCH if none are left).
   globfree must then free what is left exactly once.  */

#include <array_length.h>
#include <errno.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <support/check.h>
#include <support/namespace.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xunistd.h>

struct shared_data
{
  /* Allocations counted so far, while COUNTING.  */
  volatile unsigned int allocation_count;
  /* The allocation that fails (~0U: none).  */
  volatile unsigned int failing_allocation;
  volatile bool counting;
  /* Whether the failing allocation was reached.  */
  volatile bool injected;
  /* The result of the run without failures.  */
  volatile int expected_ret;
  char expected[8192];
};

static struct shared_data *shared;

static bool
fail_this_allocation (void)
{
  if (shared == NULL || !shared->counting)
    return false;
  unsigned int count = shared->allocation_count;
  shared->allocation_count = count + 1;
  if (count == shared->failing_allocation)
    {
      shared->injected = true;
      return true;
    }
  return false;
}

void *
malloc (size_t size)
{
  if (fail_this_allocation ())
    {
      errno = ENOMEM;
      return NULL;
    }
  extern __typeof (malloc) __libc_malloc;
  return __libc_malloc (size);
}

void *
calloc (size_t a, size_t b)
{
  if (fail_this_allocation ())
    {
      errno = ENOMEM;
      return NULL;
    }
  extern __typeof (calloc) __libc_calloc;
  return __libc_calloc (a, b);
}

void *
realloc (void *ptr, size_t size)
{
  if (fail_this_allocation ())
    {
      errno = ENOMEM;
      return NULL;
    }
  extern __typeof (realloc) __libc_realloc;
  return __libc_realloc (ptr, size);
}

struct test_case
{
  const char *pattern;
  int flags;
  /* With GLOB_APPEND: the pattern of the first, unfailing call.  */
  const char *first;
};

static const struct test_case cases[] =
  {
    /* prefix_array, which puts the directory in front of each name
       found in it, used to free the names it had already made when an
       allocation failed, and glob then freed them again.  */
    { "d*/*", 0 },
    { "d*/*", GLOB_ONLYDIR },
    { "d*/*", GLOB_MARK | GLOB_APPEND | GLOB_DOOFFS, "d2/*" },
    { "{d1,d2}/*", GLOB_BRACE },
    { "d1/\\a.txt", 0 },
    { "*", GLOB_PERIOD },
    { "zz*", GLOB_NOCHECK },
  };

static const struct test_case *current;

/* Join PGLOB's matches (after its offsets) into BUF, one per line.  */
static void
join (const glob_t *pglob, char *buf, size_t size)
{
  buf[0] = '\0';
  size_t used = 0;
  for (size_t i = 0; i < pglob->gl_pathc; ++i)
    {
      const char *p = pglob->gl_pathv[pglob->gl_offs + i];
      size_t len = strlen (p);
      TEST_VERIFY_EXIT (used + len + 2 <= size);
      memcpy (buf + used, p, len);
      used += len;
      buf[used++] = '\n';
      buf[used] = '\0';
    }
}

/* Run CURRENT's glob, with failure injection armed for the call with
   CURRENT's pattern only.  Return glob's result; *PGLOB holds the
   matches.  */
static int
run_glob (glob_t *pglob)
{
  memset (pglob, 0, sizeof (*pglob));
  int flags = current->flags;
  if (flags & GLOB_DOOFFS)
    pglob->gl_offs = 2;
  if (flags & GLOB_APPEND)
    TEST_COMPARE (glob (current->first, flags & ~GLOB_APPEND, NULL, pglob),
                  0);
  shared->allocation_count = 0;
  shared->counting = true;
  int ret = glob (current->pattern, flags, NULL, pglob);
  shared->counting = false;
  return ret;
}

/* Whether every line of GOT is a line of EXPECTED, in the same
   order.  */
static bool
is_subsequence (const char *got, const char *expected)
{
  while (*got != '\0')
    {
      const char *end = strchr (got, '\n');
      size_t len = end + 1 - got;
      while (*expected != '\0' && strncmp (expected, got, len) != 0)
        expected = strchr (expected, '\n') + 1;
      if (*expected == '\0')
        return false;
      expected += len;
      got += len;
    }
  return true;
}

/* Whether NAME[0..LEN), without trailing slashes, is a line of
   EXPECTED, without trailing slashes.  */
static bool
among (const char *name, size_t len, const char *expected)
{
  while (len > 1 && name[len - 1] == '/')
    --len;
  for (const char *e = expected; *e != '\0'; e = strchr (e, '\n') + 1)
    {
      size_t elen = strchr (e, '\n') - e;
      while (elen > 1 && e[elen - 1] == '/')
        --elen;
      if (elen == len && memcmp (e, name, len) == 0)
        return true;
    }
  return false;
}

static void
record_expected (void *closure)
{
  glob_t gl;
  shared->expected_ret = run_glob (&gl);
  join (&gl, shared->expected, sizeof (shared->expected));
  globfree (&gl);
}

static void
run_failing (void *closure)
{
  glob_t gl;
  char before[sizeof (shared->expected)] = "";
  if (current->flags & GLOB_APPEND)
    {
      /* The matches of the first call, which a failing second call
         must leave alone.  */
      memset (&gl, 0, sizeof (gl));
      if (current->flags & GLOB_DOOFFS)
        gl.gl_offs = 2;
      TEST_COMPARE (glob (current->first,
                          current->flags & ~GLOB_APPEND, NULL, &gl), 0);
      join (&gl, before, sizeof (before));
      globfree (&gl);
    }

  int ret = run_glob (&gl);
  char got[sizeof (shared->expected)];
  join (&gl, got, sizeof (got));
  if (ret == GLOB_NOSPACE || ret == GLOB_ABORTED)
    {
      /* POSIX leaves the matches found before the error in *PGLOB,
         not necessarily sorted or marked yet.  With GLOB_APPEND, the
         earlier ones come first, unless glob freed them all, as
         upstream's error paths do.  */
      size_t blen = strlen (before);
      if (got[0] != '\0')
        TEST_COMPARE_BLOB (got, strlen (got) < blen ? strlen (got) : blen,
                           before, blen);
      for (const char *p = got + (strlen (got) >= blen ? blen : 0);
           *p != '\0'; p = strchr (p, '\n') + 1)
        if (!among (p, strchr (p, '\n') - p, shared->expected))
          FAIL ("pattern \"%s\", flags %#x, allocation %u failing:"
                " match \"%.*s\" not among\n%s", current->pattern,
                current->flags, shared->failing_allocation,
                (int) (strchr (p, '\n') - p), p, shared->expected);
    }
  else if (shared->expected_ret == 0
           && (ret == 0 || ret == GLOB_NOMATCH))
    {
      if (!is_subsequence (got, shared->expected))
        FAIL ("pattern \"%s\", flags %#x, allocation %u failing:"
              " matches\n%snot among\n%s", current->pattern,
              current->flags, shared->failing_allocation, got,
              shared->expected);
    }
  else
    {
      TEST_COMPARE (ret, shared->expected_ret);
      TEST_COMPARE_STRING (got, shared->expected);
    }
  globfree (&gl);
}

static int
do_test (void)
{
  char *dir = support_create_temp_directory ("tst-glob-nomem-");
  xchdir (dir);
  static const char *const dirs[] =
    { "d1", "d1/sub", "d1/sub/deep", "d2" };
  for (size_t i = 0; i < array_length (dirs); ++i)
    {
      xmkdir (dirs[i], 0755);
      add_temp_file (xasprintf ("%s/%s", dir, dirs[i]));
    }
  static const char *const files[] =
    { "f1", "d1/a.txt", "d1/b.c", "d1/sub/c.txt", "d1/sub/deep/e.txt",
      "d2/x.txt", ".hidden" };
  for (size_t i = 0; i < array_length (files); ++i)
    {
      support_write_file_string (files[i], "");
      add_temp_file (xasprintf ("%s/%s", dir, files[i]));
    }

  shared = support_shared_allocate (sizeof (*shared));
  for (size_t c = 0; c < array_length (cases); ++c)
    {
      current = &cases[c];
      shared->failing_allocation = ~0U;
      support_isolate_in_subprocess (record_expected, NULL);
      unsigned int total = shared->allocation_count;
      printf ("info: \"%s\" (flags %#x): %u allocations, result %d\n",
              current->pattern, current->flags, total,
              shared->expected_ret);
      for (unsigned int n = 0; n < total; ++n)
        {
          shared->failing_allocation = n;
          shared->injected = false;
          support_isolate_in_subprocess (run_failing, NULL);
          TEST_VERIFY (shared->injected);
        }
    }
  support_shared_free (shared);
  shared = NULL;

  free (dir);
  return 0;
}

#include <support/test-driver.c>
