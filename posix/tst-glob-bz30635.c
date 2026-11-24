/* Test that glob does not overflow the stack with many slashes.
   Copyright (C) 2025-2026 Free Software Foundation, Inc.
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

#include <glob.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <support/test-driver.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xunistd.h>
#include <support/check.h>
#include <sys/resource.h>

/* Allocation size.  */
#define SIZE 4096

/* This test would cause a stack overflow on glibc 2.42 and earlier.  */
#define MAX_STACK_SIZE (8 * 1024 * 1024)

static void
touch_temp_reg (const char *path)
{
  int fd = xopen (path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  xclose (fd);
  add_temp_file (path);
}

static const char *
discover_squashfs_prefix (char *buf, size_t buf_sz)
{
  FILE *fp = fopen ("/proc/self/mountinfo", "re");
  if (fp == NULL)
    return NULL;

  char line[2048];
  while (fgets (line, sizeof (line), fp) != NULL)
    {
      char *sep = strstr (line, " - ");
      if (sep == NULL)
        continue;
      char fstype[64] = "";
      if (sscanf (sep + 3, "%63s", fstype) != 1
          || strcmp (fstype, "squashfs") != 0)
        continue;
      unsigned id = 0, par = 0;
      char dev[64] = "", root[256] = "", mp[512] = "";
      if (sscanf (line, "%u %u %63s %255s %511s",
                  &id, &par, dev, root, mp) != 5)
        continue;
      char *slash = strrchr (mp, '/');
      if (slash == NULL || slash == mp)
        continue;
      *slash = '\0';
      if (strlen (mp) + 1 <= buf_sz && access (mp, R_OK | X_OK) == 0)
        {
          strcpy (buf, mp);
          fclose (fp);
          return buf;
        }
    }
  fclose (fp);
  return NULL;
}

static int
do_test (void)
{
  struct rlimit stack_limit = { MAX_STACK_SIZE, MAX_STACK_SIZE };
  TEST_VERIFY_EXIT (setrlimit (RLIMIT_STACK, &stack_limit) == 0);
  glob_t g;
  char *pattern = xmalloc (SIZE);

  /* Test based on BZ #30635.  "/////////".  */
  memset (pattern, '/', SIZE - 1);
  pattern[SIZE - 1] = '\0';
  TEST_VERIFY (glob (pattern, 0, NULL, &g) == 0);
  globfree (&g);

  /* Test based on BZ #33537 using a self-contained temp directory so the test
     does not assume /bin/sh or /sw exists on the host.  */
  char *tdir = support_create_temp_directory ("tst-glob-bz30635-");
  char *pkg1_bin = xasprintf ("%s/pkg1/bin", tdir);
  char *pkg1_lib = xasprintf ("%s/pkg1/lib", tdir);
  char *pkg1_inc_sys = xasprintf ("%s/pkg1/include/sys", tdir);
  char *pkg1_inc_bwd = xasprintf ("%s/pkg1/include/c++/backward", tdir);
  xmkdirp (pkg1_bin, 0755);
  xmkdirp (pkg1_lib, 0755);
  xmkdirp (pkg1_inc_sys, 0755);
  xmkdirp (pkg1_inc_bwd, 0755);

  char *f_bash = xasprintf ("%s/bash", pkg1_bin);
  char *f_libc = xasprintf ("%s/libc.so.6", pkg1_lib);
  char *f_hdr = xasprintf ("%s/pkg1/include/stdio.h", tdir);
  char *f_types = xasprintf ("%s/types.h", pkg1_inc_sys);
  add_temp_file (xasprintf ("%s/pkg1", tdir));
  add_temp_file (pkg1_bin);
  add_temp_file (pkg1_lib);
  add_temp_file (xasprintf ("%s/pkg1/include", tdir));
  add_temp_file (xasprintf ("%s/pkg1/include/c++", tdir));
  add_temp_file (pkg1_inc_sys);
  add_temp_file (pkg1_inc_bwd);
  touch_temp_reg (f_bash);
  touch_temp_reg (f_libc);
  touch_temp_reg (f_hdr);
  touch_temp_reg (f_types);

  /* "<tdir>/<star>/////bin/bash" padded to SIZE - 1 bytes.  */
  size_t tlen = strlen (tdir);
  const char *tail = "bin/bash";
  size_t tail_len = strlen (tail);
  TEST_VERIFY_EXIT (tlen + 3 + tail_len < SIZE);
  memset (pattern, '/', SIZE - 1);
  memcpy (pattern, tdir, tlen);
  pattern[tlen] = '/';
  pattern[tlen + 1] = '*';
  memcpy (pattern + (SIZE - 1 - tail_len), tail, tail_len);
  pattern[SIZE - 1] = '\0';
  TEST_VERIFY (glob (pattern, 0, NULL, &g) == 0);
  globfree (&g);
  free (pattern);

  /* Verify wildcard fast paths vs uncached errfunc slow path on both the
     guaranteed temp tree and (when present) any SquashFS parent prefix.  */
  int dummy_err (const char *epath, int eerrno) { (void) epath; (void) eerrno; return 0; }
  static const char *const rel_pats[] =
    {
      "/*/bin/bash",
      "/*/bin/nonexistent_fluffy_test_binary",
      "/*/bin",
      "/*/bin/",
      "/*/lib/libc.so*",
      "/*/include/*.h",
      "/*/include/sys/types.h",
      "/*/include/sys/nonexistent_fluffy_test.h",
      "/*/include/c++/backward"
    };
  char sq_buf[512];
  const char *sq_pfx = discover_squashfs_prefix (sq_buf, sizeof (sq_buf));
  const char *roots[2] = { tdir, sq_pfx };
  for (size_t r = 0; r < 2; ++r)
    {
      if (roots[r] == NULL || access (roots[r], F_OK) != 0)
        continue;
      for (size_t i = 0; i < sizeof (rel_pats) / sizeof (rel_pats[0]); ++i)
        {
          char *full_pat = xasprintf ("%s%s", roots[r], rel_pats[i]);
          for (int pass = 0; pass < 2; ++pass)
            {
              glob_t g_fast, g_slow;
              int r_fast = glob (full_pat, 0, NULL, &g_fast);
              int r_slow = glob (full_pat, 0, dummy_err, &g_slow);
              TEST_COMPARE (r_fast, r_slow);
              if (r == 0 && strstr (rel_pats[i], "nonexistent") == NULL)
                TEST_COMPARE (r_fast, 0);
              if (r_fast == 0)
                {
                  TEST_COMPARE (g_fast.gl_pathc, g_slow.gl_pathc);
                  for (size_t j = 0; j < g_fast.gl_pathc; ++j)
                    TEST_COMPARE_STRING (g_fast.gl_pathv[j], g_slow.gl_pathv[j]);
                  globfree (&g_fast);
                  globfree (&g_slow);
                }
            }
          free (full_pat);
        }
    }

  /* Verify execvp sets errno = ENOENT when wildcard PATH lookup misses
     (using a non-empty wildcard PATH so PATH="" never probes CWD).  */
  char *safe_path = sq_pfx != NULL
                    ? xasprintf ("%s/*/bin:%s/*/bin", tdir, sq_pfx)
                    : xasprintf ("%s/*/bin", tdir);
  TEST_COMPARE (setenv ("PATH", safe_path, 1), 0);
  for (int pass = 0; pass < 2; ++pass)
    {
      char *const argv[] = { (char *) "nonexistent_fluffy_test_binary", NULL };
      errno = 0;
      TEST_COMPARE (execvp (argv[0], argv), -1);
      TEST_COMPARE (errno, ENOENT);
    }
  free (safe_path);

  free (f_types);
  free (f_hdr);
  free (f_libc);
  free (f_bash);
  free (pkg1_inc_bwd);
  free (pkg1_inc_sys);
  free (pkg1_lib);
  free (pkg1_bin);
  free (tdir);

  return 0;
}

#include <support/test-driver.c>
