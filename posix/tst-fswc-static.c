/* Static-linking (libc.a) FSWC test: BSS state, init, fork, glob, and VFS.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <support/check.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xunistd.h>

#ifndef SQUASHFS_MAGIC
# define SQUASHFS_MAGIC 0x73717368
#endif

static int
rm_child_cb (const char *fpath, const struct stat *sb, int tflag,
             struct FTW *ftwbuf)
{
  (void) sb;
  (void) tflag;
  if (ftwbuf->level > 0)
    remove (fpath);
  return 0;
}

static const char *
find_squash_prefix (char *pfx_out, size_t pfx_sz,
                    char *pkg_dir_out, size_t pkg_dir_sz)
{
  const char *env_p = getenv ("FSWC_TEST_PREFIX");
  if (env_p != NULL && strcmp (env_p, "none") == 0)
    return NULL;
  if (env_p != NULL && env_p[0] == '/')
    {
      DIR *ed = opendir (env_p);
      if (ed != NULL)
        {
          struct dirent *de;
          while ((de = readdir (ed)) != NULL)
            {
              if (de->d_name[0] == '.')
                continue;
              char sub[768];
              snprintf (sub, sizeof (sub), "%s/%s", env_p, de->d_name);
              struct stat st;
              struct statfs sfs;
              if (lstat (sub, &st) == 0 && S_ISDIR (st.st_mode)
                  && statfs (sub, &sfs) == 0 && sfs.f_type == SQUASHFS_MAGIC)
                {
                  snprintf (pfx_out, pfx_sz, "%s", env_p);
                  snprintf (pkg_dir_out, pkg_dir_sz, "%s", sub);
                  closedir (ed);
                  return pfx_out;
                }
            }
          closedir (ed);
        }
      return NULL;
    }

  FILE *fp = fopen ("/proc/self/mountinfo", "r");
  if (fp == NULL)
    return NULL;

  char best[512] = "";
  char best_pkg[768] = "";
  size_t best_cnt = 0;
  char line[2048];
  while (fgets (line, sizeof (line), fp) != NULL)
    {
      const char *sep = strstr (line, " - ");
      if (sep == NULL)
        continue;
      const char *fstype = sep + 3;
      if (strncmp (fstype, "squashfs ", 9) != 0
          && strncmp (fstype, "squashfs\t", 9) != 0)
        continue;
      const char *p = line;
      for (int f = 0; f < 4 && p < sep; ++f)
        {
          while (p < sep && *p != ' ')
            ++p;
          while (p < sep && *p == ' ')
            ++p;
        }
      const char *mp_end = p;
      while (mp_end < sep && *mp_end != ' ')
        ++mp_end;
      size_t mp_len = (size_t) (mp_end - p);
      if (mp_len < 3 || mp_len >= sizeof (best) || p[0] != '/'
          || memchr (p, '\\', mp_len) != NULL)
        continue;
      const char *last_slash = NULL;
      size_t slashes = 0;
      for (size_t i = 0; i < mp_len; ++i)
        if (p[i] == '/')
          {
            last_slash = p + i;
            ++slashes;
          }
      if (last_slash == NULL || last_slash == p || slashes >= 15)
        continue;
      size_t par_len = (size_t) (last_slash - p);
      char par[512];
      memcpy (par, p, par_len);
      par[par_len] = '\0';
      if (strcmp (par, best) == 0)
        continue;
      DIR *d = opendir (par);
      if (d == NULL)
        continue;
      size_t sq_cnt = 0;
      char first_sub[768] = "";
      struct dirent *de;
      while ((de = readdir (d)) != NULL)
        {
          if (de->d_name[0] == '.')
            continue;
          char sub[768];
          snprintf (sub, sizeof (sub), "%s/%s", par, de->d_name);
          struct stat st;
          struct statfs sfs;
          if (lstat (sub, &st) == 0 && S_ISDIR (st.st_mode)
              && statfs (sub, &sfs) == 0 && sfs.f_type == SQUASHFS_MAGIC)
            {
              if (sq_cnt == 0)
                snprintf (first_sub, sizeof (first_sub), "%s", sub);
              ++sq_cnt;
            }
        }
      closedir (d);
      if (sq_cnt > best_cnt)
        {
          best_cnt = sq_cnt;
          memcpy (best, par, par_len + 1);
          snprintf (best_pkg, sizeof (best_pkg), "%s", first_sub);
        }
    }
  fclose (fp);
  if (best_cnt == 0)
    return NULL;
  snprintf (pfx_out, pfx_sz, "%s", best);
  snprintf (pkg_dir_out, pkg_dir_sz, "%s", best_pkg);
  return pfx_out;
}

static int
do_test (void)
{
  char *tmp = support_create_temp_directory ("tst-fswc-static-");
  char *d1 = xasprintf ("%s/pkg1/bin", tmp);
  xmkdirp (d1, 0755);
  char *f1 = xasprintf ("%s/tool", d1);
  int fd = xopen (f1, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  xclose (fd);

  char pat[1024];
  snprintf (pat, sizeof (pat), "%s/*/bin/tool", tmp);
  glob_t gl;
  TEST_COMPARE (glob (pat, 0, NULL, &gl), 0);
  TEST_COMPARE (gl.gl_pathc, 1);
  TEST_COMPARE_STRING (gl.gl_pathv[0], f1);
  globfree (&gl);

  char pfx_buf[512] = "";
  char pkg_dir[768] = "";
  const char *sq_pfx = find_squash_prefix (pfx_buf, sizeof (pfx_buf),
                                           pkg_dir, sizeof (pkg_dir));
  const char *probe_dir = sq_pfx != NULL ? pkg_dir : d1;
  if (sq_pfx != NULL)
    {
      snprintf (pat, sizeof (pat), "%s/*", sq_pfx);
      for (int pass = 0; pass < 2; ++pass)
        {
          TEST_COMPARE (glob (pat, GLOB_ONLYDIR, NULL, &gl), 0);
          TEST_VERIFY (gl.gl_pathc >= 1);
          globfree (&gl);
        }
    }

  char miss[840];
  snprintf (miss, sizeof (miss), "%s/nonexistent_static_probe", probe_dir);
  for (int pass = 0; pass < 2; ++pass)
    {
      errno = 0;
      TEST_COMPARE (open (miss, O_RDONLY), -1);
      TEST_COMPARE (errno, ENOENT);

      struct statx stx;
      errno = 0;
      TEST_COMPARE (statx (AT_FDCWD, miss, 0, STATX_BASIC_STATS, &stx), -1);
      TEST_COMPARE (errno, ENOENT);

      errno = 0;
      TEST_COMPARE (access (miss, F_OK), -1);
      TEST_COMPARE (errno, ENOENT);
    }

  /* Verify fork() in static binary keeps FSWC working cleanly.  */
  pid_t pid = xfork ();
  if (pid == 0)
    {
      snprintf (pat, sizeof (pat), "%s/*/bin/tool", tmp);
      if (glob (pat, 0, NULL, &gl) != 0 || gl.gl_pathc != 1)
        _exit (2);
      globfree (&gl);
      _exit (0);
    }
  int status = 0;
  xwaitpid (pid, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);

  nftw (tmp, rm_child_cb, 32, FTW_DEPTH | FTW_PHYS);
  free (f1);
  free (d1);
  free (tmp);
  return 0;
}

#include <support/test-driver.c>
