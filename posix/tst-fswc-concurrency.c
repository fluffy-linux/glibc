/* 16-thread post-RELRO prefix stampede + pthread_cancel open() point test.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <support/check.h>
#include <support/subprocess.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/test-driver.h>
#include <support/xthread.h>
#include <support/xunistd.h>

#ifndef SQUASHFS_MAGIC
# define SQUASHFS_MAGIC 0x73717368
#endif

#define NTHREADS 16

static pthread_barrier_t start_barrier;
static const char *g_cold_prefixes[8];
static size_t g_num_prefixes;
static const char *g_first_pkg_dir;

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

static void *
stampede_worker (void *arg)
{
  size_t tid = (size_t) (uintptr_t) arg;
  xpthread_barrier_wait (&start_barrier);

  for (int iter = 0; iter < 25; ++iter)
    {
      const char *pfx = g_cold_prefixes[(tid + (size_t) iter) % g_num_prefixes];
      char pat[512];
      snprintf (pat, sizeof (pat), "%s/*", pfx);

      glob_t gl;
      int r = glob (pat, GLOB_ONLYDIR, NULL, &gl);
      TEST_COMPARE (r, 0);
      TEST_VERIFY (gl.gl_pathc >= 1);
      globfree (&gl);

      if (tid == 0 && (iter % 5) == 0)
        {
          /* Exercise multi-threaded __libc_fork quiescing while 15 sibling
             threads concurrently acquire/revalidate FSWC slots.  */
          pid_t cpid = xfork ();
          if (cpid == 0)
            {
              glob_t cgl;
              if (glob (pat, GLOB_ONLYDIR, NULL, &cgl) != 0)
                _exit (3);
              globfree (&cgl);
              _exit (0);
            }
          int cst = 0;
          xwaitpid (cpid, &cst, 0);
          TEST_VERIFY (WIFEXITED (cst) && WEXITSTATUS (cst) == 0);
        }
      else if (tid == 1 && (iter % 4) == 0)
        {
          /* Credential syscalls concurrently with slot acquisition & fork.  */
          (void) setegid (getegid ());
        }

      if (g_first_pkg_dir != NULL)
        {
          char miss[840];
          snprintf (miss, sizeof (miss), "%s/nonexistent_conc_%zu_%d",
                    g_first_pkg_dir, tid, iter);
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
    }
  return NULL;
}

static void *
cancel_open_worker (void *arg)
{
  const char *miss_path = (const char *) arg;
  /* Self-cancel while deferred cancellation is enabled, then invoke open() on
     a missing path inside a cached package: POSIX requires open() to act as
     a cancellation point rather than returning -1/ENOENT.  */
  TEST_COMPARE (pthread_cancel (pthread_self ()), 0);
  int fd = open (miss_path, O_RDONLY);
  if (fd >= 0)
    close (fd);
  return (void *) 1;
}

static int
do_test (int argc, char *argv[])
{
  (void) argc;
  (void) argv;
  char *tmp = support_create_temp_directory ("tst-fswc-conc-");
  char *plain = xasprintf ("%s/plain", tmp);
  char *p1 = xasprintf ("%s/pkgA", plain);
  xmkdirp (p1, 0755);

  char pfx_buf[512] = "";
  char pkg_dir_buf[768] = "";
  const char *real_pfx = find_squash_prefix (pfx_buf, sizeof (pfx_buf),
                                             pkg_dir_buf, sizeof (pkg_dir_buf));
  if (real_pfx == NULL)
    {
      real_pfx = plain;
      g_first_pkg_dir = p1;
    }
  else
    g_first_pkg_dir = pkg_dir_buf;

  /* Create both real cold directory prefixes (exercising fswc_perm_alloc_locked)
     and symlink prefixes so all 16 threads race on cold slot initialization
     and multi-threaded fork simultaneously.  */
  char *syms[4];
  char *real_dirs[3];
  g_num_prefixes = 0;
  g_cold_prefixes[g_num_prefixes++] = real_pfx;
  for (int i = 0; i < 3; ++i)
    {
      real_dirs[i] = xasprintf ("%s/cold_real_%d", tmp, i);
      char *sub = xasprintf ("%s/pkg0", real_dirs[i]);
      xmkdirp (sub, 0755);
      free (sub);
      g_cold_prefixes[g_num_prefixes++] = real_dirs[i];
    }
  for (int i = 0; i < 4; ++i)
    {
      syms[i] = xasprintf ("%s/cold_pfx_%d", tmp, i);
      xsymlink (real_pfx, syms[i]);
      g_cold_prefixes[g_num_prefixes++] = syms[i];
    }

  xpthread_barrier_init (&start_barrier, NULL, NTHREADS);
  pthread_t th[NTHREADS];
  for (size_t i = 0; i < NTHREADS; ++i)
    th[i] = xpthread_create (NULL, stampede_worker, (void *) (uintptr_t) i);
  for (size_t i = 0; i < NTHREADS; ++i)
    xpthread_join (th[i]);
  xpthread_barrier_destroy (&start_barrier);

  /* Verify _Fork resets the FSWC lock cleanly in a multithreaded process.  */
  pid_t fpid = xfork ();
  if (fpid == 0)
    {
      char pat[512];
      snprintf (pat, sizeof (pat), "%s/*", syms[0]);
      glob_t gl;
      if (glob (pat, GLOB_ONLYDIR, NULL, &gl) != 0)
        _exit (2);
      globfree (&gl);
      _exit (0);
    }
  int status = 0;
  xwaitpid (fpid, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);

  /* Verify open() on a missing path inside a cached package remains a POSIX
     cancellation point (the wrapper is unmodified upstream).  */
  if (g_first_pkg_dir != NULL)
    {
      char miss[840];
      snprintf (miss, sizeof (miss), "%s/nonexistent_cancel_target",
                g_first_pkg_dir);
      TEST_COMPARE (open (miss, O_RDONLY), -1);

      pthread_t cth = xpthread_create (NULL, cancel_open_worker, miss);
      void *res = xpthread_join (cth);
      TEST_VERIFY (res == PTHREAD_CANCELED);
    }

  nftw (tmp, rm_child_cb, 32, FTW_DEPTH | FTW_PHYS);
  for (int i = 0; i < 4; ++i)
    free (syms[i]);
  for (int i = 0; i < 3; ++i)
    free (real_dirs[i]);
  free (p1);
  free (plain);
  free (tmp);
  return 0;
}

#define TEST_FUNCTION_ARGV do_test
#include <support/test-driver.c>
