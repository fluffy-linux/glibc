/* FSWC on the real package prefix.
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

/* What no synthetic prefix can show, checked where /sw holds SquashFS
   package mounts (a Fluffy system, or swctl's build sandbox), and
   UNSUPPORTED elsewhere:

   - a fresh dynamically linked process leaves an index for /sw;
   - the index lists every entry of /sw, and seals exactly the packages
     the rules allow (the root of a SquashFS mount, nothing mounted
     beneath, every directory world-readable, no POSIX ACL), worked out
     here independently of the builder;
   - at least one package is sealed, so lookups do use the index (a
     correct but always-unsealed index would pass every other test while
     costing the plain walk);
   - searches over the real /sw, with its image files beside the
     packages, give the plain walk's answers: a missing command fails
     with ENOENT in execvp and posix_spawnp, a missing library with "No
     such file or directory", and glob matches the reference walk.  */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/* The index format; its declarations of internal functions need this.  */
#ifndef attribute_hidden
# define attribute_hidden
#endif
#include <fswc-index.h>
#include <support/check.h>
#include <support/subprocess.h>
#include <support/support.h>
#include <support/xunistd.h>

#define PREFIX "/sw"
#ifndef SQUASHFS_MAGIC
# define SQUASHFS_MAGIC 0x73717368
#endif
#ifndef STATX_ATTR_MOUNT_ROOT
# define STATX_ATTR_MOUNT_ROOT 0x2000
#endif
#ifndef NS_GET_MNTNS_ID
# define NS_GET_MNTNS_ID _IOR (0xb7, 0x5, uint64_t)
#endif

/* Is every directory beneath the current nftw walk world-listable and
   searchable, and free of POSIX ACLs?  */
static bool tree_ok;

static int
check_dir (const char *path, const struct stat *st, int type,
           struct FTW *ftw)
{
  if (type == FTW_D || type == FTW_DNR)
    {
      if ((st->st_mode & 0005) != 0005 || type == FTW_DNR)
        tree_ok = false;
      else if (lgetxattr (path, "system.posix_acl_access", NULL, 0) >= 0)
        tree_ok = false;
    }
  return tree_ok ? 0 : 1;
}

/* Is anything mounted beneath /sw/NAME?  */
static bool
mounted_beneath (const char *name)
{
  FILE *fp = fopen ("/proc/self/mountinfo", "re");
  TEST_VERIFY_EXIT (fp != NULL);
  char *below = xasprintf (PREFIX "/%s/", name);
  size_t below_len = strlen (below);
  char line[4096];
  bool found = false;
  while (!found && fgets (line, sizeof line, fp) != NULL)
    {
      char mp[4096];
      if (sscanf (line, "%*u %*u %*s %*s %4095s", mp) == 1
          && strncmp (mp, below, below_len) == 0)
        found = true;
    }
  fclose (fp);
  free (below);
  return found;
}

/* Would the builder seal /sw/NAME?  Also counts the SquashFS mount roots
   in *SQUASH.  */
static bool
should_seal (const char *name, int *squash)
{
  char *path = xasprintf (PREFIX "/%s", name);
  struct statx stx;
  bool seal = false;
  if (statx (AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_TYPE, &stx) == 0
      && S_ISDIR (stx.stx_mode)
      && (stx.stx_attributes & STATX_ATTR_MOUNT_ROOT))
    {
      struct statfs sfs;
      if (statfs (path, &sfs) == 0 && sfs.f_type == SQUASHFS_MAGIC)
        {
          ++*squash;
          tree_ok = true;
          seal = !mounted_beneath (name)
                 && nftw (path, check_dir, 16, FTW_PHYS) == 0 && tree_ok;
        }
    }
  free (path);
  return seal;
}

/* This process's index of /sw, or NULL.  */
static char *
find_index (void)
{
  struct stat st;
  xstat (PREFIX, &st);
  uint64_t mntns = 0;
  int ns = open ("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  bool have_ns = ns >= 0 && ioctl (ns, NS_GET_MNTNS_ID, &mntns) == 0;
  if (ns >= 0)
    xclose (ns);
  char *pat = xasprintf ("/dev/shm/.fswc-%u-*/idx-%s-%llu-%llu",
                         (unsigned int) geteuid (), "*",
                         ((unsigned long long) major (st.st_dev) << 32)
                         | minor (st.st_dev),
                         (unsigned long long) st.st_ino);
  glob_t g;
  char *found = NULL;
  if (glob (pat, 0, NULL, &g) == 0)
    {
      char *want = xasprintf ("/idx-%llu-", (unsigned long long) mntns);
      for (size_t i = 0; found == NULL && i < g.gl_pathc; ++i)
        if (have_ns ? strstr (g.gl_pathv[i], want) != NULL
                    : g.gl_pathc == 1)
          found = xstrdup (g.gl_pathv[i]);
      free (want);
      globfree (&g);
    }
  free (pat);
  return found;
}

/* Start a fresh dynamically linked process, whose startup builds the
   index when there is none.  */
static void
start_dynamic (char *self)
{
  pid_t pid = xfork ();
  if (pid == 0)
    {
      setenv ("FSWC_REAL_PROBE", "1", 1);
      char *argv[] = { self, (char *) "--direct", NULL };
      struct support_spawn_wrapped *w = support_spawn_wrap (self, argv,
                                                            NULL, 0);
      execve (w->path, w->argv, w->envp);
      _exit (127);
    }
  int status;
  xwaitpid (pid, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
}

/* glob with caller hooks bypasses FSWC: the reference walk.  */
static void
check_glob (const char *pattern)
{
  glob_t got, want;
  memset (&want, 0, sizeof want);
  want.gl_opendir = (void *(*) (const char *)) opendir;
  want.gl_readdir = (struct dirent *(*) (void *)) readdir;
  want.gl_closedir = (void (*) (void *)) closedir;
  want.gl_stat = stat;
  want.gl_lstat = lstat;
  int rg = glob (pattern, 0, NULL, &got);
  int rw = glob (pattern, GLOB_ALTDIRFUNC, NULL, &want);
  TEST_COMPARE (rg, rw);
  if (rg == 0 && rw == 0)
    {
      TEST_COMPARE (got.gl_pathc, want.gl_pathc);
      for (size_t i = 0; i < got.gl_pathc && i < want.gl_pathc; ++i)
        TEST_COMPARE_STRING (got.gl_pathv[i], want.gl_pathv[i]);
    }
  if (rg == 0)
    globfree (&got);
  if (rw == 0)
    globfree (&want);
}

static int
do_test (int argc, char *argv[])
{
  if (getenv ("FSWC_REAL_PROBE") != NULL)
    return 0;

  DIR *d = opendir (PREFIX);
  if (d == NULL)
    FAIL_UNSUPPORTED ("no " PREFIX);
  char **names = NULL;
  bool *seal = NULL;
  size_t n = 0;
  int squash = 0;
  for (struct dirent *e; (e = readdir (d)) != NULL; )
    {
      if (e->d_name[0] == '.')
        continue;
      names = xrealloc (names, (n + 1) * sizeof *names);
      seal = xrealloc (seal, (n + 1) * sizeof *seal);
      names[n] = xstrdup (e->d_name);
      seal[n] = should_seal (e->d_name, &squash);
      ++n;
    }
  closedir (d);
  if (squash == 0)
    FAIL_UNSUPPORTED ("no SquashFS package mounts in " PREFIX);
  if (access ("/dev/shm", W_OK | X_OK) != 0)
    FAIL_UNSUPPORTED ("/dev/shm is not writable, so FSWC cannot work here");
  printf ("info: %zu entries in " PREFIX ", %d SquashFS mounts\n", n, squash);

  /* A build declines while /sw changed within the current coarse-clock
     tick, so retry for a while.  */
  char *idx = NULL;
  for (int i = 0; i < 50 && (idx = find_index ()) == NULL; ++i)
    {
      start_dynamic (argv[0]);
      struct timespec ts = { 0, 20 * 1000 * 1000 };
      nanosleep (&ts, NULL);
    }
  if (idx == NULL)
    FAIL_EXIT1 ("no FSWC index for " PREFIX " after 50 fresh processes: "
                "every lookup takes the plain walk");
  printf ("info: index %s\n", idx);

  int fd = xopen (idx, O_RDONLY, 0);
  struct stat ist;
  xfstat (fd, &ist);
  TEST_COMPARE (ist.st_mode & 07777, 0400);
  TEST_COMPARE (ist.st_uid, geteuid ());
  const char *map = xmmap (NULL, ist.st_size, PROT_READ, MAP_PRIVATE, fd);
  xclose (fd);
  const struct fswc_idx_header *h = (const void *) map;
  TEST_VERIFY_EXIT ((size_t) ist.st_size >= sizeof *h);
  TEST_VERIFY_EXIT (h->top_off + (uint64_t) h->num_top
                    * sizeof (struct fswc_top) <= (uint64_t) ist.st_size);
  const struct fswc_top *tops = (const void *) (map + h->top_off);
  const char *strtab = map + h->strtab_off;

  int sealed = 0;
  for (size_t i = 0; i < n; ++i)
    {
      const struct fswc_top *t = NULL;
      for (uint32_t j = 0; t == NULL && j < h->num_top; ++j)
        if (tops[j].name_len == strlen (names[i])
            && memcmp (strtab + tops[j].name_off, names[i],
                       tops[j].name_len) == 0)
          t = &tops[j];
      if (t == NULL)
        {
          support_record_failure ();
          printf ("error: " PREFIX "/%s is missing from the index\n",
                  names[i]);
          continue;
        }
      sealed += t->sealed != 0;
      if ((t->sealed != 0) != seal[i])
        {
          support_record_failure ();
          printf ("error: " PREFIX "/%s: sealed %d, should be %d\n",
                  names[i], t->sealed, seal[i]);
        }
    }
  printf ("info: %d packages sealed\n", sealed);
  TEST_VERIFY (sealed > 0);
  xmunmap ((void *) map, ist.st_size);

  /* The plain walk's answers over the real prefix.  */
  TEST_COMPARE (setenv ("PATH", PREFIX "/*/bin", 1), 0);
  char *cargv[] = { (char *) "fswc-real-no-such-command", NULL };
  pid_t pid;
  errno = EXDEV;
  TEST_COMPARE (posix_spawnp (&pid, cargv[0], NULL, NULL, cargv, environ),
                ENOENT);
  pid = xfork ();
  if (pid == 0)
    {
      errno = EXDEV;
      execvp (cargv[0], cargv);
      _exit (errno == ENOENT ? 0 : 1);
    }
  int status;
  xwaitpid (pid, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
  TEST_VERIFY (dlopen ("libfswc-real-no-such-library.so", RTLD_NOW) == NULL);
  const char *err = dlerror ();
  TEST_VERIFY (err != NULL
               && strstr (err, "No such file or directory") != NULL);
  if (err != NULL)
    printf ("info: dlopen: %s\n", err);
  check_glob (PREFIX "/*/bin/sh");
  check_glob (PREFIX "/*/lib/libc.so*");
  check_glob (PREFIX "/*/bin/fswc-real-no-such-command");
  check_glob (PREFIX "/*");

  for (size_t i = 0; i < n; ++i)
    free (names[i]);
  free (names);
  free (seal);
  free (idx);
  return 0;
}

#define TEST_FUNCTION_ARGV do_test
#include <support/test-driver.c>
