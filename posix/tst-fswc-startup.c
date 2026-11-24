/* FSWC's startup builder.
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

/* __libc_early_init builds the index of each configured prefix (/sw)
   when there is no valid one: in a dynamically linked program only, and
   never under AT_SECURE.  This test runs in a user and mount namespace
   of its own with a tmpfs mounted over /sw, so it needs /sw to exist,
   and checks that

   - a statically linked program starts without building;
   - a dynamically linked program builds, publishing a regular file of
     mode 0400 owned by its euid, in a directory of its own;
   - an index left by a mount namespace that no longer exists is swept
     away by the next build of a process with CAP_SYS_ADMIN, which is
     the only one listmount tells apart a dead namespace from a live one
     it may not see;
   - an unprivileged build never sweeps the index of a live namespace
     (to it, every other namespace looks dead), and sweeps one that only
     may be dead once it is more than a day old;
   - a change to /sw makes the next start rebuild (a new file is renamed
     over the old one);
   - with /dev/shm read-only, or too small for the index, a start builds
     nothing, leaves no temporary file behind, and runs normally.

   AT_SECURE cannot be tested without privileges (a set-user-ID program
   owned by another user); the builder returns at once when
   __libc_enable_secure is set.  */

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/securebits.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <support/check.h>
#include <support/subprocess.h>
#include <support/support.h>
#include <support/xunistd.h>

#define PREFIX "/sw"

/* The indexes of PREFIX for this euid, in any mount namespace.  */
static size_t
indexes (glob_t *g)
{
  struct stat st;
  xstat (PREFIX, &st);
  char *pat = xasprintf ("/dev/shm/.fswc-%u-*/idx-*-%llu-%llu",
                         (unsigned int) geteuid (),
                         ((unsigned long long) major (st.st_dev) << 32)
                         | minor (st.st_dev),
                         (unsigned long long) st.st_ino);
  int r = glob (pat, 0, NULL, g);
  free (pat);
  if (r == GLOB_NOMATCH)
    {
      g->gl_pathc = 0;
      return 0;
    }
  TEST_COMPARE (r, 0);
  return g->gl_pathc;
}

static size_t
count_indexes (void)
{
  glob_t g;
  size_t n = indexes (&g);
  if (n > 0)
    globfree (&g);
  return n;
}

/* Print what this euid's FSWC directories hold, after STEP.  */
static void
show (const char *step)
{
  glob_t g;
  char *pat = xasprintf ("/dev/shm/.fswc-%u-*/*", (unsigned int) geteuid ());
  printf ("info: after %s:", step);
  if (glob (pat, GLOB_PERIOD, NULL, &g) == 0)
    {
      for (size_t i = 0; i < g.gl_pathc; ++i)
        printf (" %s", strrchr (g.gl_pathv[i], '/') + 1);
      globfree (&g);
    }
  puts ("");
  free (pat);
}

/* Run PATH with ARGV and wait for it to exit successfully.  */
static void
run (const char *path, char *const argv[])
{
  pid_t pid = xfork ();
  if (pid == 0)
    {
      int null = xopen ("/dev/null", O_WRONLY, 0);
      xdup2 (null, STDOUT_FILENO);
      execv (path, argv);
      _exit (127);
    }
  int status;
  xwaitpid (pid, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
}

/* Start a fresh dynamically linked process (this test, as a probe that
   only exits) through the loader invocation the harness used.  With
   NEWNS, in a mount namespace of its own, which dies with it.  Without
   PRIVILEGED, it runs with no capabilities: still uid 0, but with
   SECBIT_NOROOT, so execve grants it none.  */
static void
start_dynamic (char *self, bool newns, bool privileged)
{
  pid_t pid = xfork ();
  if (pid == 0)
    {
      if (newns && unshare (CLONE_NEWNS) != 0)
        _exit (126);
      if (!privileged
          && prctl (PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED)
             != 0)
        _exit (125);
      setenv ("FSWC_STARTUP_PROBE", "1", 1);
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

/* Enter a user namespace as uid 0 (not, as support_become_root does, as
   our own uid), so that the processes we start keep their capabilities
   across execve, and a mount namespace with private propagation.  */
static bool
become_root (void)
{
  char map[64];
  uid_t uid = getuid ();
  gid_t gid = getgid ();
  if (unshare (CLONE_NEWUSER | CLONE_NEWNS) != 0)
    return false;
  int fd = xopen ("/proc/self/uid_map", O_WRONLY, 0);
  int len = snprintf (map, sizeof map, "0 %u 1\n", (unsigned int) uid);
  xwrite (fd, map, len);
  xclose (fd);
  fd = xopen ("/proc/self/setgroups", O_WRONLY, 0);
  xwrite (fd, "deny", 4);
  xclose (fd);
  fd = xopen ("/proc/self/gid_map", O_WRONLY, 0);
  len = snprintf (map, sizeof map, "0 %u 1\n", (unsigned int) gid);
  xwrite (fd, map, len);
  xclose (fd);
  return mount ("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0;
}

/* The index in G other than OURS.  */
static char *
other_index (const char *ours)
{
  glob_t g;
  char *r = NULL;
  indexes (&g);
  for (size_t i = 0; i < g.gl_pathc; ++i)
    if (strcmp (g.gl_pathv[i], ours) != 0)
      r = xstrdup (g.gl_pathv[i]);
  if (g.gl_pathc > 0)
    globfree (&g);
  TEST_VERIFY_EXIT (r != NULL);
  return r;
}

/* Make PATH look two days old.  */
static void
age (const char *path)
{
  struct timespec ts[2];
  TEST_COMPARE (clock_gettime (CLOCK_REALTIME, &ts[0]), 0);
  ts[0].tv_sec -= 2 * 24 * 60 * 60;
  ts[1] = ts[0];
  TEST_COMPARE (utimensat (AT_FDCWD, path, ts, 0), 0);
}

/* Let a coarse-clock tick pass, so that the builder does not decline
   because PREFIX changed in the current one.  */
static void
next_tick (void)
{
  struct timespec ts = { 0, 100 * 1000 * 1000 };
  nanosleep (&ts, NULL);
}

static int
do_test (int argc, char *argv[])
{
  if (getenv ("FSWC_STARTUP_PROBE") != NULL)
    return 0;                   /* Startup has done the work.  */

  struct stat st;
  if (stat (PREFIX, &st) != 0 || !S_ISDIR (st.st_mode))
    FAIL_UNSUPPORTED ("no " PREFIX " directory to mount over");
  if (!become_root ())
    FAIL_UNSUPPORTED ("cannot enter a user and mount namespace");
  if (mount ("tmpfs", PREFIX, "tmpfs", 0, "mode=0755") != 0)
    FAIL_UNSUPPORTED ("cannot mount over " PREFIX ": %m");
  xmkdirp (PREFIX "/pkg/bin", 0755);
  xclose (xopen (PREFIX "/pkg/bin/cmd", O_WRONLY | O_CREAT, 0755));
  xclose (xopen (PREFIX "/pkg-1.0.squashfs", O_WRONLY | O_CREAT, 0644));
  next_tick ();

  /* This process started before the mount, so there is nothing yet.  */
  TEST_COMPARE (count_indexes (), 0);

  /* A static program never builds.  */
  char *helper = xasprintf ("%s/posix/tst-fswc-oracle-exec",
                            support_objdir_root);
  char *hargv[] = { helper, NULL };
  run (helper, hargv);
  TEST_COMPARE (count_indexes (), 0);

  /* A dynamic one does.  */
  start_dynamic (argv[0], false, true);
  show ("a dynamic start");
  glob_t g;
  TEST_COMPARE (indexes (&g), 1);
  char *ours = xstrdup (g.gl_pathv[0]);
  globfree (&g);
  struct stat ist;
  TEST_COMPARE (lstat (ours, &ist), 0);
  TEST_VERIFY (S_ISREG (ist.st_mode));
  TEST_COMPARE (ist.st_mode & 07777, 0400);
  TEST_COMPARE (ist.st_uid, geteuid ());
  char *dir = xstrdup (ours);
  *strrchr (dir, '/') = '\0';
  struct stat dst;
  xstat (dir, &dst);
  TEST_COMPARE (dst.st_uid, geteuid ());
  TEST_COMPARE (dst.st_mode & 0077, 0);
  free (dir);

  /* A second start finds the index valid and leaves it alone.  */
  start_dynamic (argv[0], false, true);
  struct stat again;
  TEST_COMPARE (lstat (ours, &again), 0);
  TEST_COMPARE (again.st_ino, ist.st_ino);

  /* A start in a mount namespace of its own builds that namespace's
     index and keeps ours, whose namespace is alive.  Once that namespace
     is gone, the next privileged build sweeps its index.  */
  start_dynamic (argv[0], true, true);
  show ("a privileged start in a new mount namespace");
  TEST_COMPARE (count_indexes (), 2);
  TEST_COMPARE (unlink (ours), 0);
  start_dynamic (argv[0], false, true);
  show ("removing ours and a privileged start");
  TEST_COMPARE (indexes (&g), 1);
  TEST_COMPARE_STRING (g.gl_pathv[0], ours);
  globfree (&g);

  /* An unprivileged build in a namespace of its own cannot see ours, but
     must not take it for dead.  */
  start_dynamic (argv[0], true, false);
  show ("an unprivileged start in a new mount namespace");
  TEST_COMPARE (count_indexes (), 2);
  char *dead = other_index (ours);

  /* That namespace is gone now, but an unprivileged build cannot tell, so
     its index stays while it is young...  */
  TEST_COMPARE (unlink (ours), 0);
  start_dynamic (argv[0], false, false);
  show ("removing ours and an unprivileged start");
  TEST_COMPARE (count_indexes (), 2);
  TEST_VERIFY (access (dead, F_OK) == 0);

  /* ... and goes once it is more than a day old.  */
  age (dead);
  TEST_COMPARE (unlink (ours), 0);
  start_dynamic (argv[0], false, false);
  show ("aging it, removing ours and an unprivileged start");
  TEST_COMPARE (indexes (&g), 1);
  TEST_COMPARE_STRING (g.gl_pathv[0], ours);
  globfree (&g);
  free (dead);

  /* A change to the prefix makes the next start rebuild.  */
  TEST_COMPARE (lstat (ours, &ist), 0);
  xmkdir (PREFIX "/newpkg", 0755);
  next_tick ();
  start_dynamic (argv[0], false, true);
  TEST_COMPARE (lstat (ours, &again), 0);
  TEST_VERIFY (again.st_ino != ist.st_ino);

  /* /dev/shm read-only, then too small: no index, nothing left over.
     A thousand more names make the index larger than the small one.  */
  TEST_COMPARE (unlink (ours), 0);
  for (int i = 0; i < 1000; ++i)
    {
      char *f = xasprintf (PREFIX "/fill-%04d", i);
      xclose (xopen (f, O_WRONLY | O_CREAT, 0644));
      free (f);
    }
  next_tick ();
  if (mount ("tmpfs", "/dev/shm", "tmpfs", MS_RDONLY, "mode=1777") != 0)
    FAIL_EXIT1 ("mount read-only tmpfs on /dev/shm: %m");
  start_dynamic (argv[0], false, true);
  TEST_COMPARE (count_indexes (), 0);
  TEST_COMPARE (umount2 ("/dev/shm", MNT_DETACH), 0);
  if (mount ("tmpfs", "/dev/shm", "tmpfs", 0, "mode=1777,size=8k") != 0)
    FAIL_EXIT1 ("mount small tmpfs on /dev/shm: %m");
  start_dynamic (argv[0], false, true);
  show ("a start with a full /dev/shm");
  TEST_COMPARE (count_indexes (), 0);
  glob_t left;
  char *pat = xasprintf ("/dev/shm/.fswc-%u-*/.tmp-*",
                         (unsigned int) geteuid ());
  TEST_COMPARE (glob (pat, GLOB_PERIOD, NULL, &left), GLOB_NOMATCH);
  free (pat);
  TEST_COMPARE (umount2 ("/dev/shm", MNT_DETACH), 0);

  /* With room again, the index is built, and it is bigger than the small
     /dev/shm was, so that case really ran out of space.  */
  start_dynamic (argv[0], false, true);
  TEST_COMPARE (lstat (ours, &ist), 0);
  TEST_VERIFY (ist.st_size > 8192);

  free (ours);
  free (helper);
  return 0;
}

#define TEST_FUNCTION_ARGV do_test
#include <support/test-driver.c>
