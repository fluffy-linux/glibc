/* Test execveat at the various corner cases.
   Copyright (C) 2021-2026 Free Software Foundation, Inc.
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

#include <fcntl.h>
#include <errno.h>
#include <glob.h>
#include <paths.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <support/check.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xdlfcn.h>
#include <support/xstdio.h>
#include <support/xunistd.h>
#include <wait.h>
#include <support/test-driver.h>

int
call_execveat (int fd, const char *pathname, int flags, int expected_fail,
               int num)
{
  char *envp[] = { (char *) "FOO=3", NULL };
  char *argv[] = { (char *) "sh", (char *) "-c", (char *) "exit $FOO", NULL };
  pid_t pid;
  int status;

  if (test_verbose > 0)
    printf ("call line number: %d\n", num);

  pid = xfork ();
  if (pid == 0)
    {
      TEST_COMPARE (execveat (fd, pathname, argv, envp, flags), -1);
      if (errno == ENOSYS)
	exit (EXIT_UNSUPPORTED);
      else if (errno == expected_fail)
        {
          if (test_verbose > 0)
            printf ("expected fail: errno %d\n", errno);
          _exit (0);
        }
      else
        FAIL_EXIT1 ("execveat failed: %m (%d)", errno);
    }
  xwaitpid (pid, &status, 0);

  if (!WIFEXITED (status))
    FAIL_RET ("child hasn't exited normally");

  if (WIFEXITED (status))
    {
      if (WEXITSTATUS (status) == EXIT_UNSUPPORTED)
        FAIL_UNSUPPORTED ("execveat is unimplemented");
      else if (expected_fail != 0)
        TEST_COMPARE (WEXITSTATUS (status), 0);
      else
        TEST_COMPARE (WEXITSTATUS (status), 3);
    }
  return 0;
}

static bool
write_exit3_elf_stub (const char *path)
{
#if defined (__x86_64__)
  static const unsigned char stub[120] =
    {
      0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      2, 0, 62, 0, 1, 0, 0, 0,
      0x78, 0x00, 0x40, 0x00, 0, 0, 0, 0,
      0x40, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 64, 0, 56, 0, 1, 0, 0, 0, 0, 0, 0, 0,
      1, 0, 0, 0, 5, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0,
      0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0,
      132, 0, 0, 0, 0, 0, 0, 0,
      132, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x10, 0x00, 0x00, 0, 0, 0, 0
    };
  static const unsigned char code[12] =
    {
      0xb8, 0x3c, 0x00, 0x00, 0x00, /* mov $60, %eax */
      0xbf, 0x03, 0x00, 0x00, 0x00, /* mov $3, %edi */
      0x0f, 0x05                    /* syscall */
    };
  int sfd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (sfd < 0)
    return false;
  bool ok = (write (sfd, stub, sizeof (stub)) == (ssize_t) sizeof (stub)
             && write (sfd, code, sizeof (code)) == (ssize_t) sizeof (code));
  xclose (sfd);
  return ok;
#elif defined (__aarch64__)
  static const unsigned char stub[120] =
    {
      0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      2, 0, 183, 0, 1, 0, 0, 0,
      0x78, 0x00, 0x40, 0x00, 0, 0, 0, 0,
      0x40, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 64, 0, 56, 0, 1, 0, 0, 0, 0, 0, 0, 0,
      1, 0, 0, 0, 5, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0,
      0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0,
      132, 0, 0, 0, 0, 0, 0, 0,
      132, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x10, 0x00, 0x00, 0, 0, 0, 0
    };
  static const unsigned char code[12] =
    {
      0x60, 0x00, 0x80, 0x52, /* mov w0, #3 */
      0xa8, 0x0b, 0x80, 0xd2, /* mov w8, #93 */
      0x01, 0x00, 0x00, 0xd4  /* svc #0 */
    };
  int sfd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (sfd < 0)
    return false;
  bool ok = (write (sfd, stub, sizeof (stub)) == (ssize_t) sizeof (stub)
             && write (sfd, code, sizeof (code)) == (ssize_t) sizeof (code));
  xclose (sfd);
  return ok;
#else
  (void) path;
  return false;
#endif
}

static int
do_test (void)
{
  DIR *dirp;
  int fd;
  char *tmp_dir = support_create_temp_directory ("tst-execveat_dir");
  char *stub_dir = NULL;
  char *stub_sh = NULL;
#ifdef O_PATH
  int fd_out;
  char *symlink_name, *tmp_sh;
  struct stat64 st;
#endif

  char *resolved_dir = NULL;
  char *resolved_prog = NULL;
  char *resolved_sh = NULL;
  const char *bin_dir = NULL;
  const char *bin_prog = NULL;
  const char *bin_sh = NULL;

  /* Probe _PATH_BSHELL first, then _PATH_DEFPATH / _PATH_STDPATH via glob,
     falling back to a self-contained static ELF stub when no shell exists.  */
  if (access (_PATH_BSHELL, X_OK) == 0)
    {
      const char *bshell = _PATH_BSHELL;
      const char *sl = strrchr (bshell, '/');
      if (sl != NULL && sl > bshell)
        {
          resolved_dir = xstrndup (bshell, (size_t) (sl - bshell));
          resolved_prog = xstrdup (sl + 1);
          resolved_sh = xstrdup (bshell);
          bin_dir = resolved_dir;
          bin_prog = resolved_prog;
          bin_sh = resolved_sh;
        }
    }
  if (bin_sh == NULL)
    {
      glob_t gl;
      memset (&gl, 0, sizeof (gl));
      if (glob (_PATH_DEFPATH ":" _PATH_STDPATH,
                GLOB_PATHS | GLOB_NOESCAPE, NULL, &gl) == 0)
        {
          static const char *const sh_names[] = { "sh", "bash" };
          for (size_t i = 0; i < gl.gl_pathc && bin_sh == NULL; ++i)
            for (size_t s = 0; s < sizeof (sh_names) / sizeof (sh_names[0]); ++s)
              {
                char *cand = xasprintf ("%s/%s", gl.gl_pathv[i], sh_names[s]);
                if (access (cand, X_OK) == 0)
                  {
                    resolved_dir = xstrdup (gl.gl_pathv[i]);
                    resolved_prog = xstrdup (sh_names[s]);
                    resolved_sh = cand;
                    bin_dir = resolved_dir;
                    bin_prog = resolved_prog;
                    bin_sh = resolved_sh;
                    break;
                  }
                free (cand);
              }
          globfree (&gl);
        }
    }
  if (bin_sh == NULL)
    {
      stub_dir = xasprintf ("%s/stub_bin", tmp_dir);
      xmkdirp (stub_dir, 0700);
      add_temp_file (stub_dir);
      stub_sh = xasprintf ("%s/sh", stub_dir);
      if (!write_exit3_elf_stub (stub_sh))
        FAIL_UNSUPPORTED ("no shell found and no static ELF stub for arch");
      add_temp_file (stub_sh);
      bin_dir = stub_dir;
      bin_prog = "sh";
      bin_sh = stub_sh;
    }

  dirp = opendir (bin_dir);
  if (dirp == NULL)
    FAIL_EXIT1 ("failed to open %s", bin_dir);
  fd = dirfd (dirp);

  /* Call execveat for various fd/pathname combinations.  */

  /* Check the pathname relative to a valid dirfd.  */
  call_execveat (fd, bin_prog, 0, 0, __LINE__);
  xchdir (bin_dir);
  /* Use the special value AT_FDCWD as dirfd. Quoting open(2):
     If pathname is relative and dirfd is the special value AT_FDCWD, then
     pathname is interpreted relative to the current working directory of
     the calling process.  */
  call_execveat (AT_FDCWD, bin_prog, 0, 0, __LINE__);
  closedir (dirp);
#ifdef O_PATH
  /* Check the pathname relative to a valid dirfd with O_PATH.  */
  fd = xopen (bin_dir, O_PATH | O_DIRECTORY, O_RDONLY);
  call_execveat (fd, bin_prog, 0, 0, __LINE__);
  xclose (fd);

  /* Check absolute pathname, dirfd should be ignored.  */
  call_execveat (AT_FDCWD, bin_sh, 0, 0, __LINE__);
  fd = xopen (tmp_dir, O_PATH | O_DIRECTORY, 0);
  /* Same check for absolute pathname, but with input file descriptor
     opened with different flags.  The dirfd should be ignored.  */
  call_execveat (fd, bin_sh, 0, 0, __LINE__);
  xclose (fd);
#endif

  fd = xopen (tmp_dir, O_RDONLY, 0);
  /* Same check for absolute pathname, but with input file descriptor
     opened with different flags.  The dirfd should be ignored.  */
  call_execveat (fd, bin_sh, 0, 0, __LINE__);
  xclose (fd);

  fd = xopen (bin_sh, O_RDONLY, 0);
  /* Check relative pathname, where dirfd does not point to a directory.  */
  call_execveat (fd, "sh", 0, ENOTDIR, __LINE__);
  /* Check absolute pathname, but dirfd is a regular file.  The dirfd
     should be ignored.  */
  call_execveat (fd, bin_sh, 0, 0, __LINE__);
  xclose (fd);

#ifdef O_PATH
  /* Quoting open(2): O_PATH
     Obtain a file descriptor that can be used for two purposes: to
     indicate a location in the filesystem tree and to perform
     operations that act purely at the file descriptor level.  */
  fd = xopen (bin_sh, O_PATH, 0);
  /* Check the empty pathname.  Dirfd is a regular file with O_PATH.  */
  call_execveat (fd, "", 0, ENOENT, __LINE__);
  /* Same check for an empty pathname, but with AT_EMPTY_PATH flag.
     Quoting open(2):
     If oldpath is an empty string, create a link to the file referenced
     by olddirfd (which may have been obtained using the open(2) O_PATH flag. */
  call_execveat (fd, "", AT_EMPTY_PATH, 0, __LINE__);
  call_execveat (fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, 0, __LINE__);
  xclose (fd);

  /* Create a symbolic link tmp_sh inside tmp_dir.  Open dirfd as a
     symbolic link.  */
  symlink_name = xasprintf ("%s/symlink", tmp_dir);
  xsymlink ("tmp_sh", symlink_name);
  add_temp_file (symlink_name);
  tmp_sh = xasprintf ("%s/tmp_sh", tmp_dir);
  add_temp_file (tmp_sh);
  fd_out = xopen (symlink_name, O_CREAT | O_WRONLY, 0);
  xstat64 (bin_sh, &st);
  fd = xopen (bin_sh, O_RDONLY, 0);
  xcopy_file_range (fd, 0, fd_out, 0, st.st_size, 0);
  xfchmod (fd_out, 0700);
  xclose (fd);
  xclose (fd_out);
  fd_out = xopen (symlink_name, O_PATH, 0);

 /* Check the empty pathname. Dirfd is a symbolic link.  */
  call_execveat (fd_out, "", 0, ENOENT, __LINE__);
  call_execveat (fd_out, "", AT_EMPTY_PATH, 0, __LINE__);
  call_execveat (fd_out, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, 0,
                 __LINE__);
  xclose (fd_out);
  free (symlink_name);
  free (tmp_sh);
#endif

  /* Call execveat with closed fd, we expect this to fail with EBADF.  */
  call_execveat (fd, "sh", 0, EBADF, __LINE__);
  /* Call execveat with closed fd, we expect this to pass because the pathname is
     absolute.  */
  call_execveat (fd, bin_sh, 0, 0, __LINE__);

  free (resolved_sh);
  free (resolved_prog);
  free (resolved_dir);
  free (stub_sh);
  free (stub_dir);
  free (tmp_dir);
  return 0;
}

#include <support/test-driver.c>
