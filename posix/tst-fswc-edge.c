/* Edge-case, errno, symlink-prefix, raw-syscall, and search-list tests.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <link.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <support/check.h>
#include <support/subprocess.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/test-driver.h>
#include <support/xunistd.h>

#ifndef SQUASHFS_MAGIC
# define SQUASHFS_MAGIC 0x73717368
#endif

static bool
find_any_reg_file_rec (const char *dir, int depth, char *out, size_t out_sz)
{
  if (depth > 4)
    return false;
  DIR *d = opendir (dir);
  if (d == NULL)
    return false;
  struct dirent *de;
  while ((de = readdir (d)) != NULL)
    {
      if (de->d_name[0] == '.'
          && (de->d_name[1] == '\0'
              || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        continue;
      char child[1024];
      if ((size_t) snprintf (child, sizeof (child), "%s/%s", dir, de->d_name)
          >= sizeof (child))
        continue;
      struct stat st;
      if (lstat (child, &st) != 0)
        continue;
      if (S_ISREG (st.st_mode))
        {
          snprintf (out, out_sz, "%s", child);
          closedir (d);
          return true;
        }
      if (S_ISDIR (st.st_mode)
          && find_any_reg_file_rec (child, depth + 1, out, out_sz))
        {
          closedir (d);
          return true;
        }
    }
  closedir (d);
  return false;
}

static bool
scan_prefix_for_squash_reg (const char *par, char *pkg_out, size_t pkg_sz,
                            char *reg_out, size_t reg_sz)
{
  DIR *d = opendir (par);
  if (d == NULL)
    return false;
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
          && statfs (sub, &sfs) == 0 && sfs.f_type == SQUASHFS_MAGIC
          && find_any_reg_file_rec (sub, 0, reg_out, reg_sz))
        {
          snprintf (pkg_out, pkg_sz, "%s", de->d_name);
          closedir (d);
          return true;
        }
    }
  closedir (d);
  return false;
}

static const char *
find_squash_prefix_and_file (char *pfx_out, size_t pfx_sz,
                             char *pkg_out, size_t pkg_sz,
                             char *reg_out, size_t reg_sz)
{
  const char *env_p = getenv ("FSWC_TEST_PREFIX");
  if (env_p != NULL)
    {
      if (strcmp (env_p, "none") == 0)
        return NULL;
      if (env_p[0] == '/'
          && scan_prefix_for_squash_reg (env_p, pkg_out, pkg_sz, reg_out, reg_sz))
        {
          snprintf (pfx_out, pfx_sz, "%s", env_p);
          return pfx_out;
        }
      return NULL;
    }

  FILE *fp = fopen ("/proc/self/mountinfo", "r");
  if (fp == NULL)
    return NULL;

  char best[512] = "";
  char best_pkg[260] = "";
  char best_reg[1024] = "";
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
            ++sq_cnt;
        }
      closedir (d);
      if (sq_cnt > best_cnt)
        {
          char cpkg[260] = "", creg[1024] = "";
          if (scan_prefix_for_squash_reg (par, cpkg, sizeof (cpkg),
                                          creg, sizeof (creg)))
            {
              best_cnt = sq_cnt;
              memcpy (best, par, par_len + 1);
              snprintf (best_pkg, sizeof (best_pkg), "%s", cpkg);
              snprintf (best_reg, sizeof (best_reg), "%s", creg);
            }
        }
    }
  fclose (fp);
  if (best_cnt == 0)
    return NULL;
  snprintf (pfx_out, pfx_sz, "%s", best);
  snprintf (pkg_out, pkg_sz, "%s", best_pkg);
  snprintf (reg_out, reg_sz, "%s", best_reg);
  return pfx_out;
}

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

static bool
serinfo_contains_dir (void *handle, const char *want_dir)
{
  Dl_serinfo sz;
  memset (&sz, 0, sizeof (sz));
  TEST_COMPARE (dlinfo (handle, RTLD_DI_SERINFOSIZE, &sz), 0);
  Dl_serinfo *si = xmalloc (sz.dls_size);
  TEST_COMPARE (dlinfo (handle, RTLD_DI_SERINFOSIZE, si), 0);
  TEST_COMPARE (si->dls_cnt, sz.dls_cnt);
  TEST_COMPARE (si->dls_size, sz.dls_size);
  TEST_COMPARE (dlinfo (handle, RTLD_DI_SERINFO, si), 0);
  bool found = false;
  for (unsigned int i = 0; i < si->dls_cnt; ++i)
    if (strcmp (si->dls_serpath[i].dls_name, want_dir) == 0)
      {
        found = true;
        break;
      }
  free (si);
  return found;
}

static int
dlopen_errno_worker (void)
{
  errno = EBADF;
  void *h = dlopen ("libnonexistent_fswc_probe_xyz.so", RTLD_NOW);
  TEST_VERIFY_EXIT (h == NULL);
  const char *err = dlerror ();
  TEST_VERIFY_EXIT (err != NULL);
  TEST_VERIFY_EXIT (strstr (err, "Success") == NULL);
  TEST_VERIFY_EXIT (strstr (err, "Bad file descriptor") == NULL);

  char overlong[NAME_MAX + 8];
  memset (overlong, 'q', NAME_MAX + 3);
  memcpy (overlong + NAME_MAX + 3, ".so", 4);
  h = dlopen (overlong, RTLD_NOW);
  TEST_VERIFY_EXIT (h == NULL);
  err = dlerror ();
  TEST_VERIFY_EXIT (err != NULL);
  TEST_VERIFY_EXIT (strstr (err, "Success") == NULL);

  /* Post-startup dynamic wildcard directory creation: verify both open_path
     and dlinfo(RTLD_DI_SERINFO) observe newly created <dyn_root>/<pkg>/lib
     immediately without static startup freezing!  */
  const char *dyn_root = getenv ("FSWC_EDGE_DLOPEN_DYN_ROOT");
  if (dyn_root != NULL && dyn_root[0] != '\0')
    {
      void *main_h = dlopen (NULL, RTLD_NOW);
      TEST_VERIFY_EXIT (main_h != NULL);

      char *new_lib = xasprintf ("%s/dynpkg/lib", dyn_root);
      TEST_VERIFY_EXIT (!serinfo_contains_dir (main_h, new_lib));

      h = dlopen ("libdyn_post_startup_probe.so", RTLD_NOW);
      TEST_VERIFY_EXIT (h == NULL);
      err = dlerror ();
      TEST_VERIFY_EXIT (err != NULL);
      TEST_VERIFY_EXIT (strstr (err, "cannot open shared object file") != NULL);

      xmkdirp (new_lib, 0755);
      char *bad_elf = xasprintf ("%s/libdyn_post_startup_probe.so", new_lib);
      int bfd = xopen (bad_elf, O_WRONLY | O_CREAT | O_TRUNC, 0755);
      const char payload[] = "NOT_AN_ELF_FILE";
      TEST_COMPARE (write (bfd, payload, sizeof (payload)),
                    (ssize_t) sizeof (payload));
      xclose (bfd);

      TEST_VERIFY_EXIT (serinfo_contains_dir (main_h, new_lib));

      h = dlopen ("libdyn_post_startup_probe.so", RTLD_NOW);
      TEST_VERIFY_EXIT (h == NULL);
      err = dlerror ();
      TEST_VERIFY_EXIT (err != NULL);
      /* open_path located and opened the new file; open_verify rejected header!  */
      TEST_VERIFY_EXIT (strstr (err, "cannot open shared object file") == NULL);

      unlink (bad_elf);
      free (bad_elf);
      free (new_lib);
      dlclose (main_h);
    }

  return 0;
}

static int
globstar_casefold_worker (const char *prefix)
{
  char pat[512], expect_first[512];
  snprintf (pat, sizeof (pat), "%s/**", prefix);
  snprintf (expect_first, sizeof (expect_first), "%s/", prefix);
  glob_t g;
  memset (&g, 0, sizeof (g));
  int r = glob (pat, GLOB_GLOBSTAR | GLOB_CASEFOLD | GLOB_ONLYDIR, NULL, &g);
  TEST_VERIFY_EXIT (r == 0 && g.gl_pathc >= 1);
  TEST_COMPARE_STRING (g.gl_pathv[0], expect_first);
  globfree (&g);
  return 0;
}

static void
exec_self_direct (char *argv[])
{
  char *const child_argv[] = { argv[0], (char *) "--direct", NULL };
  struct support_spawn_wrapped *w
    = support_spawn_wrap (argv[0], child_argv, NULL, 0);
  const char *extra_llp = getenv ("LD_LIBRARY_PATH");
  if (extra_llp != NULL && extra_llp[0] != '\0')
    {
      for (size_t i = 0; w->argv[i] != NULL; ++i)
        {
          if (strcmp (w->argv[i], "--library-path") == 0
              && w->argv[i + 1] != NULL)
            {
              ((char **) w->argv)[i + 1]
                = xasprintf ("%s:%s", w->argv[i + 1], extra_llp);
              break;
            }
        }
    }
  execve (w->path, w->argv, w->envp);
  _exit (127);
}

static int
trail_exec_worker (const char *trail_pat)
{
  /* Warm the FSWC slot first, so a cached index cannot change the result.  */
  size_t len = strlen (trail_pat);
  TEST_VERIFY_EXIT (len > 2 && trail_pat[len - 1] == '/');
  char *warm_pat = xstrdup (trail_pat);
  warm_pat[len - 1] = '\0';
  glob_t wg;
  memset (&wg, 0, sizeof (wg));
  TEST_COMPARE (glob (warm_pat, 0, NULL, &wg), 0);
  globfree (&wg);
  free (warm_pat);

  char *const eargv[] = { (char *) "fswc_trail_probe", NULL };
  char *const eenvp[] = { NULL };
  errno = 0;
  TEST_COMPARE (execve (trail_pat, eargv, eenvp), -1);
  TEST_COMPARE (errno, ENOENT);

  /* The same pattern without the trailing slash matches an existing file,
     but execve() takes its path literally and never expands
     metacharacters, so it must fail with ENOENT too (not EACCES/ENOEXEC
     from reaching the matched file, and certainly not run anything).  */
  char *nontrail = xstrndup (trail_pat, len - 1);
  errno = 0;
  TEST_COMPARE (execve (nontrail, eargv, eenvp), -1);
  TEST_COMPARE (errno, ENOENT);
  free (nontrail);
  return 0;
}

static int
do_test (int argc, char *argv[])
{
  (void) argc;
  const char *dl_chk = getenv ("FSWC_EDGE_DLOPEN_CHECK");
  if (dl_chk != NULL && dl_chk[0] == '1')
    return dlopen_errno_worker ();
  const char *tr_pat = getenv ("FSWC_EDGE_TRAIL_EXEC_PAT");
  if (tr_pat != NULL && tr_pat[0] != '\0')
    return trail_exec_worker (tr_pat);
  const char *gscf_pfx = getenv ("FSWC_EDGE_GSCF_PREFIX");
  if (gscf_pfx != NULL && gscf_pfx[0] != '\0')
    return globstar_casefold_worker (gscf_pfx);

  char *tmp = support_create_temp_directory ("tst-fswc-edge-");

  /* 1. A plain (never sealed) directory is always answered live.  */
  char *plain = xasprintf ("%s/plain", tmp);
  char *pkg1 = xasprintf ("%s/pkg1", plain);
  xmkdirp (pkg1, 0755);

  char pat[1024];
  snprintf (pat, sizeof (pat), "%s/*/hello", plain);
  glob_t gl;
  TEST_COMPARE (glob (pat, 0, NULL, &gl), GLOB_NOMATCH);

  char *hello = xasprintf ("%s/hello", pkg1);
  int fd = xopen (hello, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  xclose (fd);

  /* Immediately visible without waiting!  */
  TEST_COMPARE (glob (pat, 0, NULL, &gl), 0);
  TEST_COMPARE (gl.gl_pathc, 1);
  TEST_COMPARE_STRING (gl.gl_pathv[0], hello);
  globfree (&gl);

  /* 2. Symlinked prefix retargeting coherence.  */
  char sq_pfx_buf[512] = "";
  char pkg_name[260] = "";
  char reg_file[1024] = "";
  const char *sq_prefix = find_squash_prefix_and_file (sq_pfx_buf,
                                                       sizeof (sq_pfx_buf),
                                                       pkg_name,
                                                       sizeof (pkg_name),
                                                       reg_file,
                                                       sizeof (reg_file));
  const char *active_pfx = sq_prefix != NULL ? sq_prefix : plain;
  const char *active_pkg = sq_prefix != NULL ? pkg_name : "pkg1";
  const char *active_reg = sq_prefix != NULL ? reg_file : hello;

  char *empty_dir = xasprintf ("%s/empty", tmp);
  xmkdirp (empty_dir, 0755);
  char *sym_pfx = xasprintf ("%s/sym_pfx", tmp);
  xsymlink (active_pfx, sym_pfx);

  snprintf (pat, sizeof (pat), "%s/*", sym_pfx);
  TEST_COMPARE (glob (pat, 0, NULL, &gl), 0);
  TEST_VERIFY (gl.gl_pathc >= 1);
  globfree (&gl);

  xunlink (sym_pfx);
  xsymlink (empty_dir, sym_pfx);
  TEST_COMPARE (glob (pat, 0, NULL, &gl), GLOB_NOMATCH);

  /* 2b. Raw SYSCALL (bypassing glibc C wrappers, like Go's runtime/stdlib)
     revalidation smoke test.  */
  {
#ifdef SYS_setresuid
    uid_t ruid = getuid ();
    uid_t euid = geteuid ();
    (void) syscall (SYS_setresuid, ruid, euid, ruid);
#endif
    snprintf (pat, sizeof (pat), "%s/*", active_pfx);
    TEST_COMPARE (glob (pat, 0, NULL, &gl), 0);
    TEST_VERIFY (gl.gl_pathc >= 1);
    globfree (&gl);
  }

  /* 3. statx invalid flags (-EINVAL on FORCE_SYNC | DONT_SYNC) on a path
     inside a cached package must reach the kernel unmodified.  */
  {
    struct statx stx;
    char miss[1024];
    snprintf (miss, sizeof (miss), "%s/%s/nonexistent_statx_flag_test",
              active_pfx, active_pkg);
    snprintf (pat, sizeof (pat), "%s/*", active_pfx);
    if (glob (pat, 0, NULL, &gl) == 0)
      globfree (&gl);

    errno = 0;
    TEST_COMPARE (statx (AT_FDCWD, miss,
                         AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC,
                         STATX_BASIC_STATS, &stx), -1);
    TEST_COMPARE (errno, EINVAL);
  }

  /* 4. ENOTDIR, ENAMETOOLONG, O_CREAT, ., .., //, and dlopen.  */
  {
    char pbuf[PATH_MAX + 32];
    struct stat st;

    /* ENOTDIR on <active_reg>/ and <active_reg>/child.  */
    snprintf (pbuf, sizeof (pbuf), "%s/", active_reg);
    errno = 0;
    TEST_COMPARE (open (pbuf, O_RDONLY), -1);
    TEST_COMPARE (errno, ENOTDIR);

    errno = 0;
    TEST_COMPARE (stat (pbuf, &st), -1);
    TEST_COMPARE (errno, ENOTDIR);

    snprintf (pbuf, sizeof (pbuf), "%s/child", active_reg);
    errno = 0;
    TEST_COMPARE (open (pbuf, O_RDONLY), -1);
    TEST_COMPARE (errno, ENOTDIR);
    errno = 0;
    TEST_COMPARE (access (pbuf, F_OK), -1);
    TEST_COMPARE (errno, ENOTDIR);

    /* O_DIRECTORY on regular file -> ENOTDIR.  */
    errno = 0;
    TEST_COMPARE (open (active_reg, O_RDONLY | O_DIRECTORY), -1);
    TEST_COMPARE (errno, ENOTDIR);

    /* O_NOFOLLOW, AT_SYMLINK_NOFOLLOW, and dfd != AT_FDCWD checks.  */
    {
      char *sym_leaf = xasprintf ("%s/sym_to_active_reg", tmp);
      xsymlink (active_reg, sym_leaf);

      errno = 0;
      TEST_COMPARE (open (sym_leaf, O_RDONLY | O_NOFOLLOW), -1);
      TEST_COMPARE (errno, ELOOP);

      struct stat lst;
      TEST_COMPARE (fstatat (AT_FDCWD, sym_leaf, &lst, AT_SYMLINK_NOFOLLOW), 0);
      TEST_VERIFY (S_ISLNK (lst.st_mode));

      snprintf (pbuf, sizeof (pbuf), "%s/%s/nonexistent_nofollow_leaf",
                active_pfx, active_pkg);
      errno = 0;
      TEST_COMPARE (fstatat (AT_FDCWD, pbuf, &lst, AT_SYMLINK_NOFOLLOW), -1);
      TEST_COMPARE (errno, ENOENT);

      char *reg_dup = xstrdup (active_reg);
      char *last_sl = strrchr (reg_dup, '/');
      TEST_VERIFY_EXIT (last_sl != NULL);
      *last_sl = '\0';
      const char *reg_base = last_sl + 1;
      int par_dfd = xopen (reg_dup, O_RDONLY | O_DIRECTORY, 0);

      errno = 0;
      TEST_COMPARE (openat (par_dfd, "nonexistent_rel_dfd_leaf", O_RDONLY), -1);
      TEST_COMPARE (errno, ENOENT);

      errno = 0;
      TEST_COMPARE (fstatat (par_dfd, "nonexistent_rel_dfd_leaf", &lst,
                             AT_SYMLINK_NOFOLLOW), -1);
      TEST_COMPARE (errno, ENOENT);

      errno = 0;
      TEST_COMPARE (openat (par_dfd, reg_base, O_RDONLY | O_DIRECTORY), -1);
      TEST_COMPARE (errno, ENOTDIR);

      /* Absolute path passed with dfd != AT_FDCWD ignores dfd per POSIX.  */
      errno = 0;
      TEST_COMPARE (openat (par_dfd, pbuf, O_RDONLY), -1);
      TEST_COMPARE (errno, ENOENT);

      xclose (par_dfd);
      free (reg_dup);
      xunlink (sym_leaf);
      free (sym_leaf);
    }

    if (sq_prefix != NULL)
      {
        /* O_CREAT | O_RDONLY on missing path in SquashFS -> EROFS or EACCES,
           NEVER cached ENOENT!  */
        snprintf (pbuf, sizeof (pbuf), "%s/%s/fswc_rofs_creat_probe",
                  sq_prefix, pkg_name);
        errno = 0;
        TEST_COMPARE (open (pbuf, O_RDONLY | O_CREAT, 0600), -1);
        TEST_VERIFY (errno == EROFS || errno == EACCES || errno == EPERM);
      }

    /* ENAMETOOLONG on 257-byte component (> SQUASHFS_NAME_LEN == 256) and
       256-byte component on tmpfs/ext4/btrfs.  */
    char comp257[258];
    memset (comp257, 'x', 257);
    comp257[257] = '\0';
    snprintf (pbuf, sizeof (pbuf), "%s/%s/%s", active_pfx, active_pkg, comp257);
    errno = 0;
    TEST_COMPARE (open (pbuf, O_RDONLY), -1);
    TEST_COMPARE (errno, ENAMETOOLONG);
    errno = 0;
    TEST_COMPARE (stat (pbuf, &st), -1);
    TEST_COMPARE (errno, ENAMETOOLONG);

    char comp256[257];
    memset (comp256, 'y', 256);
    comp256[256] = '\0';
    snprintf (pbuf, sizeof (pbuf), "%s/%s/leaf", plain, comp256);
    errno = 0;
    TEST_COMPARE (open (pbuf, O_RDONLY), -1);
    TEST_COMPARE (errno, ENAMETOOLONG);

    /* ENAMETOOLONG on >= PATH_MAX path.  */
    size_t off = (size_t) snprintf (pbuf, sizeof (pbuf), "%s/%s",
                                    active_pfx, active_pkg);
    while (off < PATH_MAX + 4)
      {
        memcpy (pbuf + off, "/a", 2);
        off += 2;
      }
    pbuf[off] = '\0';
    errno = 0;
    TEST_COMPARE (open (pbuf, O_RDONLY), -1);
    TEST_COMPARE (errno, ENAMETOOLONG);

    /* //, ., and .. normalization.  */
    snprintf (pbuf, sizeof (pbuf), "%s///%s/./nonexistent_dir/../missing_leaf",
              active_pfx, active_pkg);
    errno = 0;
    TEST_COMPARE (open (pbuf, O_RDONLY), -1);
    TEST_COMPARE (errno, ENOENT);

    /* Escaping <prefix>/<pkg>/.. falls through to kernel (<prefix>).  */
    snprintf (pbuf, sizeof (pbuf), "%s/%s/..", active_pfx, active_pkg);
    TEST_COMPARE (stat (pbuf, &st), 0);
    TEST_VERIFY (S_ISDIR (st.st_mode));

    pid_t pid;
    int status;

    /* 5b. dlopen negative FSWC skip sets ENOENT (never "Success"), safely
       handles > NAME_MAX library names, and dynamically discovers <pkg>/lib
       directories created after process startup in both dlopen & dlinfo.  */
    char *dyn_root = xasprintf ("%s/dyn_ld_root", tmp);
    char *dot_only_root = xasprintf ("%s/dot_only_ld_root/.hidden/lib", tmp);
    xmkdirp (dyn_root, 0755);
    xmkdirp (dot_only_root, 0755);
    pid = xfork ();
    if (pid == 0)
      {
        char ldp[1600];
        snprintf (ldp, sizeof (ldp), "%s/dot_only_ld_root/*/lib:%s/*:%s/*/lib",
                  tmp, active_pfx, dyn_root);
        setenv ("LD_LIBRARY_PATH", ldp, 1);
        setenv ("FSWC_EDGE_DLOPEN_DYN_ROOT", dyn_root, 1);
        setenv ("FSWC_EDGE_DLOPEN_CHECK", "1", 1);
        exec_self_direct (argv);
      }
    status = 0;
    xwaitpid (pid, &status, 0);
    free (dot_only_root);
    free (dyn_root);
    TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);

    /* 5b2. execve() never expands glob metacharacters: both
       "<pfx>/<star>/<rel_reg>/" and "<pfx>/<star>/<rel_reg>" (which would
       match an existing file as a pattern) fail with ENOENT.  */
    {
      const char *rel_reg = active_reg + strlen (active_pfx) + 1
                            + strlen (active_pkg) + 1;
      char *trail_pat = xasprintf ("%s/*/%s/", active_pfx, rel_reg);
      pid_t tpid = xfork ();
      if (tpid == 0)
        {
          setenv ("FSWC_EDGE_TRAIL_EXEC_PAT", trail_pat, 1);
          exec_self_direct (argv);
        }
      int tst = 0;
      xwaitpid (tpid, &tst, 0);
      TEST_VERIFY (WIFEXITED (tst) && WEXITSTATUS (tst) == 0);
      free (trail_pat);
    }
  }

  /* 5c. posix_spawnp search-list rule (GLOB.md 3.2) with directories
     literally named "star", "?", and "[1]": an element with two whole "*"
     components matches nothing; one "*" enumerates every name, these
     included, in byte order; "[?]" and every other character is literal.  */
  {
    char *mwild = xasprintf ("%s/mwild", tmp);
    char *d_star = xasprintf ("%s/*/bin/sub", mwild);
    char *d_qmark = xasprintf ("%s/?/bin/sub", mwild);
    char *d_brack = xasprintf ("%s/[1]/bin/sub", mwild);
    char *d_one = xasprintf ("%s/1/bin/sub", mwild);
    char *d_qsub = xasprintf ("%s/?/sub", mwild);
    char *d_asub = xasprintf ("%s/a/sub", mwild);
    xmkdirp (d_star, 0755);
    xmkdirp (d_qmark, 0755);
    xmkdirp (d_brack, 0755);
    xmkdirp (d_one, 0755);
    xmkdirp (d_qsub, 0755);
    xmkdirp (d_asub, 0755);
    char *probe_brack = xasprintf ("%s/fswc_mwild_probe", d_brack);
    int pfd = xopen (probe_brack, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    xclose (pfd);
    char *probe_asub = xasprintf ("%s/fswc_trail_qprobe", d_asub);
    pfd = xopen (probe_asub, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    xclose (pfd);

    char *wpath = xasprintf ("PATH=%s/*/bin/*", mwild);
    char *sp_argv[] = { (char *) "fswc_mwild_probe", NULL };
    char *sp_envp[] = { wpath, NULL };
    pid_t spid = 0;
    char *old_path = getenv ("PATH");
    char *saved_path = old_path != NULL ? xstrdup (old_path) : NULL;
    setenv ("PATH", wpath + 5, 1);
    /* Two "*" components: no candidates, although [1]/bin/sub has it.  */
    int sr = posix_spawnp (&spid, "fswc_mwild_probe", NULL, NULL,
                           sp_argv, sp_envp);
    TEST_COMPARE (sr, ENOENT);

    /* One "*": candidates "*", "1", "?", "[1]" in byte order; the probe in
       [1]/bin/sub is not executable.  */
    char *one_star = xasprintf ("%s/*/bin/sub", mwild);
    setenv ("PATH", one_star, 1);
    sr = posix_spawnp (&spid, "fswc_mwild_probe", NULL, NULL,
                       sp_argv, sp_envp);
    TEST_COMPARE (sr, EACCES);
    free (one_star);
    setenv ("PATH", wpath + 5, 1);

    unlink (probe_brack);
    sr = posix_spawnp (&spid, "fswc_mwild_probe", NULL, NULL,
                       sp_argv, sp_envp);
    TEST_COMPARE (sr, ENOENT);

    /* PATH="<mwild>/[?]/<star>/": "[?]" is a literal name, and no directory
       has it, so neither <mwild>/?/sub nor <mwild>/a/sub is searched.  */
    char *qpath = xasprintf ("PATH=%s/[?]/*/", mwild);
    char *qp_argv[] = { (char *) "fswc_trail_qprobe", NULL };
    char *qp_envp[] = { qpath, NULL };
    setenv ("PATH", qpath + 5, 1);
    sr = posix_spawnp (&spid, "fswc_trail_qprobe", NULL, NULL,
                       qp_argv, qp_envp);
    TEST_COMPARE (sr, ENOENT);

    char *probe_qsub = xasprintf ("%s/fswc_trail_qprobe", d_qsub);
    pfd = xopen (probe_qsub, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    xclose (pfd);
    sr = posix_spawnp (&spid, "fswc_trail_qprobe", NULL, NULL,
                       qp_argv, qp_envp);
    TEST_COMPARE (sr, ENOENT);

    /* With the literal "?" instead, the trailing-slash element finds it.  */
    char *qlit = xasprintf ("%s/?/*/", mwild);
    setenv ("PATH", qlit, 1);
    sr = posix_spawnp (&spid, "fswc_trail_qprobe", NULL, NULL,
                       qp_argv, qp_envp);
    TEST_COMPARE (sr, EACCES);
    free (qlit);

    if (saved_path != NULL)
      {
        setenv ("PATH", saved_path, 1);
        free (saved_path);
      }
    else
      unsetenv ("PATH");

    unlink (probe_qsub);
    unlink (probe_asub);
    free (probe_qsub);
    free (probe_asub);
    free (qpath);
    free (wpath);
    free (probe_brack);
    free (d_asub);
    free (d_qsub);
    free (d_one);
    free (d_brack);
    free (d_qmark);
    free (d_star);
    free (mwild);
  }

  /* 6b. execvpe splits PATH at every ':' (GLOB.md 3.2): brackets do not
     protect a colon and backslashes are literal.  */
  {
    int saved_cwd = xopen (".", O_RDONLY | O_DIRECTORY, 0);
    xchdir (tmp);

    char *esc_seg2 = xasprintf ("%s/other]/bin", tmp);
    xmkdirp (esc_seg2, 0755);
    char *esc_cmd = xasprintf ("%s/fswc_esc_probe", esc_seg2);
    int efd = xopen (esc_cmd, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    xclose (efd);

    char *old_path_dup = getenv ("PATH") != NULL ? xstrdup (getenv ("PATH")) : NULL;
    TEST_COMPARE (setenv ("PATH", "dir\\[:other]/bin", 1), 0);
    char *const eargv1[] = { (char *) "fswc_esc_probe", NULL };
    char *const eenvp1[] = { NULL };
    errno = 0;
    TEST_COMPARE (execvpe ("fswc_esc_probe", eargv1, eenvp1), -1);
    TEST_COMPARE (errno, EACCES);

    /* "[[:alpha]:[[:digit:]]]/bin" is five elements; "alpha]" is one.  */
    char *cc_seg2 = xasprintf ("%s/alpha]", tmp);
    xmkdirp (cc_seg2, 0755);
    char *cc_cmd = xasprintf ("%s/fswc_cc_probe", cc_seg2);
    efd = xopen (cc_cmd, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    xclose (efd);

    TEST_COMPARE (setenv ("PATH", "[[:alpha]:[[:digit:]]]/bin", 1), 0);
    char *const eargv2[] = { (char *) "fswc_cc_probe", NULL };
    errno = 0;
    TEST_COMPARE (execvpe ("fswc_cc_probe", eargv2, eenvp1), -1);
    TEST_COMPARE (errno, EACCES);

    /* PATH="$PWD/dir[1]/bin" is literal, even though dir1/bin exists too;
       PATH="$PWD/dir\[1\]/bin" names a directory with backslashes in it,
       which does not exist.  */
    char *lit_bdir = xasprintf ("%s/dir[1]/bin", tmp);
    char *glob_bdir = xasprintf ("%s/dir1/bin", tmp);
    xmkdirp (lit_bdir, 0755);
    xmkdirp (glob_bdir, 0755);
    char *lit_bcmd = xasprintf ("%s/fswc_lit_brack_probe", lit_bdir);
    efd = xopen (lit_bcmd, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    xclose (efd);

    char *lit_bpath = xasprintf ("%s/dir[1]/bin", tmp);
    TEST_COMPARE (setenv ("PATH", lit_bpath, 1), 0);
    char *const eargv3[] = { (char *) "fswc_lit_brack_probe", NULL };
    errno = 0;
    TEST_COMPARE (execvpe ("fswc_lit_brack_probe", eargv3, eenvp1), -1);
    TEST_COMPARE (errno, EACCES);

    char *esc_bpath = xasprintf ("%s/dir\\[1\\]/bin", tmp);
    TEST_COMPARE (setenv ("PATH", esc_bpath, 1), 0);
    errno = 0;
    TEST_COMPARE (execvpe ("fswc_lit_brack_probe", eargv3, eenvp1), -1);
    TEST_COMPARE (errno, ENOENT);

    free (esc_bpath);
    free (lit_bpath);
    free (lit_bcmd);
    free (glob_bdir);
    free (lit_bdir);

    TEST_COMPARE (fchdir (saved_cwd), 0);
    xclose (saved_cwd);

    if (old_path_dup != NULL)
      {
        setenv ("PATH", old_path_dup, 1);
        free (old_path_dup);
      }
    else
      unsetenv ("PATH");

    free (cc_cmd);
    free (cc_seg2);
    free (esc_cmd);
    free (esc_seg2);
  }

  nftw (tmp, rm_child_cb, 32, FTW_DEPTH | FTW_PHYS);
  free (sym_pfx);
  free (empty_dir);
  free (hello);
  free (pkg1);
  free (plain);
  free (tmp);
  return 0;
}

#define TEST_FUNCTION_ARGV do_test
#include <support/test-driver.c>
