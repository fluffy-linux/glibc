/* vfork() + execvpe() CLONE_VM safety, EACCES stickiness, and literal slash paths.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <paths.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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
#include <support/test-driver.h>
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

static bool
write_tiny_exit0_exe (const char *path)
{
#if defined (__linux__) && (defined (__x86_64__) || defined (__aarch64__))
  struct
  {
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdr;
    uint8_t code[16];
  } img;
  memset (&img, 0, sizeof (img));
  img.ehdr.e_ident[EI_MAG0] = ELFMAG0;
  img.ehdr.e_ident[EI_MAG1] = ELFMAG1;
  img.ehdr.e_ident[EI_MAG2] = ELFMAG2;
  img.ehdr.e_ident[EI_MAG3] = ELFMAG3;
  img.ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  img.ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  img.ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  img.ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  img.ehdr.e_type = ET_EXEC;
  img.ehdr.e_version = EV_CURRENT;
  img.ehdr.e_entry = 0x400000ULL + offsetof (__typeof__ (img), code);
  img.ehdr.e_phoff = offsetof (__typeof__ (img), phdr);
  img.ehdr.e_ehsize = sizeof (Elf64_Ehdr);
  img.ehdr.e_phentsize = sizeof (Elf64_Phdr);
  img.ehdr.e_phnum = 1;
# if defined (__x86_64__)
  img.ehdr.e_machine = EM_X86_64;
  static const uint8_t stub[] =
    { 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05 };
# elif defined (__aarch64__)
  img.ehdr.e_machine = EM_AARCH64;
  static const uint8_t stub[] =
    { 0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4 };
# endif
  memcpy (img.code, stub, sizeof (stub));
  size_t total = offsetof (__typeof__ (img), code) + sizeof (stub);
  img.phdr.p_type = PT_LOAD;
  img.phdr.p_flags = PF_R | PF_X;
  img.phdr.p_offset = 0;
  img.phdr.p_vaddr = 0x400000ULL;
  img.phdr.p_paddr = 0x400000ULL;
  img.phdr.p_filesz = total;
  img.phdr.p_memsz = total;
  img.phdr.p_align = 0x1000;

  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (fd < 0)
    return false;
  ssize_t nw = write (fd, &img, total);
  xclose (fd);
  xchmod (path, 0755);
  return nw == (ssize_t) total;
#else
  const char *path_env = getenv ("PATH");
  if (path_env == NULL)
    return false;
  for (const char *p = path_env; *p != '\0'; )
    {
      const char *col = strchr (p, ':');
      size_t len = col != NULL ? (size_t) (col - p) : strlen (p);
      char cand[PATH_MAX];
      if (len > 0 && len + 6 < sizeof (cand))
        {
          memcpy (cand, p, len);
          memcpy (cand + len, "/true", 6);
          if (access (cand, X_OK) == 0)
            {
              struct stat st;
              xstat (cand, &st);
              int sfd = xopen (cand, O_RDONLY, 0);
              int dfd = xopen (path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
              xcopy_file_range (sfd, NULL, dfd, NULL, st.st_size, 0);
              xclose (dfd);
              xclose (sfd);
              return true;
            }
        }
      if (col == NULL)
        break;
      p = col + 1;
    }
  return false;
#endif
}

static const char *
discover_squash_prefix (char *buf, size_t buf_sz)
{
  const char *env_p = getenv ("FSWC_TEST_PREFIX");
  if (env_p != NULL)
    {
      if (strcmp (env_p, "none") == 0)
        return NULL;
      if (env_p[0] == '/')
        {
          snprintf (buf, buf_sz, "%s", env_p);
          return buf;
        }
    }
  FILE *fp = fopen ("/proc/self/mountinfo", "r");
  if (fp == NULL)
    return NULL;
  char best[512] = "";
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
          best_cnt = sq_cnt;
          memcpy (best, par, par_len + 1);
        }
    }
  fclose (fp);
  if (best_cnt == 0)
    return NULL;
  snprintf (buf, buf_sz, "%s", best);
  return buf;
}

static int __attribute__ ((noinline))
vfork_execvpe_wait (const char *cmd, char *const envp[], int fail_code,
                    int *out_err)
{
  volatile int child_err = 0;
  pid_t pid = vfork ();
  if (pid < 0)
    FAIL_EXIT1 ("vfork failed: %m");
  if (pid == 0)
    {
      char *const av[] = { (char *) cmd, NULL };
      execvpe (av[0], av, envp);
      child_err = errno;
      _exit (fail_code);
    }
  int status = 0;
  xwaitpid (pid, &status, 0);
  if (out_err != NULL)
    *out_err = child_err;
  return status;
}

static int
do_test (int argc, char *argv[])
{
  (void) argc;
  (void) argv;

  char *tmp = support_create_temp_directory ("tst-fswc-vfork-");

  /* Build a synthetic package tree under tmp/pkgs/{pkgA,pkgB}/bin with:
     - pkgA/bin/only_nonexec (mode 0644 -> EACCES)
     - pkgB/bin/vfork_ok_cmd (self-contained static exit(0) executable)  */
  char *pkgA_bin = xasprintf ("%s/pkgs/pkgA/bin", tmp);
  char *pkgB_bin = xasprintf ("%s/pkgs/pkgB/bin", tmp);
  xmkdirp (pkgA_bin, 0755);
  xmkdirp (pkgB_bin, 0755);

  char *nonexec = xasprintf ("%s/only_nonexec", pkgA_bin);
  int fd = xopen (nonexec, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  xclose (fd);

  char *good_cmd = xasprintf ("%s/vfork_ok_cmd", pkgB_bin);
  bool have_good_cmd = write_tiny_exit0_exe (good_cmd);

  char sq_buf[512] = "";
  const char *sq_pfx = discover_squash_prefix (sq_buf, sizeof (sq_buf));
  char *cold_sym = xasprintf ("%s/cold_sq", tmp);
  if (sq_pfx != NULL)
    xsymlink (sq_pfx, cold_sym);
  else
    xmkdirp (cold_sym, 0755);

  /* Heap canary in parent to verify vfork() child never corrupts parent heap. */
  char *canary = xstrdup ("FLUFFY_VFORK_HEAP_CANARY_OK");

  char path_val[2000];
  snprintf (path_val, sizeof (path_val),
            "%s/*/bin:%s/*/usr/bin:%s/pkgs/*/bin",
            cold_sym, cold_sym, tmp);
  TEST_COMPARE (setenv ("PATH", path_val, 1), 0);

  char path_env[2048];
  snprintf (path_env, sizeof (path_env), "PATH=%s", path_val);
  char *const envp[] = { path_env, NULL };

  /* 1. Sticky EACCES across vfork() + execvpe() on cold & warm wildcard PATH.  */
  for (int iter = 0; iter < 16; ++iter)
    {
      int child_err = 0;
      int status = vfork_execvpe_wait ("only_nonexec", envp, 126, &child_err);
      TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 126);
      TEST_COMPARE (child_err, EACCES);
      TEST_COMPARE_STRING (canary, "FLUFFY_VFORK_HEAP_CANARY_OK");
    }

  /* 2. Positive wildcard PATH execvpe() via vfork() + slash-wildcard execvpe()
     + ENOEXEC #!-less script fallback when _PATH_BSHELL exists.  */
  if (have_good_cmd)
    {
      for (int iter = 0; iter < 16; ++iter)
        {
          int status = vfork_execvpe_wait ("vfork_ok_cmd", envp, 127, NULL);
          TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
        }

      /* A path containing a slash is always literal: execvpe() never
         expands glob metacharacters in it, even when the pattern would
         match an executable.  "<tmp>/pkgs/<star>/bin/vfork_ok_cmd" does not
         exist literally, so the exec must fail and nothing may run.  */
      char slash_wild[1024];
      snprintf (slash_wild, sizeof (slash_wild),
                "%s/pkgs/*/bin/vfork_ok_cmd", tmp);
      int sstatus = vfork_execvpe_wait (slash_wild, envp, 127, NULL);
      TEST_VERIFY (WIFEXITED (sstatus) && WEXITSTATUS (sstatus) == 127);

      /* #!-less +x script -> ENOEXEC fallback via _PATH_BSHELL (only if
         _PATH_BSHELL is executable in this environment).  */
      if (access (_PATH_BSHELL, X_OK) == 0)
        {
          char *nohash = xasprintf ("%s/nohash_script", pkgB_bin);
          FILE *fp = fopen (nohash, "wb");
          TEST_VERIFY_EXIT (fp != NULL);
          fputs ("exit 0\n", fp);
          TEST_COMPARE (fclose (fp), 0);
          TEST_COMPARE (chmod (nohash, 0755), 0);

          int nstatus = vfork_execvpe_wait ("nohash_script", envp, 127, NULL);
          TEST_VERIFY (WIFEXITED (nstatus) && WEXITSTATUS (nstatus) == 0);
          free (nohash);
        }
    }

  TEST_COMPARE_STRING (canary, "FLUFFY_VFORK_HEAP_CANARY_OK");

  nftw (tmp, rm_child_cb, 32, FTW_DEPTH | FTW_PHYS);
  free (canary);
  free (cold_sym);
  free (good_cmd);
  free (nonexec);
  free (pkgB_bin);
  free (pkgA_bin);
  free (tmp);
  return 0;
}

#define TEST_FUNCTION_ARGV do_test
#include <support/test-driver.c>
