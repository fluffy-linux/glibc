/* Exhaustive unit tests for Fluffy <glob.h> and <fnmatch.h> extensions.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <locale.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <support/check.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xunistd.h>

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

static void
touch_file (const char *path)
{
  int fd = xopen (path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  xclose (fd);
}

static void
expect_glob (const char *pattern, int flags, size_t offs, int exp_ret, ...)
{
  glob_t gl;
  memset (&gl, 0, sizeof (gl));
  gl.gl_offs = offs;
  int r = glob (pattern, flags, NULL, &gl);
  TEST_COMPARE (r, exp_ret);
  if (exp_ret != 0)
    {
      globfree (&gl);
      return;
    }

  va_list ap;
  va_start (ap, exp_ret);
  size_t idx = 0;
  while (true)
    {
      const char *exp = va_arg (ap, const char *);
      if (exp == NULL)
        break;
      if (idx >= gl.gl_pathc)
        FAIL_EXIT1 ("pattern \"%s\" (flags=0x%x): fewer results (%zu) than expected (missing \"%s\")",
                    pattern, flags, gl.gl_pathc, exp);
      TEST_COMPARE_STRING (gl.gl_pathv[offs + idx], exp);
      ++idx;
    }
  va_end (ap);
  TEST_COMPARE (gl.gl_pathc, idx);
  for (size_t i = 0; i < offs; ++i)
    TEST_VERIFY (gl.gl_pathv[i] == NULL);
  TEST_VERIFY (gl.gl_pathv[offs + idx] == NULL);
  globfree (&gl);
}

static int
do_test (void)
{
  /* 1. FNM_DOTDOT tests (leading wildcards skip "." and "..", whereas literal
     leading "." in ".*" matches "." and ".." unless GLOB_SKIPDOTS is set).  */
  TEST_COMPARE (fnmatch ("*", ".", FNM_DOTDOT), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("*", "..", FNM_DOTDOT), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("?", ".", FNM_DOTDOT), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("[.]", ".", FNM_DOTDOT), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("*", ".hidden", FNM_DOTDOT), 0);
  TEST_COMPARE (fnmatch ("*", ".hidden", FNM_PERIOD | FNM_DOTDOT), FNM_NOMATCH);
  TEST_COMPARE (fnmatch (".*", ".", FNM_DOTDOT), 0);
  TEST_COMPARE (fnmatch (".*", "..", FNM_DOTDOT), 0);
  TEST_COMPARE (fnmatch (".*", ".hidden", FNM_DOTDOT), 0);

  char *base = support_create_temp_directory ("tst-glob-fluffy-");
  xchdir (base);

  xmkdirp ("d1/sub", 0755);
  xmkdirp ("d2/sub/deep", 0755);
  xmkdirp ("d:colon", 0755);
  xmkdirp ("@(escdir)", 0755);
  xmkdirp ("+(plusdir)", 0755);
  xmkdirp ("MixedCase", 0755);

  touch_file ("d1/a.txt");
  touch_file ("d1/b.txt");
  touch_file ("d1/.dotfile");
  touch_file ("d1/sub/leaf.txt");
  touch_file ("d2/c.txt");
  touch_file ("d2/sub/deep/leaf.txt");
  touch_file ("d:colon/item");
  touch_file ("@(escdir)/inside");
  touch_file ("+(plusdir)/inside");
  touch_file ("MixedCase/ReadMe.MD");
  touch_file ("root.txt");

  /* Symlink loop inside d2 to verify cycle-free GLOB_GLOBSTAR.  */
  xsymlink ("..", "d2/sub/loop_up");

  /* 2. GLOB_PATHS empty segments: ":d1/a.txt", "d1/a.txt::d2/c.txt",
     "d1/a.txt:", and "" -> ".".  */
  expect_glob ("", GLOB_PATHS, 0, 0, ".", NULL);
  expect_glob (":d1/a.txt", GLOB_PATHS, 0, 0, ".", "d1/a.txt", NULL);
  expect_glob ("d1/a.txt::d2/c.txt", GLOB_PATHS, 0, 0,
               "d1/a.txt", ".", "d2/c.txt", NULL);
  expect_glob ("d1/a.txt:", GLOB_PATHS, 0, 0, "d1/a.txt", ".", NULL);

  /* 3. GLOB_PATHS search lists (GLOB.md 3.2): every ':' separates
     elements, backslashes are literal, and a whole "*" component is the
     only wildcard; brackets, extglob, and braces are literal names, and
     pattern-syntax flags do not apply.  */
  expect_glob ("d\\:colon/item:d1/a.txt", GLOB_PATHS, 0, 0,
               "d1/a.txt", NULL);

  xmkdirp ("bslash\\", 0755);
  touch_file ("bslash\\/f");
  expect_glob ("bslash\\:d1/a.txt", GLOB_PATHS, 0, 0,
               "bslash\\", "d1/a.txt", NULL);

  expect_glob ("d[x:y]/item", GLOB_PATHS, 0, GLOB_NOMATCH);
  expect_glob ("d[:]colon/item", GLOB_PATHS, 0, GLOB_NOMATCH);
  expect_glob ("d*/a.txt", GLOB_PATHS, 0, GLOB_NOMATCH);
  /* A name with a colon is still reachable through "*".  */
  expect_glob ("*/item:*/a.txt", GLOB_PATHS, 0, 0,
               "d:colon/item", "d1/a.txt", NULL);

  expect_glob ("@(escdir)/inside", GLOB_PATHS | GLOB_EXTMATCH, 0, 0,
               "@(escdir)/inside", NULL);
  expect_glob ("@(d:colon|d2)/*", GLOB_PATHS | GLOB_EXTMATCH, 0,
               GLOB_NOMATCH);

  /* "{LIST}/NAME" looks up a literal NAME in every element; an empty
     element is ".".  Without "}/" the braces are literal.  */
  expect_glob ("{d1:d2}/c.txt", GLOB_PATHS, 0, 0, "d2/c.txt", NULL);
  expect_glob ("{d1:d2:}/a.txt", GLOB_PATHS, 0, 0, "d1/a.txt", NULL);
  expect_glob ("{:d1}/root.txt", GLOB_PATHS, 0, 0, "./root.txt", NULL);
  expect_glob ("{d1/a.txt:d2/c.txt,root.txt}", GLOB_PATHS | GLOB_BRACE, 0,
               GLOB_NOMATCH);

  /* 4. GLOB_PATHS + GLOB_DOOFFS: gl_offs initialized once, before the
     first element.  */
  expect_glob ("d2/*:d1/*", GLOB_PATHS | GLOB_DOOFFS, 3, 0,
               "d2/c.txt", "d2/sub", "d1/a.txt", "d1/b.txt", "d1/sub", NULL);

  /* 5. GLOB_PATHS + per-segment GLOB_NOCHECK and GLOB_NOMAGIC + GLOB_MAGCHAR. */
  {
    glob_t gl;
    memset (&gl, 0, sizeof (gl));
    /* NOCHECK: every element without a match stands for itself.  */
    TEST_COMPARE (glob ("missing_lit:d1/*:missing/*",
                        GLOB_PATHS | GLOB_NOCHECK, NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 5);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "missing_lit");
    TEST_COMPARE_STRING (gl.gl_pathv[1], "d1/a.txt");
    TEST_COMPARE_STRING (gl.gl_pathv[2], "d1/b.txt");
    TEST_COMPARE_STRING (gl.gl_pathv[3], "d1/sub");
    TEST_COMPARE_STRING (gl.gl_pathv[4], "missing/*");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) != 0);
    globfree (&gl);

    /* NOMAGIC: only elements without a "*" do.  */
    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("missing_lit:d1/*:missing/*",
                        GLOB_PATHS | GLOB_NOMAGIC, NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 4);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "missing_lit");
    TEST_COMPARE_STRING (gl.gl_pathv[1], "d1/a.txt");
    TEST_COMPARE_STRING (gl.gl_pathv[2], "d1/b.txt");
    TEST_COMPARE_STRING (gl.gl_pathv[3], "d1/sub");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) != 0);
    globfree (&gl);
  }
  /* "{LIST}/NAME" with GLOB_NOCHECK keeps the element and NAME.  */
  expect_glob ("{missing}/name", GLOB_PATHS | GLOB_NOCHECK, 0, 0,
               "missing/name", NULL);
  /* A symlink to a directory counts as one for GLOB_MARK and
     GLOB_ONLYDIR, as it does for glob's other patterns, with or without
     GLOB_ALTDIRFUNC hooks (here the real functions).  */
  expect_glob ("d2/sub/*", GLOB_PATHS | GLOB_MARK, 0, 0,
               "d2/sub/deep/", "d2/sub/loop_up/", NULL);
  expect_glob ("d2/sub/*:d2/*", GLOB_PATHS | GLOB_ONLYDIR, 0, 0,
               "d2/sub/deep", "d2/sub/loop_up", "d2/sub", NULL);
  {
    glob_t gl;
    memset (&gl, 0, sizeof (gl));
    gl.gl_opendir = (void *(*) (const char *)) opendir;
    gl.gl_readdir = (struct dirent *(*) (void *)) readdir;
    gl.gl_closedir = (void (*) (void *)) closedir;
    gl.gl_lstat = lstat;
    gl.gl_stat = stat;
    TEST_COMPARE (glob ("d2/sub/*", GLOB_PATHS | GLOB_MARK | GLOB_ALTDIRFUNC,
                        NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 2);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "d2/sub/deep/");
    TEST_COMPARE_STRING (gl.gl_pathv[1], "d2/sub/loop_up/");
    globfree (&gl);
  }
  /* An element too long for a path is an error with GLOB_NOCHECK, which
     would have to return it.  */
  {
    char *longp = xmalloc (5001);
    memset (longp, 'x', 5000);
    longp[5000] = '\0';
    glob_t gl;
    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob (longp, GLOB_PATHS | GLOB_NOCHECK, NULL, &gl),
                  GLOB_NOSPACE);
    TEST_COMPARE (gl.gl_pathc, 0);
    free (longp);
  }
  /* Brackets are literal: neither element exists.  */
  expect_glob ("[1/nope:d1/[a].txt", GLOB_PATHS, 0, GLOB_NOMATCH);

  /* 6. Byte order within each element, whatever LC_COLLATE says, so a
     search never depends on the locale.  */
  xmkdirp ("coll", 0755);
  touch_file ("coll/B");
  touch_file ("coll/a");
  touch_file ("coll/b");

  TEST_VERIFY (setlocale (LC_ALL, "C") != NULL);
  expect_glob ("coll/*:d1/a.txt", GLOB_PATHS, 0, 0,
               "coll/B", "coll/a", "coll/b", "d1/a.txt", NULL);

  if (setlocale (LC_ALL, "en_US.UTF-8") != NULL)
    {
      glob_t gl;
      TEST_COMPARE (glob ("coll/*:d1/a.txt", GLOB_PATHS, NULL, &gl), 0);
      TEST_COMPARE (gl.gl_pathc, 4);
      /* en_US.UTF-8 would sort "a" first; a search list does not.  */
      TEST_COMPARE_STRING (gl.gl_pathv[0], "coll/B");
      TEST_COMPARE_STRING (gl.gl_pathv[1], "coll/a");
      TEST_COMPARE_STRING (gl.gl_pathv[3], "d1/a.txt");
      globfree (&gl);
      setlocale (LC_ALL, "C");
    }

  /* 7. GLOB_KEEP_SLASHES.  */
  expect_glob ("d1///", 0, 0, 0, "d1/", NULL);
  expect_glob ("d1///", GLOB_KEEP_SLASHES, 0, 0, "d1///", NULL);
  expect_glob ("d1///", GLOB_KEEP_SLASHES | GLOB_MARK, 0, 0, "d1///", NULL);
  expect_glob ("//", GLOB_KEEP_SLASHES, 0, 0, "//", NULL);
  expect_glob ("///", GLOB_KEEP_SLASHES, 0, 0, "///", NULL);
  expect_glob ("d*///", GLOB_KEEP_SLASHES, 0, 0,
               "d1/", "d2/", "d:colon/", NULL);

  /* 8. GLOB_EXTMATCH, escaped extmatch in glob_dirscan, escaped '/', and
     no extmatch leak into GLOB_NOMAGIC when GLOB_EXTMATCH is unset.  */
  expect_glob ("\\@(escdir)/*", GLOB_EXTMATCH, 0, 0,
               "@(escdir)/inside", NULL);
  expect_glob ("\\+(plusdir)/*", GLOB_EXTMATCH, 0, 0,
               "+(plusdir)/inside", NULL);
  expect_glob ("d1\\/a.txt", 0, 0, 0, "d1/a.txt", NULL);

  {
    glob_t gl;
    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("@(nonexistent_literal)", GLOB_NOMAGIC, NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 1);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "@(nonexistent_literal)");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) == 0);
    globfree (&gl);
  }

  /* 9. GLOB_CASEFOLD, GLOB_SKIPDOTS, GLOB_DOTDOT, and GLOB_GLOBSTAR.  */
  expect_glob ("mixedcase/readme.*", GLOB_CASEFOLD, 0, 0,
               "MixedCase/ReadMe.MD", NULL);

  /* GLOB_CASEFOLD on literal patterns must NOT set GLOB_MAGCHAR, preserving
     GLOB_KEEP_SLASHES and GLOB_NOMAGIC.  */
  {
    glob_t gl;
    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("d1///", GLOB_KEEP_SLASHES | GLOB_CASEFOLD, NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 1);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "d1///");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) == 0);
    globfree (&gl);

    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("mixedcase///", GLOB_KEEP_SLASHES | GLOB_CASEFOLD,
                        NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 1);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "MixedCase///");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) == 0);
    globfree (&gl);

    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("no_such_lit", GLOB_NOMAGIC | GLOB_CASEFOLD, NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 1);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "no_such_lit");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) == 0);
    globfree (&gl);

    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("no_such_dir/leaf", GLOB_NOMAGIC | GLOB_CASEFOLD,
                        NULL, &gl), 0);
    TEST_COMPARE (gl.gl_pathc, 1);
    TEST_COMPARE_STRING (gl.gl_pathv[0], "no_such_dir/leaf");
    TEST_VERIFY ((gl.gl_flags & GLOB_MAGCHAR) == 0);
    globfree (&gl);

    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("", GLOB_NOMAGIC, NULL, &gl), GLOB_NOMATCH);
    globfree (&gl);

    memset (&gl, 0, sizeof (gl));
    TEST_COMPARE (glob ("no_such_escaped\\/", GLOB_NOMAGIC, NULL, &gl),
                  GLOB_NOMATCH);
    globfree (&gl);
  }

  expect_glob ("d1/.*", GLOB_SKIPDOTS, 0, 0, "d1/.dotfile", NULL);
  expect_glob ("d1/*", GLOB_PERIOD | GLOB_DOTDOT, 0, 0,
               "d1/.dotfile", "d1/a.txt", "d1/b.txt", "d1/sub", NULL);

  /* Intermediate hidden directory under GLOB_PERIOD vs GLOB_PERIOD | GLOB_SKIPDOTS.  */
  xmkdirp (".hiddendir", 0755);
  touch_file (".hiddendir/hfile");
  expect_glob ("*/hfile", GLOB_PERIOD, 0, GLOB_NOMATCH);
  expect_glob ("*/hfile", GLOB_PERIOD | GLOB_SKIPDOTS, 0, 0,
               ".hiddendir/hfile", NULL);
  expect_glob ("*/hfile", GLOB_PERIOD | GLOB_DOTDOT, 0, 0,
               ".hiddendir/hfile", NULL);

  /* FNM_DOTDOT + FNM_EXTMATCH + FNM_FILE_NAME component boundary tests.  */
  TEST_COMPARE (fnmatch ("+(?)", ".", FNM_DOTDOT | FNM_EXTMATCH), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("+(?)", "..", FNM_DOTDOT | FNM_EXTMATCH), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("*(?)", "..", FNM_DOTDOT | FNM_EXTMATCH), FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("+(?)", ".bashrc", FNM_DOTDOT | FNM_EXTMATCH), 0);
  TEST_COMPARE (fnmatch ("+(?)", "..hidden", FNM_DOTDOT | FNM_EXTMATCH), 0);
  TEST_COMPARE (fnmatch ("a/!(foo)", "a/..",
                         FNM_DOTDOT | FNM_EXTMATCH | FNM_FILE_NAME),
                FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("a/+(?)", "a/..",
                         FNM_DOTDOT | FNM_EXTMATCH | FNM_FILE_NAME),
                FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("*a/?", "ba/.", FNM_DOTDOT | FNM_FILE_NAME),
                FNM_NOMATCH);
  TEST_COMPARE (fnmatch ("@(.*)", "..", FNM_DOTDOT | FNM_EXTMATCH), 0);
  TEST_COMPARE (fnmatch ("@(.?)", "..", FNM_DOTDOT | FNM_EXTMATCH), 0);
  TEST_COMPARE (fnmatch ("@(*)", "..", FNM_DOTDOT | FNM_EXTMATCH), FNM_NOMATCH);

  /* GLOB_GLOBSTAR: zero-or-more levels, adjacent globstar collapse, symlink
     root prefix traversal, and cycle-free child symlink handling
     (d2/sub/loop_up -> .. must NOT loop!).  */
  xsymlink ("d1", "sym_d1");
  expect_glob ("**/leaf.txt", GLOB_GLOBSTAR, 0, 0,
               "d1/sub/leaf.txt", "d2/sub/deep/leaf.txt", NULL);
  expect_glob ("**/**/leaf.txt", GLOB_GLOBSTAR, 0, 0,
               "d1/sub/leaf.txt", "d2/sub/deep/leaf.txt", NULL);
  expect_glob ("d1/**/a.txt", GLOB_GLOBSTAR, 0, 0, "d1/a.txt", NULL);
  expect_glob ("d1/**/**/a.txt", GLOB_GLOBSTAR, 0, 0, "d1/a.txt", NULL);
  expect_glob ("d1//**/a.txt", GLOB_GLOBSTAR, 0, 0, "d1//a.txt", NULL);
  expect_glob ("sym_d1/**/a.txt", GLOB_GLOBSTAR, 0, 0, "sym_d1/a.txt", NULL);
  expect_glob ("sym_d1/**/leaf.txt", GLOB_GLOBSTAR, 0, 0,
               "sym_d1/sub/leaf.txt", NULL);
  expect_glob ("d1/**", GLOB_GLOBSTAR, 0, 0,
               "d1/", "d1/a.txt", "d1/b.txt", "d1/sub", "d1/sub/leaf.txt",
               NULL);
  expect_glob ("d1/**", GLOB_GLOBSTAR | GLOB_CASEFOLD, 0, 0,
               "d1/", "d1/a.txt", "d1/b.txt", "d1/sub", "d1/sub/leaf.txt",
               NULL);

  /* Runs of "**" collapse wherever they are, and "**" never follows the
     symlinks it finds, as in bash 5.3.  */
  expect_glob ("**//**/leaf.txt", GLOB_GLOBSTAR, 0, 0,
               "d1/sub/leaf.txt", "d2/sub/deep/leaf.txt", NULL);
  expect_glob ("**/**/d1/*.txt", GLOB_GLOBSTAR, 0, 0,
               "d1/a.txt", "d1/b.txt", NULL);
  expect_glob ("d1/**/**", GLOB_GLOBSTAR, 0, 0,
               "d1", "d1/a.txt", "d1/b.txt", "d1/sub", "d1/sub/leaf.txt",
               NULL);
  expect_glob ("d2/**/**/c.txt", GLOB_GLOBSTAR, 0, 0, "d2/c.txt", NULL);
  xchdir ("d2");
  expect_glob ("**/**", GLOB_GLOBSTAR, 0, 0,
               "c.txt", "sub", "sub/deep", "sub/deep/leaf.txt", "sub/loop_up",
               NULL);
  xchdir ("..");
  /* With GLOB_NOCHECK, a "**" pattern that matches nothing is returned
     as it is.  */
  expect_glob ("nonexistent/**", GLOB_GLOBSTAR | GLOB_NOCHECK, 0, 0,
               "nonexistent/**", NULL);

  /* Extended patterns in a directory part: brackets, a character class,
     a nested group and an escaped character inside a group are part of
     it; a group that is never closed is not one.  A wildcard group
     followed by more pattern still leaves dot files alone.  */
  expect_glob ("@(d[1])/a.txt", GLOB_EXTMATCH, 0, 0, "d1/a.txt", NULL);
  expect_glob ("@(d[[:digit:]])/a.txt", GLOB_EXTMATCH, 0, 0,
               "d1/a.txt", NULL);
  expect_glob ("@(d[!2])/a.txt", GLOB_EXTMATCH, 0, 0, "d1/a.txt", NULL);
  expect_glob ("@(d@(1)|x)/a.txt", GLOB_EXTMATCH, 0, 0, "d1/a.txt", NULL);
  expect_glob ("@(d\\1)/a.txt", GLOB_EXTMATCH, 0, 0, "d1/a.txt", NULL);
  expect_glob ("@(d1/a.txt", GLOB_EXTMATCH, 0, GLOB_NOMATCH);
  expect_glob ("d1/*(x)*", GLOB_EXTMATCH, 0, 0,
               "d1/a.txt", "d1/b.txt", "d1/sub", NULL);

  /* GLOB_TILDE with read-only .rodata HOME and backslash/globstar must never
     mutate getenv("HOME") in place or SIGSEGV on .rodata.  */
  {
    static const char ro_home[] = "HOME=/nonexistent_rodata_home_dir/with\\bs";
    const char *old_home = getenv ("HOME");
    char *saved_home = old_home != NULL ? xstrdup (old_home) : NULL;

    TEST_COMPARE (putenv ((char *) ro_home), 0);
    glob_t tg;
    memset (&tg, 0, sizeof (tg));
    TEST_COMPARE (glob ("~/**", GLOB_TILDE | GLOB_GLOBSTAR, NULL, &tg),
                  GLOB_NOMATCH);
    globfree (&tg);
    memset (&tg, 0, sizeof (tg));
    TEST_COMPARE (glob ("~/a*", GLOB_TILDE | GLOB_GLOBSTAR, NULL, &tg),
                  GLOB_NOMATCH);
    globfree (&tg);
    memset (&tg, 0, sizeof (tg));
    TEST_COMPARE (glob ("~/leaf", GLOB_TILDE, NULL, &tg), GLOB_NOMATCH);
    globfree (&tg);
    TEST_COMPARE_STRING (getenv ("HOME"),
                         "/nonexistent_rodata_home_dir/with\\bs");

    char *real_home_env = xasprintf ("HOME=%s/d1", base);
    const char *expect_home = real_home_env + 5;
    char *expect_copy = xstrdup (expect_home);
    TEST_COMPARE (putenv (real_home_env), 0);
    memset (&tg, 0, sizeof (tg));
    TEST_COMPARE (glob ("~/**", GLOB_TILDE | GLOB_GLOBSTAR, NULL, &tg), 0);
    TEST_VERIFY (tg.gl_pathc >= 5);
    globfree (&tg);
    TEST_COMPARE_STRING (getenv ("HOME"), expect_copy);
    free (expect_copy);

    if (saved_home != NULL)
      {
        TEST_COMPARE (setenv ("HOME", saved_home, 1), 0);
        free (saved_home);
      }
    else
      unsetenv ("HOME");
    free (real_home_env);
  }

  /* 10. posix_spawnp search lists (GLOB.md 3.2): a whole "*" component is
     the only wildcard, so "[[:alpha:]]*" is a literal name; a file path
     given directly is always literal, even when it would match an
     executable as a pattern.  */
  {
    xmkdirp ("xpkg/bin", 0755);
    xmkdirp ("xpkg/b*n", 0755);
    if (write_tiny_exit0_exe ("xpkg/bin/okcmd")
        && write_tiny_exit0_exe ("xpkg/b*n/star*cmd"))
      {
        const char *old_path = getenv ("PATH");
        char *saved_path = old_path != NULL ? xstrdup (old_path) : NULL;
        char *env1[] = { NULL };
        char *argv1[] = { (char *) "okcmd", NULL };
        pid_t spid = 0;
        char *p0 = xasprintf ("%s/[[:alpha:]]*/bin", base);
        TEST_COMPARE (setenv ("PATH", p0, 1), 0);
        int sr = posix_spawnp (&spid, "okcmd", NULL, NULL, argv1, env1);
        TEST_COMPARE (sr, ENOENT);
        free (p0);

        char *p1 = xasprintf ("%s/[1/nope:%s/*/bin", base, base);
        TEST_COMPARE (setenv ("PATH", p1, 1), 0);
        sr = posix_spawnp (&spid, "okcmd", NULL, NULL, argv1, env1);
        TEST_COMPARE (sr, 0);
        int st1 = 0;
        xwaitpid (spid, &st1, 0);
        TEST_VERIFY (WIFEXITED (st1) && WEXITSTATUS (st1) == 0);
        free (p1);

        /* As a pattern this matches xpkg/b*n/star*cmd, but no file has this
           literal name, so neither call may run anything.  */
        char *wfile = xasprintf ("%s/[[:alpha:]]*/b\\*n/star\\*cmd", base);
        char *argv2[] = { (char *) "star*cmd", NULL };
        sr = posix_spawnp (&spid, wfile, NULL, NULL, argv2, env1);
        TEST_COMPARE (sr, ENOENT);

        sr = posix_spawn (&spid, wfile, NULL, NULL, argv2, env1);
        TEST_COMPARE (sr, ENOENT);
        free (wfile);
        if (saved_path != NULL)
          {
            setenv ("PATH", saved_path, 1);
            free (saved_path);
          }
        else
          unsetenv ("PATH");
      }
  }

  /* A HOME too long for alloca is copied into malloc'd memory.  */
  {
    const char *old_home = getenv ("HOME");
    char *saved_home = old_home != NULL ? xstrdup (old_home) : NULL;
    char *long_home = xmalloc (70002);
    long_home[0] = '/';
    memset (long_home + 1, 'h', 70000);
    long_home[70001] = '\0';
    TEST_COMPARE (setenv ("HOME", long_home, 1), 0);
    glob_t tg;
    memset (&tg, 0, sizeof (tg));
    TEST_COMPARE (glob ("~/x", GLOB_TILDE | GLOB_NOCHECK, NULL, &tg), 0);
    TEST_COMPARE (tg.gl_pathc, 1);
    TEST_COMPARE_STRING (tg.gl_pathv[0], "~/x");
    globfree (&tg);
    if (saved_home != NULL)
      {
        TEST_COMPARE (setenv ("HOME", saved_home, 1), 0);
        free (saved_home);
      }
    else
      unsetenv ("HOME");
    free (long_home);
  }

  xchdir ("/");
  nftw (base, rm_child_cb, 32, FTW_DEPTH | FTW_PHYS);
  free (base);
  return 0;
}

#include <support/test-driver.c>
