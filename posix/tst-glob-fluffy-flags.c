/* Exhaustive unit tests for Fluffy <glob.h> and <fnmatch.h> extensions.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <fcntl.h>
#include <fnmatch.h>
#include <ftw.h>
#include <glob.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <support/check.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xunistd.h>

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
