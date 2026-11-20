/* Exhaustive unit tests for Fluffy <glob.h> and <fnmatch.h> extensions.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <fnmatch.h>

#include <support/check.h>

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

  return 0;
}

#include <support/test-driver.c>
