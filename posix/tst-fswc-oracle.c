/* Differential oracle: FSWC must never change an answer.
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

/* glob(), execvpe(), posix_spawnp() and dlopen() are probed over a fixed
   synthetic tree and compared with the reference walk: glob() itself,
   called with caller-supplied GLOB_ALTDIRFUNC hooks that reach the
   filesystem through raw system calls only.  Caller hooks bypass FSWC, so
   the reference is the plain walk with glob()'s own matcher, and any
   difference is FSWC's.  Whether glob()'s pattern semantics are right is
   tst-glob-fluffy-flags's job, not this test's.

   The probes run in a fresh process for each FSWC state, so library
   initialization runs as it does for real programs.

   tst-fswc-oracle-static is this test linked statically: such a program
   has FSWC state of its own (no ld.so), reads the same indexes, and has
   no dlopen, LD_DEBUG, or LD_AUDIT to probe.  */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <link.h>
#include <locale.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array_length.h>
#include <support/check.h>
#include <support/namespace.h>
#include <support/subprocess.h>
#include <support/support.h>
#include <support/temp_file.h>
#include <support/xdlfcn.h>
#include <support/xthread.h>
#include <support/xsocket.h>
#include <support/xunistd.h>

/* The reference walk.  */

/* Calls made through the reference hooks.  A reference walk that makes
   none did not look at the filesystem, which would mean something
   answered in its place.  */
static __thread unsigned long ref_calls;

/* One record as the kernel's getdents64 writes it.  */
struct ref_dirent64
{
  uint64_t d_ino;
  int64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

struct ref_dir
{
  int fd;
  long len;                     /* Bytes of BUF the last getdents64 filled.  */
  long pos;                     /* Offset of the next record in BUF.  */
  struct dirent ent;            /* What ref_readdir hands to glob().  */
  char buf[8192] __attribute__ ((aligned (8)));
};

static void *
ref_opendir (const char *path)
{
  ++ref_calls;
  long fd = syscall (SYS_openat, AT_FDCWD, path,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    return NULL;                /* syscall has set errno.  */
  struct ref_dir *d = xmalloc (sizeof (*d));
  d->fd = fd;
  d->len = d->pos = 0;
  return d;
}

static struct dirent *
ref_readdir (void *stream)
{
  struct ref_dir *d = stream;
  ++ref_calls;
  if (d->pos >= d->len)
    {
      long n = syscall (SYS_getdents64, d->fd, d->buf, sizeof (d->buf));
      if (n <= 0)
        return NULL;            /* 0: end of directory; -1: errno is set.  */
      d->len = n;
      d->pos = 0;
    }
  const struct ref_dirent64 *k = (const void *) (d->buf + d->pos);
  d->pos += k->d_reclen;
  d->ent.d_ino = k->d_ino;
  d->ent.d_off = k->d_off;
  d->ent.d_reclen = sizeof (d->ent);
  d->ent.d_type = k->d_type;
  strcpy (d->ent.d_name, k->d_name);    /* The kernel caps it at NAME_MAX.  */
  return &d->ent;
}

static void
ref_closedir (void *stream)
{
  struct ref_dir *d = stream;
  syscall (SYS_close, d->fd);
  free (d);
}

/* glob() only looks at the file type and at success, but identity is
   filled in too so that the result is an honest struct stat.  */
static int
ref_statx (const char *path, struct stat *st, int at_flags)
{
  ++ref_calls;
  struct statx sx;
  if (syscall (SYS_statx, AT_FDCWD, path, at_flags,
               STATX_TYPE | STATX_MODE | STATX_INO, &sx) != 0)
    return -1;
  memset (st, 0, sizeof (*st));
  st->st_dev = makedev (sx.stx_dev_major, sx.stx_dev_minor);
  st->st_ino = sx.stx_ino;
  st->st_mode = sx.stx_mode;
  return 0;
}

static int
ref_stat (const char *path, struct stat *st)
{
  return ref_statx (path, st, 0);
}

static int
ref_lstat (const char *path, struct stat *st)
{
  return ref_statx (path, st, AT_SYMLINK_NOFOLLOW);
}

/* glob (PATTERN, FLAGS), answered by the plain walk.  */
static int
ref_glob (const char *pattern, int flags, glob_t *g)
{
  memset (g, 0, sizeof (*g));
  g->gl_opendir = ref_opendir;
  g->gl_readdir = ref_readdir;
  g->gl_closedir = ref_closedir;
  g->gl_stat = ref_stat;
  g->gl_lstat = ref_lstat;
  unsigned long before = ref_calls;
  int r = glob (pattern, flags | GLOB_ALTDIRFUNC, NULL, g);
  /* The one case where glob() rightly never looks: a pattern without
     metacharacters under GLOB_NOCHECK or GLOB_NOMAGIC is its own result
     whatever exists.  */
  bool may_skip = (flags & (GLOB_NOCHECK | GLOB_NOMAGIC)) != 0
                  && !glob_pattern_p (pattern, !(flags & GLOB_NOESCAPE));
  if (ref_calls == before && !may_skip)
    {
      support_record_failure ();
      printf ("error: reference walk of \"%s\" never touched the filesystem\n",
              pattern);
    }
  return r;
}

/* The synthetic tree.  */

/* Root of the tree, standing in for a package prefix such as /sw.  */
static const char *tree;

/* Two more prefixes for search lists only (the glob pattern matrix stays
   on TREE).  WIDE has so many entries that its listing overflows every
   walker buffer (execvp's 4 KiB and the 64 KiB of glob, ld.so and dlinfo),
   with packages first, in the middle, and last.  DEEP is so long a path
   that some candidates exceed PATH_MAX.  */
static const char *wide, *deep;

/* JUMBLE has JUMBLE_PACKAGES packages with names of pseudo-random length
   (1 to 250 bytes) created in pseudo-random order, each holding bin/jcmd
   (executable only in one).  Its listing (about 78 KiB) overflows every
   walker buffer in an order that makes the listing evict names for
   smaller ones and then meet larger ones that would fit, so a pass that
   kept a name above one it left out would lose packages.  */
static const char *jumble;

/* LOCKED can be searched but not listed (mode 0300), so the plain walk
   finds no packages in it, though LOCKED/pkg/bin/lockedcmd exists; no
   index can be built for it.  TLINK is a symbolic link to TREE: FSWC
   indexes no prefix through a symlink, so it is always walked.  */
static const char *locked, *tlink;
enum { JUMBLE_PACKAGES = 600 };

/* The prefix the mk_* helpers below create things in.  */
static const char *cur_root;

static char *
tpath (const char *rel)
{
  return xasprintf ("%s/%s", cur_root, rel);
}

/* Create the directories leading to P.  */
static void
mk_parent (const char *p)
{
  char *dir = xstrdup (p);
  *strrchr (dir, '/') = '\0';
  xmkdirp (dir, 0755);
  free (dir);
}

static void
mk_dir (const char *rel)
{
  char *p = tpath (rel);
  xmkdirp (p, 0755);
  free (p);
}

static void
mk_file (const char *rel, mode_t mode)
{
  char *p = tpath (rel);
  mk_parent (p);
  xclose (xopen (p, O_WRONLY | O_CREAT | O_TRUNC, mode));
  free (p);
}

static void
mk_fifo (const char *rel)
{
  char *p = tpath (rel);
  mk_parent (p);
  TEST_COMPARE (mkfifo (p, 0644), 0);
  free (p);
}

static void
mk_socket (const char *rel)
{
  char *p = tpath (rel);
  mk_parent (p);
  struct sockaddr_un sa = { .sun_family = AF_UNIX };
  TEST_VERIFY_EXIT (strlen (p) < sizeof (sa.sun_path));
  strcpy (sa.sun_path, p);
  int fd = xsocket (AF_UNIX, SOCK_STREAM, 0);
  xbind (fd, (struct sockaddr *) &sa, sizeof (sa));
  xclose (fd);
  free (p);
}

static void
mk_link (const char *target, const char *rel)
{
  char *p = tpath (rel);
  mk_parent (p);
  xsymlink (target, p);
  free (p);
}

/* Copy FROM to REL with MODE.  A copy rather than a hard link, because
   the build tree and the temporary directory need not share a file
   system.  */
static void
mk_copy (const char *from, const char *rel, mode_t mode)
{
  char *p = tpath (rel);
  mk_parent (p);
  int in = xopen (from, O_RDONLY, 0);
  int out = xopen (p, O_WRONLY | O_CREAT | O_TRUNC, mode);
  char buf[65536];
  ssize_t n;
  while ((n = read (in, buf, sizeof (buf))) > 0)
    xwrite (out, buf, n);
  TEST_VERIFY_EXIT (n == 0);
  xclose (in);
  xclose (out);
  free (p);
}

/* Under the prefix's top directory NAME, a chain of directories whose
   relative path is longer than PATH_MAX.  */
enum { LONG_LINKS = 20 };

static void
mk_long (const char *name)
{
  char *top = tpath (name);
  xmkdir (top, 0755);
  int fd = xopen (top, O_RDONLY | O_DIRECTORY, 0);
  char comp[251];
  memset (comp, 'p', 250);
  comp[250] = '\0';
  for (int i = 0; i < LONG_LINKS; ++i)
    {
      TEST_COMPARE (mkdirat (fd, comp, 0755), 0);
      int next = openat (fd, comp, O_RDONLY | O_DIRECTORY);
      TEST_VERIFY_EXIT (next >= 0);
      xclose (fd);
      fd = next;
    }
  xclose (openat (fd, "deepfile", O_WRONLY | O_CREAT, 0644));
  xclose (fd);
  free (top);
}

/* Remove what mk_long made under ROOT (nftw cannot: its paths are too
   long), deepest first.  */
static void
rm_long (const char *root, const char *name)
{
  char comp[251];
  memset (comp, 'p', 250);
  comp[250] = '\0';
  int fds[LONG_LINKS + 1];
  char *top = xasprintf ("%s/%s", root, name);
  fds[0] = open (top, O_RDONLY | O_DIRECTORY);
  free (top);
  if (fds[0] < 0)
    return;
  int n = 0;
  while (n < LONG_LINKS
         && (fds[n + 1] = openat (fds[n], comp, O_RDONLY | O_DIRECTORY)) >= 0)
    ++n;
  unlinkat (fds[n], "deepfile", 0);
  for (; n > 0; --n)
    {
      xclose (fds[n]);
      unlinkat (fds[n - 1], comp, AT_REMOVEDIR);
    }
  xclose (fds[0]);
}

/* Package names chosen so that C (byte) order and en_US.UTF-8 order
   differ: in C, "B" < "_u" < "a" < "c"; in en_US, "a" < "B" < "c" < "_u".
   execvpe, posix_spawnp and dlopen run in the C locale; ld.so has no
   locale at all.  */
static void
build_tree (const char *helper, const char *module)
{
  /* Same command in two packages: the first in PATH order wins.  */
  mk_copy (helper, "B/bin/tool", 0755);
  mk_copy (helper, "a/bin/tool", 0755);

  /* An earlier candidate that is not executable: EACCES is remembered,
     but a later executable candidate still wins.  */
  mk_file ("B/bin/late", 0644);
  mk_copy (helper, "a/bin/late", 0755);

  /* Only non-executable candidates: EACCES.  */
  mk_file ("B/bin/noexec", 0644);

  /* A directory where a command is expected, then the real command.  */
  mk_dir ("B/bin/dirhere");
  mk_copy (helper, "a/bin/dirhere", 0755);

  /* A symlinked command: execve gets the symlink's path, not its target.  */
  mk_copy (helper, "a/bin/bash", 0755);
  mk_link ("bash", "a/bin/sh");

  /* A command only in a hidden package, which must never be found.  */
  mk_copy (helper, ".hid/bin/hidden", 0755);

  /* Hidden files inside a package.  */
  mk_file ("a/bin/.dot", 0644);

  /* A package whose bin is search-only: names inside it cannot be listed
     but can be found and run.  Made 0111 after everything is in place.  */
  mk_copy (helper, "c/bin/sx", 0755);

  /* A directory symlink inside a package: FSWC has to defer to the
     kernel for anything below it.  */
  mk_file ("a/include/curses.h", 0644);
  mk_link (".", "a/include/ncursesw");

  /* Libraries.  "_u" precedes "a" in C order, so _u's copy wins.  */
  mk_copy (module, "_u/lib/tst-fswc-oracle-mod.so", 0755);
  mk_copy (module, "a/lib/tst-fswc-oracle-mod.so", 0755);
  mk_copy (module, ".hid/lib/tst-fswc-oracle-mod.so", 0755);
  mk_dir ("B/lib");

  /* Things at the top that are not packages: a plain file (never a
     candidate: "plainfile" sorts last, so if it were one, a failed search
     would end in ENOTDIR instead of ENOENT) and a symlink to a package.  */
  mk_file ("plainfile", 0644);
  mk_link ("a", "link");

  /* The other kinds of non-package entries a prefix can hold.  */
  mk_fifo ("fifo");
  mk_link ("plainfile", "filelink");
  mk_link ("nowhere", "dangling");

  /* Odd package names, all holding "edge" (the first in byte order wins):
     a colon (literal inside a candidate), a space, UTF-8, and an invalid
     UTF-8 byte that sorts last and alone holds "onlylast".  Their order
     differs between C and en_US.  */
  mk_copy (helper, "co:lon/bin/edge", 0755);
  mk_copy (helper, "sp ace/bin/edge", 0755);
  mk_copy (helper, "\xc3\xa9t\xc3\xa9/bin/edge", 0755);
  mk_copy (helper, "\xff" "last/bin/edge", 0755);
  mk_copy (helper, "\xff" "last/bin/onlylast", 0755);

  /* A package whose name is NAME_MAX bytes long.  */
  {
    char name[NAME_MAX + 1];
    memset (name, 'n', NAME_MAX);
    name[NAME_MAX] = '\0';
    char *rel = xasprintf ("%s/bin/longcmd", name);
    mk_copy (helper, rel, 0755);
    free (rel);
  }

  /* Odd commands inside a package.  A FIFO and a dangling symlink cannot
     run (EACCES, ENOENT).  A symlink loop gives ELOOP, which ends the
     search at once (execvp only goes on after errors that mean "not
     here"), so c's real "loopcmd" after it must never run.  */
  mk_fifo ("a/bin/fifocmd");
  mk_link ("nowhere", "a/bin/dangle");
  mk_link ("loopcmd", "a/bin/loopcmd");
  mk_copy (helper, "c/bin/loopcmd", 0755);
  mk_socket ("a/bin/sock");
  mk_copy (helper, "B/rootcmd", 0755);

  /* Packages the builder cannot walk completely, so they stay unsealed
     (answered by the kernel) while the rest of the index is used: one
     nested deeper than the builder's 64 levels, and one holding a path
     longer than PATH_MAX (made with mkdirat, since no absolute path can
     name it; rm_long removes it).  Every process start runs the builder,
     so neither may crash it.  */
  {
    char *rel = xstrdup ("nest");
    for (int i = 0; i < 80; ++i)
      {
        char *next = xasprintf ("%s/d", rel);
        free (rel);
        rel = next;
      }
    char *cmd = xasprintf ("%s/nestcmd", rel);
    mk_copy (helper, cmd, 0755);
    free (cmd);
    free (rel);
  }
  mk_long ("lp");

  char *sx = tpath ("c/bin");
  xchmod (sx, 0111);
  free (sx);
}

/* Fillers in WIDE: an empty package directory and an image file beside
   it, as swctl leaves /sw.  Enough of them that the listing (about 47
   bytes a pair) is larger than the 60 KiB the biggest walker buffer has
   for names.  */
enum { WIDE_FILLERS = 1400 };

static void
build_wide (const char *helper, const char *module)
{
  cur_root = wide;
  mk_copy (helper, "aaa-first/bin/wfirst", 0755);
  for (int i = 0; i < WIDE_FILLERS; ++i)
    {
      char *d = xasprintf ("filler-%04d", i);
      char *f = xasprintf ("filler-%04d-1.0.squashfs", i);
      mk_dir (d);
      mk_file (f, 0644);
      free (d);
      free (f);
    }
  mk_copy (helper, "m-mid/bin/wmid", 0755);
  mk_copy (helper, "zzz-last/bin/wlast", 0755);
  mk_copy (module, "zzz-last/lib/tst-fswc-oracle-wide.so", 0755);
  cur_root = tree;
}

static void
build_jumble (const char *helper)
{
  cur_root = jumble;
  uint32_t x = 88172645u;
  for (int i = 0; i < JUMBLE_PACKAGES; ++i)
    {
      x ^= x << 13;
      x ^= x >> 17;
      x ^= x << 5;
      size_t len = 1 + x % 250;
      char name[256];
      for (size_t j = 0; j < len; ++j)
        {
          x ^= x << 13;
          x ^= x >> 17;
          x ^= x << 5;
          name[j] = "abcdefghijklmnopqrstuvwxyz0123456789_-"[x % 38];
        }
      name[len] = '\0';
      char *dir = xasprintf ("%s/%s", jumble, name);
      if (mkdir (dir, 0755) == 0)
        {
          char *rel = xasprintf ("%s/bin/jcmd", name);
          if (i == JUMBLE_PACKAGES / 2)
            mk_copy (helper, rel, 0755);
          else
            mk_file (rel, 0644);
          free (rel);
        }
      else
        TEST_COMPARE (errno, EEXIST);     /* A repeated name; harmless.  */
      free (dir);
    }
  cur_root = tree;
}

/* DEEP is ROOT extended with directories until it is DEEP_LEN bytes long.
   Then a package named with NAME_MAX bytes still fits (ROOT/<name>/bin is
   under PATH_MAX) but its candidate <name>/bin/deepcmd does not, while a
   short package's does.  "L..." sorts first and "~..." last, so a search
   meets ENAMETOOLONG both before a hit and as its final error.  */
enum { DEEP_LEN = 3832 };

static char *
make_deep (const char *root)
{
  char *path = xstrdup (root);
  while (strlen (path) < DEEP_LEN)
    {
      size_t room = DEEP_LEN - strlen (path) - 1;
      size_t n = room < 250 ? room : 250;
      if (n == 0)
        n = 1;
      char comp[256];
      memset (comp, 'd', n);
      comp[n] = '\0';
      char *next = xasprintf ("%s/%s", path, comp);
      xmkdir (next, 0755);
      free (path);
      path = next;
    }
  return path;
}

static void
build_deep (const char *helper, const char *module)
{
  cur_root = deep;
  char name[NAME_MAX + 1];
  name[NAME_MAX] = '\0';
  memset (name, 'L', NAME_MAX);
  char *rel = xasprintf ("%s/bin", name);
  mk_dir (rel);
  free (rel);
  memset (name, '~', NAME_MAX);
  rel = xasprintf ("%s/bin", name);
  mk_dir (rel);
  free (rel);
  mk_copy (helper, "s/bin/deepcmd", 0755);
  mk_copy (module, "s/lib/tst-fswc-oracle-deep.so", 0755);
  cur_root = tree;
}

/* With a scribbled index body behind a valid header, answers may be wrong
   by design (GLOB.md 4.5); the probes then only have to run without
   crashing, so mismatches are not failures.  */
static bool tolerant;

static void
mismatch (void)
{
  if (!tolerant)
    support_record_failure ();
}

/* glob probes.  */

static void
check_glob (const char *pattern, int flags)
{
  glob_t got, want;
  memset (&got, 0, sizeof (got));
  int rg = glob (pattern, flags, NULL, &got);
  int rw = ref_glob (pattern, flags, &want);

  bool same = rg == rw;
  if (same && rg == 0)
    {
      same = ((got.gl_flags & ~GLOB_ALTDIRFUNC)
              == (want.gl_flags & ~GLOB_ALTDIRFUNC))
             && got.gl_pathc == want.gl_pathc;
      for (size_t i = 0; same && i < got.gl_pathc; ++i)
        same = strcmp (got.gl_pathv[i], want.gl_pathv[i]) == 0;
    }
  if (!same)
    {
      mismatch ();
      printf ("error: glob \"%s\" flags %#x (locale %s): got %d, want %d\n",
              pattern, flags, setlocale (LC_COLLATE, NULL), rg, rw);
      for (size_t i = 0; rg == 0 && i < got.gl_pathc; ++i)
        printf ("  got[%zu]  %s\n", i, got.gl_pathv[i]);
      for (size_t i = 0; rw == 0 && i < want.gl_pathc; ++i)
        printf ("  want[%zu] %s\n", i, want.gl_pathv[i]);
    }
  if (rg == 0)
    globfree (&got);
  if (rw == 0)
    globfree (&want);
}

static void
glob_probes (void)
{
  /* Every pattern runs under every flag set, plus the flags it needs.  */
  static const int flag_sets[] =
    {
      0, GLOB_ONLYDIR, GLOB_MARK, GLOB_PERIOD, GLOB_PERIOD | GLOB_SKIPDOTS,
      GLOB_NOCHECK, GLOB_NOMAGIC, GLOB_ERR, GLOB_NOSORT,
    };
  static const struct { const char *suffix; int needs; } patterns[] =
    {
      { "/*", 0 },
      { "/*/bin", 0 },
      { "/*/bin/*", 0 },
      { "/*/bin/.*", 0 },
      { "/*/bin/tool", 0 },
      { "/*/bin/bash", 0 },
      { "/*/bin/bash/x", 0 },
      { "/*/bin/sx", 0 },
      { "/*/bin/missing", 0 },
      { "/*/bin/[bt]*", 0 },
      { "/*/*/bash", 0 },
      { "/*/*/*", 0 },
      { "/*/lib/*.so", 0 },
      { "/*/include/ncursesw/*", 0 },
      { "/*/include/ncursesw/ncursesw/curses.h", 0 },
      { "/*/@(bin|lib)", GLOB_EXTMATCH },
      { "/*/BIN/BASH", GLOB_CASEFOLD },
      { "/{a,B}/bin/*", GLOB_BRACE },
      { "/**/curses.h", GLOB_GLOBSTAR },
      { "/nest/**/nestcmd", GLOB_GLOBSTAR },
      { "/lp/*/*", 0 },
      { "/*/bin/**", GLOB_GLOBSTAR },
      { "/NOPE", 0 },
    };
  for (size_t p = 0; p < array_length (patterns); ++p)
    for (size_t f = 0; f < array_length (flag_sets); ++f)
      {
        char *pat = xasprintf ("%s%s", tree, patterns[p].suffix);
        check_glob (pat, flag_sets[f] | patterns[p].needs);
        free (pat);
      }

  /* GLOB_PATHS lists, including empty segments ("." twice).  */
  char *list = xasprintf (":%s/*/bin:%s/*/include:", tree, tree);
  check_glob (list, GLOB_PATHS | GLOB_NOESCAPE | GLOB_ONLYDIR);
  check_glob (list, GLOB_PATHS | GLOB_NOESCAPE | GLOB_NOCHECK);
  free (list);
  list = xasprintf ("%s/*/bin/bash:%s/a/bin/sh:%s/*/bin/missing",
                    tree, tree, tree);
  check_glob (list, GLOB_PATHS | GLOB_NOESCAPE);
  check_glob (list, GLOB_PATHS | GLOB_NOESCAPE | GLOB_NOCHECK);
  free (list);

  /* The wide and deep prefixes, once each.  */
  static const char *const few[] = { "/*/bin/*", "/*/bin", "/*/lib/*" };
  for (size_t i = 0; i < array_length (few); ++i)
    {
      char *pat = xasprintf ("%s%s", wide, few[i]);
      check_glob (pat, 0);
      check_glob (pat, GLOB_ONLYDIR);
      free (pat);
      pat = xasprintf ("%s%s", deep, few[i]);
      check_glob (pat, 0);
      free (pat);
    }
  list = xasprintf ("%s/*/bin:%s/*/bin", wide, deep);
  check_glob (list, GLOB_PATHS);
  check_glob (list, GLOB_PATHS | GLOB_MARK);
  free (list);
  list = xasprintf ("%s/*/bin/*", locked);
  check_glob (list, 0);
  free (list);
  list = xasprintf ("%s/*/bin/tool", tlink);
  check_glob (list, 0);
  free (list);
  list = xasprintf ("{%s/*/bin}/jcmd", jumble);
  check_glob (list, GLOB_PATHS);
  free (list);
  list = xasprintf ("%s/*/bin/jcmd", jumble);
  check_glob (list, 0);
  free (list);
}

/* execvpe and posix_spawnp probes.  */

static char *search_path;       /* PATH for the probes.  */

/* What execvp must do with NAME, worked out by the plain walk: the
   candidates of each PATH element in order (a whole "*" component expands
   to every directory in that directory whose name does not start with
   ".", in byte order; the command name always follows it), tried until
   one is an executable regular file.  An error that means "not here"
   (ENOENT, ESTALE, ENOTDIR, ENAMETOOLONG, ENODEV, ETIMEDOUT, or EACCES,
   which is remembered) moves on to the next candidate; any other error
   (ELOOP, say) ends the search with that error at once.  Otherwise the
   search fails with EACCES if a candidate existed but could not be run,
   else with the error of the last candidate (statx gives the same error
   execve would).  Returns the path that must run, or NULL
   and *ERR.  */
/* The existing candidates the last expected_exec call saw, in order:
   what glob ("{PATH}/NAME", GLOB_PATHS) must return.  */
static char **existing;
static size_t num_existing;

static char *
expected_exec (const char *name, int *err)
{
  for (size_t i = 0; i < num_existing; ++i)
    free (existing[i]);
  free (existing);
  existing = NULL;
  num_existing = 0;
  /* execvp refuses a name longer than NAME_MAX before searching.  */
  if (strlen (name) > NAME_MAX)
    {
      *err = ENAMETOOLONG;
      return NULL;
    }
  bool eacces = false;
  int last = ENOENT;
  int stop = 0;                 /* An error that ended the search.  */
  char *result = NULL;
  char *elems = xstrdup (search_path);
  char *save;
  for (char *e = strtok_r (elems, ":", &save); e != NULL;
       e = strtok_r (NULL, ":", &save))
    {
      /* The candidates of this element.  */
      char **cands = NULL;
      size_t ncands = 0;
      /* The components that are exactly "*", wherever they are (a
         relative element may start with one).  */
      size_t stars = 0;
      char *star = NULL;
      for (char *c = e; ; )
        {
          char *end = strchrnul (c, '/');
          if (end - c == 1 && *c == '*')
            {
              ++stars;
              star = c;
            }
          if (*end == '\0')
            break;
          c = end + 1;
        }
      if (stars > 1)
        ;                       /* More than one "*": no candidates.  */
      else if (stars == 1)
        {
          char *rest = star + 1;
          char *pat = xasprintf ("%.*s*", (int) (star - e), e);
          glob_t g;
          if (ref_glob (pat, 0, &g) == 0)
            {
              cands = xcalloc (g.gl_pathc, sizeof (char *));
              for (size_t i = 0; i < g.gl_pathc; ++i)
                {
                  struct stat st;
                  if (ref_stat (g.gl_pathv[i], &st) == 0
                      && S_ISDIR (st.st_mode))
                    cands[ncands++] = xasprintf ("%s%s/%s", g.gl_pathv[i],
                                                 rest, name);
                }
              globfree (&g);
            }
          free (pat);
        }
      else
        {
          cands = xcalloc (1, sizeof (char *));
          cands[ncands++] = xasprintf ("%s/%s", e, name);
        }

      char *found = NULL;
      for (size_t i = 0; i < ncands; ++i)
        {
          struct stat st;
          if (ref_lstat (cands[i], &st) == 0)
            {
              existing = xrealloc (existing,
                                   (num_existing + 1) * sizeof (char *));
              existing[num_existing++] = xstrdup (cands[i]);
            }
          if (found == NULL && result == NULL && stop == 0)
            {
              if (ref_stat (cands[i], &st) != 0)
                {
                  last = errno;
                  if (errno == EACCES)
                    eacces = true;
                  else if (errno != ENOENT && errno != ESTALE
                           && errno != ENOTDIR && errno != ENAMETOOLONG
                           && errno != ENODEV && errno != ETIMEDOUT)
                    stop = errno;
                }
              else if (S_ISREG (st.st_mode)
                       && syscall (SYS_faccessat2, AT_FDCWD, cands[i],
                                   X_OK, AT_EACCESS) == 0)
                found = xstrdup (cands[i]);
              else
                {
                  eacces = true;
                  last = EACCES;
                }
            }
          free (cands[i]);
        }
      free (cands);
      if (found != NULL && result == NULL)
        result = found;
      else
        free (found);
    }
  free (elems);
  if (result == NULL)
    *err = stop != 0 ? stop : eacces ? EACCES : last;
  return result;
}

/* Read everything from FD.  */
static char *
slurp (int fd)
{
  size_t len = 0, cap = 256;
  char *buf = xmalloc (cap);
  ssize_t n;
  while ((n = read (fd, buf + len, cap - len - 1)) > 0)
    {
      len += n;
      if (cap - len - 1 == 0)
        buf = xrealloc (buf, cap *= 2);
    }
  buf[len] = '\0';
  return buf;
}

/* The ways a command is run: execvpe after fork, posix_spawnp (whose
   child shares memory with the parent), and execvpe after vfork (which
   may only read an index the parent already mapped).  */
enum exec_how { EXEC_FORK, EXEC_SPAWN, EXEC_VFORK, EXEC_HOWS };
static const char *const exec_how_name[] =
  { "execvpe", "posix_spawnp", "vfork+execvpe" };

/* Run NAME as HOW says.  Returns what the helper printed (the path that
   ran), or "errno N".  */
static char *
actual_exec (const char *name, enum exec_how how)
{
  bool spawn = how == EXEC_SPAWN;
  int pfd[2];
  xpipe (pfd);
  char *argv[] = { (char *) name, NULL };
  pid_t pid;
  if (spawn)
    {
      posix_spawn_file_actions_t fa;
      TEST_COMPARE (posix_spawn_file_actions_init (&fa), 0);
      TEST_COMPARE (posix_spawn_file_actions_adddup2 (&fa, pfd[1], 1), 0);
      /* A stale errno must never leak into the result.  */
      errno = EXDEV;
      int r = posix_spawnp (&pid, name, &fa, NULL, argv, environ);
      posix_spawn_file_actions_destroy (&fa);
      if (r != 0)
        {
          xclose (pfd[0]);
          xclose (pfd[1]);
          return xasprintf ("errno %d", r);
        }
    }
  else if (how == EXEC_VFORK)
    {
      pid = vfork ();
      TEST_VERIFY_EXIT (pid >= 0);
      if (pid == 0)
        {
          /* Only async-signal-safe calls in a vfork child.  */
          if (dup2 (pfd[1], 1) < 0)
            _exit (126);
          errno = EXDEV;
          execvpe (name, argv, environ);
          char buf[32] = "errno ";
          char digits[12];
          int e = errno, k = 0;
          do
            digits[k++] = '0' + e % 10;
          while ((e /= 10) > 0);
          char *q = buf + 6;
          while (k > 0)
            *q++ = digits[--k];
          if (write (1, buf, q - buf) < 0)
            _exit (125);
          _exit (0);
        }
    }
  else
    {
      pid = xfork ();
      if (pid == 0)
        {
          xclose (pfd[0]);
          if (dup2 (pfd[1], 1) < 0)
            _exit (126);
          errno = EXDEV;
          execvpe (name, argv, environ);
          dprintf (1, "errno %d", errno);
          _exit (0);
        }
    }
  xclose (pfd[1]);
  char *out = slurp (pfd[0]);
  xclose (pfd[0]);
  int status;
  xwaitpid (pid, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
  return out;
}

/* glob with GLOB_PATHS must list exactly the candidates execvp considers,
   in the same order: they share one walker.  */
static void
check_search_list (const char *name)
{
  char *pat = xasprintf ("{%s}/%s", search_path, name);
  glob_t g;
  memset (&g, 0, sizeof (g));
  int r = glob (pat, GLOB_PATHS, NULL, &g);
  bool same = r == (num_existing > 0 ? 0 : GLOB_NOMATCH)
              && (r != 0 || g.gl_pathc == num_existing);
  for (size_t i = 0; same && r == 0 && i < g.gl_pathc; ++i)
    same = strcmp (g.gl_pathv[i], existing[i]) == 0;
  if (!same)
    {
      mismatch ();
      printf ("error: glob \"%s\" GLOB_PATHS: got %d\n", pat, r);
      for (size_t i = 0; r == 0 && i < g.gl_pathc; ++i)
        printf ("  got[%zu]  %s\n", i, g.gl_pathv[i]);
      for (size_t i = 0; i < num_existing; ++i)
        printf ("  want[%zu] %s\n", i, existing[i]);
    }
  if (r == 0)
    globfree (&g);
  free (pat);
}

static void
check_exec (const char *name)
{
  int err = 0;
  char *want_path = expected_exec (name, &err);
  check_search_list (name);
  char *want = want_path != NULL ? want_path : xasprintf ("errno %d", err);
  for (int how = 0; how < EXEC_HOWS; ++how)
    {
      char *got = actual_exec (name, how);
      if (strcmp (got, want) != 0)
        {
          mismatch ();
          printf ("error: %s \"%s\": got \"%s\", want \"%s\"\n",
                  exec_how_name[how], name, got, want);
        }
      free (got);
    }
  free (want);
}

static void
exec_probes (const char *const *names)
{
  for (; *names != NULL; ++names)
    check_exec (*names);
}

/* A command name one byte longer than NAME_MAX.  */
static char toolong_name[NAME_MAX + 2];

static const char *const tree_names[] =
  { "tool", "late", "noexec", "dirhere", "sh", "bash", "sx", "hidden",
    "edge", "onlylast", "longcmd", "fifocmd", "dangle", "loopcmd", "sock",
    toolong_name, "missing", NULL };
static const char *const top_names[] = { "rootcmd", "tool", "missing", NULL };
static const char *const locked_names[] = { "lockedcmd", "missing", NULL };
static const char *const wide_names[] =
  { "wfirst", "wmid", "wlast", "missing", NULL };
static const char *const deep_names[] = { "deepcmd", "missing", NULL };
static const char *const jumble_names[] = { "jcmd", "missing", NULL };

/* dlopen probes.  */

#ifdef FSWC_ORACLE_STATIC
static void
check_dlopen (const char *name)
{
}
#else
static void
check_dlopen (const char *name)
{
  char *want = NULL;
  const char *const roots[] = { tree, deep, wide };
  for (size_t r = 0; r < array_length (roots) && want == NULL; ++r)
    {
      char *pat = xasprintf ("%s/*/lib/%s", roots[r], name);
      glob_t g;
      if (ref_glob (pat, 0, &g) == 0)
        {
          want = xstrdup (g.gl_pathv[0]);
          globfree (&g);
        }
      free (pat);
    }

  void *h = dlopen (name, RTLD_NOW);
  const char *got = NULL;
  struct link_map *lm = NULL;
  if (h != NULL && dlinfo (h, RTLD_DI_LINKMAP, &lm) == 0)
    got = lm->l_name;
  if ((got == NULL) != (want == NULL)
      || (got != NULL && strcmp (got, want) != 0))
    {
      mismatch ();
      printf ("error: dlopen \"%s\": got %s, want %s\n", name,
              got != NULL ? got : "(not found)",
              want != NULL ? want : "(not found)");
    }
  /* A miss reports the last candidate's error.  The tree's plain file
     sorts last but is not a package, so that is ENOENT, never ENOTDIR
     (upstream's tst-dlopenfail checks the same over the real /sw).  */
  if (h == NULL && want == NULL)
    {
      const char *err = dlerror ();
      if (err == NULL || strstr (err, "No such file or directory") == NULL)
        {
          mismatch ();
          printf ("error: dlopen \"%s\": dlerror %s, want ENOENT\n", name,
                  err != NULL ? err : "(none)");
        }
    }
  if (h != NULL)
    xdlclose (h);
  free (want);
}

#endif

static void
dlopen_probes (void)
{
  check_dlopen ("tst-fswc-oracle-mod.so");
  check_dlopen ("tst-fswc-oracle-wide.so");
  check_dlopen ("tst-fswc-oracle-deep.so");
  check_dlopen ("tst-fswc-oracle-missing.so");
}

/* Driver.  */

/* The FSWC test hook (GLIBC_PRIVATE): register a prefix whose directories
   all count as sealed, then check, build, or remove its index.  Returns 0
   if a valid index is in use.  */
enum { HOOK_CHECK, HOOK_BUILD, HOOK_REMOVE };
static int (*fswc_hook) (const char *, int);

static void
get_hook (void)
{
#ifdef FSWC_ORACLE_STATIC
  extern int __fswc_test_prefix (const char *, int);
  fswc_hook = __fswc_test_prefix;
#else
  fswc_hook = dlsym (RTLD_DEFAULT, "__fswc_test_prefix");
#endif
  TEST_VERIFY_EXIT (fswc_hook != NULL);
}

/* Put the FSWC index for the tree into STATE, and prove it is there.  */
/* Ways to damage a published index (parent_corrupt), each of which a
   fresh process must reject, except "body", which it must survive.  */
static const char *const corrupt_kinds[] =
  { "truncated", "half", "header", "mode", "symlink", "body" };

static bool
is_corrupt_kind (const char *state)
{
  for (size_t i = 0; i < array_length (corrupt_kinds); ++i)
    if (strcmp (state, corrupt_kinds[i]) == 0)
      return true;
  return false;
}

/* Build PREFIX's index, retrying while a build declines (it does when
   the prefix changed within the current tick of the coarse clock).  */
static int
build_index_of (const char *prefix)
{
  int r = ENOENT;
  for (int i = 0; i < 200 && (r = fswc_hook (prefix, HOOK_BUILD)) != 0; ++i)
    {
      struct timespec ts = { 0, 10 * 1000 * 1000 };
      nanosleep (&ts, NULL);
    }
  return r;
}

static int
build_index (void)
{
  return build_index_of (tree);
}

/* The search-list prefixes, which the states other than the damaged-index
   ones treat like TREE.  DEEP is longer than any prefix FSWC indexes
   (FSWC_PREFIX_MAX, 256 bytes), so it is refused and always walked.  */
static void
others_hook (int op)
{
  const char *const others[] = { wide, jumble };
  for (size_t i = 0; i < array_length (others); ++i)
    if (op == HOOK_BUILD)
      TEST_COMPARE (build_index_of (others[i]), 0);
    else if (op == HOOK_CHECK)
      TEST_COMPARE (fswc_hook (others[i], op), ENOENT);
    else
      fswc_hook (others[i], op);  /* Our own mapping outlives the unlink.  */
  if (op != HOOK_REMOVE)
    TEST_COMPARE (fswc_hook (deep, op), ENOSPC);
  if (op == HOOK_BUILD)
    {
      TEST_COMPARE (fswc_hook (locked, op), ENOENT);
      TEST_COMPARE (fswc_hook (tlink, op), ENOENT);
    }
}

static void
enter_state (const char *state)
{
  get_hook ();
  if (strcmp (state, "none") == 0)
    {
      TEST_COMPARE (fswc_hook (tree, HOOK_CHECK), ENOENT);
      others_hook (HOOK_CHECK);
      return;
    }
  if (strcmp (state, "body") == 0)
    {
      /* The header is intact, so the index is accepted and the probes
         below run their lookups over the scribbled entries.  */
      TEST_COMPARE (fswc_hook (tree, HOOK_CHECK), 0);
      tolerant = true;
      int null = xopen ("/dev/null", O_WRONLY, 0);
      xdup2 (null, STDOUT_FILENO);
      xclose (null);
      return;
    }
  if (is_corrupt_kind (state))
    {
      /* The parent damaged the index this process now finds.  */
      TEST_COMPARE (fswc_hook (tree, HOOK_CHECK), ENOENT);
      return;
    }
  if (strcmp (state, "mount") == 0)
    {
      /* The parent changed the mounts beneath the tree after a child built
         its index: the index must be refused, and the probes then see the
         plain walk.  */
      TEST_COMPARE (fswc_hook (tree, HOOK_CHECK), ENOENT);
      return;
    }
  if (strcmp (state, "build") == 0)
    {
      /* Build for the parent, which must never map an index it is about to
         damage: truncating a file under a mapping raises SIGBUS (as with
         any mmapped cache).  */
      TEST_COMPARE (build_index (), 0);
      return;
    }
  if (strcmp (state, "stampede") == 0)
    {
      /* Many processes at once: one builds, the others carry on without
         an index or with the one just published.  Either way every
         answer must be right.  */
      fswc_hook (tree, HOOK_BUILD);
      fswc_hook (wide, HOOK_BUILD);
      fswc_hook (deep, HOOK_BUILD);
      fswc_hook (jumble, HOOK_BUILD);
      return;
    }

  TEST_COMPARE (build_index (), 0);
  others_hook (HOOK_BUILD);

  if (strcmp (state, "stale") == 0)
    {
      /* A new name in the prefix makes the snapshot out of date.  */
      char *p = tpath ("zz");
      xmkdir (p, 0755);
      free (p);
      TEST_COMPARE (fswc_hook (tree, HOOK_CHECK), ENOENT);
    }
}

static void
leave_state (const char *state)
{
  if (strcmp (state, "stale") == 0)
    {
      char *p = tpath ("zz");
      TEST_COMPARE (rmdir (p), 0);
      free (p);
    }
  /* Don't leave the index in /dev/shm.  This process keeps its mapping,
     as any process does after an unlink, so the result is not checked.
     The parent cleans up after damaged indexes and stampedes.  */
  if (strcmp (state, "valid") == 0 || strcmp (state, "stale") == 0)
    {
      fswc_hook (tree, HOOK_REMOVE);
      others_hook (HOOK_REMOVE);
    }
}

#ifndef FSWC_ORACLE_STATIC
/* Under LD_DEBUG=libs or LD_AUDIT, ld.so must try every candidate the
   plain walk would, even with a valid index: the debug output lists each
   file tried and an audit module sees each one through la_objsearch.  The
   packages of TREE whose lib directory shows up in LOG (one path per
   line, after "trying file=" for LD_DEBUG) must be exactly TREE's
   directories.  */
static void
check_tried (const char *log)
{
  int fd = open (log, O_RDONLY);
  TEST_VERIFY_EXIT (fd >= 0);
  char *text = slurp (fd);
  xclose (fd);

  glob_t g;
  char *pat = xasprintf ("%s/*", tree);
  TEST_COMPARE (ref_glob (pat, 0, &g), 0);
  free (pat);
  size_t prefix_len = strlen (tree) + 1;
  for (size_t i = 0; i < g.gl_pathc; ++i)
    {
      struct stat st;
      bool dir = ref_stat (g.gl_pathv[i], &st) == 0 && S_ISDIR (st.st_mode);
      char *want = xasprintf ("%s/lib/", g.gl_pathv[i]);
      bool tried = strstr (text, want) != NULL;
      if (tried != dir)
        {
          support_record_failure ();
          printf ("error: %s: package %s %s\n", log,
                  g.gl_pathv[i] + prefix_len,
                  dir ? "was never tried" : "is not a directory but was tried");
        }
      free (want);
    }
  globfree (&g);
  free (text);
}

static void
tried_probe (const char *state)
{
  /* The index exists and is valid; ld.so must not answer from it.  */
  TEST_COMPARE (build_index (), 0);
  TEST_COMPARE (fswc_hook (tree, HOOK_CHECK), 0);
  void *h = dlopen ("tst-fswc-oracle-missing.so", RTLD_NOW);
  TEST_VERIFY (h == NULL);
  char *log = strcmp (state, "debug") == 0
              ? xasprintf ("%s.%d", getenv ("LD_DEBUG_OUTPUT"), (int) getpid ())
              : xstrdup (getenv ("FSWC_ORACLE_AUDIT_LOG"));
  check_tried (log);
  free (log);
  fswc_hook (tree, HOOK_REMOVE);
}
#else
static void
tried_probe (const char *state)
{
}
#endif

/* Many threads at once, with an index being rebuilt by another process
   all the while: glob, posix_spawnp, and dlopen must still give the
   plain walk's answers, and nothing may crash or deadlock.  One thread
   forks as well, and globs in the child.  */
enum { THREADS = 8, THREAD_ROUNDS = 25 };

static const char *const thread_globs[] =
  { "/*/bin/tool", "/*/bin/*", "/*/lib/*.so", "/*/bin/missing", "/*" };
static const char *const thread_cmds[] = { "tool", "late", "noexec",
                                           "missing" };
static char *thread_want[array_length (thread_cmds)];

static void *
thread_main (void *arg)
{
  uintptr_t n = (uintptr_t) arg;
  for (int round = 0; round < THREAD_ROUNDS; ++round)
    {
      char *pat = xasprintf ("%s%s", tree,
                             thread_globs[(n + round)
                                          % array_length (thread_globs)]);
      check_glob (pat, 0);
      free (pat);
      size_t c = (n + round) % array_length (thread_cmds);
      char *got = actual_exec (thread_cmds[c], EXEC_SPAWN);
      if (strcmp (got, thread_want[c]) != 0)
        {
          support_record_failure ();
          printf ("error: thread %d: posix_spawnp \"%s\": got \"%s\", want "
                  "\"%s\"\n", (int) n, thread_cmds[c], got, thread_want[c]);
        }
      free (got);
      check_dlopen ("tst-fswc-oracle-mod.so");
      if (n == 0)
        {
          pid_t pid = xfork ();
          if (pid == 0)
            {
              char *p = xasprintf ("%s/*/bin/*", tree);
              check_glob (p, 0);
              free (p);
              _exit (0);
            }
          int status;
          xwaitpid (pid, &status, 0);
          TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
        }
    }
  return NULL;
}

static void
threads_probe (char *self);

/* The other process of the threads state: drop and rebuild the index
   until the file STOP exists.  */
static void
rebuilder (const char *stop)
{
  while (access (stop, F_OK) != 0)
    {
      fswc_hook (tree, HOOK_REMOVE);
      fswc_hook (tree, HOOK_BUILD);
    }
  fswc_hook (tree, HOOK_REMOVE);
}

/* Run every probe twice in this process: the first pass may be the one
   that maps FSWC state, the second must reuse it.  */
static int
worker (const char *state)
{
  if (strcmp (state, "debug") == 0 || strcmp (state, "audit") == 0)
    {
      get_hook ();
      tried_probe (state);
      return 0;
    }
  if (strcmp (state, "rebuilder") == 0)
    {
      get_hook ();
      rebuilder (getenv ("FSWC_ORACLE_STOP"));
      return 0;
    }
  if (strcmp (state, "threads") == 0)
    {
      get_hook ();
      threads_probe (getenv ("FSWC_ORACLE_SELF"));
      return 0;
    }
  enter_state (state);
  if (strcmp (state, "build") == 0)
    return 0;
  /* A literal element last, and a wildcard element alone (so no literal
     execve attempt can mask what the wildcard search leaves in errno).  */
  char *paths[] =
    {
      xasprintf ("%s/*/bin:%s/a/bin", tree, tree),
      xasprintf ("%s/*/bin", tree),
      /* No candidates at all: no execve runs to set errno.  */
      xasprintf ("%s/missing/*/bin", tree),
      xasprintf ("%s/*/bin/*", tree),
      xasprintf ("%s/*/bin", wide),
      xasprintf ("%s/*/bin", deep),
      xasprintf ("%s/*/bin", jumble),
      /* Doubled and trailing slashes are kept as written.  */
      xasprintf ("%s//*//bin//", tree),
      /* "*" as the last component: the command in the package itself.  */
      xasprintf ("%s/*", tree),
      xasprintf ("%s/*/bin", locked),
      xasprintf ("%s/*/bin", tlink),
      /* Directly under the root.  */
      xstrdup ("/*/fswc-oracle-no-such-dir"),
    };
  const char *const *names[] =
    { tree_names, tree_names, tree_names, tree_names, wide_names,
      deep_names, jumble_names, tree_names, top_names, locked_names,
      tree_names, wide_names };
  memset (toolong_name, 'q', NAME_MAX + 1);
  for (int pass = 0; pass < 2; ++pass)
    {
      TEST_VERIFY_EXIT (setlocale (LC_ALL, "en_US.UTF-8") != NULL);
      glob_probes ();
      TEST_VERIFY_EXIT (setlocale (LC_ALL, "C") != NULL);
      glob_probes ();
      for (size_t i = 0; i < array_length (paths); ++i)
        {
          search_path = paths[i];
          TEST_COMPARE (setenv ("PATH", search_path, 1), 0);
          exec_probes (names[i]);
        }
      dlopen_probes ();

      /* Relative elements, which no index serves, from inside the tree.  */
      xchdir (tree);
      static const char *const relative[] = { "*/bin", "./*/bin" };
      for (size_t i = 0; i < array_length (relative); ++i)
        {
          search_path = (char *) relative[i];
          TEST_COMPARE (setenv ("PATH", search_path, 1), 0);
          exec_probes (tree_names);
        }
      xchdir ("/");
    }
  for (size_t i = 0; i < array_length (paths); ++i)
    free (paths[i]);
  leave_state (state);
  return 0;
}

/* Re-run this program as a worker in a fresh process, through the same
   loader invocation the test harness used, with LD_LIBRARY_PATH (which
   carries the tree's wildcard library directory) folded into
   --library-path.  */
static pid_t
spawn_worker (char *self, const char *state)
{
  TEST_COMPARE (setenv ("FSWC_ORACLE_STATE", state, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_SELF", self, 1), 0);
  /* Workers run with glibc's malloc checking, which aborts on a write
     past the end of a block from malloc (glob's, say; ld.so's own
     allocations do not go through the checker).  Not
     the threads state: the checker's own lock is not reset by fork, so a
     child forked while another thread holds it would wait forever.  */
  if (strcmp (state, "threads") != 0 && strcmp (state, "rebuilder") != 0)
    {
      char *debug = xasprintf ("%s/malloc/libc_malloc_debug.so",
                               support_objdir_root);
      TEST_COMPARE (setenv ("LD_PRELOAD", debug, 1), 0);
      TEST_COMPARE (setenv ("MALLOC_CHECK_", "3", 1), 0);
      free (debug);
    }
  pid_t pid = xfork ();
  if (pid == 0)
    {
      char *child_argv[] = { self, (char *) "--direct", NULL };
      struct support_spawn_wrapped *w
        = support_spawn_wrap (self, child_argv, NULL, 0);
      const char *llp = getenv ("LD_LIBRARY_PATH");
      for (size_t i = 0; w->argv[i] != NULL; ++i)
        if (strcmp (w->argv[i], "--library-path") == 0
            && w->argv[i + 1] != NULL)
          {
            ((char **) w->argv)[i + 1]
              = xasprintf ("%s:%s", w->argv[i + 1], llp);
            break;
          }
      execve (w->path, w->argv, w->envp);
      _exit (127);
    }
  unsetenv ("LD_PRELOAD");
  unsetenv ("MALLOC_CHECK_");
  return pid;
}

static void
threads_probe (char *self)
{
  TEST_COMPARE (build_index (), 0);
  search_path = xasprintf ("%s/*/bin", tree);
  TEST_COMPARE (setenv ("PATH", search_path, 1), 0);
  for (size_t i = 0; i < array_length (thread_cmds); ++i)
    {
      int err = 0;
      char *want = expected_exec (thread_cmds[i], &err);
      thread_want[i] = want != NULL ? want : xasprintf ("errno %d", err);
    }
  char *stop = xasprintf ("%s.stop", tree);
  unlink (stop);
  TEST_COMPARE (setenv ("FSWC_ORACLE_STOP", stop, 1), 0);
  pid_t rb = spawn_worker (self, "rebuilder");
  pthread_t th[THREADS];
  for (uintptr_t i = 0; i < THREADS; ++i)
    th[i] = xpthread_create (NULL, thread_main, (void *) i);
  for (size_t i = 0; i < THREADS; ++i)
    xpthread_join (th[i]);
  xclose (xopen (stop, O_WRONLY | O_CREAT, 0644));
  int status;
  xwaitpid (rb, &status, 0);
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
  unlink (stop);
  free (stop);
  for (size_t i = 0; i < array_length (thread_cmds); ++i)
    free (thread_want[i]);
  fswc_hook (tree, HOOK_REMOVE);
}

static void
wait_worker (pid_t pid)
{
  int status;
  xwaitpid (pid, &status, 0);
  /* A crash (say, SIGSEGV on a damaged index) fails here.  */
  TEST_VERIFY (WIFEXITED (status) && WEXITSTATUS (status) == 0);
}

static void
run_worker (char *self, const char *state)
{
  printf ("info: FSWC state: %s\n", state);
  wait_worker (spawn_worker (self, state));
}

/* The published index file for the tree: idx-<mntns>-<dev>-<ino> in this
   user's directory.  */
static char *
index_path (void)
{
  struct stat st;
  xstat (tree, &st);
  char *pat = xasprintf ("/dev/shm/.fswc-*/idx-*-%llu-%llu",
                         ((unsigned long long) major (st.st_dev) << 32)
                         | minor (st.st_dev),
                         (unsigned long long) st.st_ino);
  glob_t g;
  TEST_COMPARE (glob (pat, 0, NULL, &g), 0);
  TEST_COMPARE (g.gl_pathc, 1);
  char *r = xstrdup (g.gl_pathv[0]);
  globfree (&g);
  free (pat);
  return r;
}

/* Have a child build the tree's index, then damage it as KIND says.  */
static void
parent_corrupt (char *self, const char *kind)
{
  wait_worker (spawn_worker (self, "build"));
  char *idx = index_path ();
  struct stat st;
  xstat (idx, &st);
  xchmod (idx, 0600);
  if (strcmp (kind, "truncated") == 0)
    TEST_COMPARE (truncate (idx, 0), 0);
  else if (strcmp (kind, "half") == 0)
    TEST_COMPARE (truncate (idx, st.st_size / 2), 0);
  else if (strcmp (kind, "header") == 0 || strcmp (kind, "body") == 0)
    {
      /* "header": the first 64 bytes.  "body": everything after the
         header and the mount list (which validation checks against the
         kernel), with a deterministic pseudo-random pattern, so that the
         index is accepted and lookups run over garbage.  */
      bool body = kind[0] == 'b';
      int fd = xopen (idx, O_RDWR, 0);
      uint32_t mounts[2];       /* num_mounts, mounts_off: bytes 72..79.  */
      TEST_COMPARE (pread (fd, mounts, sizeof mounts, 72), sizeof mounts);
      off_t from = body ? mounts[1] + (off_t) mounts[0] * 8 : 0;
      off_t to = body ? st.st_size : 64;
      uint32_t x = 2463534242u;
      for (off_t off = from; off < to; ++off)
        {
          x ^= x << 13;
          x ^= x >> 17;
          x ^= x << 5;
          unsigned char c = body ? (unsigned char) x : 0xa5;
          TEST_COMPARE (pwrite (fd, &c, 1, off), 1);
        }
      xclose (fd);
    }
  if (strcmp (kind, "mode") == 0)
    xchmod (idx, 0644);
  else
    xchmod (idx, 0400);
  if (strcmp (kind, "symlink") == 0)
    {
      char *real = xasprintf ("%s.real", idx);
      TEST_COMPARE (rename (idx, real), 0);
      xsymlink (real, idx);
      free (real);
    }
  free (idx);
}

static void
parent_cleanup (const char *kind)
{
  if (strcmp (kind, "symlink") == 0)
    {
      char *idx = index_path ();
      char *real = xasprintf ("%s.real", idx);
      unlink (real);
      free (real);
      free (idx);
    }
  fswc_hook (tree, HOOK_REMOVE);
}

/* The mount rows, in a user and mount namespace of their own: the tree is
   a mount, as /sw is, and so is each package; then each way the mounts
   beneath it can change must make the index stale, and the probes must
   then see the plain walk.  */
static const char *const mounted_packages[] = { "B", "_u", "a", "c" };

static void
xmount_tmpfs (const char *path)
{
  if (mount ("tmpfs", path, "tmpfs", 0, "mode=0755") != 0)
    FAIL_EXIT1 ("mount tmpfs on %s: %m", path);
}

static void
mount_change (char *self, const char *what, void (*change) (void))
{
  printf ("info: FSWC state: mount (%s)\n", what);
  wait_worker (spawn_worker (self, "build"));
  change ();
  wait_worker (spawn_worker (self, "mount"));
  fswc_hook (tree, HOOK_REMOVE);
}

static const char *mount_helper, *mount_module;

static void
change_replace (void)
{
  /* Package "a" is replaced by a mount with other contents.  */
  char *a = tpath ("a");
  TEST_COMPARE (umount2 (a, MNT_DETACH), 0);
  xmount_tmpfs (a);
  mk_copy (mount_helper, "a/bin/tool", 0755);
  mk_copy (mount_helper, "a/bin/newcmd", 0755);
  free (a);
}

static void
change_unmount (void)
{
  /* Package "c" is unmounted, leaving its empty mount point.  */
  char *c = tpath ("c");
  TEST_COMPARE (umount2 (c, MNT_DETACH), 0);
  free (c);
}

static void
change_nested (void)
{
  /* Something is mounted inside package "B", hiding its commands.  */
  char *bin = tpath ("B/bin");
  xmount_tmpfs (bin);
  free (bin);
}

static void
change_same (void)
{
  /* Package "_u" is remounted with the very same contents: the answers
     do not change, but the snapshot no longer describes these mounts.  */
  char *u = tpath ("_u");
  TEST_COMPARE (umount2 (u, MNT_DETACH), 0);
  xmount_tmpfs (u);
  mk_copy (mount_module, "_u/lib/tst-fswc-oracle-mod.so", 0755);
  free (u);
}

static void
change_over (void)
{
  /* A new, empty file system is mounted over the whole prefix.  */
  xmount_tmpfs (tree);
}

static void
mount_rows (char *self, const char *tmp, const char *helper,
            const char *module)
{
  pid_t pid = xfork ();
  if (pid != 0)
    {
      wait_worker (pid);
      return;
    }
  if (!support_become_root () || !support_enter_mount_namespace ())
    {
      puts ("info: no user and mount namespace here: mount rows skipped");
      _exit (0);
    }
  char *mtree = xasprintf ("%s/mounted", tmp);
  xmkdir (mtree, 0755);
  if (mount ("tmpfs", mtree, "tmpfs", 0, "mode=0755") != 0)
    {
      printf ("info: cannot mount tmpfs here (%m): mount rows skipped\n");
      _exit (0);
    }
  tree = cur_root = mtree;
  for (size_t i = 0; i < array_length (mounted_packages); ++i)
    {
      char *p = tpath (mounted_packages[i]);
      xmkdir (p, 0755);
      xmount_tmpfs (p);
      free (p);
    }
  build_tree (helper, module);
  mount_helper = helper;
  mount_module = module;
  TEST_COMPARE (setenv ("FSWC_ORACLE_TREE", tree, 1), 0);
  char *llp = xasprintf ("%s/*/lib:%s/*/lib:%s/*/lib", tree, deep, wide);
  TEST_COMPARE (setenv ("LD_LIBRARY_PATH", llp, 1), 0);
  free (llp);

  run_worker (self, "none");
  run_worker (self, "valid");
  mount_change (self, "a package replaced", change_replace);
  mount_change (self, "a package unmounted", change_unmount);
  mount_change (self, "a mount inside a package", change_nested);
  mount_change (self, "a package remounted unchanged", change_same);
  mount_change (self, "the prefix mounted over", change_over);
  TEST_COMPARE (umount2 (tree, MNT_DETACH), 0);
  rm_long (tree, "lp");
  _exit (0);
}

static int
rm_entry (const char *path, const struct stat *st, int type, struct FTW *ftw)
{
  (void) st;
  (void) type;
  if (ftw->level > 0)
    remove (path);
  return 0;
}

static int
do_test (int argc, char *argv[])
{
  (void) argc;
  const char *worker_tree = getenv ("FSWC_ORACLE_TREE");
  if (worker_tree != NULL)
    {
      tree = cur_root = worker_tree;
      wide = getenv ("FSWC_ORACLE_WIDE");
      deep = getenv ("FSWC_ORACLE_DEEP");
      jumble = getenv ("FSWC_ORACLE_JUMBLE");
      locked = getenv ("FSWC_ORACLE_LOCKED");
      tlink = getenv ("FSWC_ORACLE_TLINK");
      return worker (getenv ("FSWC_ORACLE_STATE"));
    }

  char *tmp = support_create_temp_directory ("tst-fswc-oracle-");
  char *root = xasprintf ("%s/sw", tmp);
  xmkdir (root, 0755);
  tree = cur_root = root;
  char *wide_root = xasprintf ("%s/wide", tmp);
  xmkdir (wide_root, 0755);
  wide = wide_root;
  deep = make_deep (tmp);
  char *jumble_root = xasprintf ("%s/jumble", tmp);
  xmkdir (jumble_root, 0755);
  jumble = jumble_root;
  char *helper = xasprintf ("%s/posix/tst-fswc-oracle-exec",
                            support_objdir_root);
  char *module = xasprintf ("%s/posix/tst-fswc-oracle-mod.so",
                            support_objdir_root);
  build_tree (helper, module);
  build_wide (helper, module);
  build_deep (helper, module);
  build_jumble (helper);
  char *locked_root = xasprintf ("%s/locked", tmp);
  locked = locked_root;
  cur_root = locked;
  mk_copy (helper, "pkg/bin/lockedcmd", 0755);
  cur_root = tree;
  xchmod (locked_root, 0300);
  char *tlink_path = xasprintf ("%s/tlink", tmp);
  xsymlink ("sw", tlink_path);
  tlink = tlink_path;
  TEST_COMPARE (setenv ("FSWC_ORACLE_TREE", tree, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_WIDE", wide, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_DEEP", deep, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_JUMBLE", jumble, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_LOCKED", locked, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_TLINK", tlink, 1), 0);
  /* DEEP's candidates are longer than the element as written by up to
     NAME_MAX bytes, more than the loader's per-element buffer allows; its
     "L..." package's candidates do not fit in PATH_MAX at all.  WIDE comes
     last, so a miss ends on its plain ENOENT.  */
  char *llp = xasprintf ("%s/*/lib:%s/*/lib:%s/*/lib", tree, deep, wide);
  TEST_COMPARE (setenv ("LD_LIBRARY_PATH", llp, 1), 0);

  /* No index yet (the plain walk), a valid one, and one the tree has
     changed under (the plain walk again).  Each runs in a fresh process,
     so library initialization runs as it does for real programs.  */
  run_worker (argv[0], "none");
  run_worker (argv[0], "valid");
  run_worker (argv[0], "stale");

  /* This process drives the damaged-index states, so it needs the hook
     and the tree registered too.  */
  get_hook ();

  /* Sixteen fresh processes all trying to build the same index.  */
  printf ("info: FSWC state: stampede (16 processes)\n");
  pid_t pids[16];
  for (size_t i = 0; i < array_length (pids); ++i)
    pids[i] = spawn_worker (argv[0], "stampede");
  for (size_t i = 0; i < array_length (pids); ++i)
    wait_worker (pids[i]);
  fswc_hook (tree, HOOK_REMOVE);
  fswc_hook (wide, HOOK_REMOVE);
  fswc_hook (deep, HOOK_REMOVE);
  fswc_hook (jumble, HOOK_REMOVE);

  for (size_t i = 0; i < array_length (corrupt_kinds); ++i)
    {
      parent_corrupt (argv[0], corrupt_kinds[i]);
      run_worker (argv[0], corrupt_kinds[i]);
      parent_cleanup (corrupt_kinds[i]);
    }

#ifndef FSWC_ORACLE_STATIC
  /* LD_DEBUG and LD_AUDIT, each with a valid index ld.so must ignore.  */
  printf ("info: FSWC state: debug\n");
  char *dbg = xasprintf ("%s/ld-debug", tmp);
  TEST_COMPARE (setenv ("LD_DEBUG", "libs", 1), 0);
  TEST_COMPARE (setenv ("LD_DEBUG_OUTPUT", dbg, 1), 0);
  wait_worker (spawn_worker (argv[0], "debug"));
  unsetenv ("LD_DEBUG");
  unsetenv ("LD_DEBUG_OUTPUT");
  free (dbg);
  printf ("info: FSWC state: audit\n");
  char *audit = xasprintf ("%s/posix/tst-fswc-oracle-audit.so",
                           support_objdir_root);
  char *audit_log = xasprintf ("%s/audit.log", tmp);
  TEST_COMPARE (setenv ("LD_AUDIT", audit, 1), 0);
  TEST_COMPARE (setenv ("FSWC_ORACLE_AUDIT_LOG", audit_log, 1), 0);
  wait_worker (spawn_worker (argv[0], "audit"));
  unsetenv ("LD_AUDIT");
  free (audit);
  free (audit_log);
#endif

  printf ("info: FSWC state: threads (%d, with an index rebuilt under "
          "them)\n", THREADS);
  wait_worker (spawn_worker (argv[0], "threads"));

  mount_rows (argv[0], tmp, helper, module);

  char *sx = tpath ("c/bin");
  xchmod (sx, 0755);
  free (sx);
  rm_long (tree, "lp");
  xchmod (locked_root, 0755);
  nftw (tmp, rm_entry, 32, FTW_DEPTH | FTW_PHYS);
  free (llp);
  free (module);
  free (helper);
  free (root);
  free (tmp);
  return 0;
}

#define TEST_FUNCTION_ARGV do_test
/* Every state runs in fresh processes over about five thousand entries.  */
#define TIMEOUT 300
#include <support/test-driver.c>
