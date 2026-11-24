/* Helper for tst-fswc-oracle: report which file the kernel executed.
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

/* Every execvpe/posix_spawnp candidate in the oracle's tree is a copy of
   this program.  It writes AT_EXECFN, the path execve was given, so the
   oracle can tell which of several same-named files ran.  It is linked
   statically so that running it never involves the host's ld.so.  */

#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

int
main (void)
{
  const char *path = (const char *) getauxval (AT_EXECFN);
  if (path == NULL)
    return 2;
  size_t len = strlen (path);
  return write (STDOUT_FILENO, path, len) == (ssize_t) len ? 0 : 3;
}
