/* Audit module for tst-fswc-oracle: log every library candidate tried.
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

/* Under LD_AUDIT, ld.so must try every candidate the plain walk would,
   so that la_objsearch sees each one; the FSWC index must not answer in
   its place.  This module appends each name la_objsearch receives to
   the file FSWC_ORACLE_AUDIT_LOG names, one per line.  */

#include <fcntl.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned int
la_version (unsigned int version)
{
  return LAV_CURRENT;
}

char *
la_objsearch (const char *name, uintptr_t *cookie, unsigned int flag)
{
  const char *log = getenv ("FSWC_ORACLE_AUDIT_LOG");
  if (log != NULL)
    {
      int fd = open (log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (fd >= 0)
        {
          size_t len = strlen (name);
          if (write (fd, name, len) == (ssize_t) len)
            (void) write (fd, "\n", 1);
          close (fd);
        }
    }
  return (char *) name;
}
