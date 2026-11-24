/* Initgroups handling in nss_files module.
   Copyright (C) 2011-2026 Free Software Foundation, Inc.
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

#include <errno.h>
#include <grp.h>
#include <nss.h>
#include <stdio_ext.h>
#include <string.h>
#include <sys/param.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <scratch_buffer.h>
#include <nss_files.h>

static uint32_t
initgroups_hash_name (const char *s)
{
  uint32_t h = 2166136261u;
  for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; ++p)
    h = (h ^ *p) * 16777619u;
  return h == 0 ? 1u : h;
}

static int
initgroups_check_seen (struct nss_files_seen_slot **slots_p,
                       size_t *count_p, size_t *cap_p,
                       const char *name, int file_idx)
{
  if (file_idx < 0 || name == NULL || name[0] == '\0'
      || name[0] == '+' || name[0] == '-')
    return 0;

  uint32_t h = initgroups_hash_name (name);
  struct nss_files_seen_slot *slots = *slots_p;
  size_t cap = *cap_p;

  if (cap > 0)
    {
      size_t mask = cap - 1;
      size_t idx = h & mask;
      while (slots[idx].name != NULL)
        {
          if (slots[idx].hash == h && strcmp (slots[idx].name, name) == 0)
            return slots[idx].file_idx < file_idx ? 1 : 0;
          idx = (idx + 1) & mask;
        }
    }

  if ((*count_p + 1) * 2 >= cap)
    {
      size_t new_cap = cap == 0 ? 32 : cap * 2;
      struct nss_files_seen_slot *new_slots
        = calloc (new_cap, sizeof (*new_slots));
      if (new_slots == NULL)
        return -1;
      size_t new_mask = new_cap - 1;
      for (size_t i = 0; i < cap; ++i)
        if (slots[i].name != NULL)
          {
            size_t nidx = slots[i].hash & new_mask;
            while (new_slots[nidx].name != NULL)
              nidx = (nidx + 1) & new_mask;
            new_slots[nidx] = slots[i];
          }
      free (slots);
      *slots_p = slots = new_slots;
      *cap_p = cap = new_cap;
    }

  char *dup = __strdup (name);
  if (dup == NULL)
    return -1;

  size_t mask = cap - 1;
  size_t idx = h & mask;
  while (slots[idx].name != NULL)
    idx = (idx + 1) & mask;
  slots[idx].name = dup;
  slots[idx].hash = h;
  slots[idx].file_idx = file_idx;
  ++(*count_p);
  return 0;
}

enum nss_status
_nss_files_initgroups_dyn (const char *user, gid_t group, long int *start,
			   long int *size, gid_t **groupsp, long int limit,
			   int *errnop)
{
  FILE *stream = __nss_files_fopen ("/etc/group");
  if (stream == NULL)
    {
      *errnop = errno;
      return *errnop == ENOMEM ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;
    }

  char *line = NULL;
  size_t linelen = 0;
  enum nss_status status = NSS_STATUS_SUCCESS;
  bool any = false;
  bool multifile = __nss_files_file_index (stream, 0) >= 0;
  struct nss_files_seen_slot *seen_slots = NULL;
  size_t seen_count = 0;
  size_t seen_cap = 0;

  struct scratch_buffer tmpbuf;
  scratch_buffer_init (&tmpbuf);

  gid_t *groups = *groupsp;

  /* We have to iterate over the entire file.  */
  while (1)
    {
      off64_t line_off = __ftello64 (stream);
      ssize_t n = __getline (&line, &linelen, stream);
      if (n < 0)
	{
	  if (! __feof_unlocked (stream))
	    status = ((*errnop = errno) == ENOMEM
		      ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL);
	  break;
	}

      struct group grp;
      int res = _nss_files_parse_grent (line, &grp,
					tmpbuf.data, tmpbuf.length, errnop);
      if (res == -1)
	{
	  if (!scratch_buffer_grow (&tmpbuf))
	    {
	      *errnop = ENOMEM;
	      status = NSS_STATUS_TRYAGAIN;
	      goto out;
	    }
	  /* Reread current line, the parser has clobbered it.  */
	  __fseeko64 (stream, line_off, SEEK_SET);
	  continue;
	}

      if (res > 0 && multifile)
	{
	  int fidx = __nss_files_file_index (stream, line_off);
	  int sres = initgroups_check_seen (&seen_slots, &seen_count,
					    &seen_cap, grp.gr_name, fidx);
	  if (sres < 0)
	    {
	      *errnop = ENOMEM;
	      status = NSS_STATUS_TRYAGAIN;
	      goto out;
	    }
	  if (sres > 0)
	    continue;
	}

      if (res > 0 && grp.gr_gid != group)
	for (char **m = grp.gr_mem; *m != NULL; ++m)
	  if (strcmp (*m, user) == 0)
	    {
	      bool dup_gid = false;
	      for (long int gi = 0; gi < *start; ++gi)
		if (groups[gi] == grp.gr_gid)
		  {
		    dup_gid = true;
		    break;
		  }
	      if (dup_gid)
		{
		  any = true;
		  break;
		}

	      /* Matches user.  Insert this group.  */
	      if (*start == *size)
		{
		  /* Need a bigger buffer.  */
		  if (limit > 0 && *size == limit)
		    /* We reached the maximum.  */
		    goto out;

		  long int newsize;
		  if (limit <= 0)
		    newsize = 2 * *size;
		  else
		    newsize = MIN (limit, 2 * *size);

		  gid_t *newgroups = realloc (groups,
					      newsize * sizeof (*groups));
		  if (newgroups == NULL)
		    {
		      *errnop = ENOMEM;
		      status = NSS_STATUS_TRYAGAIN;
		      goto out;
		    }
		  *groupsp = groups = newgroups;
		  *size = newsize;
		}

	      groups[*start] = grp.gr_gid;
	      *start += 1;
	      any = true;

	      break;
	    }
    }

 out:
  /* Free memory.  */
  if (seen_slots != NULL)
    {
      for (size_t i = 0; i < seen_cap; ++i)
        free (seen_slots[i].name);
      free (seen_slots);
    }
  scratch_buffer_free (&tmpbuf);
  free (line);

  fclose (stream);

  return status == NSS_STATUS_SUCCESS && !any ? NSS_STATUS_NOTFOUND : status;
}
libc_hidden_def (_nss_files_initgroups_dyn)
