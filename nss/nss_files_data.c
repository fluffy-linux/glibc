/* Returns a pointer to the global nss_files data structure.
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

#include <nss_files.h>

#include <allocate_once.h>
#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* This collects all per file-data.   */
struct nss_files_data
{
  struct nss_files_per_file_data files[nss_file_count];
};

/* For use with allocate_once.  */
static void *nss_files_global;
static void *
nss_files_global_allocate (void *closure)
{
  struct nss_files_data *result = malloc (sizeof (*result));
  if (result != NULL)
    {
      for (int i = 0; i < nss_file_count; ++i)
        {
          result->files[i].stream = NULL;
          result->files[i].seen_slots = NULL;
          result->files[i].seen_count = 0;
          result->files[i].seen_cap = 0;
          __libc_lock_init (result->files[i].lock);
        }
    }
  return result;
}

static uint32_t
nss_seen_hash (const char *s)
{
  uint32_t h = 2166136261u;
  for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; ++p)
    h = (h ^ *p) * 16777619u;
  return h == 0 ? 1u : h;
}

static void
nss_seen_clear (struct nss_files_per_file_data *data)
{
  if (data->seen_slots != NULL)
    {
      for (size_t i = 0; i < data->seen_cap; ++i)
        free (data->seen_slots[i].name);
      free (data->seen_slots);
      data->seen_slots = NULL;
    }
  data->seen_count = 0;
  data->seen_cap = 0;
}

int
__nss_files_data_check_seen (struct nss_files_per_file_data *data,
                             const char *name, int file_idx)
{
  if (file_idx < 0 || name == NULL || name[0] == '\0')
    return 0;

  uint32_t h = nss_seen_hash (name);
  if (data->seen_cap > 0)
    {
      size_t mask = data->seen_cap - 1;
      size_t idx = h & mask;
      while (data->seen_slots[idx].name != NULL)
        {
          if (data->seen_slots[idx].hash == h
              && strcmp (data->seen_slots[idx].name, name) == 0)
            return data->seen_slots[idx].file_idx < file_idx ? 1 : 0;
          idx = (idx + 1) & mask;
        }
    }

  if ((data->seen_count + 1) * 2 >= data->seen_cap)
    {
      size_t new_cap = data->seen_cap == 0 ? 32 : data->seen_cap * 2;
      struct nss_files_seen_slot *new_slots
        = calloc (new_cap, sizeof (*new_slots));
      if (new_slots == NULL)
        return -1;
      size_t new_mask = new_cap - 1;
      for (size_t i = 0; i < data->seen_cap; ++i)
        if (data->seen_slots[i].name != NULL)
          {
            size_t nidx = data->seen_slots[i].hash & new_mask;
            while (new_slots[nidx].name != NULL)
              nidx = (nidx + 1) & new_mask;
            new_slots[nidx] = data->seen_slots[i];
          }
      free (data->seen_slots);
      data->seen_slots = new_slots;
      data->seen_cap = new_cap;
    }

  char *dup = __strdup (name);
  if (dup == NULL)
    return -1;

  size_t mask = data->seen_cap - 1;
  size_t idx = h & mask;
  while (data->seen_slots[idx].name != NULL)
    idx = (idx + 1) & mask;
  data->seen_slots[idx].name = dup;
  data->seen_slots[idx].hash = h;
  data->seen_slots[idx].file_idx = file_idx;
  ++data->seen_count;
  return 0;
}

/* Like __nss_files_data_open, but does not perform the open call.  */
static enum nss_status
__nss_files_data_get (struct nss_files_per_file_data **pdata,
                      enum nss_files_file file, int *errnop, int *herrnop)
{
  struct nss_files_data *data = allocate_once (&nss_files_global,
                                               nss_files_global_allocate,
                                               NULL, NULL);
  if (data == NULL)
    {
      if (errnop != NULL)
        *errnop = errno;
      if (herrnop != NULL)
        {
          __set_h_errno (NETDB_INTERNAL);
          *herrnop = NETDB_INTERNAL;
        }
      return NSS_STATUS_TRYAGAIN;
    }

  *pdata = &data->files[file];
  __libc_lock_lock ((*pdata)->lock);
  return NSS_STATUS_SUCCESS;
}

/* Helper function for opening the backing file at PATH.  */
static enum nss_status
__nss_files_data_internal_open (struct nss_files_per_file_data *data,
                                const char *path)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  if (data->stream == NULL)
    {
      data->stream = __nss_files_fopen (path);

      if (data->stream == NULL)
        status = errno == EAGAIN ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;
    }

  return status;
}


enum nss_status
__nss_files_data_open (struct nss_files_per_file_data **pdata,
                       enum nss_files_file file, const char *path,
                       int *errnop, int *herrnop)
{
  enum nss_status status = __nss_files_data_get (pdata, file, errnop, herrnop);
  if (status != NSS_STATUS_SUCCESS)
    return status;

  /* Be prepared that the set*ent function was not called before.  */
  if ((*pdata)->stream == NULL)
    {
      int saved_errno = errno;
      status = __nss_files_data_internal_open (*pdata, path);
      __set_errno (saved_errno);
      if (status != NSS_STATUS_SUCCESS)
        __nss_files_data_put (*pdata);
    }

  return status;
}

libc_hidden_def (__nss_files_data_open)

void
__nss_files_data_put (struct nss_files_per_file_data *data)
{
  __libc_lock_unlock (data->lock);
}
libc_hidden_def (__nss_files_data_put)

enum nss_status
__nss_files_data_setent (enum nss_files_file file, const char *path)
{
  struct nss_files_per_file_data *data;
  enum nss_status status = __nss_files_data_get (&data, file, NULL, NULL);
  if (status != NSS_STATUS_SUCCESS)
    return status;

  nss_seen_clear (data);
  if (data->stream == NULL)
    status = __nss_files_data_internal_open (data, path);
  else
    rewind (data->stream);

  __nss_files_data_put (data);
  return status;
}
libc_hidden_def (__nss_files_data_setent)

enum nss_status
__nss_files_data_endent (enum nss_files_file file)
{
  /* No cleanup is necessary if not initialized.  */
  struct nss_files_data *data = atomic_load_acquire (&nss_files_global);
  if (data == NULL)
    return NSS_STATUS_SUCCESS;

  struct nss_files_per_file_data *fdata = &data->files[file];
  __libc_lock_lock (fdata->lock);
  nss_seen_clear (fdata);
  if (fdata->stream != NULL)
    {
      fclose (fdata->stream);
      fdata->stream = NULL;
    }
  __libc_lock_unlock (fdata->lock);

  return NSS_STATUS_SUCCESS;
}
libc_hidden_def (__nss_files_data_endent)
