/* Test Fluffy stateless /etc multi-file NSS, nsswitch, host.conf, resolv.conf.
   Copyright (C) 2026 Free Software Foundation, Inc.  */

#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <resolv.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <support/check.h>
#include <support/support.h>
#include <support/xunistd.h>

static void
write_text (const char *path, const char *content)
{
  FILE *fp = fopen (path, "wb");
  TEST_VERIFY_EXIT (fp != NULL);
  size_t len = strlen (content);
  if (len > 0)
    TEST_COMPARE (fwrite (content, 1, len, fp), len);
  TEST_COMPARE (fclose (fp), 0);
}

static int
do_test (void)
{
  /* Ensure clean starting /etc inside the container.  */
  unlink ("/etc/nsswitch.conf");
  unlink ("/etc/host.conf");
  unlink ("/etc/resolv.conf");
  unlink ("/etc/passwd");
  unlink ("/etc/group");
  unlink ("/etc/hosts");
  unlink ("/etc/services");

  xmkdirp ("/sw/glibc/etc", 0755);
  xmkdirp ("/sw/pkgA/etc", 0755);
  xmkdirp ("/sw/pkgB/etc", 0755);
  xmkdirp ("/sw/systemd/etc", 0755);

  /* Vendor nsswitch.conf + host.conf (multi on) without /etc copies.  */
  write_text ("/sw/glibc/etc/nsswitch.conf",
              "passwd: files\n"
              "group: files\n"
              "hosts: files\n"
              "services: files\n");
  write_text ("/sw/glibc/etc/host.conf", "multi on\n");

  /* Vendor passwd across multiple packages, including no trailing newline
     and a long GECOS field to exercise ERANGE retry + seeking.  */
  char long_gecos[700];
  memset (long_gecos, 'G', sizeof (long_gecos) - 1);
  long_gecos[sizeof (long_gecos) - 1] = '\0';

  write_text ("/sw/glibc/etc/passwd",
              "root:x:0:0:root:/root:/sw/bash/bin/bash\n"
              "nobody:*:65534:65534:Unprivileged:/var/empty:/bin/false");
  /* Note: /sw/glibc/etc/passwd intentionally omits trailing newline!  */

  char *pkgA_pw = xasprintf ("svcA:*:1400000001:1400000001:%s:/:/bin/false\n"
                             "shared:*:1400000002:1400000002:VendorShared:/vendor:/bin/false\n",
                             long_gecos);
  write_text ("/sw/pkgA/etc/passwd", pkgA_pw);
  free (pkgA_pw);

  write_text ("/sw/pkgB/etc/passwd",
              "svcB:*:1400000003:1400000003:ServiceB:/:/bin/false\n");

  /* User /etc/passwd overrides 'shared' and adds local user 'alice'.  */
  write_text ("/etc/passwd",
              "shared:x:1400000002:1400000002:UserOverride:/home/shared:/sw/bash/bin/bash\n"
              "alice:x:1000:1000:Alice:/home/alice:/sw/bash/bin/bash");

  /* Direct lookups: user /etc wins over /sw/<pkg>, vendor users resolve cleanly.  */
  struct passwd *pw = getpwnam ("shared");
  TEST_VERIFY_EXIT (pw != NULL);
  TEST_COMPARE_STRING (pw->pw_gecos, "UserOverride");
  TEST_COMPARE_STRING (pw->pw_dir, "/home/shared");

  pw = getpwuid (65534);
  TEST_VERIFY_EXIT (pw != NULL);
  TEST_COMPARE_STRING (pw->pw_name, "nobody");

  pw = getpwnam ("svcB");
  TEST_VERIFY_EXIT (pw != NULL);
  TEST_COMPARE (pw->pw_uid, 1400000003U);

  /* Explicit small-buffer ERANGE retry on multi-file stream.  */
  size_t buflen = 32;
  char *buf = xmalloc (buflen);
  struct passwd pwbuf;
  struct passwd *pwres = NULL;
  int r;
  while ((r = getpwnam_r ("svcA", &pwbuf, buf, buflen, &pwres)) == ERANGE)
    {
      buflen *= 2;
      buf = xrealloc (buf, buflen);
    }
  TEST_COMPARE (r, 0);
  TEST_VERIFY_EXIT (pwres != NULL);
  TEST_COMPARE_STRING (pwres->pw_gecos, long_gecos);
  free (buf);

  /* Missing user must not clobber errno.  */
  errno = 0;
  TEST_VERIFY (getpwnam ("no_such_fluffy_user") == NULL);
  TEST_COMPARE (errno, 0);

  /* Enumeration via getpwent + setpwent rewind must deduplicate 'shared'.  */
  for (int pass = 0; pass < 2; ++pass)
    {
      setpwent ();
      int total = 0;
      int shared_cnt = 0;
      while ((pw = getpwent ()) != NULL)
        {
          ++total;
          if (strcmp (pw->pw_name, "shared") == 0)
            {
              ++shared_cnt;
              TEST_COMPARE_STRING (pw->pw_gecos, "UserOverride");
            }
        }
      TEST_COMPARE (shared_cnt, 1);
      TEST_COMPARE (total, 6);
    }
  endpwent ();

  /* Enough users for the table of names already seen to grow, with one
     of them overridden in /etc.  */
  {
    char *many = xstrdup ("");
    for (int i = 0; i < 40; ++i)
      {
        char *n = xasprintf ("%suser%02d:*:%d:%d:Vendor:/:/bin/false\n",
                             many, i, 1500000000 + i, 1500000000 + i);
        free (many);
        many = n;
      }
    xmkdirp ("/sw/pkgC/etc", 0755);
    write_text ("/sw/pkgC/etc/passwd", many);
    free (many);
    write_text ("/etc/passwd",
                "shared:x:1400000002:1400000002:UserOverride:/home/shared:/sw/bash/bin/bash\n"
                "alice:x:1000:1000:Alice:/home/alice:/sw/bash/bin/bash\n"
                "user07:x:1500000007:1500000007:EtcUser07:/:/bin/false\n");
    setpwent ();
    int total = 0;
    int user07_cnt = 0;
    while ((pw = getpwent ()) != NULL)
      {
        ++total;
        if (strcmp (pw->pw_name, "user07") == 0)
          {
            ++user07_cnt;
            TEST_COMPARE_STRING (pw->pw_gecos, "EtcUser07");
          }
      }
    endpwent ();
    TEST_COMPARE (user07_cnt, 1);
    TEST_COMPARE (total, 46);
  }

  /* Multi-file group + getgrouplist member removal override.
     pkgA puts alice in 'wheel' (gid 2001) and 'audio' (gid 2002).
     pkgB puts alice in 'video' (gid 2003).
     /etc/group overrides 'wheel' WITHOUT alice!  */
  write_text ("/sw/pkgA/etc/group",
              "wheel:x:2001:alice,bob\n"
              "audio:x:2002:alice\n");
  write_text ("/sw/pkgB/etc/group",
              "video:x:2003:alice");
  write_text ("/etc/group",
              "alice:x:1000:\n"
              "wheel:x:2001:bob\n");

  struct group *gr = getgrnam ("wheel");
  TEST_VERIFY_EXIT (gr != NULL);
  TEST_VERIFY (gr->gr_mem[0] != NULL && strcmp (gr->gr_mem[0], "bob") == 0);
  TEST_VERIFY (gr->gr_mem[1] == NULL);

  gid_t gids[16];
  int ngids = 16;
  TEST_VERIFY (getgrouplist ("alice", 1000, gids, &ngids) >= 0);
  bool has_1000 = false, has_2001 = false, has_2002 = false, has_2003 = false;
  for (int i = 0; i < ngids; ++i)
    {
      if (gids[i] == 1000) has_1000 = true;
      if (gids[i] == 2001) has_2001 = true;
      if (gids[i] == 2002) has_2002 = true;
      if (gids[i] == 2003) has_2003 = true;
    }
  TEST_VERIFY (has_1000);
  TEST_VERIFY (!has_2001); /* Removed by /etc/group override!  */
  TEST_VERIFY (has_2002);
  TEST_VERIFY (has_2003);

  /* Enough groups for initgroups' table of names already seen to grow,
     with one of them overridden in /etc without alice.  */
  {
    char *many = xstrdup ("");
    for (int i = 0; i < 20; ++i)
      {
        char *n = xasprintf ("%sg%02d:x:%d:alice\n", many, i, 3000 + i);
        free (many);
        many = n;
      }
    write_text ("/sw/pkgC/etc/group", many);
    free (many);
    write_text ("/etc/group",
                "alice:x:1000:\n"
                "wheel:x:2001:bob\n"
                "g05:x:3005:bob\n");
    gid_t many_gids[64];
    int nmany = 64;
    TEST_VERIFY (getgrouplist ("alice", 1000, many_gids, &nmany) >= 0);
    int in_range = 0;
    for (int i = 0; i < nmany; ++i)
      {
        TEST_VERIFY (many_gids[i] != 3005);
        if (many_gids[i] >= 3000 && many_gids[i] < 3020)
          ++in_range;
      }
    TEST_COMPARE (in_range, 19);
  }

  /* Vendor hosts + multi on: localhost resolves to both 127.0.0.1 and ::1,
     while /etc/hosts overrides custom host entries.  */
  write_text ("/sw/glibc/etc/hosts",
              "127.0.0.1 localhost\n"
              "::1 localhost ip6-localhost ip6-loopback\n"
              "10.0.0.1 box.fluffy\n");
  write_text ("/etc/hosts",
              "10.0.0.99 box.fluffy\n");

  struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
  struct addrinfo *ai = NULL;
  TEST_COMPARE (getaddrinfo ("localhost", NULL, &hints, &ai), 0);
  bool got_v4 = false, got_v6 = false;
  for (struct addrinfo *p = ai; p != NULL; p = p->ai_next)
    {
      if (p->ai_family == AF_INET)
        got_v4 = true;
      else if (p->ai_family == AF_INET6)
        got_v6 = true;
    }
  freeaddrinfo (ai);
  TEST_VERIFY (got_v4);
  TEST_VERIFY (got_v6);

  /* AF_INET6 lookups must parse the hosts files as AF_INET6: only ::1, never
     the IPv4 line.  With "multi on" the file walk continues past the first
     match, and an entry parsed as the wrong family used to abort in
     gethostbyname3_multi (h_length != 16).  */
  struct addrinfo hints6 = { .ai_family = AF_INET6, .ai_socktype = SOCK_STREAM };
  ai = NULL;
  TEST_COMPARE (getaddrinfo ("localhost", NULL, &hints6, &ai), 0);
  TEST_VERIFY_EXIT (ai != NULL);
  for (struct addrinfo *p = ai; p != NULL; p = p->ai_next)
    {
      TEST_COMPARE (p->ai_family, AF_INET6);
      TEST_VERIFY (IN6_IS_ADDR_LOOPBACK
                   (&((struct sockaddr_in6 *) p->ai_addr)->sin6_addr));
    }
  freeaddrinfo (ai);

  struct hostent *he6 = gethostbyname2 ("localhost", AF_INET6);
  TEST_VERIFY_EXIT (he6 != NULL);
  TEST_COMPARE (he6->h_addrtype, AF_INET6);
  TEST_COMPARE (he6->h_length, 16);
  TEST_VERIFY (IN6_IS_ADDR_LOOPBACK ((struct in6_addr *) he6->h_addr_list[0]));
  TEST_VERIFY (he6->h_addr_list[1] == NULL);

  struct addrinfo hints4 = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
  ai = NULL;
  TEST_COMPARE (getaddrinfo ("box.fluffy", NULL, &hints4, &ai), 0);
  TEST_VERIFY_EXIT (ai != NULL);
  struct sockaddr_in *sin = (struct sockaddr_in *) ai->ai_addr;
  TEST_COMPARE (ntohl (sin->sin_addr.s_addr), 0x0a000063U); /* 10.0.0.99 */
  freeaddrinfo (ai);

  /* Vendor resolv.conf symlink fallback + dangling symlink resilience +
     /etc/resolv.conf user override.  */
  write_text ("/tmp/stub-resolv.conf",
              "nameserver 127.0.0.53\n"
              "options ndots:3\n");
  xmkdirp ("/sw/aaa-dangling/etc", 0755);
  xsymlink ("/nonexistent/broken-vendor-resolv.conf",
            "/sw/aaa-dangling/etc/resolv.conf");
  xsymlink ("/nonexistent/broken-etc-resolv.conf", "/etc/resolv.conf");
  xsymlink ("/tmp/stub-resolv.conf", "/sw/systemd/etc/resolv.conf");

  struct __res_state statp;
  memset (&statp, 0, sizeof (statp));
  TEST_COMPARE (res_ninit (&statp), 0);
  TEST_COMPARE (statp.nscount, 1);
  TEST_COMPARE (ntohl (statp.nsaddr_list[0].sin_addr.s_addr), 0x7f000035U);
  TEST_COMPARE (statp.ndots, 3);
  res_nclose (&statp);

  unlink ("/etc/resolv.conf");

  write_text ("/etc/resolv.conf",
              "nameserver 1.1.1.1\n"
              "options ndots:2\n");
  memset (&statp, 0, sizeof (statp));
  TEST_COMPARE (res_ninit (&statp), 0);
  TEST_COMPARE (statp.nscount, 1);
  TEST_COMPARE (ntohl (statp.nsaddr_list[0].sin_addr.s_addr), 0x01010101U);
  TEST_COMPARE (statp.ndots, 2);
  res_nclose (&statp);

  /* A directory where a file should be is skipped: protocols from one
     package next to a directory of that name in another is that
     package's file alone, and networks with only directories has none.  */
  xmkdirp ("/sw/pkgA/etc/protocols", 0755);
  write_text ("/sw/pkgB/etc/protocols", "fluffyproto 253 FLUFFYPROTO\n");
  struct protoent *pe = getprotobyname ("fluffyproto");
  TEST_VERIFY_EXIT (pe != NULL);
  TEST_COMPARE (pe->p_proto, 253);
  xmkdirp ("/sw/pkgA/etc/networks", 0755);
  xmkdirp ("/sw/pkgB/etc/networks", 0755);
  TEST_VERIFY (getnetbyname ("fluffynet") == NULL);

  /* Partial /etc/nsswitch.conf override: disable 'services' while keeping
     'passwd: files' inherited from /sw/glibc/etc/nsswitch.conf!  */
  write_text ("/sw/glibc/etc/services", "fluffysvc 4242/tcp\n");
  struct servent *sv = getservbyname ("fluffysvc", "tcp");
  TEST_VERIFY_EXIT (sv != NULL);
  TEST_COMPARE (ntohs (sv->s_port), 4242);

  write_text ("/etc/nsswitch.conf", "services: nonexist_mod\n");
  TEST_VERIFY (getservbyname ("fluffysvc", "tcp") == NULL);
  /* passwd still works via vendor /sw/glibc/etc/nsswitch.conf!  */
  pw = getpwnam ("root");
  TEST_VERIFY_EXIT (pw != NULL);
  TEST_COMPARE (pw->pw_uid, 0U);

  return 0;
}

#include <support/test-driver.c>
