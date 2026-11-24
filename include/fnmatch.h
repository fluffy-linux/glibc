#ifndef _FNMATCH_H

#include <posix/fnmatch.h>

#ifndef _ISOMAC
libc_hidden_proto (fnmatch)
extern int __fnmatch (const char *__pattern, const char *__name, int __flags);
libc_hidden_proto (__fnmatch)
#endif

#endif
