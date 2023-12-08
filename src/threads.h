#pragma once

#ifdef __GNUC__
#  ifndef __has_warning
#    define __has_warning(x) 0
#  endif
#  pragma GCC diagnostic push
#  if __has_warning("-Wreserved-identifier")
#    pragma GCC diagnostic ignored "-Wreserved-identifier"
#  endif
#endif // __GNUC__
#include <tinycthread.h>
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif // __GNUC__
