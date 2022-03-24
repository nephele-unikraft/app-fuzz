#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <stdio.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#endif

/* Logging */

//#define ENABLE_DEBUG_PRINT 1
#ifdef ENABLE_DEBUG_PRINT
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif
#define INFO(...)  printf(__VA_ARGS__)
#define ERROR(...) fprintf(stderr, __VA_ARGS__)


#endif /* SRC_UTILS_H_ */
