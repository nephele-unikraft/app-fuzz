#ifndef SRC_OS_SYSCALL_H_
#define SRC_OS_SYSCALL_H_

#define _GNU_SOURCE
#include <unistd.h>

#define OS_SYSCALL(...) syscall(__VA_ARGS__)

#endif /* SRC_OS_SYSCALL_H_ */
