#ifndef SRC_OS_SYSCALL_H_
#define SRC_OS_SYSCALL_H_

#include <uk/syscall.h>

#define OS_SYSCALL(...) uk_syscall(__VA_ARGS__)

#endif /* SRC_OS_SYSCALL_H_ */
