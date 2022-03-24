#ifndef SRC_OS_H_
#define SRC_OS_H_

#ifdef __Unikraft__
#include <os/unikraft/syscall.h>
#else
/* Linux */
#include <os/linux/syscall.h>
#endif

extern int os_syscall_params_num[];

long os_syscall_num(void);

int  os_fuzz_init(void);
long os_fuzz(void);

#endif /* SRC_OS_H_ */
