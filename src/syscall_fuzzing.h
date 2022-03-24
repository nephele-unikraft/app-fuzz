#ifndef SRC_SYSCALL_FUZZING_H_
#define SRC_SYSCALL_FUZZING_H_

#include <stdint.h>

#pragma pack(1)
typedef struct {
	uint32_t id;
	struct {
		uint32_t param0;
		uint32_t param1;
		uint32_t param2;
		uint32_t param3;
		uint32_t param4;
		uint32_t param5;
	} p;
} call_t;

extern call_t gCall;
extern int do_write_ready;
extern int do_trace_syscalls;

int  syscall_fuzzing_init(void *init_content);
long syscall_fuzzing_exec(void);

#endif /* SRC_SYSCALL_FUZZING_H_ */
